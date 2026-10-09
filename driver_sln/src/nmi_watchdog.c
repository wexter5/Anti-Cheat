/* ==========================================================================
 * nmi_watchdog.c -- контур NMI-вачдога (второй слой anti-tamper)
 * --------------------------------------------------------------------------
 * Восстановлен из цензуса массовых трейсов (RECON2_INVENTORY напр. 9,
 * "редкие api_resolve вне 259-таблицы"):
 *   api_resolve KeRegisterNmiCallback x2 независимые цепочки:
 *     0x1402b1c16 (цепочка C_088934; enl-тело fullbody6/bodies/
 *     ac_enl_2b1c06.c: api_resolve fnv 0xaa520fe89918f267 ->
 *     KeRegisterNmiCallback, tail-call continuation @0x1402b1c46)
 *     0x1403bd850 (цепочка A_087ecc)
 *   api_resolve KeDeregisterNmiCallback 0x1402b1c24
 *   api_resolve HalSendNMI 0x1402b1bfa
 *   api_resolve HalPerformEndOfInterrupt 0x1402a78bf
 *   api_resolve HalReturnToFirmware 0x14012afb2 (путь ребута)
 *   api_resolve HalSetEnvironmentVariableEx 0x140215e57 (запись UEFI-переменной)
 * Роль: per-CPU периодические проверки целостности из NMI-контекста --
 * слой anti-debug/anti-tamper НАД LSTAR-вачдогом (NMI не маскируется
 * локальным отладчиком/гипервизорным хуком syscall-пути); HalSendNMI
 * загоняет остальные CPU в ту же проверку (cross-CPU свип). Регистрация
 * едет на цепочке отложенного init'а (ничего не регистрируется в
 * DriverEntry, KERNEL_WALLS_FINAL §1.1).
 * Само тело callback'а -- VM-хаб (payload-selected интерьер); контракт
 * регистрации/teardown ниже -- восстановленная логика.
 * ========================================================================== */
#include <ntddk.h>

#include "provenance.h"
#include "tables.h"
#include "nmi_watchdog.h"
#include "anti_tamper.h"

/* HalSendNMI / HalPerformEndOfInterrupt отсутствуют в заголовках этого
 * WDK; объявлены по публичному контракту (сайты resolve доказывают usage) */
NTSYSAPI
NTSTATUS
NTAPI
HalSendNMI(
    _In_ PVOID Reserved
    );

NTSYSAPI
VOID
NTAPI
HalPerformEndOfInterrupt(
    VOID
    );

/* состояние вачдога NMI-контекста (KeRegisterNmiCallback возвращает HANDLE) */
static PVOID g_NmiHandle;
static volatile LONG g_NmiHits;

/* --------------------------------------------------------------------------
 * [0x1402b1c16]/[0x1403bd850] тело NMI-callback'а.
 * Исполняется на NMI IRQL на NMI'нутом CPU: легальны только lock-free
 * чтения. NMI-безопасные зонды целостности:
 *   - сравнение MSR_LSTAR с эталонной XOR-парой (тот же класс, что
 *     per-IOCTL вачдог, но из неперехватываемого контекста);
 *   - состояние LBR IA32_DEBUGCTL (0x1d9) (сбросы отладчика видны здесь).
 * Глубокая (VM) часть callback'а -- payload-selected: NMI-контекст в
 * оригинале входит в виртуализованный хаб через continuation-хвост
 * (@0x1402b1c46, fullbody6/bodies/ac_enl_2b1c06.c).
 * ------------------------------------------------------------------------ */
static BOOLEAN
NTAPI
AcNmiCallback(
    _In_ PVOID Context,
    _In_ BOOLEAN Handled
    )
{
    UINT64 lstar;
    UINT64 reference;

    UNREFERENCED_PARAMETER(Context);

    InterlockedIncrement(&g_NmiHits);

    /* NMI-безопасный зонд LSTAR (lock-free чтение pair-ячеек) */
    lstar = __readmsr(0xC0000082);
    reference = AC_SLOT64(AC_CELL_LSTAR_REF) ^
                AC_SLOT64(AC_CELL_LSTAR_REF + 8);
    if (lstar != reference && reference != 0) {
        /* пометка для passive-level форензик-пути (воркайтем-механика
         * LSTAR-вачдога работает на passive level) */
        AC_SLOT8(0x2dd1) = 1;       /* флаг NMI-аномалии (своя ячейка) */
    }

    /* перевооружение IA32_DEBUGCTL делается на passive level монитором LBR
     * ([0x140052201]); из NMI-контекста мы только флагаем сброс */
    if ((__readmsr(0x1d9) & 1) == 0)
        AC_SLOT8(0x2dd2) = 1;

    return Handled;
}

/* --------------------------------------------------------------------------
 * Регистрация (шаг отложенного init'а).
 * [0x1402b1c16]/[0x1403bd850] KeRegisterNmiCallback (две независимые
 * цепочки -- регистрация зовётся из отложенного пути, как и любая другая
 * регистрация этого драйвера)
 * ------------------------------------------------------------------------ */
NTSTATUS
AcNmiWatchdogRegister(
    VOID
    )
{
    if (g_NmiHandle != NULL)
        return STATUS_SUCCESS;

    /* KeRegisterNmiCallback возвращает HANDLE регистрации (контракт WDK) */
    g_NmiHandle = KeRegisterNmiCallback(AcNmiCallback, NULL);
    return (g_NmiHandle != NULL) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

/* [0x1402b1c24] KeDeregisterNmiCallback (teardown, путь DriverUnload) */
VOID
AcNmiWatchdogUnregister(
    VOID
    )
{
    if (g_NmiHandle != NULL) {
        KeDeregisterNmiCallback(g_NmiHandle);
        g_NmiHandle = NULL;
    }
}

/* --------------------------------------------------------------------------
 * Cross-CPU свип: [0x1402b1bfa] HalSendNMI загоняет каждый другой CPU в
 * его NMI-callback (те же зонды целостности выполняются на всех
 * процессорах), [0x1402a78bf] HalPerformEndOfInterrupt закрывает
 * последовательность
 * ------------------------------------------------------------------------ */
VOID
AcNmiWatchdogSweepAllCpus(
    VOID
    )
{
    if (g_NmiHandle == NULL)
        return;

    HalSendNMI(NULL);
    HalPerformEndOfInterrupt();
}

/* флаги NMI-аномалий, потребляемые passive-level механикой (возвращает и
 * очищает; LSTAR/LBR-воркеры читают эти ячейки) */
/* [0x1402b1c16] передача флагов passive-level воркерам
 * (цепочка регистрации выше) */
UINT32
AcNmiWatchdogConsumeFlags(
    VOID
    )
{
    UINT32 flags = 0;

    if (AC_SLOT8(0x2dd1) != 0) {
        flags |= 1;
        AC_SLOT8(0x2dd1) = 0;
    }
    if (AC_SLOT8(0x2dd2) != 0) {
        flags |= 2;
        AC_SLOT8(0x2dd2) = 0;
    }
    return flags;
}

/* --------------------------------------------------------------------------
 * Компаньоны HAL-контура (тот же кластер редких resolve'ов):
 * [0x14012afb2] HalReturnToFirmware -- путь ребута через firmware
 *   (действие последней инстанции реакционной цепочки; разрешён, вызов
 *   едет на VM)
 * [0x140215e57] HalSetEnvironmentVariableEx -- запись UEFI-переменной из
 *   kernel (маркер персистентности/boot-состояния; разрешён, вызов едет
 *   на VM) -- оба resolved-and-consumed за VM-диспетчем
 *   (payload-selected call-сайты; RECON2 редкие api_resolve)
 * ------------------------------------------------------------------------ */
NTSTATUS
AcNmiWatchdogFirmwareReset(
    VOID
    )
{
    /* payload-selected: путь вызова HalReturnToFirmware -- VM-continuation;
     * resolve доказывает, что возможность существует */
    return STATUS_NOT_SUPPORTED;
}
