/* ==========================================================================
 * env_checks.c -- гейты окружения (цепочка P0 + инвентарь зондов)
 * --------------------------------------------------------------------------
 * Provenance:
 *   KERNEL_WALLS_FINAL §1.1 (P0 replay irpreg_de3.jsonl, 4.87M шагов):
 *     MmGetSystemRoutineAddress(InitSafeBootMode) -> cpuid(1) ->
 *     QSI 0x23 (SystemKernelDebuggerInformation) ->
 *     QSI 0x0B (SystemModuleInformation) -> lowercase-скан имён ->
 *     ExFreePool -> ret 0xC0EB0004
 *   client/devirt/_chk_ac_bodies.jsonl (qsi_pair replay-хиты): полный
 *   инвентарь QSI-классов драйвера (ниже, EnvRunProbes)
 *   client/ghidra/out/ac_region_names.json (имена по сайтам + evidence)
 *   HWID_DRIVER_COLLECTORS_CODE §7 (TPM/SecureBoot negative-доказательство)
 * ========================================================================== */
#include <ntddk.h>
#include <intrin.h>

#include "provenance.h"
#include "env_checks.h"
#include "kldr.h"
#include "tables.h"

/* ZwQuerySystemInformation не имеет прототипа в km-заголовках этого
 * WDK; объявлен по публичному контракту syscall'а */
NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
    _In_ UINT32 SystemInformationClass,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ UINT32 SystemInformationLength,
    _Out_opt_ PUINT32 ReturnLength
    );

/* --------------------------------------------------------------------------
 * Инвентарь QSI-классов драйвера (на replay, qsi_pair-события
 * _chk_ac_bodies.jsonl; имена по ac_region_names.json):
 *
 *   class 0x00 SystemBasicInformation        x21 сайтов (ac_qsi_basic_s01..s15)
 *   class 0x05 SystemProcessInformation      x 3 (ac_qsi_proc_info_s01..s03)
 *   class 0x0B SystemModuleInformation       цепочка boot P0 (скан списка модулей)
 *   class 0x10 SystemHandleInformation       x 1 (ac_qsi_c10_s01 0x1401f6dba)
 *   class 0x18 SystemDpcBehaviorInformation  x 2 (ac_qsi_c18_s01/s02)
 *   class 0x20 SystemCrashDumpInformation    x 2 (ac_qsi_c20_s01/s02)
 *   class 0x23 SystemKernelDebuggerInformation  цепочка boot P0 (2-байтовый зонд)
 *   class 0x28 SystemVerifierAddDriverInformation x 7 (ac_qsi_c28_s01..s07)
 *   class 0x4C SystemFirmwareTableInformation   fw_query_producer 0x14009cbb0
 *   class 0x5A SystemBootEnvironmentInformation x 1 (ac_qsi_c5a_s01 0x14018fa92)
 *   class 0x5B SystemHypervisorInformation      x 1 (тело 0x14030789b)
 *   class 0x67 SystemCodeIntegrityInformation   x 1 (ac_qsi_code_integrity_s01
 *                                                  0x140133ee1) -- проверка HVCI/CI
 * (хиты rcx=0x200/0x70 -- stale-регистровые replay-контексты, не классы)
 * ------------------------------------------------------------------------ */
#define AC_QSI_BASIC          0x00
#define AC_QSI_PROC_INFO      0x05
#define AC_QSI_MODULES        0x0B
#define AC_QSI_HANDLES        0x10
#define AC_QSI_DPC_BEHAVIOR   0x18
#define AC_QSI_CRASHDUMP      0x20
#define AC_QSI_KD             0x23
#define AC_QSI_VERIFIER_ADD   0x28
#define AC_QSI_FIRMWARE_TABLE 0x4C
#define AC_QSI_BOOT_ENV       0x5A
#define AC_QSI_HYPERVISOR     0x5B
#define AC_QSI_CODE_INTEGRITY 0x67

/* --------------------------------------------------------------------------
 * Обёртка generic-зонда (семейство хостов ac_qsi_*, 28 replay-сайтов).
 * [0x14012c4c0] ac_qsi_basic_s02 (env_checks.c v4 INDEX; цепочки C_012574)
 * ------------------------------------------------------------------------ */
NTSTATUS
EnvQsiProbe(
    _In_ UINT32 InfoClass,
    _Out_ PVOID Buffer,
    _In_ UINT32 BufferSize
    )
{
    return ZwQuerySystemInformation(InfoClass, Buffer, BufferSize, NULL);
}

/* --------------------------------------------------------------------------
 * Проверка HVCI / code-integrity.
 * [0x140133ee1] ac_qsi_code_integrity_s01 (replay: ZwQSI infoclass
 * code_integrity x1, ac_region_names.json idx 464, conf high)
 * SYSTEM_CODE_INTEGRITY_INFORMATION {Length, CodeIntegrityOptions}:
 *   bit0 CODEINTEGRITY_OPTION_ENABLED, bit1 CODEINTEGRITY_OPTION_TESTSIGN
 * (layout по публичному контракту; состояние HVCI едет на том же семействе
 * запросов, cf. service-side классы политики 0xA4/0xA5, SERVICE_HWID §1)
 * ------------------------------------------------------------------------ */
#pragma pack(push, 1)
typedef struct _AC_CODE_INTEGRITY_INFO {
    UINT32 Length;
    UINT32 CodeIntegrityOptions;
} AC_CODE_INTEGRITY_INFO, *PAC_CODE_INTEGRITY_INFO;
#pragma pack(pop)

NTSTATUS
EnvCheckCodeIntegrity(
    _Out_ UINT32* Options
    )
{
    AC_CODE_INTEGRITY_INFO info;
    NTSTATUS status;

    info.Length = sizeof(info);
    info.CodeIntegrityOptions = 0;

    status = ZwQuerySystemInformation(AC_QSI_CODE_INTEGRITY, &info,
                                      sizeof(info), NULL);
    if (NT_SUCCESS(status))
        *Options = info.CodeIntegrityOptions;
    return status;
}

/* --------------------------------------------------------------------------
 * Проверка boot-окружения (устройство/раздел, с которого загружена ОС).
 * [0x14018fa92] ac_qsi_c5a_s01 (replay: ZwQSI infoclass c5a = 0x5A
 * SystemBootEnvironmentInformation, цепочки B_0401e8/B_0738f4)
 * ------------------------------------------------------------------------ */
NTSTATUS
EnvCheckBootEnvironment(
    _Out_writes_bytes_(64) UINT8* Info
    )
{
    return ZwQuerySystemInformation(AC_QSI_BOOT_ENV, Info, 64, NULL);
}

/* --------------------------------------------------------------------------
 * Зонд класса гипервизора (OS-level информация о присутствии гипервизора).
 * [replay: ZwQSI class 0x5B SystemHypervisorInformation x1, тело
 * 0x14030789b, _chk_ac_bodies.jsonl]
 * ------------------------------------------------------------------------ */
NTSTATUS
EnvCheckHypervisorClass(
    _Out_writes_bytes_(16) UINT8* Info
    )
{
    return ZwQuerySystemInformation(AC_QSI_HYPERVISOR, Info, 16, NULL);
}

/* --------------------------------------------------------------------------
 * Детект VM: HV-гейт #1.
 * [0x1401c29f4] hv_gate_cpuid1_site: сайт cpuid(1).ecx bit 31 (hypervisor
 * present) в цепочке DriverEntry (P0); HV-ветка входит в HV-регион
 * 0x1403ee023 и выдаёт cpuid leaf 0x40000000 (vendor id, 12 символов в
 * ebx/ecx/edx: "Microsoft Hv" / "VMwareVMware" / "KVMKVMKVM" /
 * "XenVMMXenVMM") -- под HV зонд SystemKernelDebuggerInformation НЕ
 * исполняется (доказанный порядок, DISPATCH_CHAIN_C §1;
 * HYPERVISOR_DETECTION.md через golden v1 env_checks.c)
 * [0x140017960] hv_gate_chain2: голова цепочки HV-гейта #2 (тот же отчёт)
 *
 * Тело HV-региона -- VM-байткод (payload-selected внутренности); контракт
 * гейта ниже -- восстановленная, replay-доказанная форма.
 * [0x1400021fc] native role twin: нативная anti-VM проверка через 'aswVmm\vmm.cpp' (strings.h 0x14000232c; va_map)
 * ------------------------------------------------------------------------ */
BOOLEAN
EnvCheckHypervisor(
    VOID
    )
{
    INT cpuInfo[4];
    CHAR vendor[13];

    __cpuid(cpuInfo, 1);
    if ((cpuInfo[2] & (1u << 31)) == 0)
        return FALSE;

    /* hv_gate_cpuid1_site HV-ветка: чтение vendor по cpuid 0x40000000 */
    __cpuid(cpuInfo, 0x40000000);
    ((UINT32*)vendor)[0] = (UINT32)cpuInfo[1];   /* ebx */
    ((UINT32*)vendor)[1] = (UINT32)cpuInfo[2];   /* ecx */
    ((UINT32*)vendor)[2] = (UINT32)cpuInfo[3];   /* edx */
    vendor[12] = '\0';

    /* классификация вендора едет на HV-регионе; известные id гипервизоров:
     * "Microsoft Hv" (Hyper-V), "VMwareVMware", "KVMKVMKVM",
     * "XenVMMXenVMM", "VBoxVBoxVBox", "prl hyperv" (Parallels) */
    return TRUE;
}

/* --------------------------------------------------------------------------
 * Нативный детект CPU-фич (тот же набор leaf'ов, что использует HV/CPU
 * профиль).
 * [0x14003d8c8] cpu_feature_detect: cpuid 0/1/7 + xgetbv -> флаги фич
 * (дословное тело восстановлено, golden v1 hwid.c):
 *   cpuid(0): 0 в eax -> return -1 (сентинел)
 *   cpuid(1): ecx&1 (SSE3), edx>>26&1 (SSE2), ecx>>9&1 (SSSE3),
 *             ecx>>19&1 (SSE4.1), AVX-гейт ((ecx&0x1c000000)==0x1c000000
 *             && (xgetbv(0)&6)==6) -> AVX-флаг, затем cpuid(7): ebx>>5&1
 *             (AVX2), ecx>>1&1 (PCLMULQDQ), ecx>>25&1 (AES-NI)
 *   флаги хранятся в .data 0x140108d04..0x140108d2c; сентинел-ячейка
 *   0x140108d00=1 по завершении (struct в env_checks.h)
 * [0x1400a4250] native role twin: нативный детект cpuid+xgetbv, близнец роли cited 0x14003d8c8 (AC_NATIVE 6 bridge; va_map)
 * ------------------------------------------------------------------------ */
UINT32
EnvDetectCpuFeatures(
    _Out_ PAC_CPU_FEATURES Features
    )
{
    INT info[4];
    UINT32 ecx1;
    UINT32 edx1;
    BOOLEAN avxCapable;

    RtlZeroMemory(Features, sizeof(*Features));

    __cpuid(info, 0);
    if (info[0] == 0)
        return (UINT32)-1;                  /* сентинел (дословно) */

    __cpuid(info, 1);
    ecx1 = (UINT32)info[2];
    edx1 = (UINT32)info[3];

    Features->Sse3  = ecx1 & 1;
    Features->Sse2  = (edx1 >> 26) & 1;
    Features->Ssse3 = (ecx1 >> 9) & 1;
    Features->Sse41 = (ecx1 >> 19) & 1;

    /* AVX-гейт: флаги OSXSAVE+AVX+xsave все выставлены И в xcr0 есть XMM+YMM */
    avxCapable = FALSE;
    if ((ecx1 & 0x1c000000) == 0x1c000000) {
        UINT64 xcr0 = _xgetbv(0);
        if ((xcr0 & 6) == 6) {
            Features->Avx = 1;
            avxCapable = TRUE;
        }
    }

    Features->Avx2 = 0;
    if (avxCapable) {
        __cpuid(info, 7);
        Features->Avx2 = ((UINT32)info[1] >> 5) & 1;
    }

    Features->Pclmulqdq = (ecx1 >> 1) & 1;
    Features->AesNi     = (ecx1 >> 25) & 1;
    Features->Present   = 1;
    return 0;
}

/* --------------------------------------------------------------------------
 * Зонд kernel-отладчика (0x23): чтение 2 байтов {Enabled, NotPresent};
 * доказуемо ПРОПУСКАЕТСЯ под HV (порядок replay P0, DISPATCH_CHAIN_C §1)
 * ------------------------------------------------------------------------ */
/* [0x140006a90] шаг цепочки P0 (QSI 0x23; replay irpreg_de3.jsonl,
 * KERNEL_WALLS_FINAL раздел 1.1) */
static BOOLEAN
EnvCheckKernelDebugger(
    VOID
    )
{
    struct {
        UINT8 Enabled;
        UINT8 NotPresent;
    } kdInfo;
    NTSTATUS status;

    status = ZwQuerySystemInformation(AC_QSI_KD, &kdInfo, sizeof(kdInfo),
                                      NULL);
    if (!NT_SUCCESS(status))
        return FALSE;
    return (BOOLEAN)(kdInfo.Enabled != 0);
}

/* --------------------------------------------------------------------------
 * IRQL-гейты.
 * [0x140144a9e] ac_env_irql_check_s01 (+s02..s09: проверки expected-IRQL на
 * точках входа; env_checks.c v4 INDEX)
 * [0x1401271e6] vmexit_outbyte_port01_check_irql (зонд port I/O в паре
 * с проверкой IRQL; env_checks.c v4)
 * ------------------------------------------------------------------------ */
BOOLEAN
EnvCheckIrql(
    _In_ KIRQL Expected
    )
{
    return (BOOLEAN)(KeGetCurrentIrql() == Expected);
}

/* --------------------------------------------------------------------------
 * [0x140053a90] build_gate_offsets: таблица гейт-смещений, зависящая от
 * билда ОС (выбор семейства build 0x4a61 = 19041, заметка заголовка golden
 * v1 env_checks.c "build gate 0x4a61 (19041): structure-offset selection (v2)")
 * ------------------------------------------------------------------------ */
NTSTATUS
EnvBuildGateOffsets(
    VOID
    )
{
    RTL_OSVERSIONINFOW ver;

    ver.dwOSVersionInfoSize = sizeof(ver);
    if (!NT_SUCCESS(RtlGetVersion(&ver)))
        return STATUS_UNSUCCESSFUL;

    /* выбор таблицы гейт-смещений по номеру билда (19041/19045 = 22H2;
     * восстановленный сайт специализируется по билду) */
    AC_SLOT32(0x2dc8) = ver.dwBuildNumber;
    return STATUS_SUCCESS;
}

/* --------------------------------------------------------------------------
 * Скан списка модулей в P0 (boot-start / inventory-гейт).
 * [0x140006a90] шаг цепочки P0: ZwQuerySystemInformation(0x0B
 * SystemModuleInformation) -> lowercase-скан имён модулей ->
 * ExFreePool (replay KERNEL_WALLS_FINAL §1.1); сам драйвер -- boot-драйвер
 * SYSTEM_START (Start=1, присутствует в этом списке -- replay R150),
 * поэтому скан верифицирует boot-окружение модулей, на котором он едет
 * ------------------------------------------------------------------------ */
NTSTATUS
EnvScanModuleList(
    VOID
    )
{
    return AcKldrScanModuleNames();
}

/* --------------------------------------------------------------------------
 * Цепочка env-гейтов P0 (тело DriverEntry).
 * [0x1403d0389] ac_driverentry_hub: VM-хаб цепочки (ac_region_names
 * idx 13921, AC_REPLAY_BASE §5)
 * [0x140006a90] порядок replay P0 (KERNEL_WALLS_FINAL §1.1):
 *   1. MmGetSystemRoutineAddress(InitSafeBootMode) -> флаг safeboot
 *   2. HV-ветка cpuid(1) (hv_gate_cpuid1_site; HV -> cpuid 0x40000000,
 *      kd-зонд пропускается)
 *   3. QSI 0x23 SystemKernelDebuggerInformation
 *   4. QSI 0x0B SystemModuleInformation + lowercase-скан имён -> free
 *   5. ret токена
 *
 * Заметка по TPM/SecureBoot [neg, доказано]: драйвер НЕ выполняет проверок
 * TPM/TBS/PCR и SystemSecureBootInformation -- полный свип обоих корпусов
 * драйвера даёт 0 совпадений (HWID_DRIVER_COLLECTORS_CODE §7); этот класс
 * проверок живёт в user-mode сервисе. Kernel-side гейт целостности --
 * code-integrity QSI (0x67) выше.
 * ------------------------------------------------------------------------ */
NTSTATUS
EnvRunBootGates(
    VOID
    )
{
    UNICODE_STRING routineName;
    PVOID initSafeBootMode = NULL;
    BOOLEAN underHv;
    NTSTATUS status;
    UINT32 ciOptions;

    /* шаг 1: флаг safeboot */
    RtlInitUnicodeString(&routineName, L"InitSafeBootMode");
    initSafeBootMode = MmGetSystemRoutineAddress(&routineName);
    if (initSafeBootMode != NULL && *(UINT8*)initSafeBootMode != 0)
        return STATUS_UNSUCCESSFUL;

    /* шаг 2: HV-гейт #1 (cpuid(1) bit 31; HV-ветка -> cpuid 0x40000000) */
    underHv = EnvCheckHypervisor();

    /* шаг 3: kd-зонд -- доказуемо не исполняется под HV */
    if (!underHv && EnvCheckKernelDebugger())
        return STATUS_UNSUCCESSFUL;

    /* шаг 4: скан списка модулей (0x0B) + lowercase имён -> ExFreePool */
    status = EnvScanModuleList();
    if (!NT_SUCCESS(status))
        return status;

    /* гейт code-integrity (опции HVCI/CI) -- kernel-side проверка
     * целостности [0x140133ee1]; отказ самого запроса не фатален */
    if (NT_SUCCESS(EnvCheckCodeIntegrity(&ciOptions)))
        AC_SLOT32(0x2dcc) = ciOptions;

    return EnvBuildGateOffsets();
}

/* --------------------------------------------------------------------------
 * Оставшееся семейство зондов (исполняются из своих VM host-сайтов;
 * классы и числа сайтов на replay выше). Каждый возвращает сырой payload
 * класса.
 * ------------------------------------------------------------------------ */
/* классы/сайты зондов (replay): 0x14012c4c0 basic_s02,
 * 0x140189790 proc_info_s01, 0x1401f6dba c10, 0x14012f382 c18,
 * 0x140142146 c20, 0x140166365 c28, 0x14018fa92 c5a */
NTSTATUS
EnvRunProbes(
    VOID
    )
{
    UINT8 buf[0x200];

    /* ac_qsi_basic_s01..s15: SystemBasicInformation */
    ZwQuerySystemInformation(AC_QSI_BASIC, buf, sizeof(buf), NULL);
    /* ac_qsi_proc_info_s01..s03: SystemProcessInformation */
    ZwQuerySystemInformation(AC_QSI_PROC_INFO, buf, sizeof(buf), NULL);
    /* ac_qsi_c10_s01 0x1401f6dba: SystemHandleInformation */
    ZwQuerySystemInformation(AC_QSI_HANDLES, buf, sizeof(buf), NULL);
    /* ac_qsi_c18_s01/s02 0x14012f382/0x1403e3494: SystemDpcBehaviorInformation */
    ZwQuerySystemInformation(AC_QSI_DPC_BEHAVIOR, buf, sizeof(buf), NULL);
    /* ac_qsi_c20_s01/s02 0x140142146/0x140244367: SystemCrashDumpInformation */
    ZwQuerySystemInformation(AC_QSI_CRASHDUMP, buf, sizeof(buf), NULL);
    /* ac_qsi_c28_s01..s07: SystemVerifierAddDriverInformation */
    ZwQuerySystemInformation(AC_QSI_VERIFIER_ADD, buf, sizeof(buf), NULL);
    /* ac_qsi_c5a_s01 0x14018fa92: SystemBootEnvironmentInformation */
    ZwQuerySystemInformation(AC_QSI_BOOT_ENV, buf, sizeof(buf), NULL);

    return STATUS_SUCCESS;
}

/* --------------------------------------------------------------------------
 * Тайминг-детектор VM-exit по CPUID/FPU.
 * [0x140018324] cpuid_fpu_timing_protocol (дословное тело, golden v1
 * anti_tamper.c) -- 3-ролевый протокол, драйвится из VM блоком параметров
 * [a1]=fn0, [a1+8]=fn1(роль), [a1+16]=флаг FPU-нагрузки
 * (master-версия: timing_protocol_master 0x140018af0, сайт 0x140018B60;
 * 0 code-вызывающих -- адрес сидит в VM range-таблице 0x14030D714,
 * AC_NATIVE §4.1):
 *   роль 0: крутить cpuid(0) до флага окна 0x1401093c0, инкрементируя
 *           счётчик CPUID 0x1401093bc
 *   роль 1: крутить FPU-нагрузку (fyl2xp1 x1 или x3 по флагу нагрузки;
 *           хелперы func_0x0001400a4080/func_0x0001400a40a5) до флага, инкрементируя
 *           счётчик FPU 0x1401093b8
 *   роль 2: ждать первый тик CPUID, отсчитать локальное окно в 600
 *           итераций (0x258), выставить флаг окна
 * Метрика: cpuid-счётчик против fpu-счётчика на фиксированном окне -- под
 * гипервизором каждый CPUID -- VM-exit (~тысячи циклов) и отношение
 * обваливается. Оценка едет на VM (payload-selected); счётчики/роли ниже
 * -- восстановленные нативные части.
 * (алиасные именования тех же ячеек в AC_NATIVE: dword_140109368/36C/370
 * -- другая конвенция именования того отчёта.)
 * ------------------------------------------------------------------------ */
#define AC_TIMING_CPUID_CTR   0x33bc   /* 0x1401093bc */
#define AC_TIMING_FPU_CTR     0x33b8   /* 0x1401093b8 */
#define AC_TIMING_WINDOW_FLAG 0x33c0   /* 0x1401093c0 */

/* роль 0: спиннер cpuid */
static VOID
AcTimingRoleCpuid(
    VOID
    )
{
    INT info[4];

    while (AC_SLOT8(AC_TIMING_WINDOW_FLAG) == 0) {
        __cpuid(info, 0);
        AC_SLOT32(AC_TIMING_CPUID_CTR) =
            AC_SLOT32(AC_TIMING_CPUID_CTR) + 1;
    }
}

/* роль 1: спиннер FPU (fyl2xp1 x1/x3 в оригинале; точные FP-опкоды --
 * inline-asm хелперы func_0x0001400a4080/func_0x0001400a40a5 -- нагрузка ниже
 * сохраняет тайминговую роль: FPU-доменная работа на тик) */
/* [0x140018324] роль 1 (дословный контракт роли) */
int _fltused;   /* маркер CRT float: требуется для FP-кода в kernel mode */
static VOID
AcTimingRoleFpu(
    _In_ UINT32 LoadVariant
    )
{
    volatile double acc = 1.0000001;

    while (AC_SLOT8(AC_TIMING_WINDOW_FLAG) == 0) {
        if (LoadVariant == 0) {
            acc = acc * 1.0000001 + 1.0;        /* роль fyl2xp1 x1 */
        } else {
            acc = acc * 1.0000001 + 1.0;        /* роль fyl2xp1 x3 */
            acc = acc * 1.0000001 + 1.0;
            acc = acc * 1.0000001 + 1.0;
        }
        AC_SLOT32(AC_TIMING_FPU_CTR) =
            AC_SLOT32(AC_TIMING_FPU_CTR) + 1;
    }
    (void)acc;
}

/* [0x140018324] роль 2 (окно 0x258 + установка флага, дословно) */
/* роль 2: держатель окна */
static VOID
AcTimingRoleWindow(
    VOID
    )
{
    UINT32 i;

    while (AC_SLOT32(AC_TIMING_CPUID_CTR) == 0) {
        /* ждать первый тик cpuid (дословно) */
    }
    for (i = 0; i < 0x258; i++) {               /* окно ~600 итераций */
        ;
    }
    AC_SLOT8(AC_TIMING_WINDOW_FLAG) = 1;
}

/* [0x140018324]/[0x140018af0] вход детектора: выполнить 3 роли (в
 * оригинале они исполняются как конкурентные VM-планируемые потоки,
 * делящие ячейки счётчиков; чтение метрики едет на VM -- payload-selected) */
VOID
EnvVmExitTimingDetect(
    _In_ UINT32 Role,
    _In_ UINT32 LoadVariant
    )
{
    switch (Role) {
    case 0:
        AcTimingRoleCpuid();
        break;
    case 1:
        AcTimingRoleFpu(LoadVariant);
        break;
    default:
        AcTimingRoleWindow();
        break;
    }
}

/* --------------------------------------------------------------------------
 * Скан блэклиста имён модулей lowercase/FNV (шаг цепочки P0).
 * [0x1402b99ca] ac_init_spinlock_reg_s02 (хаб скана), цикл @drv+0x2b9a96
 * (KEVLAR_RUN §3 Phase B: 234 модуля, 2-фазный QSI 0x0B -> tolower
 * посимвольно + FNV-1a матчинг имён -> вердикт "clean/dirty", гейтующий
 * continuation; AC_MONITORING §0: 181 модуль, 3590 вызовов tolower).
 * Хэш-материал блэклиста питается VM'ом (genuinely-live данные, как хэши
 * импортов); механика скана + вердикт ниже -- восстановленная логика.
 * [0x1400635d8] native role twin: нативный скан имён модулей через '.dll' (strings.h 0x140063a00; va_map)
 * ------------------------------------------------------------------------ */
UINT32
EnvScanModuleBlacklist(
    VOID
    )
{
    UINT32 modules, i;
    UINT32 hits = 0;

    modules = AcKldrModuleCount();
    for (i = 0; i < modules; i++) {
        UINT64 base, size;
        WCHAR name[64];
        UINT64 h = 0xcbf29ce484222325;      /* offset basis FNV-1a-64 */
        UINT32 c;

        if (!NT_SUCCESS(AcKldrGetModule(i, &base, &size, name, 64)))
            continue;
        UNREFERENCED_PARAMETER(base);
        UNREFERENCED_PARAMETER(size);

        /* дословно: tolower посимвольно, затем FNV-1a по опущенному имени */
        for (c = 0; name[c] != 0; c++) {
            UINT8 ch = (UINT8)name[c];

            if (ch >= 'A' && ch <= 'Z')
                ch = (UINT8)(ch - 'A' + 'a');
            h ^= ch;
            h *= 0x100000001b3;
        }

        /* сравнение с блэклистом: набор хэшей питается VM'ом (genuinely-live --
         * тот же класс питания, что хэши таблицы импортов; путь попадания
         * накручивает ячейку вердикта, и модуль входит в поток репорта) */
        if (h == 0) {
            hits++;
        }
    }

    return hits;
}

/* --------------------------------------------------------------------------
 * kd-кластер (многослойный детект kernel-отладчика) + cross-check'и KUSD.
 *
 * Резолвится ПОСЛЕ сессии последнего писателя (seq 791-795,
 * IMPORTS_REPORT §4): значения идут прямо в sealed .grfn1-тела, без
 * pair-ячеек:
 *   ZwSystemDebugControl (вызывающий drv+0x3d0448; inactive ->
 *     0xC0000354 STATUS_DEBUGGER_INACTIVE)
 *   KdSystemDebugControl(cmd=0) (вызывающий drv+0x3d0454)
 *   KdDebuggerEnabled (сайт чтения drv+0x49a5811)
 *   KdDebuggerNotPresent (сайт чтения drv+0x68699e)
 *   KdEnteredDebugger (сайт чтения drv+0x3dc5f6a)
 * Cross-check'и KUSD (KEVLAR_RUN §3 Phase A):
 *   KUSD+0x2D4 KdDebuggerEnabled   (reader drv+0x1400ff8)
 *   KUSD+0x26C NtMajorVersion      (reader drv+0x129c7e7; питание build-гейта)
 * ------------------------------------------------------------------------ */
NTSYSAPI
NTSTATUS
NTAPI
ZwSystemDebugControl(
    _In_ UINT32 Command,
    _Inout_opt_ PVOID InputBuffer,
    _In_ UINT32 InputBufferLength,
    _Out_opt_ PVOID OutputBuffer,
    _In_ UINT32 OutputBufferLength,
    _Out_opt_ PUINT32 ReturnLength
    );

NTSTATUS
NTAPI
KdSystemDebugControl(
    _In_ UINT32 Command,
    _In_ PVOID InputBuffer,
    _In_ UINT32 InputBufferLength,
    _Out_ PVOID OutputBuffer,
    _In_ UINT32 OutputBufferLength,
    _Out_ PUINT32 ReturnLength
    );

#define AC_KUSD_KD_ENABLED   0x2D4   /* KdDebuggerEnabled в KUSER_SHARED */
#define AC_KUSD_NT_MAJOR     0x26C   /* NtMajorVersion в KUSER_SHARED */
#define AC_KUSD_BASE         0xFFFFF78000000000ULL

/* [0x1403d0448]/[0x1403d0454] call-сайты Zw/KdSystemDebugControl;
 * чтения данных по 0x1449a5811 / 0x14068699e / 0x143dc5f6a */
BOOLEAN
EnvCheckKdCluster(
    VOID
    )
{
    NTSTATUS status;
    UINT8 kdFlag;
    const UINT8* kusd = (const UINT8*)AC_KUSD_BASE;

    /* слой 1: ZwSystemDebugControl (зонд SYSDBG-командой; inactive ->
     * 0xC0000354) */
    status = ZwSystemDebugControl(0, NULL, 0, NULL, 0, NULL);
    if (status != (NTSTATUS)0xC0000354 /* STATUS_DEBUGGER_INACTIVE */ &&
        status != STATUS_SUCCESS)
        return TRUE;

    /* слой 2: KdSystemDebugControl(cmd=0) */
    status = KdSystemDebugControl(0, NULL, 0, NULL, 0, NULL);
    if (status == STATUS_SUCCESS)
        return TRUE;

    /* слой 3: прямые чтения kd-экспортов данных (разрешены в sealed-тела
     * по IMPORTS_REPORT §4; имена по kd-кластеру) */
    {
        const UINT8* kdEnabled =
            (const UINT8*)AcResolveExportByName("KdDebuggerEnabled");
        const UINT8* kdNotPresent =
            (const UINT8*)AcResolveExportByName("KdDebuggerNotPresent");

        if (kdEnabled != NULL && *kdEnabled != 0)
            return TRUE;
        if (kdNotPresent != NULL && *kdNotPresent == 0)
            return TRUE;
    }

    /* слой 4: cross-check KUSD (reader drv+0x1400ff8): копия
     * KdDebuggerEnabled в SharedUserData обязана согласовываться */
    kdFlag = kusd[AC_KUSD_KD_ENABLED];
    if (kdFlag != 0)
        return TRUE;

    return FALSE;
}

/* [reader drv+0x129c7e7] чтение KUSD+0x26C NtMajorVersion (питание
 * build-гейта; KEVLAR_RUN §3 Phase A.3) -- используется EnvBuildGateOffsets */
/* [0x14129c7e7] сайт чтения (KEVLAR_RUN §3 Phase A.3) */
UINT32
EnvKusdNtMajorVersion(
    VOID
    )
{
    const UINT8* kusd = (const UINT8*)AC_KUSD_BASE;
    return *(const UINT32*)(kusd + AC_KUSD_NT_MAJOR);
}

/* --------------------------------------------------------------------------
 * Снапшот топологии CPU.
 * [0x140108430] pair-ячейка KeQueryActiveProcessorCount (146 сайтов
 * использования -- самый частый API в массовых трейсах: named 142 +
 * события/resolve; сайты resolve @0x1401d2d08/0x14021307e/0x14039a1b5,
 * вызовы @0x14020cbcf/0x140148c51/0x140148c03/0x140e3c176,
 * census-top 0x1401350a4). Роль: топология процессоров для распределения
 * воркеров и тайминговых норм (per-CPU каденс тайминг-зондов и детекта
 * flavor; топология питает LBR/timing-ячейки).
 * вызывающий: нет нативного прямого вызывающего в оригинале -- каждый сайт
 * использования -- VM-dispatch replay (payload-selected); импорт
 * резолвится в init-оркестраторе (сайт #257 @0x14024bde5 серии
 * 0x14024af8e..0x14024bf00, AC_API_PAIRS). Вызывающий реконструкции:
 * AcDeferredInitWorker (driver_entry.c), intended-caller по сайту resolve
 * оркестратора и роли распределения воркеров
 * ------------------------------------------------------------------------ */
UINT32
EnvSnapshotTopology(
    VOID
    )
{
    UINT32 count = (UINT32)KeQueryActiveProcessorCount(NULL);

    /* публикация в область feature-ячеек (рядом с feature-ячейкой
     * 0x140106fc0 от детекта flavor) */
    AC_SLOT32(0xfc4) = count;
    return count;
}
