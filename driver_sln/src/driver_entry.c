/* ==========================================================================
 * driver_entry.c -- DriverEntry (P0) + отложенный init устройства
 * --------------------------------------------------------------------------
 * ДОКАЗАННАЯ структура (KERNEL_WALLS_FINAL §1.1, replay irpreg_de3.jsonl
 * 4.87M шагов + полные вочи dobj/dext/handler):
 *
 *   EP stub 0x14010d000 (нативный, дословный дизасм):
 *     rbx=RegistryPath, rdi=DriverObject
 *     call 0x14010d02c  (__security_init_cookie vs 0x2b992ddfa232)
 *     call 0x140006a90  (P0 -- ЕДИНСТВЕННЫЙ вызов)
 *     return eax = P0 = 0xC0EB0004
 *
 *   P0 = ТОЛЬКО env-проверки:
 *     MmGetSystemRoutineAddress(InitSafeBootMode)
 *     -> cpuid(1)                     [HV gate #1 сайт 0x1401c29f4]
 *     -> ZwQuerySystemInformation(0x23 SystemKernelDebuggerInformation)
 *     -> ZwQuerySystemInformation(0x0B SystemModuleInformation)
 *        -> lowercase-скан имён модулей -> ExFreePool
 *     -> ret 0xC0EB0004  (токен manual-мапперу: env-проверки пройдены;
 *        KEVLAR --nohv ран наблюдал 0xC0EB0005, старый трейс 0xC021001D)
 *
 *   НОЛЬ создания устройств / регистрации MajorFunction / установки
 *   callback'ов в P0 (0 записей dobj/dext/handler/dev по всем replay).
 *
 *   Init устройства идёт ОТЛОЖЕННО: хаб оркестратора 0x14024af8e
 *   (region 7341) резолвит IoCreateDevice @0x14024b1f4,
 *   IoCreateSymbolicLink @0x14024b202, IoDeleteDevice @0x14024b8bc,
 *   IoAllocateWorkItem @0x14024b494, IoFreeWorkItem @0x14024b4a2,
 *   IoQueueWorkItem @0x14024b4b0, KeInitializeTimer @0x14024ba36,
 *   ExQueueWorkItem @0x14024bd70 (replay irpreg_orch2/orch4.jsonl) и
 *   вызывается из no-caller VM-тела FUN_140282319 (4 аргумента;
 *   FACEIT_AC_all.c:8016384) -- идиома work-item -- доказанный триггер
 *   регистрации этого драйвера (KERNEL_WALLS_FINAL §1.1).
 *
 *   Модель загрузки: FACEIT_AC.sys -- boot-драйвер SYSTEM_START (Start=1,
 *   присутствует в списке kernel-модулей -- replay R150). preloader.dll --
 *   отдельный manual-маппер драйвера (reflective-загрузка, путь обновления);
 *   семейство токенов 0xC0EB000x сигналит ему, что env-проверки пройдены.
 * ========================================================================== */
#include <fltKernel.h>   /* первым: гард-идиома _NTIFS_ (типы SD/SID/ACL) */
#include <ntddk.h>

#include "provenance.h"
#include "tables.h"
#include "imports.h"
#include "ioctl.h"
#include "channels.h"
#include "anti_tamper.h"
#include "env_checks.h"
#include "kldr.h"
#include "events.h"
#include "nmi_watchdog.h"
#include "vmwall_engines.h"

DRIVER_UNLOAD AcDriverUnload;

static VOID AcApplyDeviceDacl(_In_ PDEVICE_OBJECT DeviceObject);

/* нет в km-заголовках этого WDK; публичные контракты */
NTKERNELAPI
NTSTATUS
NTAPI
ObSetSecurityObjectByPointer(
    _In_ PVOID Object,
    _In_ UINT32 SecurityInformation,
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor
    );


/* --------------------------------------------------------------------------
 * Контекст воркайтема отложенного init'а (continuation оркестратора)
 * ------------------------------------------------------------------------ */
typedef struct _AC_DEFERRED_INIT {
    WORK_QUEUE_ITEM WorkItem;        /* путь ExQueueWorkItem (до устройства) */
    PDRIVER_OBJECT DriverObject;
    PUNICODE_STRING RegistryPath;
    PDEVICE_OBJECT ControlDevice;    /* \\Device\\FACEITAC (имя с wire) */
    PDEVICE_OBJECT EventDevice;      /* event-устройство 0xC350 (имя собрано MBA) */
    HANDLE WorkerThread;
} AC_DEFERRED_INIT, *PAC_DEFERRED_INIT;

static AC_DEFERRED_INIT g_Init;

/* --------------------------------------------------------------------------
 * Poll-воркер (heartbeat + отложенная телеметрия).
 * [0x14001278c] worker_thread_trampoline (golden v1 app_workers.c)
 * [0x14029003d] poll_worker_body: KeSetTimer(-30 s) +
 * KeWaitForMultipleObjects({event,timer}, WaitAny); ветка таймера нативная
 * (heartbeat @0x140290191), выход по сигналу -> KeCancelTimer
 * ------------------------------------------------------------------------ */
typedef struct _AC_WORKER_CTX {
    KEVENT      WakeEvent;          /* [worker_ctx+0x88] */
    KTIMER      Timer;              /* 30-секундный heartbeat-таймер */
    UINT32      State;              /* [worker_ctx+0xa8]: 2 = выполнить отложенное */
    UINT8       HookInfraReady;     /* [worker_ctx+0x7c] */
    UINT8       StopRequested;      /* [worker_ctx+0x7e] */
    UINT64      ResolvedPairs[10];  /* [worker_ctx+0x00..0x4F] XOR-пары */
} AC_WORKER_CTX, *PAC_WORKER_CTX;

static AC_WORKER_CTX g_WorkerCtx;

/* [0x140163c0a] hook_infra_init: одноразовая инфраструктура syscall-хуков
 * (дословный инвентарь DISPATCH_CHAIN_C §6; сайты resolve по RECON2
 * редкие api_resolve). 6 FNV-resolve'ов кэшированы как XOR-пары в
 * worker_ctx+0x00..0x4F, флаг ctx+0x7c=1, KfRaiseIrql(DISPATCH_LEVEL):
 *
 *   NtMapViewOfSection   (api_resolve 0x14035fbe8) -- память механики
 *   NtAllocateVirtualMemory (0x1401f1e95)          -- память механики
 *   NtWaitForSingleObject   (0x14027cef3)          -- примитив синхронизации
 *   ZwSetSystemInformation  (0x1403ca075)          -- модификация
 *                                                     системного состояния
 *   NtTraceControl       (0x14020a959/0x14017fbea) -- управление
 *                                                     ETW/trace-сессией
 *   HalPrivateDispatchTable (0x140370a84/0x14037dd47) -- HAL dispatch
 *                                                     table (путь syscall
 *                                                     через HAL)
 *
 * Роль: это тот же воркер, которого будит session dispatch; набор готовит
 * контур мониторинга/управления syscall-путём рядом с LSTAR-вачдогом
 * (trace control + HAL dispatch + собственная память), а не HWID-
 * коллекторы (доказано: worker VM continuation резолвит ровно эти шесть,
 * DISPATCH_CHAIN_C §6 "worker VM continuation is NOT collectors") */
static NTSTATUS
AcHookInfraInit(
    _Inout_ PAC_WORKER_CTX Ctx
    )
{
    static const char *const names[] = {
        "NtMapViewOfSection", "NtAllocateVirtualMemory",
        "NtWaitForSingleObject", "ZwSetSystemInformation",
        "NtTraceControl", "HalPrivateDispatchTable"
    };
    KIRQL oldIrql;
    ULONG i;

    if (Ctx->HookInfraReady)
        return STATUS_SUCCESS;

    KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
    for (i = 0; i < ARRAYSIZE(names); i++) {
        Ctx->ResolvedPairs[i] = (UINT64)AcResolveExportByName(names[i]);
    }
    KeLowerIrql(oldIrql);

    Ctx->HookInfraReady = 1;
    return STATUS_SUCCESS;
}

/* [0x14000bfa0] адаптер переотправки для флашера отложенной очереди:
 * сохранённые записи 0x658 переиздаются через channel sender (вызов
 * флашера FUN_14000bfa0(node+0x28, 0x658) в оригинале) */
static VOID NTAPI
AcDeferredResend(
    _In_ const UINT8* Rec0x658,
    _In_opt_ PVOID UserCtx
    )
{
    UNREFERENCED_PARAMETER(UserCtx);
    (VOID)AcChannelSend(Rec0x658, AC_REC12_SIZE);
}

/* [0x14029003d] poll_worker_body (см. блочную заметку выше) */
static VOID
AcPollWorkerBody(
    _In_ PVOID StartContext
    )
{
    PAC_WORKER_CTX ctx = (PAC_WORKER_CTX)StartContext;
    PVOID waits[2];
    LARGE_INTEGER dueTime;
    NTSTATUS wait;
    KIRQL oldIrql;

    KeInitializeEvent(&ctx->WakeEvent, NotificationEvent, FALSE);
    KeInitializeTimer(&ctx->Timer);

    dueTime.QuadPart = -30LL * 1000LL * 1000LL * 10LL;  /* -30 s относительное */
    KeSetTimer(&ctx->Timer, dueTime, NULL);

    waits[0] = &ctx->WakeEvent;
    waits[1] = &ctx->Timer;

    for (;;) {
        wait = KeWaitForMultipleObjects(2, waits, WaitAny,
                                        Executive, KernelMode, FALSE,
                                        NULL, NULL);
        if (ctx->StopRequested)
            break;

        if (wait == STATUS_WAIT_0) {
            /* разбужен session dispatch (было выставлено [worker_ctx+0xa8]=2) */
            if (ctx->State == 2) {
                ctx->State = 0;
                AcHookInfraInit(ctx);
            }
        } else {
            /* ветка таймера: heartbeat-запись 0x24 (каденс ~30 s)
             * [0x140290191] -> heartbeat_producer */
            AcEventHeartbeat();

            /* [0x1400586ec] флашер отложенной очереди на том же каденсе
             * ~30 s KTIMER (DRIVER_CHANNEL_PROTOCOL §4.5); порядок цепочки
             * "flusher -> drain 0xC3502004" (FULL_CHAIN_IRP_TO_HWID_C §0).
             * вызывающий в оригинале: VM-сайты 0x14017c466/0x140209d30
             * (FULL_CHAIN §7.4 -- VM-диспетч, нет нативных call-сайтов);
             * здесь intended-caller по evidence каденса. Переотправка
             * неотправленных записей 0x12 идёт через сендер [0x14000bfa0]
             * под deferred-локом (ctx 0x140108de8 +0x70) */
            KeAcquireSpinLock(&g_AcDeferredLock, &oldIrql);
            (VOID)AcChannelFlushDeferred(&g_AcDeferredQueue,
                                         AcDeferredResend, NULL);
            KeReleaseSpinLock(&g_AcDeferredLock, oldIrql);
        }

        KeSetTimer(&ctx->Timer, dueTime, NULL);
    }

    KeCancelTimer(&ctx->Timer);
    PsTerminateSystemThread(STATUS_SUCCESS);
}

/* [0x14001278c] worker_thread_trampoline (форма алиаса из отчёта
 * 0x1401278c, 8-значное написание того же VA) */
static VOID
AcWorkerThreadTrampoline(
    _In_ PVOID StartContext
    )
{
    AcPollWorkerBody(StartContext);
}

/* --------------------------------------------------------------------------
 * Воркер отложенного init'а устройства (доказанный триггер регистрации).
 * [0x14024af8e] continuation хаба оркестратора (KERNEL_WALLS_FINAL §1.1):
 *   259 api_resolve -> pair_alloc 0x18 -> сборка имени устройства через
 *   _vsnwprintf_s @0x140001067 в .data 0x14010a500 (format-ячейка
 *   0x14010a4f0) -> сборка VM jump-table (14749 store_code_ptr) ->
 *   pair_alloc 0x658 -> cpuid(0,1,7) @0x1400a425a/269/2ba ->
 *   feature-ячейка 0x140106fc0=9 -> flavor/LBR телеметрия 0x658-запись ->
 *   SENDER -> ...регистрация устройства глубже по цепочке
 * Планируется через ExQueueWorkItem (сайт resolve @0x14024bd70) --
 * pre-device идиома, не требующая DEVICE_OBJECT; IoAllocateWorkItem/
 * IoQueueWorkItem (@0x14024b494/@0x14024b4b0) обслуживают post-device
 * отложенную работу того же оркестратора
 * ------------------------------------------------------------------------ */
static VOID
AcDeferredInitWorker(
    _In_ PVOID Context
    )
{
    PAC_DEFERRED_INIT init = (PAC_DEFERRED_INIT)Context;
    UNICODE_STRING devName;
    UNICODE_STRING dosName;
    NTSTATUS status;

    /* [0x14010a500] буфер сборки имени устройства: строится _vsnwprintf_s
     * @0x140001067 с format-ячейкой 0x14010a4f0 (replay оркестратора
     * KERNEL_WALLS_FINAL §1.3); используется наблюдавшееся на wire имя
     * \\??\\FACEITAC (собранный MBA литерал payload-selected,
     * AC_IOCTL_HANDLER §6.5) */
    RtlInitUnicodeString(&devName, L"\\Device\\FACEITAC");
    RtlInitUnicodeString(&dosName, L"\\??\\FACEITAC");

    /* IoCreateDevice @0x14024b1f4 (сайт resolve в оркестраторе) */
    status = IoCreateDevice(init->DriverObject, 0, &devName, 0x2202,
                            FILE_DEVICE_SECURE_OPEN, FALSE,
                            &init->ControlDevice);
    if (!NT_SUCCESS(status))
        return;

    /* IoCreateSymbolicLink @0x14024b202 */
    status = IoCreateSymbolicLink(&dosName, &devName);
    if (!NT_SUCCESS(status)) {
        /* IoDeleteDevice @0x14024b8bc */
        IoDeleteDevice(init->ControlDevice);
        init->ControlDevice = NULL;
        return;
    }

    /* второе устройство: event-канал 0xC350 (тип устройства 0xC350 !=
     * 0x2202 -> второй device object, AC_IOCTL_HANDLER §5) */
    RtlInitUnicodeString(&devName, L"\\Device\\FACEITAC_EVT");
    status = IoCreateDevice(init->DriverObject, 0, &devName, 0xC350,
                            FILE_DEVICE_SECURE_OPEN, FALSE,
                            &init->EventDevice);
    if (!NT_SUCCESS(status)) {
        IoDeleteSymbolicLink(&dosName);
        IoDeleteDevice(init->ControlDevice);
        init->ControlDevice = NULL;
        return;
    }

    /* регистрация MajorFunction[IRP_MJ_DEVICE_CONTROL]: пишется generic
     * виртуализованным store (серия store(dobj, off, shim) из init-цепочки,
     * KERNEL_WALLS_FINAL §1.2); зарегистрированная обёртка доказана
     * anti-tamper вачдогом: 0x14001a5f4 / 0x14001a87c */
    init->DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] =
        AcDispatchDeviceControl;
    init->DriverObject->DriverUnload = AcDriverUnload;

    /* [0x14016c813] init состояния протокола канала (CHAIN 241) */
    AcChannelInit();

    /* DACL-харденинг device-объектов: SD-кластер
     * (9 API, сайты resolve 0x1403e2e44..0x1403e2eb4:
     * RtlSelfRelativeToAbsoluteSD2, ZwQuerySecurityObject,
     * RtlGetDaclSecurityDescriptor, RtlCopySid, RtlLengthSid, RtlValidSid,
     * RtlAddAce, RtlSetDaclSecurityDescriptor, ZwSetSecurityObject) */
    AcApplyDeviceDacl(init->ControlDevice);
    AcApplyDeviceDacl(init->EventDevice);

    /* notify-callback'и: image-load (аудит хуков на kernel-пути) и
     * module-notify (продюсер 0x26 + вооружение PCI на клиенте сессии)
     * [0x14001b910]/[0x140043258] (golden v1 notify_callbacks.c) */
    AcRegisterNotifyCallbacks();

    /* NMI-вачдог (второй слой anti-tamper):
     * [0x1402b1c16]/[0x1403bd850] KeRegisterNmiCallback (RECON2 напр. 9) */
    AcNmiWatchdogRegister();

    /* установка LBR-трекинга вызывающих (идиома отложенной телеметрии)
     * [0x140051670] (KERNEL_WALLS_FINAL §1.1) */
    AcLbrInstallCallerTracking(init->ControlDevice);

    /* [0x140108430] снапшот топологии процессоров: импорт резолвится внутри
     * этого init-оркестратора (сайт #257 @0x14024bde5 серии resolve
     * 0x14024af8e..0x14024bf00, AC_API_PAIRS); все сайты использования
     * оригинала -- VM-dispatch replay (payload-selected, 146 сайтов --
     * нет нативного прямого вызывающего). Контур публикует количество в
     * окно feature-ячеек (смещение 0xfc4, рядом с flavor-ячейкой
     * 0x140106fc0) для распределения воркеров и тайминговых норм --
     * снапшотится до старта poll-воркера */
    (VOID)EnvSnapshotTopology();

    /* [0x14001278c] поток poll-воркера */
    status = PsCreateSystemThread(&init->WorkerThread, THREAD_ALL_ACCESS,
                                  NULL, NULL, NULL,
                                  AcWorkerThreadTrampoline, &g_WorkerCtx);
    if (NT_SUCCESS(status))
        ZwClose(init->WorkerThread);
}

/* --------------------------------------------------------------------------
 * DACL-харденинг device-объекта.
 * [0x1403e2e44..0x1403e2eb4] SD-кластер (9 API, RECON2 редкие api_resolve;
 * api_call ZwQuerySecurityObject @0x1403e2ecd):
 *   прочитать текущий security descriptor (ZwQuerySecurityObject),
 *   построить новый DACL (SID'ы через RtlCopySid/RtlLengthSid/RtlValidSid,
 *   ACE через RtlAddAce), установить через RtlSetDaclSecurityDescriptor и
 *   закоммитить ZwSetSecurityObject; RtlSelfRelativeToAbsoluteSD2
 *   конвертирует self-relative блоб в absolute-форму.
 * Политика (anti-open контур канала): полный доступ SYSTEM (faceitservice
 * работает как SYSTEM-сервис) и Administrators; остальным -- никакого
 * доступа: устройство не может быть открыто произвольным процессом
 * (соответствует CN-гейтованному слою handshake над ним).
 * Точный набор ACE оригинала строится VM (payload-selected);
 * последовательность построения/применения ниже -- восстановленный
 * контракт.
 * ------------------------------------------------------------------------ */
static VOID
AcApplyDeviceDacl(
    _In_ PDEVICE_OBJECT DeviceObject
    )
{
    SECURITY_DESCRIPTOR absSd;
    PACL dacl;
    SID localSystemSid;
    SID adminsSid;
    UINT32 daclSize;

    if (DeviceObject == NULL)
        return;

    /* ZwQuerySecurityObject @0x1403e2ecd (сайт api_call) -- текущий
     * SD device-объекта (сторона чтения кластера) */

    /* построить DACL: SYSTEM full + Administrators full, больше ничего */
    daclSize = sizeof(ACL) +
               FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart) +
               (UINT32)RtlLengthRequiredSid(1) +
               FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart) +
               (UINT32)RtlLengthRequiredSid(2);

    dacl = (PACL)ExAllocatePool2(POOL_FLAG_PAGED, daclSize, 'lcdA');
    if (dacl == NULL)
        return;

    if (!NT_SUCCESS(RtlCreateAcl(dacl, daclSize, ACL_REVISION)))
        goto Free;

    /* SID-хелперы кластера: RtlValidSid/RtlLengthSid/RtlCopySid */
    {
        SID_IDENTIFIER_AUTHORITY ntAuth = { 0, 0, 0, 0, 0, 5 };

        RtlInitializeSid(&localSystemSid, &ntAuth, 1);
        *RtlSubAuthoritySid(&localSystemSid, 0) =
            SECURITY_LOCAL_SYSTEM_RID;

        RtlInitializeSid(&adminsSid, &ntAuth, 2);
        *RtlSubAuthoritySid(&adminsSid, 0) = SECURITY_BUILTIN_DOMAIN_RID;
        *RtlSubAuthoritySid(&adminsSid, 1) = DOMAIN_ALIAS_RID_ADMINS;
    }

    /* RtlAddAce (кластер): два ALLOWED ACE, строятся на стеке по
     * WDK-сигнатуре RtlAddAce(Acl, Revision, StartingIndex, AceList, Len) */
    {
        struct {
            ACE_HEADER Header;
            ACCESS_MASK Mask;
            UINT8 Sid[16];
        } aceSystem, aceAdmins;
        UINT32 sysSidLen = (UINT32)RtlLengthSid(&localSystemSid);
        UINT32 admSidLen = (UINT32)RtlLengthSid(&adminsSid);

        aceSystem.Header.AceType = ACCESS_ALLOWED_ACE_TYPE;
        aceSystem.Header.AceFlags = 0;
        aceSystem.Header.AceSize = (UINT16)(
            FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart) + sysSidLen);
        aceSystem.Mask = GENERIC_ALL;
        RtlCopySid(sysSidLen, (PSID)aceSystem.Sid, &localSystemSid);

        aceAdmins.Header.AceType = ACCESS_ALLOWED_ACE_TYPE;
        aceAdmins.Header.AceFlags = 0;
        aceAdmins.Header.AceSize = (UINT16)(
            FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart) + admSidLen);
        aceAdmins.Mask = GENERIC_ALL;
        RtlCopySid(admSidLen, (PSID)aceAdmins.Sid, &adminsSid);

        if (!NT_SUCCESS(RtlAddAce(dacl, ACL_REVISION, 0, &aceSystem,
                                  aceSystem.Header.AceSize)) ||
            !NT_SUCCESS(RtlAddAce(dacl, ACL_REVISION, 0, &aceAdmins,
                                  aceAdmins.Header.AceSize))) {
            goto Free;
        }
    }

    /* RtlSetDaclSecurityDescriptor + ZwSetSecurityObject (сторона применения) */
    if (NT_SUCCESS(RtlCreateSecurityDescriptor(&absSd,
                                               SECURITY_DESCRIPTOR_REVISION))) {
        if (NT_SUCCESS(RtlSetDaclSecurityDescriptor(&absSd, TRUE, dacl,
                                                    FALSE))) {
            ObSetSecurityObjectByPointer(DeviceObject,
                                         DACL_SECURITY_INFORMATION,
                                         &absSd);
        }
    }

    /* верификация read-back оставшимися вызовами кластера:
     * ZwQuerySecurityObject (сайт api_call @0x1403e2ecd) -> self-relative
     * SD -> RtlGetDaclSecurityDescriptor -> RtlValidSid по SID'ам ACE;
     * RtlSelfRelativeToAbsoluteSD2 [@0x1403e2e44] конвертирует
     * self-relative блоб, когда ниже нужна absolute-форма */
    {
        UINT8 sdBuf[256];
        UINT32 sdLen = 0;
        HANDLE devHandle = NULL;
        NTSTATUS qstatus;

        qstatus = ObOpenObjectByPointer(DeviceObject, OBJ_KERNEL_HANDLE,
                                        NULL, READ_CONTROL, NULL,
                                        KernelMode, &devHandle);
        if (NT_SUCCESS(qstatus)) {
            qstatus = ZwQuerySecurityObject(devHandle,
                                            DACL_SECURITY_INFORMATION,
                                            sdBuf, sizeof(sdBuf), &sdLen);
            if (NT_SUCCESS(qstatus)) {
                PSECURITY_DESCRIPTOR sd =
                    (PSECURITY_DESCRIPTOR)sdBuf;
                PACL readDacl = NULL;
                BOOLEAN daclPresent = FALSE, daclDefaulted = FALSE;

                if (NT_SUCCESS(RtlGetDaclSecurityDescriptor(sd,
                                &daclPresent, &readDacl,
                                &daclDefaulted)) &&
                    daclPresent && readDacl != NULL) {
                    /* RtlValidSid по SID'у первого ACE (кластер) */
                    if (readDacl->AceCount > 0) {
                        PACCESS_ALLOWED_ACE firstAce =
                            (PACCESS_ALLOWED_ACE)(readDacl + 1);

                        if (!RtlValidSid((PSID)&firstAce->SidStart)) {
                            /* порченый DACL read-back: применить повторно */
                            ObSetSecurityObjectByPointer(DeviceObject,
                                DACL_SECURITY_INFORMATION, &absSd);
                        }
                    }
                }
            }
            ZwClose(devHandle);
        }
    }

Free:
    /* SD ссылается на ACL, пока тот установлен на объекте; оригинал
     * держит его живым (пул не освобождается после коммита) */
    return;
}

/* --------------------------------------------------------------------------
 * DriverUnload
 * [0x140066c18] teardown канала (запись 0x02; доказанный layout
 * AC_EVENT_CHANNEL §1); удаление устройства/симлинка = путь
 * IoDeleteDevice @0x14024b8bc
 * ------------------------------------------------------------------------ */
VOID
AcDriverUnload(
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    UNICODE_STRING dosName;

    AcChannelTeardown();

    /* [0x1402b1c24] KeDeregisterNmiCallback (teardown NMI-вачдога) */
    AcNmiWatchdogUnregister();

    g_WorkerCtx.StopRequested = 1;
    KeSetEvent(&g_WorkerCtx.WakeEvent, IO_NO_INCREMENT, FALSE);

    RtlInitUnicodeString(&dosName, L"\\??\\FACEITAC");
    IoDeleteSymbolicLink(&dosName);

    while (DriverObject->DeviceObject) {
        IoDeleteDevice(DriverObject->DeviceObject);
    }
}

/* --------------------------------------------------------------------------
 * DriverEntry
 * [0x14010d000] EP stub (дословный дизасм, KERNEL_WALLS_FINAL §1.1):
 *   init куки (call 0x14010d02c) + P0 (call 0x140006a90), возврат eax из P0
 * [0x14010d02c] __security_init_cookie (GS-куки против значения образа
 *   0x2b992ddfa232; per-boot рандомизация ячейки pair-8 0x140106080,
 *   класс boot-random -- anti_tamper.c)
 * [0x140006a90] P0: ТОЛЬКО env-проверки (replay KERNEL_WALLS_FINAL §1.1);
 *   полная цепочка проверок в env_checks.c (EnvRunBootGates)
 * [0x1400a49f5] native role twin: нативное тело входа цепочки 'entry @ 14010d000' (AC_NATIVE 1.1; va_map)
 * ------------------------------------------------------------------------ */
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS status;

    /* --- init куки (call 0x14010d02c): per-boot рандомизация pair-8 */
    AcSecurityCookieInit();

    /* --- P0 (call 0x140006a90): цепочка env-проверок --------------------
     * InitSafeBootMode -> cpuid(1) -> QSI 0x23 (kd) -> QSI 0x0B (модули
     * + lowercase-скан имён) -> free -> токен (evidence: KERNEL_WALLS_FINAL
     * §1.1, replay irpreg_de3.jsonl) */
    status = EnvRunBootGates();

    /* --- отложенная регистрация устройства --------------------------------
     * НЕ в P0 (доказано: 0 записей dobj/dext/handler в DriverEntry);
     * хаб оркестратора 0x14024af8e прогоняет её по идиоме work-item
     * (сайт resolve ExQueueWorkItem @0x14024bd70 -- путь pre-device;
     * IoAllocateWorkItem/IoQueueWorkItem @0x14024b494/@0x14024b4b0 для
     * post-device отложенной работы), вызывается из VM-тела FUN_140282319
     * (4 аргумента) */
    if (NT_SUCCESS(status)) {
        g_Init.DriverObject = DriverObject;
        g_Init.RegistryPath = RegistryPath;
        /* доказанная идиома оригинала (сайты resolve 0x14024bd70/
         * 0x14024b4b0): legacy Ex* API work-очереди, deprecated в новых
         * WDK -- оставлено сознательно, warning подавлен локально */
#pragma warning(suppress: 4996)
        ExInitializeWorkItem(&g_Init.WorkItem, AcDeferredInitWorker,
                             &g_Init);
#pragma warning(suppress: 4996)
        ExQueueWorkItem(&g_Init.WorkItem, CriticalWorkQueue);
    }

    /* --- возврат токена ----------------------------------------------------
     * P0 возвращает 0xC0EB0004 детерминированно (replay irpreg_de3.jsonl;
     * 0xC0EB0005 в KEVLAR --nohv ране, 0xC021001D в старом трейсе) --
     * наблюдавшиеся варианты токена: 0xC0EB0001 (ветка HV,
     * COVERAGE_INVENTORY), и MBA-финалайзер, вычисляющий токен как
     * `imul eax, r10d, 0x9b2371c7` (DISPATCH_CHAIN_C #1/#2 legacy
     * заметка о пути возврата) --
     * токен "env-проверки пройдены" для manual-маппера (preloader).
     * В нормально загруженном билде DriverEntry обязан завершиться успехом
     * для OS-лоадера; токен маппера эмитится только для manual-map билда. */
#ifdef AC_MANUAL_MAPPER
    if (NT_SUCCESS(status))
        return (NTSTATUS)0xC0EB0004;
#endif
    return status;
}
