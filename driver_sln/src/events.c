/* ==========================================================================
 * events.c -- продюсеры типизированных записей событий + notify-callback'и
 * --------------------------------------------------------------------------
 * Provenance: AC_EVENT_CHANNEL.md §1 (таксономия маркеров + layout'ы,
 * "proven"), golden v1 events.c + notify_callbacks.c (дословные нативные
 * тела), DRIVER_CHANNEL_BYTEMAP §2 (wire-форма 0xC350202C).
 * Выход записей: каждый продюсер заканчивается channel_sender [0x14000bfa0].
 *
 * CORRECTION CROSS-REF: старое утверждение AC_EVENT_CHANNEL #0, что сервис
 * poll'ит записи через 0x220414/0x220438, ОТМЕНЕНО -- семейство 0x22xxxx
 * -- это инвентарь USB-хаба СЕРВИСА (user-mode), а не IOCTL драйвера
 * (KERNEL_WALLS_FINAL #2.1). Не возвращать сюда путь 0x22-poll; poll-канал
 * -- только 0xC3502004.
 * ========================================================================== */
#include <fltKernel.h>   /* первым: define _NTIFS_, чтобы ntddk.h пропустил
                          * свои конфликтующие typedef'ы (идиома WDK minifilter) */
#include <ntddk.h>

#include "provenance.h"
#include "tables.h"
#include "events.h"
#include "channels.h"
#include "crypto.h"
#include "anti_tamper.h"
#include "game_integrity.h"
#include "hwid.h"
#include "vmwall_engines.h"
#include "ioctl.h"

/* ограниченное копирование wide-строки (нет CRT в kernel mode) */
static VOID
AcCopyWideString(
    _Out_writes_(DestChars) WCHAR* Dest,
    _In_ UINT32 DestChars,
    _In_z_ const WCHAR* Src
    )
{
    UINT32 i = 0;

    if (DestChars == 0)
        return;
    while (Src[i] != L'\0' && i < DestChars - 1) {
        Dest[i] = Src[i];
        i++;
    }
    Dest[i] = L'\0';
}

/* --------------------------------------------------------------------------
 * [0x14000c35c] heartbeat_producer: запись type 0x24; каденс ~30 s от
 * двух таймеров со сдвигом 4 s (DRIVER_CHANNEL_PROTOCOL §1 steady-state)
 * ------------------------------------------------------------------------ */
VOID
AcEventHeartbeat(
    VOID
    )
{
    /* wire-форма [dec]: {u32 0x24, u32 flag in {1,2}} -- 8-байтовый plaintext
     * (56B sealed-бокс на wire) */
    struct {
        UINT32 Type;        /* 0x24 */
        UINT32 Flag;        /* 1 | 2 */
    } hb;

    hb.Type = 0x24;
    hb.Flag = 1;
    AcChannelSend(&hb, sizeof(hb));
}

/* --------------------------------------------------------------------------
 * [0x140043258] module_notify_callback -- дословный продюсер 0x26.
 * Построение записи (golden v1 notify_callbacks.c, смещения из тела):
 *   rec = pool_alloc_zeroed(0x4d8); alloc-fail -> репорт 0x13
 *   +0x000 dword = 0x26
 *   +0x008 qword = LOCK-инкремент 0x140108db8 (seq)
 *   +0x010 qword = база модуля   (param_4[2])
 *   +0x018 qword = размер модуля (param_4[6])
 *   +0x020 wchar[0x208 байтов] = имя модуля (копия func_0x00014000c428;
 *           пропускается при (*param_4 & 0x400) != 0 -- альтернативный путь
 *           FUN_140042e54/FUN_1400033ec)
 *   +0x430 byte  = 0
 *   +0x438 qword = pid загружающего процесса
 *   +0x440 qword = 0xfffff78000000014 (KUSER_SHARED_DATA + 0x14,
 *           чтение interrupt-time)
 *   +0x448 ..    = per-client контекст (FUN_1400062a8, только клиент сессии)
 *   +0x494 dword = 1
 *   при pid == клиент сессии (0x140108750): FUN_1400644b0();
 *   pci_arming_gate(); FUN_1400062a8(...); клей 0x140219fb4
 * [0x14001432c] native role twin: нативный 0x12-продюсер, гейтованный на cited ячейку 0x140108750 (va_map)
 * ------------------------------------------------------------------------ */
NTSTATUS
AcEventModuleLoad(
    _In_ UINT64 Base,
    _In_ UINT64 Size,
    _In_z_ const WCHAR* Path,
    _In_ UINT32 Flags,
    _In_ NTSTATUS VerifyStatus
    )
{
    UINT8* rec;
    UINT64 seq;

    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VerifyStatus);

    if (!AcEventRateLimitAllow(AC_EV_MODULE_LOAD))
        return STATUS_SUCCESS;              /* дедупнуто */

    rec = (UINT8*)ExAllocatePool2(POOL_FLAG_NON_PAGED, 0x4D8, '26vE');
    if (rec == NULL) {
        AcEventReportFailure(0x13, 0);      /* дословно: код alloc-fail */
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(rec, 0x4D8);

    *(UINT32*)(rec + 0x000) = AC_EV_MODULE_LOAD;

    /* [0x140108db8] LOCK-инкремент (дословная пара LOCK/UNLOCK в теле) */
    seq = AcChannelNextSeq();
    *(UINT64*)(rec + 0x008) = seq;

    *(UINT64*)(rec + 0x010) = Base;
    *(UINT64*)(rec + 0x018) = Size;

    /* копия имени 0x208 байтов (эквивалент func_0x00014000c428) */
    AcCopyWideString((WCHAR*)(rec + 0x020), 0x104, Path);

    *(UINT8*)(rec + 0x430) = 0;
    *(UINT64*)(rec + 0x438) = (UINT64)PsGetCurrentProcessId();

    /* 0xfffff78000000014 = KUSER_SHARED_DATA + 0x14 (InterruptTime) */
    *(UINT64*)(rec + 0x440) = *(UINT64*)(UINT_PTR)0xfffff78000000014ULL;

    /* +0x448: per-client контекст (заполняется для клиента сессии
     * FUN_1400062a8 в оригинале; payload-selected извлечение) */

    *(UINT32*)(rec + 0x494) = 1;

    AcChannelSend(rec, 0x4D8);
    ExFreePoolWithTag(rec, '26vE');
    return STATUS_SUCCESS;
}

/* --------------------------------------------------------------------------
 * [0x14003f0bc] событие состояния модуля 0x1E (0x210): {dword 0x1e, pad,
 * wchar path[0x208] @+8, byte state @+0x20C}; state: 2 = открытие файла не
 * удалось (fallback), 3 = классифицирован/верифицирован; гейт 0x140108d50 != 0
 * (AC_EVENT_CHANNEL §1 proven layout)
 * [0x140045448] native role twin: нативный хаб, драйвящий cited 0x1E-продюсер 0x14003f0bc (va_map)
 * [0x14003f008] native role twin: нативный вызывающий cited 0x1E-продюсера 0x14003f0bc (va_map)
 *
 * Цепочка валидации twin'а (аудит agent-515, AUDIT_MISSED_AC.md §2.1):
 * [0x14003f008] --(сайт [0x14003fc68])--> кластер PE-валидатора
 * [0x140042278] --(сайт [0x1400423ee])--> таймстамп-блэклист
 * [0x140040a00] (driver_ts_blacklist.c:AcValidateModulePe /
 * AcIsNotBlacklistedTimestamp); hit -> флаг [state+0x19]=1 + репорт
 * [0x140041ed4] (gap-регион, payload-selected)
 * ------------------------------------------------------------------------ */
NTSTATUS
AcEventModuleState(
    _In_z_ const WCHAR* Path,
    _In_ UINT8 State
    )
{
    UINT8 rec[0x210];

    RtlZeroMemory(rec, sizeof(rec));
    *(UINT32*)(rec + 0x00) = AC_EV_MODULE_STATE;
    AcCopyWideString((WCHAR*)(rec + 0x08), 0x100, Path);
    *(UINT8*)(rec + 0x20C) = State;

    return AcChannelSend(rec, sizeof(rec));
}

/* --------------------------------------------------------------------------
 * [0x1400713c8] событие файл+подпись 0x2B: база 0x4D4, на wire
 * 0x498 + sigsize: seq, 3 object-qword'а, 2 wchar-пути, 143-байтовый ASCII
 * hex-фингерпринт @+0x451, var-len Authenticode-блоб @+0x498
 * {dword size, dword NTSTATUS, bytes}; rate-limit дедуп 10/600
 * (AC_EVENT_CHANNEL §1 proven)
 *
 * FNV-гейт сайт-2 [0x140052a84]: CN-проверка продюсера 0x2B прогоняет ТОТ
 * ЖЕ гейт FNV-1a-64 в порядке T3 -> T2 -> T1 (иммедиаты по
 * 0x140052b1e / 0x140052b41 / 0x140052b5c; вход -- prefix dword по
 * struct+0x38, хэш от struct+0x44+prefix по subject CN Authenticode-
 * подписанта образа процесса -- AC_FNV_GATE #2)
 * ------------------------------------------------------------------------ */
NTSTATUS
AcEventFileSignature(
    _In_z_ const WCHAR* Path,
    _In_ const UINT8* SignatureBlob,
    _In_ UINT32 SignatureSize
    )
{
    UINT8 rec[0x4D8];
    UINT32 total;

    if (!AcEventRateLimitAllow(AC_EV_FILE_SIGNATURE))
        return STATUS_SUCCESS;              /* dedup 10/600 */

    RtlZeroMemory(rec, sizeof(rec));
    *(UINT32*)(rec + 0x00) = AC_EV_FILE_SIGNATURE;
    *(UINT64*)(rec + 0x08) = AcChannelNextSeq();
    AcCopyWideString((WCHAR*)(rec + 0x20), 0x100, Path);

    /* +0x451: ASCII hex-фингерпринт содержимого отображённого файла
     * (AC_EVENT_CHANNEL §2.3/§4: заполняется FUN_14009be44(map_base,
     * file_size, out); дедуп-сравнение FUN_140070d20 покрывает ровно
     * 0x41 байтов = 64 hex + NUL). CNG-дайджест едет на VM-теле
     * фингерпринта [0x140375b79] (payload-selected); hex-кодирование
     * 32-байтового дайджеста -- восстановленная логика (AcFingerprintHex).
     * 65 байтов @+0x451..+0x491 влезают под sig-блоб @+0x498 */
    {
        UINT8 digest[32];

        RtlZeroMemory(digest, sizeof(digest));  /* граница CNG [0x140375b79] */
        AcFingerprintHex(digest, (CHAR*)(rec + 0x451));
    }

    /* Authenticode-блоб {size, NTSTATUS, bytes} по +0x498 */
    *(UINT32*)(rec + 0x498) = SignatureSize;
    *(LONG*)(rec + 0x49C) = STATUS_SUCCESS;
    total = 0x498 + 8;
    if (SignatureBlob != NULL) {
        UINT32 room = sizeof(rec) - total;
        UINT32 take = SignatureSize < room ? SignatureSize : room;
        RtlCopyMemory(rec + total, SignatureBlob, take);
        total += take;
    }

    return AcChannelSend(rec, total);
}

/* --------------------------------------------------------------------------
 * [0x140073c04] сессионный продюсер 0x12-записей (0x658), стреляет из
 * session dispatch, когда флаг выставлен и id клиента известен
 * (DISPATCH_CHAIN_C §6; AC_EVENT_CHANNEL §1: layout 0x12)
 * ------------------------------------------------------------------------ */
VOID
AcEventSessionRecord(
    _In_ UINT64 ClientId
    )
{
    UINT8 rec[0x658];

    RtlZeroMemory(rec, sizeof(rec));
    *(UINT32*)(rec + 0x00) = AC_EV_DETECTION;
    *(UINT64*)(rec + 0x08) = AcChannelNextSeq();
    *(UINT32*)(rec + 0x10) = AC_EV12_OBJECT_WALK;   /* subtype @+0x10 */
    *(UINT64*)(rec + 0x18) = ClientId;
    AcChannelSend(rec, sizeof(rec));
}

/* --------------------------------------------------------------------------
 * [0x140052268] проверка code-integrity в сессионной цепочке
 * (FULL_CHAIN_IRP_TO_HWID_C §2: триггерит цепочку fanout'а коллекторов;
 * хвост цепочки упирается в стену W2 @0x14356b4cf за ней)
 * ------------------------------------------------------------------------ */
VOID
AcEventCodeIntegrityCheck(
    VOID
    )
{
    /* опции ci.dll / результат зонда SystemCodeIntegrityInformation,
     * кэшированный boot-гейтами (env_checks.c EnvCheckCodeIntegrity ->
     * AC_SLOT32 0x2dcc); fanout к коллекторам гейтован на пробуждении
     * воркера (§6). Репортится в канал как запись module-state (layout
     * 0x1E: tag@0x00, wide-путь@0x08, state@0x20C) с запакованными
     * CI-опциями. */
    UINT8 rec[0x210];
    UINT32 ciOptions = AC_SLOT32(0x2dcc);

    RtlZeroMemory(rec, sizeof(rec));
    *(UINT32*)(rec + 0x00) = AC_EV_MODULE_STATE;
    AcCopyWideString((WCHAR*)(rec + 0x08), 0x100, L"\\SystemRoot\\system32\\ci.dll");
    *(UINT8*)(rec + 0x20C) = (UINT8)(ciOptions & 0x3);   /* bit0 Enabled, bit1 TestSigning */
    *(UINT32*)(rec + 0x204) = ciOptions;                 /* полное слово опций */

    AcChannelSend(rec, sizeof(rec));
}

/* --------------------------------------------------------------------------
 * [0xC350202C] push события драйвера: plaintext {u32 0x14, 0, u32 value, 0,
 * u32 code, 0} (24B); code in {0x12 pattern, 0x26 module-load, 0x2b
 * file+sig}; всплески игровой сессии (818 за 2 мин наблюдалось)
 * (evidence: DRIVER_CHANNEL_BYTEMAP §2 таблица фреймов)
 * ------------------------------------------------------------------------ */
/* [0x14014c9fd] sealed-open оркестратор; маршрутизируемые коды от
 * продюсеров записей [0x14003f78c] (0x26) и семейства 0x12/0x2b */
NTSTATUS
AcEventDriverEvent(
    _In_ const VOID* Buf,
    _In_ UINT32 Len
    )
{
    UINT8 plain[24];
    UINT32 plainLen = sizeof(plain);
    NTSTATUS status;
    const AC_DRIVER_EVENT* ev;

    status = AcCryptoOpenSealed(Buf, Len, plain, &plainLen);
    if (!NT_SUCCESS(status))
        return status;

    if (plainLen < sizeof(AC_DRIVER_EVENT))
        return STATUS_INVALID_PARAMETER;

    ev = (const AC_DRIVER_EVENT*)plain;
    if (ev->Tag == 1 && ev->Code == 1) {
        /* ранний вариант 0xC350202C (wire-фрейм `{1,5,0x6a60,0,1,0}`):
         * tag=1, value=PID игры, code=1 = класс process-attach
         * (DRIVER_CHANNEL_BYTEMAP §2 заметка + cross-check RECON2) */
        return STATUS_SUCCESS;
    }
    if (ev->Tag != 0x14)
        return STATUS_INVALID_PARAMETER;

    /* маршрут по коду события (wire-доказанный набор) */
    switch (ev->Code) {
    case AC_EV_DETECTION:       /* попадание паттерна 0x12 */
    case AC_EV_MODULE_LOAD:     /* 0x26 */
    case AC_EV_FILE_SIGNATURE:  /* 0x2b */
        return STATUS_SUCCESS;
    default:
        return STATUS_INVALID_PARAMETER;
    }
}

/* --------------------------------------------------------------------------
 * [0x140070e9c] rate_limit_dedup: 10 событий на окно 600 s на вид
 * (AC_EVENT_CHANNEL §1, golden v1 events.c INDEX)
 * ------------------------------------------------------------------------ */
BOOLEAN
AcEventRateLimitAllow(
    _In_ UINT32 EventKind
    )
{
    static const UINT32 MaxPerWindow = 10;
    static const UINT64 WindowTicks = 600;   /* секунды */

    typedef struct {
        UINT64 WindowStart;
        UINT32 Count;
    } AC_RATE_SLOT;

    static AC_RATE_SLOT slots[0x30];
    static UINT64 perfFreq;
    UINT64 now;
    AC_RATE_SLOT* slot;

    if (perfFreq == 0) {
        LARGE_INTEGER f;
        KeQueryPerformanceCounter(&f);
        perfFreq = (UINT64)f.QuadPart;
    }
    if (perfFreq == 0)
        return TRUE;                         /* нет таймбазы: разрешить */
    now = (UINT64)KeQueryPerformanceCounter(NULL).QuadPart;

    if (EventKind >= 0x30)
        return TRUE;
    slot = &slots[EventKind];

    if (slot->WindowStart == 0 ||
        (now - slot->WindowStart) / perfFreq > WindowTicks) {
        slot->WindowStart = now;
        slot->Count = 0;
    }
    if (slot->Count >= MaxPerWindow)
        return FALSE;
    slot->Count++;
    return TRUE;
}

/* --------------------------------------------------------------------------
 * [0x14000c2c4] report_event_vm_thunk: внутренний репортёр ошибок/
 * живости (284 вызывающих в оригинале). Полная карта 33 кодов репортёра
 * (AC_STATIC_VERDICTS P.4, свип всех call-сайтов):
 *   0x00 dynamic code | 0x03 | 0x12 | 0x13 (x10) | 0x14 | 0x16 (ACPI query)
 *   0x1c (0x10B work-item) | 0x26 (0x26-продюсеры) | 0x2b (x9)
 *   0x2c/0x2d/0x2e | 0x34 (FUN_14009cca0) | 0x36 (инвентарь) | 0x38=56 (x7,
 *   alloc-fail семейства 0x700B) | 0x3c | 0x40 | 0x41 | 0x44=68
 *   (alloc-fail LBR) | 0x46 | 0x48 | 0x4a | 0x61 | 0x6a | 0x6d | 0x70
 *   | 0x71 | 0x7b | 0x7c | 0x7f | 0x81 | 0x82=130 (x7) | 0x85 | 0x8a
 * Роли: alloc-fail'ы продюсеров записей (0x38/0x44/0x1c),
 * маркеры инвентаря/жизненного цикла (0x36/0x26/0x2b/0x16), специфичная
 * диагностика продюсеров (остальные -- 284 call-сайта всего).
 * ------------------------------------------------------------------------ */
VOID
AcEventReportFailure(
    _In_ UINT32 Code,
    _In_ UINT64 Context
    )
{
    struct {
        UINT32 Code;
        UINT32 Pad;
        UINT64 Context;
    } rec;

    rec.Code = Code;
    rec.Pad = 0;
    rec.Context = Context;
    AcChannelSend(&rec, sizeof(rec));
}

/* --------------------------------------------------------------------------
 * [0xC350201C] обработчик match-over (IOCTL 0/0): WSS-push сервиса в конце
 * матча мгновенно успокаивает детект-активность до конца матча
 * (MATCH_SESSION_TIMELINE #0.1 [dec/wire]) -- флаг match-состояния
 * драйвера сбрасывается; пендящиеся тяжёлые детект-пути
 * (watchlist/BYOVD/сканы паттернов) простаивают до следующего push
 * match-join
 * ------------------------------------------------------------------------ */
/* [0xC350201C] обработчик match-over (MATCH_SESSION_TIMELINE #0.1);
 * маршрут диспетча через session dispatcher [0x140066b3c] */
NTSTATUS
AcEventMatchOver(
    VOID
    )
{
    /* сброс ячейки match-состояния (свой слот окна; выставляется push'ем
     * match-join 0xC3502018) */
    AC_SLOT8(0x2dd3) = 0;
    return STATUS_SUCCESS;
}

/* --------------------------------------------------------------------------
 * тело воркайтема: отправляет форензик-запись, захваченную LSTAR-вачдогом
 * (поставленную в очередь через IoQueueWorkItem в anti_tamper.c), затем
 * освобождает запись и воркайтем (поток DISPATCH_CHAIN_C §3: воркайтем +
 * буфер 0x700 + очередь 0x140018dac)
 * ------------------------------------------------------------------------ */
VOID
AcEventForensicWorkItem(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_opt_ PVOID Context
    )
{
    PVOID rec = Context;
    PIO_WORKITEM workItem;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (rec == NULL)
        return;

    workItem = (PIO_WORKITEM)*(PVOID*)((UINT8*)rec + 0x6E0);
    AcChannelSend(rec, 0x700);
    ExFreePoolWithTag(rec, 'rcfA');
    IoFreeWorkItem(workItem);
}

/* --------------------------------------------------------------------------
 * Notify-callback'и.
 * [0x14001b910] image_load_notify_callback (PLOAD_IMAGE_NOTIFY_ROUTINE;
 * pid == 0 -> kernel-путь -> hook_slot_audit(param_1, [image+8]))
 * (дословное тело, golden v1 notify_callbacks.c)
 * ------------------------------------------------------------------------ */
static VOID
AcImageLoadNotify(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo
    )
{
    /* дословное разделение поведения двух callback'ов:
     * [0x14001b910]: pid == 0 (kernel-путь) -> аудит перевооружения хуков
     *   hook_slot_audit(name, [image+8]=ImageBase)
     * [0x140043258]: pid == клиент сессии (0x140108750) ->
     *   FUN_1400644b0(); pci_arming_gate(); + продюсер записи 0x26 */
    if (ProcessId == (HANDLE)0) {
        AcHookSlotAuditEx(FullImageName, ImageInfo->ImageBase);

        /* пайплайн verified-модулей на каждый свежезагруженный kernel-образ:
         * [0x140234578] ac_verifmod_hub_s04 цепляет addr->module
         * [0x1400010a4] -> verified-кэш [0x14009cca0]
         * (паттерн вызовов AC_IOCTL_HANDLER §4.2) */
        if (GameIntegrityIsAddressVerified(
                (UINT64)ImageInfo->ImageBase) == FALSE &&
            FullImageName != NULL) {
            BOOLEAN verified = FALSE;

            GameIntegrityVerifyModule(FullImageName->Buffer, &verified);
        }
        return;
    }

    if ((UINT64)(UINT_PTR)ProcessId == AC_SLOT64(AC_CELL_CLIENT_ID)) {
        /* загрузка образа клиента сессии: гейт вооружения PCI-механики
         * [0x14005876c] (внутри tail-сравнение \matchmaking.dll) */
        AcPciArmingGate();
    }

    if (FullImageName != NULL) {
        /* game watch-list (cs2.exe/csrss.exe/services.exe,
         * strings/decoded.json): наблюдаемый образ процесса -> приоритетный путь */
        if (GameIntegrityIsWatchedProcess(FullImageName->Buffer)) {
            /* проверка флага -tools едет на командной строке process-notify;
             * само попадание в воч репортится как событие module-load */
        }

        AcEventModuleLoad((UINT64)ImageInfo->ImageBase,
                          (UINT64)ImageInfo->ImageSize,
                          FullImageName->Buffer, 0, STATUS_SUCCESS);
    }
}

/* [0x140043258] заметка: оригинальное тело module-notify выполняет
 * FUN_1400644b0() перед гейтом вооружения и заполняет per-client контекст
 * +0x448 через FUN_1400062a8; оба -- VM-side хелперы (payload-selected
 * извлечение, восстановленная политика сохранена выше) */

/* --------------------------------------------------------------------------
 * Process-create notify.
 * [0x14020496f] ac_event_producer_s02 (путь process-notify, med,
 * AC_CALLBACK_HUBS §1/§2): PsSetCreateProcessNotifyRoutineEx
 * (#135, сайт resolve 0x14024b739):
 *   arg2 = PS_CREATE_NOTIFY_INFO (pid @+0x10, обход CreateInfo:
 *   ImageFileName/CommandLine); UTF-16 матчер пути; постановка в очередь
 *   события 0x2b process/handle с бампом seq (LOCK inc 0x140108db8)
 * ------------------------------------------------------------------------ */
static VOID
AcProcessCreateNotify(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
    )
{
    UNREFERENCED_PARAMETER(Process);

    if (CreateInfo == NULL) {
        /* выход процесса: нечего атрибутировать (сторона выхода сессии
         * несётся teardown-записью канала 0x02) */
        return;
    }

    /* обход CreateInfo: ImageFileName (UNICODE_STRING) + CommandLine;
     * матчер проверяет game watch-list и флаг -tools */
    if (CreateInfo->ImageFileName != NULL) {
        const WCHAR* path = CreateInfo->ImageFileName->Buffer;
        BOOLEAN watched;

        if (path == NULL)
            return;

        watched = GameIntegrityIsWatchedProcess(path);
        if (CreateInfo->CommandLine != NULL &&
            CreateInfo->CommandLine->Buffer != NULL &&
            GameIntegrityHasToolsFlag(CreateInfo->CommandLine->Buffer)) {
            /* на наблюдаемой командной строке детектнут CS2 tools-режим */
        }

        if (watched) {
            /* событие 0x2b process/handle для наблюдаемого процесса
             * (дословный бамп seq: LOCK inc из 0x140108db8) */
            AcEventFileSignature(path, NULL, 0);
        }
    }
}

/* --------------------------------------------------------------------------
 * Object-handle callback'и.
 * [ObRegisterCallbacks, хэш 0xC5184623A938587 -- разрешён И вызван
 * (rcx=&reg-блок, rdx=0x18): AC_NDIS §2; тела callback'ов -- VM-хабы
 * мегачанка 0x140293018 (payload-selected внутренности)]
 * pre/post-операции на создании хэндлов процесса/потока -- anti-tamper
 * на хэндлах игры и собственных.
 * ------------------------------------------------------------------------ */
static OB_PREOP_CALLBACK_STATUS
AcObjectPreCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInfo
    )
{
    UNREFERENCED_PARAMETER(RegistrationContext);
    UNREFERENCED_PARAMETER(OperationInfo);

    /* политика pre-op: VM-хабовые тела в оригинале (мегачанк
     * 0x140293018); восстановленный контракт регистрации ниже */
    return OB_PREOP_SUCCESS;
}

/* [0x140293018] потребитель post-op хаба (мегачанк; AC_NDIS §2) */
static VOID
AcObjectPostCallback(
    _In_ PVOID RegistrationContext,
    _In_ POB_POST_OPERATION_INFORMATION OperationInfo
    )
{
    UNREFERENCED_PARAMETER(RegistrationContext);
    UNREFERENCED_PARAMETER(OperationInfo);
}

/* --------------------------------------------------------------------------
 * Registry notify (воч GameConfigStore).
 * [CmRegisterCallbackEx #148, сайт resolve 0x14024b7ef; воч-набор:
 * \System\GameConfigStore\Parents\Children, WorkingDirectory,
 * MitigationOptions (AC_MONITORING §1.3 suspected + декодированные строки
 * 0x140067e88/0x140067cdc/0x140067e48/0x140067ec8)]
 * ------------------------------------------------------------------------ */
static NTSTATUS
AcRegistryCallback(
    _In_ PVOID CallbackContext,
    _In_opt_ PVOID Argument1,
    _In_opt_ PVOID Argument2
    )
{
    REG_NOTIFY_CLASS notifyClass = (REG_NOTIFY_CLASS)(UINT_PTR)Argument1;

    UNREFERENCED_PARAMETER(CallbackContext);
    UNREFERENCED_PARAMETER(Argument2);

    switch (notifyClass) {
    case RegNtPreSetValueKey:
    case RegNtPreCreateKeyEx:
        /* сигнал -- активность записи GameConfigStore по наблюдаемым
         * ключам; VM-side вердикт едет на notify-хабах */
        break;
    default:
        break;
    }
    return STATUS_SUCCESS;
}

/* --------------------------------------------------------------------------
 * Minifilter (мониторинг файлов игры, CS2).
 * [18 Flt* resolve'ов #131-148 (семейство FltRegisterFilter, заметка
 * IMPORTS_REPORT §2: все 18 запрошены live и привязаны); кандидатная роль:
 * мониторинг файлов игры по артефактам CS2 (.vpk/_dir.vpk/gameinfo.gi/
 * \shaders\/\csgo_lv\/\workshop\/\cfg\gamestate_integration_,
 * AC_MONITORING §1.3 suspected + декодированные строки game_path)]
 * Классификатор pre-create использует восстановленный воч-лист путей CS2
 * (game_integrity.c GameIntegrityIsCs2Path); сами тела filter-callback'ов
 * -- VM-хабы (payload-selected внутренности).
 * ------------------------------------------------------------------------ */
/* контур имён файлов minifilter'а (43 sealed-тела, кластер recon2):
 * обход name-info идёт под триадой Flt push-lock'ов:
 *   FltAcquirePushLockShared    [ячейка 0x1401079e0, 167 сайтов]
 *   FltAcquirePushLockExclusive [ячейка 0x140108200, 254 сайта]
 *   FltReleasePushLock          [ячейка 0x1401078b0, 301 сайт]
 * запрос имени через FltGetFileNameInformationUnsafe
 * [ячейка 0x140108320 / тело 0x142c540bd] + FltReleaseFileNameInformation
 * [ячейка 0x140108350 / тело 0x140276580]; классификатор воч-листа CS2
 * (game_integrity.c) гейтует пайплайн глубокой верификации */
static AC_CHANNEL_STATE* AcFltNameCacheChannel(VOID);
static EX_PUSH_LOCK AcFltNameCacheLock;

static FLT_PREOP_CALLBACK_STATUS
AcMinifilterPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Outptr_result_maybenull_ PVOID* CompletionContext
    )
{
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (Data == NULL || Data->Iopb == NULL)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    /* [0x1401079e0] FltAcquirePushLockShared: кэш имён читается под
     * shared-локом (sealed-контур держит список имён файлов за этими
     * локами) */
    FltAcquirePushLockShared(&AcFltNameCacheLock);
    __try {
        /* [0x140108320] FltGetFileNameInformationUnsafe на цели create
         * (тело 0x142c540bd) */
        status = FltGetFileNameInformationUnsafe(
            Data->Iopb->TargetFileObject, FltObjects->Instance,
            FLT_FILE_NAME_NORMALIZED, &nameInfo);
    } __finally {
        /* [0x1401078b0] FltReleasePushLock */
        FltReleasePushLock(&AcFltNameCacheLock);
    }

    if (NT_SUCCESS(status) && nameInfo != NULL) {
        if (GameIntegrityIsCs2Path(nameInfo->Name.Buffer)) {
            /* наблюдаемый артефакт CS2: гейт пайплайна глубокой верификации --
             * семейство событий файл+подпись (0x2b) ниже по потоку */
        }
        /* [0x140108350] FltReleaseFileNameInformation (0x140276580) */
        FltReleaseFileNameInformation(nameInfo);
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static AC_CHANNEL_STATE* AcFltNameCacheChannel(VOID)
{
    return NULL;
}

/* --------------------------------------------------------------------------
 * Регистрация всей notify/callback-механики (шаг отложенного init'а).
 * Сайты resolve (AC_API_PAIRS): #149 PsSetLoadImageNotifyRoutine
 * (0x14024b7fd), #135 PsSetCreateProcessNotifyRoutineEx (0x14024b739),
 * #136 PsSetCreateThreadNotifyRoutine (0x14024b747, класс не подтверждён),
 * ObRegisterCallbacks (хэш 0xC5184623A938587), #148 CmRegisterCallbackEx
 * (0x14024b7ef), #131-148 Flt* (minifilter), #221 ExCreateCallback
 * (0x14024bbed). Все регистрации отложенные (никогда не в DriverEntry,
 * KERNEL_WALLS_FINAL §1.1).
 * ------------------------------------------------------------------------ */
NTSTATUS
AcRegisterNotifyCallbacks(
    VOID
    )
{
    NTSTATUS status;
    static const UNICODE_STRING altitude =
        RTL_CONSTANT_STRING(L"360000");
    static const UNICODE_STRING gameKeyRoot =
        RTL_CONSTANT_STRING(L"\\System\\GameConfigStore");
    OB_CALLBACK_REGISTRATION obReg;
    OB_OPERATION_REGISTRATION obOps[2];
    PVOID obHandle = NULL;
    LARGE_INTEGER cmCookie = { 0 };

    /* #149: image-load notify */
    status = PsSetLoadImageNotifyRoutine(AcImageLoadNotify);
    if (!NT_SUCCESS(status))
        return status;

    /* #135: process-create notify */
    status = PsSetCreateProcessNotifyRoutineEx(AcProcessCreateNotify,
                                               FALSE);
    if (!NT_SUCCESS(status))
        return status;

    /* ObRegisterCallbacks: операции с хэндлами процесса + потока */
    RtlZeroMemory(&obReg, sizeof(obReg));
    RtlZeroMemory(obOps, sizeof(obOps));
    obOps[0].ObjectType = PsProcessType;
    obOps[0].Operations = OB_OPERATION_HANDLE_CREATE |
                          OB_OPERATION_HANDLE_DUPLICATE;
    obOps[0].PreOperation = AcObjectPreCallback;
    obOps[0].PostOperation = AcObjectPostCallback;
    obOps[1].ObjectType = PsThreadType;
    obOps[1].Operations = OB_OPERATION_HANDLE_CREATE |
                          OB_OPERATION_HANDLE_DUPLICATE;
    obOps[1].PreOperation = AcObjectPreCallback;
    obOps[1].PostOperation = AcObjectPostCallback;

    obReg.Version = 0x0100;     /* OB_REGISTRATION_VERSION (не макрос
                                 * в заголовках этого WDK) */
    obReg.OperationRegistrationCount = 2;
    obReg.Altitude = altitude;
    obReg.RegistrationContext = NULL;
    obReg.OperationRegistration = obOps;
    status = ObRegisterCallbacks(&obReg, &obHandle);
    if (!NT_SUCCESS(status)) {
        /* ошибка регистрации не фатальна (потребитель VM-хаба терпит) */
    }

    /* #148: registry notify (корень GameConfigStore) */
    status = CmRegisterCallbackEx(AcRegistryCallback, &altitude, NULL,
                                  &cmCookie, NULL, NULL);
    if (!NT_SUCCESS(status)) {
        /* не фатально */
    }
    UNREFERENCED_PARAMETER(gameKeyRoot);

    /* minifilter: FltRegisterFilter + FltStartFiltering едут на 18
     * Flt* resolve'ах (#131-148); дескриптор регистрации фильтра и таблица
     * контекстов в оригинале строятся VM'ом (payload-selected:
     * AC_CALLBACK_HUBS §2 -- статический fn-указатель не материализуется) */
    UNREFERENCED_PARAMETER((PVOID)AcMinifilterPreCreate);

    return STATUS_SUCCESS;
}
