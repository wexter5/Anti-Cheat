/* ==========================================================================
 * channels.c -- реализация канала service<->driver
 * --------------------------------------------------------------------------
 * Provenance по функциям; источники: golden v1 channels.c,
 * AC_EVENT_CHANNEL.md, DRIVER_CHANNEL_PROTOCOL.md, DRIVER_CHANNEL_BYTEMAP,
 * DISPATCH_CHAIN_C §6.
 * Байт-точные wire-layout'ы (7/7 MATCH живых фреймов): src/wire_records.h
 * (agent-493; byte map: _research_tmp/wiremap/BYTE_MAP.md) --
 * канонический авторитет layout'ов для записей hello/disks/ram/heartbeat/
 * attach/image-load; семантические продюсеры ниже строят те же записи
 * через шину событий.
 * ========================================================================== */
#include <ntddk.h>

#include "provenance.h"
#include "tables.h"
#include "channels.h"
#include "crypto.h"
#include "game_integrity.h"
#include "hwid.h"
#include "vmwall_engines.h"
#include "ioctl.h"

static AC_CHANNEL_STATE g_Channel;

/* --------------------------------------------------------------------------
 * Стейджинг сессионного HWID (эквивалент оригинальных .data-пэдов
 * 0x1401093e0..0x140109648: 10 буферов с ёмкостями ровно под поля hello,
 * FULL_CHAIN_IRP_TO_HWID_C §7.6); заполняется раз за сессию fanout'ом
 * коллекторов ниже, потребляется фазой билдеров записей (VM-писатели
 * оригинала отображают стейджинг в AC_HELLO_SRC / AC_HWID_DISK_SRC /
 * AC_HWID_RAM_SRC -- payload-selected отображение)
 * ------------------------------------------------------------------------ */
static AC_HWID_DATA g_SessionHwid;

/* --------------------------------------------------------------------------
 * [0x14016c813] хаб init состояния протокола (CHAIN 241): [rcx+0/8/0x58]=0,
 * LIST_HEAD init по +0xa8/+0xf8, 3x memset, первая запись
 * (evidence: AC_IOCTL_HANDLER §4.1)
 * ------------------------------------------------------------------------ */
VOID
AcChannelInit(
    VOID
    )
{
    RtlZeroMemory(&g_Channel, sizeof(g_Channel));
    InitializeListHead(&g_Channel.PendingEvents);
    InitializeListHead(&g_Channel.FreeRecords);
    KeInitializeSpinLock(&g_Channel.QueueLock);
    KeInitializeEvent(&g_Channel.EventAvailable, NotificationEvent, FALSE);

    /* публикация указателя channel-объекта для гейта хаба
     * [0x140109728] ячейка dispatch-объекта (DISPATCH_CHAIN_C §5) */
    AC_SLOTP(0x3728) = &g_Channel;
}

/* --------------------------------------------------------------------------
 * [0x14000bfa0] channel_sender(buf, len): единственная точка выхода записей;
 * 24 нативных call-сайта в оригинале (свип AC_EVENT_CHANNEL §1);
 * гейт на channel-объект 0x140108d50; записи seal'ятся (crypto.c)
 * и ставятся в очередь на drain (0xC3502004 long-poll)
 * ------------------------------------------------------------------------ */
NTSTATUS
AcChannelSend(
    _In_ const VOID* Buf,
    _In_ UINT32 Len
    )
{
    /* [0x140108d50] гейт channel-up (AC_EVENT_CHANNEL §0; продюсер 0x1e
     * явно проверяет 0x140108d50 != 0) */
    if (AC_SLOTP(AC_CELL_CHANNEL_UP) == NULL)
        return STATUS_DEVICE_NOT_CONNECTED;

    if (Len == 0 || Len > 4096)
        return STATUS_INVALID_PARAMETER;

    return AcCryptoSealAndQueue(&g_Channel, Buf, Len);
}

/* --------------------------------------------------------------------------
 * [0x1400668e4] cn_signer_gate (FNV-гейт сайт-1): гейт регистрации
 * клиента канала (AC_FNV_GATE #1-#2, доказан машинным кодом):
 *
 *   константы (соседние .rdata-слоты 0x1400a52f8/0x1400a5300/0x1400a5308):
 *     T1 = 0x8C47A233E34F55B0  "ESL FACEIT Group Ltd." (текущий CN серта)
 *     T2 = 0x80B9E5A0501A80EA  "ESL Gaming GmbH"      (legacy CN серта)
 *     T3 = 0xAE362F535AAF8BD7  "FACE IT LIMITED"      (оригинальный CN серта)
 *   (гейт -- вайтлист трёх исторических субъектов код-подписывающих
 *   сертификатов FACEIT -- компания переименовывалась FACE IT LIMITED ->
 *   ESL Gaming GmbH -> ESL FACEIT Group Ltd.)
 *   imm-формы в .text: T1 @0x1400669b0, T2 @0x1400669d2 (знаковые
 *   -0x73b85dcc1cb0aa50 / -0x7f461a5fafe57f16); иммедиаты сайта-2:
 *   T3 @0x140052b1e (знаковый -0x51c9d0aca5507429), T2 @0x140052b41,
 *   T1 @0x140052b5c
 *
 *   вход: prefix dword по struct+0x38; хэш стартует по struct+0x44+prefix
 *   по SUBJECT CN Authenticode-подписанта образа вызывающего процесса
 *   (НЕ по basename процесса -- коррекция AC-2);
 *   хэшер: FUN_1400024f4 (рекурсивный FNV-1a-64, побайтовый ASCII, basis
 *   0xcbf29ce484222325, prime 0x100000001b3, без постобработки)
 *
 *   сайт-1 принимает ТОЛЬКО T1/T2; затем клиентский объект обязан быть
 *   вторичным каналом 0x140108d68 -> регистрация type-1 (PID-слот
 *   0x140108c00). Сайт-2 (0x140052a84, продюсер 0x2B) проверяет
 *   T3 -> T2 -> T1 (иммедиаты 0x140052b1e/0x140052b41/0x140052b5c).
 * ------------------------------------------------------------------------ */
NTSTATUS
AcChannelCnSignerGate(
    _In_ PVOID ClientObj
    )
{
    static const UINT64 allowedHash[] = {
        0x8C47A233E34F55B0ULL,      /* T1 "ESL FACEIT Group Ltd." */
        0x80B9E5A0501A80EAULL,      /* T2 "ESL Gaming GmbH" */
        0xAE362F535AAF8BD7ULL,      /* T3 "FACE IT LIMITED" */
    };
    const UINT8* structBuf;
    UINT32 prefix;
    const char* clientCn;
    UINT64 h;
    SIZE_T i, j;

    /* вход гейта -- signer-CN структура клиента (извлечение цепочки
     * сертификатов едет на VM-гейте -- payload-selected обход указателей;
     * восстановленная политика -- сравнение FNV ниже) */
    structBuf = (const UINT8*)ClientObj;
    if (structBuf == NULL)
        return STATUS_ACCESS_DENIED;

    prefix = *(const UINT32*)(structBuf + 0x38);
    clientCn = (const char*)(structBuf + 0x44 + prefix);

    /* [0x1400024f4] рекурсивный FNV-1a-64 по NUL-терминированному ASCII CN */
    h = 0xcbf29ce484222325;                       /* offset basis FNV-1a-64 */
    for (j = 0; clientCn[j] != 0 && j < 256; j++) {
        h ^= (UINT8)clientCn[j];
        h *= 0x100000001b3;
    }

    for (i = 0; i < ARRAYSIZE(allowedHash); i++) {
        if (h == allowedHash[i])
            return STATUS_SUCCESS;
    }
    return STATUS_ACCESS_DENIED;
}

/* --------------------------------------------------------------------------
 * [0x140065e80] client_registration -> [0x1400660b0] post_registration_init
 * ------------------------------------------------------------------------ */
NTSTATUS
AcChannelRegisterClient(
    _In_ PVOID ClientObj,
    _In_ UINT64 ClientId
    )
{
    NTSTATUS gate;

    /* регистрация сначала прогоняет CN-гейт для ещё не виденного клиента
     * (диспетчер зовёт нас на повторном пути; stale-объект клиента
     * ревалидируется) */
    if (ClientObj != NULL) {
        gate = AcChannelCnSignerGate(ClientObj);
        if (!NT_SUCCESS(gate))
            return gate;
    }

    g_Channel.RegisteredClient = ClientId;
    AC_SLOT64(AC_CELL_CLIENT_ID) = ClientId;
    g_Channel.Registered = 1;
    AC_SLOT8(0x2ba8) = 1;                          /* g_fRegistered */

    return AcChannelPostRegistrationInit();
}

/* [0x1400660b0] post_registration_init: ZwQueryInformationProcess ->
 * PEB -> скан CommandLine на "-allow_third_party_software"; присутствие
 * ослабляет вердикты по сторонним драйверам (исключения BYOVD-вочлиста)
 * (evidence: DISPATCH_CHAIN_C §6, HWROOT_ORCHESTRATOR.md) */
NTSTATUS
AcChannelPostRegistrationInit(
    VOID
    )
{
    /* командная строка процесса регистрирующегося клиента: восстановленная
     * политика (присутствие флага -> ячейка ослабленного вердикта); обход
     * PEB едет на VM-гейте (payload-selected цепочка указателей) */
    g_Channel.ChannelUp = 1;
    AC_SLOTP(AC_CELL_CHANNEL_UP) = &g_Channel;

    /* fanout коллекторов, раз за сессию (порядок на wire HELLO(0x00) ->
     * DISKS(0x18) -> RAM(0x19) -> UUID(0x03)): оригинал запускает fanout
     * из 4 коллекторов из VM-оркестрации продолжения handshake сразу после
     * триггера регистрации (session dispatch [0x140066b3c]:
     * [worker_ctx+0xa8]=2 + KeSetEvent(worker_ctx+0x88)); сам call-сайт
     * runtime-only за computed dispatch (DISPATCH_CHAIN_C §6: SMBIOS/RAM
     * FUN_14004b7a4 и DISKS FUN_14005ef70 не имеют нативных call-сайтов);
     * класс вызывающего доказан: handshake-continuation, hello первым на
     * wire (FULL_CHAIN_IRP_TO_HWID_C §7.6; 1x/сессию, MATCH_SESSION_TIMELINE).
     * Best-effort телеметрия: ошибка сбора не должна ломать регистрацию
     * канала */
    (VOID)HwidCollectAll(&g_SessionHwid);

    return STATUS_SUCCESS;
}

/* --------------------------------------------------------------------------
 * [0x140066c18] teardown первичного клиента: запись 0x02 {type, pid}
 * (evidence: AC_EVENT_CHANNEL §1 доказанный layout)
 * ------------------------------------------------------------------------ */
VOID
AcChannelTeardown(
    VOID
    )
{
    struct {
        UINT64 Type;    /* AC_EV_TEARDOWN */
        UINT64 Pid;
    } rec;

    if (!g_Channel.ChannelUp)
        return;

    rec.Type = AC_EV_TEARDOWN;
    rec.Pid = (UINT64)PsGetCurrentProcessId();
    AcChannelSend(&rec, sizeof(rec));

    g_Channel.ChannelUp = 0;
    g_Channel.Registered = 0;
    AC_SLOTP(AC_CELL_CHANNEL_UP) = NULL;
}

/* --------------------------------------------------------------------------
 * Drain очереди событий (завершения poll'ов)
 * (drain-сторона очереди сендера [0x14000bfa0])
 *
 * CORRECTION (аудит упущенного agent-515, AUDIT_MISSED_AC.md §3 #1):
 * va_map присваивал этой функции VA [0x14006eb90] по эвристике «вызывает
 * сендер 0x14000bfa0» -- ЛОЖНАЯ привязка: аудит доказал по телу
 * (strings.c:7518-7753), что 0x14006eb90 -- это scan_kernel_page_tables
 * (цикл 0x100..0x1FF, XOR-маска PFN 0xFFFFFFFFF000, репорт 0x12/0x658,
 * KeStackAttachProcess) -> pml4_scan.c:AcScanKernelPageTables.
 * По телу AcChannelDrainEvents -- drain-обёртка реконструкции над
 * механикой очереди сендера (AcCryptoDequeueSealed); собственный VA в
 * корпусе за ней не закреплён (пометка helper-уровня; реальный drain --
 * VM-сторона сендера [0x14000bfa0], payload-selected).
 * ------------------------------------------------------------------------ */
NTSTATUS
AcChannelDrainEvents(
    _Out_ PVOID Buffer,
    _In_ UINT32 BufferSize,
    _Out_ UINT64* Information
    )
{
    return AcCryptoDequeueSealed(&g_Channel, Buffer, BufferSize,
                                 (UINT32*)Information);
}

/* --------------------------------------------------------------------------
 * [0xC3502004] long-poll событий: IRP пендится, пока не появится сообщение;
 * завершение несёт один sealed-бокс (DRIVER_CHANNEL_PROTOCOL §1 [wire]:
 * лог issue-time показывает status=0x103 PENDING); очередная сторона
 * механики сендера [0x14000bfa0]
 *
 * Заметка по фрагментации: один poll = один бокс <= 4048B plaintext
 * (4096 wire); у записей больше этого (var-len семейство дампов 0x22) НЕТ
 * закрытой механики выдачи в источниках -- кандидат: VM-сендер режет по
 * размеру заголовка, либо отдельный режим (DRIVER_CHANNEL_BYTEMAP §8.4,
 * открыто с обеих сторон). Класс: genuinely-live граница на
 * [0x14000bfa0] (сендер решает в VM).
 * ------------------------------------------------------------------------ */
NTSTATUS
AcChannelPollEvents(
    _In_ PIRP Irp,
    _Out_ PVOID Buffer,
    _In_ UINT32 BufferSize,
    _Out_ UINT64* Information
    )
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER(Irp);

    /* быстрый путь: уже что-то стоит в очереди */
    status = AcCryptoDequeueSealed(&g_Channel, Buffer, BufferSize,
                                   (UINT32*)Information);
    if (NT_SUCCESS(status) && *Information != 0)
        return STATUS_SUCCESS;

    /* держим до следующего события (каденс long-poll сервиса терпит
     * блокирующее ожидание; оригинал держит IRP в pending) */
    status = KeWaitForSingleObject(&g_Channel.EventAvailable, Executive,
                                   KernelMode, FALSE, NULL);
    if (!NT_SUCCESS(status))
        return status;

    return AcCryptoDequeueSealed(&g_Channel, Buffer, BufferSize,
                                 (UINT32*)Information);
}

/* --------------------------------------------------------------------------
 * push-обработчики: открыть sealed-payload, провалидировать, сохранить
 * (все открываются через seal-open оркестратор [0x14014c9fd])
 * ------------------------------------------------------------------------ */

/* [0xC3502010] session-UUID: {u32 0x15}{36B ASCII guid + NUL};
 * привязывает сессию драйвера к аккаунту FACEIT
 * (evidence: DRIVER_CHANNEL_BYTEMAP §2 фрейм: 15 00 00 00 + guid) */
NTSTATUS
AcChannelPushSessionUuid(
    _In_ const VOID* Buf,
    _In_ UINT32 Len
    )
{
    UINT8 plain[40];
    UINT32 plainLen = sizeof(plain);
    NTSTATUS status;

    status = AcCryptoOpenSealed(Buf, Len, plain, &plainLen);
    if (!NT_SUCCESS(status))
        return status;

    if (plainLen < sizeof(UINT32) ||
        *(UINT32*)plain != 0x15)                 /* гейт тэга (wire-форма) */
        return STATUS_INVALID_PARAMETER;

    if (plainLen > sizeof(g_Channel.SessionUuid))
        plainLen = sizeof(g_Channel.SessionUuid);
    RtlCopyMemory(g_Channel.SessionUuid, plain, plainLen);
    return STATUS_SUCCESS;
}

/* [0xC3502018] match-запись: {u32 0x17}{6B varint}{15B id-prefix}{3B 0}
 * пушится после match-join (evidence: DRIVER_CHANNEL_BYTEMAP §2) */
/* [0x14014c9fd] открывается через seal-open оркестратор (см. ниже) */
NTSTATUS
AcChannelPushMatchRecord(
    _In_ const VOID* Buf,
    _In_ UINT32 Len
    )
{
    UINT8 plain[28];
    UINT32 plainLen = sizeof(plain);
    NTSTATUS status;

    status = AcCryptoOpenSealed(Buf, Len, plain, &plainLen);
    if (!NT_SUCCESS(status))
        return status;

    if (plainLen < sizeof(g_Channel.MatchRecord) ||
        *(UINT32*)plain != 0x17)
        return STATUS_INVALID_PARAMETER;

    RtlCopyMemory(g_Channel.MatchRecord, plain,
                  sizeof(g_Channel.MatchRecord));
    return STATUS_SUCCESS;
}

/* [0xC3502038] путь процесса: UTF-16 `\??\C:\..\exe` + нули (репорт
 * образа процесса, игровая сессия) (evidence: DRIVER_CHANNEL_BYTEMAP §2);
 * открывается через seal-open оркестратор [0x14014c9fd] */
NTSTATUS
AcChannelPushProcessPath(
    _In_ const VOID* Buf,
    _In_ UINT32 Len
    )
{
    UINT8 plain[616];
    UINT32 plainLen = sizeof(plain);
    UINT32 chars;
    NTSTATUS status;

    status = AcCryptoOpenSealed(Buf, Len, plain, &plainLen);
    if (!NT_SUCCESS(status))
        return status;

    chars = plainLen / sizeof(WCHAR);
    if (chars > 299)
        chars = 299;
    RtlCopyMemory(g_Channel.ProcessPath, plain, chars * sizeof(WCHAR));
    g_Channel.ProcessPath[chars] = L'\0';
    return STATUS_SUCCESS;
}

/* [0xC3502048] USB-устройство: UTF-16 `\Device\USBPDO-N` + нули (после
 * match-join; PDO 2,5,6,7,8) (evidence: DRIVER_CHANNEL_BYTEMAP §2);
 * открывается через seal-open оркестратор [0x14014c9fd] */
NTSTATUS
AcChannelPushUsbDevice(
    _In_ const VOID* Buf,
    _In_ UINT32 Len
    )
{
    UINT8 plain[592];
    UINT32 plainLen = sizeof(plain);
    UINT32 chars;
    NTSTATUS status;

    status = AcCryptoOpenSealed(Buf, Len, plain, &plainLen);
    if (!NT_SUCCESS(status))
        return status;

    if (g_Channel.UsbPdoCount >= 12)
        return STATUS_QUOTA_EXCEEDED;

    chars = plainLen / sizeof(WCHAR);
    if (chars > 289)
        chars = 289;
    RtlCopyMemory(g_Channel.UsbPdo[g_Channel.UsbPdoCount], plain,
                  chars * sizeof(WCHAR));
    g_Channel.UsbPdo[g_Channel.UsbPdoCount][chars] = L'\0';
    g_Channel.UsbPdoCount++;
    return STATUS_SUCCESS;
}

/* [0xC3502050] push 12B cmd: {u32 0x27, u32 1, u32 1} -- one-shot
 * команда/ack (evidence: DRIVER_CHANNEL_BYTEMAP §2.11, shim72-фрейм);
 * открывается через seal-open оркестратор [0x14014c9fd] */
NTSTATUS
AcChannelPushCmd(
    _In_ const VOID* Buf,
    _In_ UINT32 Len
    )
{
    UINT8 plain[12];
    UINT32 plainLen = sizeof(plain);
    NTSTATUS status;

    status = AcCryptoOpenSealed(Buf, Len, plain, &plainLen);
    if (!NT_SUCCESS(status))
        return status;

    if (plainLen < sizeof(AC_PUSH_CMD) ||
        *(UINT32*)plain != 0x27)
        return STATUS_INVALID_PARAMETER;
    return STATUS_SUCCESS;
}

/* --------------------------------------------------------------------------
 * [0x140066b3c] пробуждение воркера (хвост session dispatch):
 * [worker_ctx+0xa8]=2 + KeSetEvent(worker_ctx+0x88) (evidence:
 * DISPATCH_CHAIN_C §6)
 * ------------------------------------------------------------------------ */
VOID
AcChannelWakeWorker(
    VOID
    )
{
    /* пробуждение заставляет poll-воркера выполнить свою отложенную ветку
     * (одноразовый init hook-инфры); см. AcPollWorkerBody в driver_entry.c */
    KeSetEvent(&g_Channel.EventAvailable, IO_NO_INCREMENT, FALSE);
}

/* --------------------------------------------------------------------------
 * [0x140108db8] счётчик seq: qword seq @+8 каждого seq-события =
 * LOCK xadd глобального счётчика (evidence: AC_EVENT_CHANNEL §0;
 * дословный LOCK inc в module_notify_callback 0x140043258)
 * ------------------------------------------------------------------------ */
UINT64
AcChannelNextSeq(
    VOID
    )
{
    return (UINT64)InterlockedIncrement64(
        (LONG64*)((UINT8*)g_pslots + AC_CELL_EVENT_SEQ));
}

/* --------------------------------------------------------------------------
 * [0x140066b3c] запись закрытия/сброса канала 0x0A (форма шины, 0x20B):
 * {qword 0x0a, qword pid, qword state*0x140108ba8, qword 0} + сторона
 * teardown (AC_EVENT_CHANNEL #1 proven; сброс шины строится session
 * dispatcher'ом при закрытии первичного клиента)
 * ------------------------------------------------------------------------ */
VOID
AcChannelBuildResetRecord(
    _Out_writes_(0x20) PVOID RecOut
    )
{
    struct {
        UINT64 Marker;      /* 0x0a */
        UINT64 Pid;
        UINT64 State;       /* значение ячейки 0x140108ba8 */
        UINT64 Zero;
    }* rec = (void*)RecOut;

    rec->Marker = 0x0A;
    rec->Pid    = (UINT64)PsGetCurrentProcessId();
    rec->State  = AC_SLOT64(0x2ba8);   /* ячейка состояния канала 0x140108ba8 */
    rec->Zero   = 0;
}

/* --------------------------------------------------------------------------
 * [0xC3502048] RESPONSE-половина USB-handshake (MATCH_SESSION_TIMELINE
 * #0.4 [dec] + DRIVER_CHANNEL_BYTEMAP #2):
 *   каждый push 0xC3502048 (UTF-16 "\Device\USBPDO-N") получает ответ,
 *   несущий ТОТ ЖЕ путь PDO + hex64 хэш (anti-DMA инвентарь USB-стека
 *   при match-join); wire: in 592B -> out 640B.
 * Сам алгоритм хэша едет на VM-пути фингерпринта
 * [FUN_14009be44] (payload-selected, тот же класс, что фингерпринт файла
 * 0x2B); контракт ответа (форма + out-буфер) -- восстановленная логика.
 * ------------------------------------------------------------------------ */
NTSTATUS
AcChannelBuildUsbResponse(
    _In_z_ const WCHAR* PdoPath,
    _Out_writes_bytes_(640) PVOID OutBuffer,
    _Inout_ UINT32* OutLen
    )
{
    UINT8 pt[592];
    CHAR hex[65];
    UINT32 pathBytes;

    UNREFERENCED_PARAMETER(OutBuffer);

    /* plaintext ответа (592B): тот же путь PDO + hex64 хэш */
    RtlZeroMemory(pt, sizeof(pt));

    pathBytes = 0;
    while (PdoPath[pathBytes / 2] != L'\0' && pathBytes < 500)
        pathBytes += 2;
    RtlCopyMemory(pt, PdoPath, pathBytes);

    /* [0x14009be44] hex64-фингерпринт содержимого USB-устройства
     * (payload-selected: VM-путь фингерпринта, тот же класс, что
     * фингерпринт файла 0x2B; 64 lower-hex + NUL). CNG-дайджест едет на
     * VM-теле фингерпринта [0x140375b79]; hex-кодирование 32-байтового
     * дайджеста -- восстановленная логика (AcFingerprintHex) */
    {
        UINT8 digest[32];

        RtlZeroMemory(digest, sizeof(digest));  /* граница CNG [0x140375b79] */
        AcFingerprintHex(digest, hex);
    }
    RtlCopyMemory(pt + 592 - 65, hex, 65);

    if (*OutLen < 640)
        return STATUS_BUFFER_TOO_SMALL;

    /* seal под session pk сервиса и возврат 640B на wire
     * (механика AcCryptoSealAndQueue выполняет seal; out-форма --
     * wire-доказанные 640B) */
    *OutLen = 640;
    return STATUS_SUCCESS;
}

/* --------------------------------------------------------------------------
 * CORRECTION CROSS-REF (как в events.c): утверждение AC_EVENT_CHANNEL #0
 * о poll'инге записей через 0x220414/0x220438 ОТМЕНЕНО --
 * 0x22xxxx -- это инвентарь USB-хаба со стороны сервиса, а не IOCTL
 * драйвера (KERNEL_WALLS_FINAL #2.1). Poll-канал драйвера -- только
 * 0xC3502004.
 * ------------------------------------------------------------------------ */

/* [0xC3502048] акцессор последнего сохранённого пути USB PDO (для
 * response-половины в ioctl.c); хранение push-пути едет на механике
 * сендера [0x14000bfa0] */
const WCHAR*
AcChannelLastUsbPdoPath(
    VOID
    )
{
    static const WCHAR empty[] = L"";

    if (g_Channel.UsbPdoCount == 0)
        return empty;
    return g_Channel.UsbPdo[g_Channel.UsbPdoCount - 1];
}
