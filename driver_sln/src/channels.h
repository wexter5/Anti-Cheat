/* ==========================================================================
 * channels.h -- канал service<->driver: состояние, сендер, регистрация,
 *               шина записей событий, push-обработчики
 * ========================================================================== */
#ifndef FACEIT_AC_CHANNELS_H
#define FACEIT_AC_CHANNELS_H

#include <ntddk.h>
#include "ioctl.h"

/* ---- маркеры записей событий (таксономия AC_EVENT_CHANNEL §1) ------------
 * мелкие нотификации без seq: 0x02/0x0a/0x1a/0x1b/0x1e/0x29
 * seq-события (qword seq @+8 = LOCK xadd из 0x140108db8): 0x12/0x22/0x26/0x2b */
#define AC_EV_TEARDOWN        0x02   /* 0x10  {type, pid} (0x140066c18) */
#define AC_EV_CHANNEL_RESET   0x0A   /* 0x20  сброс сессии (0x140066b3c) */
#define AC_EV_DETECTION       0x12   /* 0x658 generic-детекция, subtype @+0x10 */
#define AC_EV_NAME_A          0x1A   /* 0x20C {type, wchar[0x104]} */
#define AC_EV_NAME_B          0x1B   /* 0x20C ветка ошибки верификации */
#define AC_EV_MODULE_STATE    0x1E   /* 0x210 байт состояния @+0x20C: 2/3 */
#define AC_EV_MODULE_DUMP     0x22   /* 0x228+size дамп, reason @+0x224 */
#define AC_EV_MODULE_LOAD     0x26   /* 0x4D8 событие загрузки модуля */
#define AC_EV_WATCHLIST_HIT   0x29   /* 0x20C совпадение вочлиста */
#define AC_EV_FILE_SIGNATURE  0x2B   /* 0x4D4+sigsize файл+Authenticode */

/* 0x12 подтипы (dword @+0x10) */
#define AC_EV12_PATTERN_HIT   0x06   /* попадание паттерна/строки (батч <= 0xF) */
#define AC_EV12_STRING_HIT    0x0B   /* попадание скана строк */
#define AC_EV12_OBJECT_WALK   0x18   /* обход object-листа */
#define AC_EV12_RIP_REF       0x43   /* RIP-relative ссылка вне своего образа */
#define AC_EV12_ADDR_ATTRIB   0x47   /* атрибуция addr -> module+offset */

/* объект состояния канала
 * [0x14016c813] хаб init состояния протокола (CHAIN 241): LIST_HEAD'ы по
 * +0xa8/+0xf8, 3x memset, первая запись (AC_IOCTL_HANDLER §4.1) */
typedef struct _AC_CHANNEL_STATE {
    LIST_ENTRY PendingEvents;    /* +0xa8 очередь sealed записей событий */
    LIST_ENTRY FreeRecords;      /* +0xf8 */
    KSPIN_LOCK QueueLock;
    KEVENT EventAvailable;       /* сигналит ожидающим long-poll */
    UINT64 RegisteredClient;     /* [0x140108750] ячейка id клиента */
    UINT8  ChannelUp;            /* [0x140108d50] ячейка гейта */
    UINT8  Registered;
    UINT64 ClientType;
    UINT8  Bootstrap[652];       /* 0xC3502008 сохранённый courier-блоб */
    UINT32 BootstrapSize;
    UINT8  SessionUuid[40];      /* 0xC3502010 payload (tag+36B guid) */
    UINT8  MatchRecord[28];      /* 0xC3502018 payload */
    WCHAR  ProcessPath[300];     /* 0xC3502038 payload (путь exe в UTF-16) */
    WCHAR  UsbPdo[12][290];      /* 0xC3502048 payloads (\Device\USBPDO-N) */
    UINT32 UsbPdoCount;
} AC_CHANNEL_STATE, *PAC_CHANNEL_STATE;

/* [0x14016c813] init состояния (два списка + саб-буферы) */
VOID AcChannelInit(VOID);

/* [0x14000bfa0] channel_sender(buf, len): единственная точка выхода; гейт
 * на channel-объект 0x140108d50 (AC_EVENT_CHANNEL §0) */
NTSTATUS AcChannelSend(_In_ const VOID* Buf, _In_ UINT32 Len);

/* [0x1400668e4] cn_signer_gate: FNV-1a-64 по CN подписанта клиента;
 * разрешены: "ESL FACEIT Group Ltd." / "ESL Gaming GmbH" / "FACE IT LIMITED"
 * (DISPATCH_CHAIN_C §6) */
NTSTATUS AcChannelCnSignerGate(_In_ PVOID ClientObj);

/* [0x140065e80] client_registration */
NTSTATUS AcChannelRegisterClient(_In_ PVOID ClientObj, _In_ UINT64 ClientId);

/* [0x1400660b0] post_registration_init: проверка командной строки PEB
 * "-allow_third_party_software" (DISPATCH_CHAIN_C §6) */
NTSTATUS AcChannelPostRegistrationInit(VOID);

/* [0x140066c18] teardown: запись 0x02 + drain очереди */
VOID AcChannelTeardown(VOID);

/* drain очереди событий (завершения poll'ов) */
NTSTATUS AcChannelDrainEvents(_Out_ PVOID Buffer, _In_ UINT32 BufferSize,
                              _Out_ UINT64* Information);

/* [0xC3502004] long-poll: пендится, пока не появится сообщение */
NTSTATUS AcChannelPollEvents(_In_ PIRP Irp, _Out_ PVOID Buffer,
                             _In_ UINT32 BufferSize,
                             _Out_ UINT64* Information);

/* push-обработчики (семейство 0xC350; формы plaintext в ioctl.h) */
NTSTATUS AcChannelPushSessionUuid(_In_ const VOID* Buf, _In_ UINT32 Len);
NTSTATUS AcChannelPushMatchRecord(_In_ const VOID* Buf, _In_ UINT32 Len);
NTSTATUS AcChannelPushProcessPath(_In_ const VOID* Buf, _In_ UINT32 Len);
NTSTATUS AcChannelPushUsbDevice(_In_ const VOID* Buf, _In_ UINT32 Len);
NTSTATUS AcChannelPushCmd(_In_ const VOID* Buf, _In_ UINT32 Len);

/* [0x140066b3c] пробуждение воркера: [worker_ctx+0xa8]=2 + KeSetEvent(+0x88) */
VOID AcChannelWakeWorker(VOID);

/* [0x140108db8] следующее значение seq (LOCK xadd) */
UINT64 AcChannelNextSeq(VOID);

/* [0x140066b3c] запись закрытия/сброса канала 0x0A (форма шины, 0x20B) */
VOID AcChannelBuildResetRecord(_Out_writes_(0x20) PVOID RecOut);

/* [0xC3502048] response-половина USB-handshake (путь + hex64 хэш) */
NTSTATUS AcChannelBuildUsbResponse(_In_z_ const WCHAR* PdoPath,
                                   _Out_writes_bytes_(640) PVOID OutBuffer,
                                   _Inout_ UINT32* OutLen);
const WCHAR* AcChannelLastUsbPdoPath(VOID);

#endif /* FACEIT_AC_CHANNELS_H */
