/* ==========================================================================
 * ioctl.c -- диспетч IRP_MJ_DEVICE_CONTROL для FACEIT_AC.sys
 * --------------------------------------------------------------------------
 * Цепочка диспетча (DISPATCH_CHAIN_C §0-§6, AC_IOCTL_HANDLER):
 *   обёртка MajorFunction[0xE] 0x14001a5f4 (вариант 0x14001a87c)
 *     -> гейт MajorFunction==0x0E + проверка LSTAR на каждом IOCTL
 *     -> stub 0x14008ce60 -> VM-хаб 0x140297fcd (общая стадия-2)
 *     -> session dispatcher 0x140066b3c (handshake/регистрация)
 * Инвентарь кодов: DRIVER_CHANNEL_BYTEMAP §2 (wire-доказанное семейство
 * 0xC350); семейство 0x22 УДАЛЕНО (USB-хабовые IOCTL сервиса, коррекция
 * KERNEL_WALLS_FINAL §2.1).
 * ========================================================================== */
#include <ntddk.h>

#include "provenance.h"
#include "tables.h"
#include "ioctl.h"
#include "channels.h"
#include "crypto.h"
#include "anti_tamper.h"
#include "game_integrity.h"
#include "events.h"

/* --------------------------------------------------------------------------
 * Обёртка стадии-1: LSTAR-вачдог на каждом IOCTL.
 * [0x14001a5f4] обёртка диспетча A (дословное тело DISPATCH_CHAIN_C §3)
 * [0x14001a87c] обёртка диспетча B: тот же скелет, дополнительный гейт на
 * IoControlCode 0x2a2010 (или флаговая ячейка 0x140108dd0); захват 0x200
 * ------------------------------------------------------------------------ */
static BOOLEAN
AcDispatchGate(
    _In_ PIRP Irp,
    _In_ ULONG IoControlCode
    )
{
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    BOOLEAN gated;

    /* [0x14001a5f4] первый байт stack location: MajorFunction == 0x0E */
    if (irpSp->MajorFunction != IRP_MJ_DEVICE_CONTROL)
        return FALSE;

    /* проверка LSTAR + восстановление + форензик-запись (anti_tamper.c) */
    AcTamperCheckLstar(Irp);

    /* [0x14001a87c] вариантный гейт: код 0x2a2010 или allow-флаговая ячейка
     * (ячейка 0x140108dd0 = AC-окно +0x2dd0) */
    gated = (IoControlCode == IOCTL_FACEIT_GATED) ||
            (AC_SLOT8(0x2dd0) != 0);
    if (gated) {
        AcTamperForensicCapture(Irp, IoControlCode, 0x200);
    }
    return TRUE;
}

/* таблица wire-размеров (DRIVER_CHANNEL_BYTEMAP §2; SystemBuffer несёт
 * sealed wire-форму): {code, inSize, outSize}. 0 в любом поле = любой */
static const struct {
    ULONG Code;
    ULONG InSize;
    ULONG OutSize;
} g_IoctlWireSizes[] = {
    { IOCTL_AC_EVENT_POLL,         0,    4096 },
    { IOCTL_AC_BOOTSTRAP,          652,  0    },
    { IOCTL_AC_PUSH_SESSION_UUID,  88,   0    },
    { IOCTL_AC_PUSH_MATCH_RECORD,  76,   0    },
    { IOCTL_AC_MATCH_OVER,         0,    0    },
    { IOCTL_AC_DRIVER_EVENT,       72,   0    },
    { IOCTL_AC_KEY_EXCHANGE,       32,   32   },
    { IOCTL_AC_PUSH_PROCESS_PATH,  664,  0    },
    { IOCTL_AC_PUSH_VENDOR_CN,     112,  0    },
    { IOCTL_AC_PUSH_HASH,          113,  0    },
    { IOCTL_AC_PING,               0,    0    },
    { IOCTL_AC_PUSH_USB_DEVICE,    640,  640  },
    { IOCTL_AC_PUSH_CMD,           60,   0    },
    { IOCTL_AC_PUSH_U64_SET,       152,  0    },   /* N=12; N=11 -> 144 */
    { IOCTL_AC_PUSH_WATCHLIST,     743,  0    },
};

/* валидация размеров IRP-буферов против wire-таблицы
 * (заметка cross-check RECON2 1: поведение на malformed-буферах
 * унифицировано к wire-формам) */
/* [0x140297fcd] хабовая стадия валидации (wire-размеры из
 * DRIVER_CHANNEL_BYTEMAP §2) */
static BOOLEAN
AcIoctlValidateSizes(
    _In_ ULONG Code,
    _In_ ULONG InLen,
    _In_ ULONG OutLen
    )
{
    UINT32 i;

    for (i = 0; i < ARRAYSIZE(g_IoctlWireSizes); i++) {
        if (g_IoctlWireSizes[i].Code == Code) {
            ULONG inWant = g_IoctlWireSizes[i].InSize;
            ULONG outWant = g_IoctlWireSizes[i].OutSize;

            if (inWant != 0 && InLen != inWant) {
                /* u64-набор имеет два wire-варианта (N=11 -> 144, N=12 -> 152) */
                if (Code == IOCTL_AC_PUSH_U64_SET && InLen == 144)
                    return TRUE;
                return FALSE;
            }
            if (outWant != 0 && OutLen < outWant)
                return FALSE;
            return TRUE;
        }
    }
    return TRUE;    /* неизвестные коды обрабатываются default-веткой */
}

/* --------------------------------------------------------------------------
 * Хаб стадии-2.
 * [0x14008ce60] vm_dispatch_stub (форма stub'а AC_IOCTL_HANDLER §5)
 * [0x140297fcd] vm_ioctl_hub: читает stack location (IoControlCode
 * @0x1407f4bd8, InputBufferLength @0x1407f514a, SystemBuffer @0x1407f5195),
 * гейтится на ячейку dispatch-объекта 0x140109728, единая стадия-2 для всех
 * кодов; per-code ромбы сравнений строятся MBA в VM-байткоде
 * (payload-selected: 0 plaintext-вхождений, AC_IOCTL_HANDLER §1) --
 * здесь реконструированы читаемым switch'ем по wire-доказанным кодам.
 * ------------------------------------------------------------------------ */
static NTSTATUS
AcIoctlHub(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp,
    _Out_ UINT64* Information
    )
{
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    ULONG code = irpSp->Parameters.DeviceIoControl.IoControlCode;
    ULONG inLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
    PVOID buffer = Irp->AssociatedIrp.SystemBuffer;
    NTSTATUS status = STATUS_SUCCESS;

    *Information = 0;

    /* [0x140109728] гейт "channel up": указатель dispatch-объекта
     * (DISPATCH_CHAIN_C §5: чтения [obj+8]/[obj+0] @0x1407d139b/0x1407d13b7);
     * путь bootstrap/контакта пропускается до регистрации */
    if (AC_SLOTP(0x3728) == NULL && code != IOCTL_AC_BOOTSTRAP &&
        code != IOCTL_AC_KEY_EXCHANGE) {
        return AC_STATUS_HUB_ERROR;   /* [0x1415fec5d] фрагмент ошибки */
    }

    /* валидация wire-размеров для всех кодов (таблица выше) */
    if (!AcIoctlValidateSizes(code, inLen, outLen))
        return STATUS_INVALID_PARAMETER;

    switch (code) {

    case IOCTL_AC_EVENT_POLL:           /* 0xC3502004: long-poll, 4096 out */
        /* [wire] IRP пендится, пока не появится сообщение; завершение несёт
         * sealed-бокс (DRIVER_CHANNEL_PROTOCOL §1) */
        status = AcChannelPollEvents(Irp, buffer, outLen, Information);
        break;

    case IOCTL_AC_BOOTSTRAP:            /* 0xC3502008: courier-блоб 604->652 */
        /* первый контакт сессии: прогнать session handshake dispatcher
         * (регистрация / CN-гейт), затем сохранить courier-блоб -- он
         * sealed под СЕРВЕРНЫЙ сессионный ключ, драйвер его никогда не
         * открывает (модель courier/hold, DRIVER_CHANNEL_PROTOCOL §2.2) */
        status = AcSessionDispatch(DeviceObject, buffer, (UINT64)Irp);
        if (NT_SUCCESS(status))
            status = AcCryptoStoreBootstrap(buffer, inLen);
        break;

    case IOCTL_AC_PUSH_SESSION_UUID:    /* 0xC3502010: {0x15}{36B guid} */
        status = AcChannelPushSessionUuid(buffer, inLen);
        break;

    case IOCTL_AC_PUSH_MATCH_RECORD:    /* 0xC3502018: match-запись 28B */
        status = AcChannelPushMatchRecord(buffer, inLen);
        break;

    case IOCTL_AC_MATCH_OVER:           /* 0xC350201C: конец матча, 0/0 */
        /* [dec/wire] WSS-push 83B в конце матча; мгновенно успокаивает
         * детект-активность до конца матча (сброс match-состояния,
         * MATCH_SESSION_TIMELINE #0.1) */
        status = AcEventMatchOver();
        break;

    case IOCTL_AC_DRIVER_EVENT:         /* 0xC350202C: {0x14,...,code} 24B */
        status = AcEventDriverEvent(buffer, inLen);
        break;

    case IOCTL_AC_KEY_EXCHANGE:         /* 0xC3502034: 32B in -> 32B out */
        /* [wire] IN = свежий эфемерный pk сервиса; OUT = pk драйвера
         * (собственный хэндл, раз за capture; replay R13) */
        if (inLen >= 32 && outLen >= 32) {
            status = AcCryptoKeyExchange(buffer, buffer);
            if (NT_SUCCESS(status))
                *Information = 32;
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case IOCTL_AC_PUSH_PROCESS_PATH:    /* 0xC3502038: путь exe UTF-16 616B */
        status = AcChannelPushProcessPath(buffer, inLen);
        break;

    case IOCTL_AC_PUSH_VENDOR_CN:       /* 0xC350203C: seal(64B CN) x4 */
        status = GameIntegrityPushVendorCn(buffer, inLen);
        break;

    case IOCTL_AC_PUSH_HASH:            /* 0xC3502040: seal(65B sha256-hex) */
        status = GameIntegrityPushDriverHash(buffer, inLen);
        break;

    case IOCTL_AC_PING:                 /* 0xC3502044: keepalive 0/0 */
        /* [wire] legacy-живость; новый канал вместо этого несёт D→S heartbeat
         * 0x24 (DRIVER_CHANNEL_PROTOCOL §1) */
        status = STATUS_SUCCESS;
        break;

    case IOCTL_AC_PUSH_USB_DEVICE:      /* 0xC3502048: \Device\USBPDO-N 592B */
        status = AcChannelPushUsbDevice(buffer, inLen);
        if (NT_SUCCESS(status) && outLen >= 640) {
            /* response-половина: тот же путь PDO + hex64 хэш, 640B wire
             * (MATCH_SESSION_TIMELINE #0.4 [dec]) */
            UINT32 respLen = outLen;

            status = AcChannelBuildUsbResponse(AcChannelLastUsbPdoPath(), buffer,
                                               &respLen);
            if (NT_SUCCESS(status))
                *Information = respLen;
        }
        break;

    case IOCTL_AC_PUSH_CMD:             /* 0xC3502050: {0x27,1,1} 12B */
        status = AcChannelPushCmd(buffer, inLen);
        break;

    case IOCTL_AC_PUSH_U64_SET:         /* 0xC350205C: {sid}{N}{N x u64} */
        status = GameIntegrityPushU64Set(buffer, inLen);
        break;

    case IOCTL_AC_PUSH_WATCHLIST:       /* 0xC3502064: вочлист 695B */
        status = GameIntegrityPushWatchlist(buffer, inLen);
        break;

    default:
        /* [0x140091110] охраняемый маршрут code-2: (code-2)&~2==0 && len>=0x78
         * с r8=0x100; достигается через VM-диспетч семейства D
         * (route_map.json "ok-manual") -- VM-внутренний саб-диспетч за ним
         * payload-selected */
        if (((code - AC_VM_IOCTL_CODE2) & ~2u) == 0 &&
            inLen >= AC_VM_IOCTL_CODE2_MINLEN && outLen >= 0x100) {
            /* payload-selected: тело VM саб-диспетча статически не
             * восстанавливается (охраняемый маршрут route_map.json) */
            status = STATUS_SUCCESS;
            *Information = 0x100;
            break;
        }
        /* нераспознанный код: путь ошибки хаба
         * [0x1415fec5d] -> NTSTATUS 0xC0000090 (DISPATCH_CHAIN_C §5) */
        status = AC_STATUS_HUB_ERROR;
        break;
    }

    return status;
}

/* --------------------------------------------------------------------------
 * Вход IRP_MJ_DEVICE_CONTROL (регистрируется серией виртуализованных
 * store'ов в цепочке отложенного init'а; см. заметку driver_entry.c).
 * Хвост цепочки в оригинале: (*PAIR(0x7728))(irp, dev) -- пара
 * завершения/форварда IRP (DISPATCH_CHAIN_C §3-§4)
 * ------------------------------------------------------------------------ */
/* [0x14001a5f4]/[0x14001a87c] роль зарегистрированной обёртки (доказана
 * anti-tamper вачдогом, DISPATCH_CHAIN_C раздел 2) */
NTSTATUS
AcDispatchDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
    )
{
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    UINT64 information = 0;
    NTSTATUS status;

    if (!AcDispatchGate(Irp, irpSp->Parameters.DeviceIoControl.IoControlCode)) {
        status = STATUS_INVALID_DEVICE_REQUEST;
        goto Complete;
    }

    /* long-poll может легитимно пендиться */
    status = AcIoctlHub(DeviceObject, Irp, &information);
    if (status == STATUS_PENDING)
        return STATUS_PENDING;

Complete:
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

/* --------------------------------------------------------------------------
 * Диспетчер сессионного handshake.
 * [0x140066b3c] session_dispatch (дословное тело, DISPATCH_CHAIN_C §6):
 *   если channel up (0x140108d50) и не зарегистрирован -> CN-гейт (0x1400668e4)
 *   иначе -> регистрация клиента (0x140065e80)
 *   если вызывающий == зарегистрированный клиент (0x140108750):
 *     ответная запись type 10 (0x20 байтов) через channel_sender (0x14000bfa0)
 *     проверка code-integrity (FUN_140052268)
 *     если флаг: сессионный продюсер 0x12-записей (FUN_140073c04)
 *     пробуждение воркера: [worker_ctx+0xa8]=2, KeSetEvent(worker_ctx+0x88)
 * ------------------------------------------------------------------------ */
NTSTATUS
AcSessionDispatch(
    _In_ PVOID ChannelCtx,
    _In_ PVOID ClientObj,
    _In_ UINT64 ClientId
    )
{
    UNREFERENCED_PARAMETER(ChannelCtx);

    /* [0x140108d50] гейт channel-up (AC-окно +0x2d50) */
    if (AC_SLOTP(AC_CELL_CHANNEL_UP) != NULL) {
        if (AC_SLOT8(0x2ba8) == 0) {          /* g_fRegistered */
            /* первый контакт: гейт FNV-1a по CN подписанта
             * [0x1400668e4] -> STATUS_ACCESS_DENIED для чужих */
            NTSTATUS gate = AcChannelCnSignerGate(ClientObj);
            if (!NT_SUCCESS(gate))
                return gate;
        } else {
            /* [0x140065e80] регистрация клиента -> пост-регистрационный init
             * [0x1400660b0] (проверка командной строки PEB) */
            AcChannelRegisterClient(ClientObj, ClientId);
        }
    }

    if (ClientId == AC_SLOT64(AC_CELL_CLIENT_ID) ||
        AC_SLOT64(AC_CELL_CLIENT_ID) == 0) {
        AC_SLOT64(AC_CELL_CLIENT_ID) = ClientId;

        struct {
            UINT64 Type;       /* 10 */
            UINT64 ClientId;
            UINT64 ClientType;
            UINT64 Zero;
        } reply;

        AC_SLOT64(0x2d68) = 0;                /* сброс g_SessCounter1 */
        reply.Type = 10;
        reply.ClientId = ClientId;
        reply.ClientType = AC_SLOT64(0x2758); /* g_pClientType */
        reply.Zero = 0;

        /* [0x14000bfa0] channel_sender(&reply, 0x20) */
        AcChannelSend(&reply, sizeof(reply));

        /* [0x140052268] проверка code-integrity (FULL_CHAIN_IRP_TO_HWID_C
         * §2: триггерит цепочку fanout'а коллекторов) */
        AcEventCodeIntegrityCheck();

        /* [0x140073c04] сессионный продюсер 0x12-записей (0x658),
         * гейтован флагом области 0x140108df0 + client id != 0 */
        if (AC_SLOT8(0x2df0) != 0 && ClientId != 0) {
            AcEventSessionRecord(ClientId);
        }

        /* разбудить poll-воркера */
        AcChannelWakeWorker();
    }

    return STATUS_SUCCESS;
}
