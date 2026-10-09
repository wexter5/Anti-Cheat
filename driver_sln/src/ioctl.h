/* ==========================================================================
 * ioctl.h -- IOCTL-коды, структуры запросов/ответов, прототипы диспетча
 * --------------------------------------------------------------------------
 * Драйверная IOCTL-поверхность (все METHOD_BUFFERED, тип устройства 0xC350),
 * wire-доказанная (таблица DRIVER_CHANNEL_BYTEMAP.md §2, capture shim56/72):
 *
 *   0xC3502004  event-poll (long-poll)         out 4096 sealed box
 *   0xC3502008  bootstrap seal(604B)           courier blob (server pk)
 *   0xC3502010  session-UUID 40B               {u32 0x15}{36B ASCII guid}
 *   0xC3502018  match-record 28B               {u32 0x17}{6B}{15B id}{3B 0}
 *   0xC350202C  driver-event 24B               {u32 0x14,0,v,0,code,0}
 *   0xC3502034  key-exchange 32<->32           eph pk service -> pk driver
 *   0xC3502038  process-path 616B              UTF-16 \??\C:\..\exe + zeros
 *   0xC350203C  vendor-CN 64B x4               BYOVD blocklist
 *   0xC3502040  sha256-hex 65B x4              same 4 drivers
 *   0xC3502044  ping 0/0 (legacy)
 *   0xC3502048  USB-device 592B x12            UTF-16 \Device\USBPDO-N
 *   0xC3502050  cmd 12B                        {u32 0x27, u32 1, u32 1}
 *   0xC350205C  u64-set 104/96B                {u32 sid}{u32 N}{N x u64}
 *   0xC3502064  watchlist 695B                 {0}{0x1bc len}{6}{50 names}{6 rec}
 *
 * КОРРЕКЦИЯ (KERNEL_WALLS_FINAL §2.1, живой wire): семейство 0x22xxxx
 * (0x220408/0x220410/0x220414/0x220420/0x220448) -- это СЕРВИС, говорящий
 * с USB-хаб устройствами (GET_NODE_INFORMATION / GET_NODE_CONNECTION_*), НЕ
 * IOCTL этого драйвера; ранние документы (DRIVER_76B, DRIVER_INTERFACE,
 * AC_IOCTL_HANDLER §0) трактовали их как handshake/записи драйвера и
 * отменены. Они удалены из диспетча этого драйвера.
 * ========================================================================== */
#ifndef FACEIT_AC_IOCTL_H
#define FACEIT_AC_IOCTL_H

#include <ntddk.h>

/* ---- event-устройство (тип 0xC350) ----------------------------------------*/

#define IOCTL_AC_EVENT_POLL \
    CTL_CODE(0xC350, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)   /* 0xC3502004 */
#define IOCTL_AC_BOOTSTRAP \
    CTL_CODE(0xC350, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)   /* 0xC3502008 */
#define IOCTL_AC_PUSH_SESSION_UUID \
    CTL_CODE(0xC350, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)   /* 0xC3502010 */
#define IOCTL_AC_PUSH_MATCH_RECORD \
    CTL_CODE(0xC350, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)   /* 0xC3502018 */

/* [0xC350201C] "match over": шлётся сервисом WSS-push'ем в конце матча
 * (83B push); мгновенно успокаивает всю детект-активность до конца матча
 * (MATCH_SESSION_TIMELINE #0.1 [dec/wire]) */
#define IOCTL_AC_MATCH_OVER \
    CTL_CODE(0xC350, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)   /* 0xC350201C */
#define IOCTL_AC_DRIVER_EVENT \
    CTL_CODE(0xC350, 0x80B, METHOD_BUFFERED, FILE_ANY_ACCESS)   /* 0xC350202C */
#define IOCTL_AC_KEY_EXCHANGE \
    CTL_CODE(0xC350, 0x80D, METHOD_BUFFERED, FILE_ANY_ACCESS)   /* 0xC3502034 */
#define IOCTL_AC_PUSH_PROCESS_PATH \
    CTL_CODE(0xC350, 0x80E, METHOD_BUFFERED, FILE_ANY_ACCESS)   /* 0xC3502038 */
#define IOCTL_AC_PUSH_VENDOR_CN \
    CTL_CODE(0xC350, 0x80F, METHOD_BUFFERED, FILE_ANY_ACCESS)   /* 0xC350203C */
#define IOCTL_AC_PUSH_HASH \
    CTL_CODE(0xC350, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS)   /* 0xC3502040 */
#define IOCTL_AC_PING \
    CTL_CODE(0xC350, 0x811, METHOD_BUFFERED, FILE_ANY_ACCESS)   /* 0xC3502044 */
#define IOCTL_AC_PUSH_USB_DEVICE \
    CTL_CODE(0xC350, 0x812, METHOD_BUFFERED, FILE_ANY_ACCESS)   /* 0xC3502048 */
#define IOCTL_AC_PUSH_CMD \
    CTL_CODE(0xC350, 0x814, METHOD_BUFFERED, FILE_ANY_ACCESS)   /* 0xC3502050 */
#define IOCTL_AC_PUSH_U64_SET \
    CTL_CODE(0xC350, 0x817, METHOD_BUFFERED, FILE_ANY_ACCESS)   /* 0xC350205C */
#define IOCTL_AC_PUSH_WATCHLIST \
    CTL_CODE(0xC350, 0x819, METHOD_BUFFERED, FILE_ANY_ACCESS)   /* 0xC3502064 */

/* [0x2a2010] гейтованный вариант обёртки: обёртка диспетча B (0x14001a87c)
 * стреляет форензик-захватом для этого кода (или по флаговой ячейке
 * 0x140108dd0) (evidence: DISPATCH_CHAIN_C §4) */
#define IOCTL_FACEIT_GATED \
    CTL_CODE(0x2a20, 0x04, METHOD_BUFFERED, FILE_ANY_ACCESS)    /* 0x2a2010 */

/* ---- виртуализованные маршруты диспетча (семейство D, route_map.json) -----
 * [0x140093694] tramp семейства D, маршрутится по ecx == 0x12e491 --
 * единственный IOCTL-маршрутируемый tramp из 327 (evidence: route_map.json,
 * VMENTRY_REPORT §1)
 * [0x140091110] dispatch_ioctl_2: охраняемый маршрут
 *   гард: (code-2) & ~2 == 0 && inputLength (edi) >= 0x78, r8=0x100
 *   (evidence: route_map.json "ok-manual", seeded rcx=2 r8=0x100) */
#define AC_VM_IOCTL_ROUTE      0x12e491
#define AC_VM_IOCTL_CODE2      0x2
#define AC_VM_IOCTL_CODE3      0x3
#define AC_VM_IOCTL_CODE2_MINLEN 0x78

/* ---- структуры wire-payload (формы plaintext, до seal) --------------------*/
#pragma pack(push, 1)

/* [0xC3502010] session-UUID: {u32 0x15}{36B ASCII uuid + NUL} */
typedef struct _AC_PUSH_SESSION_UUID {
    UINT32 Tag;                    /* 0x15 */
    CHAR   Guid[36];               /* "dd9ddbe6-4a3f-..." + NUL */
} AC_PUSH_SESSION_UUID, *PAC_PUSH_SESSION_UUID;

/* [0xC3502018] match-запись (после match-join) */
typedef struct _AC_PUSH_MATCH_RECORD {
    UINT32 Tag;                    /* 0x17 */
    UINT8  Varint[6];              /* varint-подобное */
    UINT8  IdPrefix[15];
    UINT8  Tail[3];                /* нули */
} AC_PUSH_MATCH_RECORD, *PAC_PUSH_MATCH_RECORD;

/* [0xC350202C] driver-event (всплески игры): {u32 0x14,0,u32 value,0,
 * u32 code,0}; code in {0x12 pattern, 0x26 module-load, 0x2b file+sig} */
typedef struct _AC_DRIVER_EVENT {
    UINT32 Tag;                    /* 0x14 */
    UINT32 Pad0;
    UINT32 Value;
    UINT32 Pad1;
    UINT32 Code;                   /* 0x12 / 0x26 / 0x2b */
    UINT32 Pad2;
} AC_DRIVER_EVENT, *PAC_DRIVER_EVENT;         /* 24 байта */

/* [0xC350205C] u64-набор: {u32 per-session}{u32 N}{N x u64} (N=11/12) */
typedef struct _AC_PUSH_U64_SET {
    UINT32 PerSession;
    UINT32 Count;
    UINT64 Values[12];
} AC_PUSH_U64_SET, *PAC_PUSH_U64_SET;

/* [0xC3502050] cmd: {u32 0x27, u32 1, u32 1} */
typedef struct _AC_PUSH_CMD {
    UINT32 Tag;                    /* 0x27 */
    UINT32 Value1;
    UINT32 Value2;
} AC_PUSH_CMD, *PAC_PUSH_CMD;

/* [0xC3502064] вочлист: {u32 0}{u32 ascii-len 0x1bc}{u32 6}
 * {50 NUL-разделённых ASCII имён}{6 записей {ascii,utf16}} */
typedef struct _AC_PUSH_WATCHLIST {
    UINT32 Zero;
    UINT32 AsciiLength;            /* 0x1bc */
    UINT32 RecordCount;            /* 6 */
    UINT8  Payload[695 - 12];
} AC_PUSH_WATCHLIST, *PAC_PUSH_WATCHLIST;

#pragma pack(pop)

/* completion status, используемый путём ошибки VM-хаба
 * [0x1415fec5d] фрагмент ошибки -> NTSTATUS 0xC0000090
 * (evidence: DISPATCH_CHAIN_C §5) */
#define AC_STATUS_HUB_ERROR   ((NTSTATUS)0xC0000090)

/* ---- точки входа диспетча --------------------------------------------------*/

DRIVER_DISPATCH AcDispatchDeviceControl;

/* [0x140066b3c] диспетчер сессионного handshake (DISPATCH_CHAIN_C §6) */
NTSTATUS
AcSessionDispatch(
    _In_ PVOID ChannelCtx,
    _In_ PVOID ClientObj,
    _In_ UINT64 ClientId
    );

#endif /* FACEIT_AC_IOCTL_H */
