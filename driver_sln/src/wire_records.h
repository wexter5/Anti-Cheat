/* ==========================================================================
 * records.h -- layout'ы wire-записей канала FACEIT_AC.sys <-> faceitservice
 *              (устройство 0xC350), байт-точные.
 * --------------------------------------------------------------------------
 * СМЕРДЖЕНО в driver_sln/src (agent-493, 7/7 MATCH); оригинальная заметка:
 * после ревью -- НЕ мержить отсюда).
 *
 * Provenance: каждое смещение либо [wire] (дешифрованные capture-фреймы,
 * poly1305-проверенные), либо [static] (нативное тело продюсера). Источники:
 *   _research_tmp/wiremap/BYTE_MAP.md  (эта сессия, байт-точные таблицы)
 *   DRIVER_CHANNEL_BYTEMAP.md / DRIVER_CHANNEL_PROTOCOL.md (база wire/dec)
 *   AC_EVENT_CHANNEL.md               (маркеры шины 0x02..0x2b, static)
 *   FULL_CHAIN_IRP_TO_HWID_C.md       (фазы билдера hello)
 *   HWID_BYTEMAP.md / HWID_FIELDS_SEMANTICS.md (cross-карта f-полей)
 * Frame evidence: _research_tmp/wiremap/frames_pt/ + frames.json.
 * ========================================================================== */
#ifndef AC_RECORDS_H
#define AC_RECORDS_H

#include <ntddk.h>
#include <stddef.h>

/* --------------------------------------------------------------------------
 * Wire-конверт: одна запись на завершение poll'а IOCTL 0xC3502004.
 * [dec] wire = eph_pk[32] || MAC[16] || ct ; nonce = BLAKE2b-192(eph||recip)
 * (libsodium crypto_box_seal; 2864+8 фреймов открыто оффлайн)
 * ------------------------------------------------------------------------ */
#define AC_WIRE_EPH_PK_SIZE     32
#define AC_WIRE_MAC_SIZE        16
#define AC_WIRE_SEAL_OVERHEAD   (AC_WIRE_EPH_PK_SIZE + AC_WIRE_MAC_SIZE)
#define AC_WIRE_POLL_BUFSIZE    4096        /* out-буфер poll'а сервиса [wire] */

#pragma pack(push, 1)
typedef struct _AC_WIRE_BOX_HDR {
    UINT8 EphPk[AC_WIRE_EPH_PK_SIZE];   /* +0x00 per-frame X25519 эфемерный */
    UINT8 Mac[AC_WIRE_MAC_SIZE];        /* +0x20 Poly1305 tag              */
    /* UINT8 Ciphertext[];              +0x30                            */
} AC_WIRE_BOX_HDR, *PAC_WIRE_BOX_HDR;
#pragma pack(pop)

/* маркеры записей, наблюдавшиеся на wire D->S (poll-канал) */
#define AC_REC_MARK_HELLO       0x00    /* 4048B идентичность машины [dec] */
#define AC_REC_MARK_DISKS       0x18    /* 664B  инвентарь хранилища [dec] */
#define AC_REC_MARK_RAM         0x19    /* 1428B SMBIOS t17         [dec] */
#define AC_REC_MARK_HEARTBEAT   0x24    /* 8B    живость x2 таймера [dec] */
#define AC_REC_MARK_PROC_ATTACH 0x0A    /* 32B   attach игрового процесса [dec] */
#define AC_REC_MARK_IMAGE_LOAD  0x1B    /* 524B  имя модуля (шина) [dec] */

/* маркеры шины (шина событий; static-proven layout'ы, AC_EVENT_CHANNEL) */
#define AC_EV_TEARDOWN          0x02
#define AC_EV_CH_RESET          0x0A
#define AC_EV_DETECTION         0x12
#define AC_EV_NAME_A            0x1A
#define AC_EV_NAME_B            0x1B
#define AC_EV_MODULE_STATE      0x1E
#define AC_EV_MODULE_DUMP       0x22
#define AC_EV_MODULE_LOAD       0x26
#define AC_EV_WATCH_MATCH       0x29
#define AC_EV_FILE_SIG          0x2B

/* источник seq для seq-событий (0x12-sub0x47/0x22/0x26/0x2b):
 * LOCK xadd глобального счётчика [0x140108db8] (AC_EVENT_CHANNEL #2.1) */

/* --------------------------------------------------------------------------
 * hello (маркер 0x00) -- 4048B plaintext, 1x/сессию, первая запись.
 * Билдер: фазовые прямые записи внутри VM handshake-continuation
 * (нет единого нативного hello_build; FULL_CHAIN_IRP_TO_HWID_C #7.6).
 * Строки: NUL-терминированный ASCII по фиксированным смещениям, zero-padded.
 * ------------------------------------------------------------------------ */
#define AC_HELLO_SIZE           0xFD0   /* 4048 = размер pool-аллокации [static] */
#define AC_HELLO_MACLIST_OFS    0x720   /* +0x648 константа [wire] */
#define AC_HELLO_MAC_SLOT       0x12    /* 17 символов + NUL [wire] */
#define AC_HELLO_MAC_MAX        ((0xFD0 - AC_HELLO_MACLIST_OFS - 0x25) / \
                                 AC_HELLO_MAC_SLOT)   /* = 121 */
#define AC_HELLO_UUID2_OFS(count) \
    (AC_HELLO_MACLIST_OFS + (count) * AC_HELLO_MAC_SLOT)  /* == +0x694 [dec] */

#pragma pack(push, 1)
typedef struct _AC_REC_HELLO {
    UINT32 Marker;              /* +0x000 = AC_REC_MARK_HELLO */
    UINT32 Build;               /* +0x004 билд драйвера (VM-собранный иммедиат;
                                 *  0x67d=1661 в обоих фреймах) [dec] */
    UINT8  Flags[4];            /* +0x008 per-run флаги; [9]=1 всегда,
                                 *  [0xA]/[0xB] варьируются 01->00 [unknown] */
    UINT8  Reserved00C[0x212];  /* +0x00C нули [dec] */
    CHAR   LabelSerial[0x50];   /* +0x21E "System Serial Number" [экстрактор
                                 *  SMBIOS t1 0x1401ed25c, стр 0x1401edae4] */
    CHAR   SystemSerial[0x3C];  /* +0x26E serial t1 ("ASUS") [live 1:1 WMI] */
    CHAR   LabelProduct[0x64];  /* +0x2AA "System Product Name" */
    CHAR   SystemUuid[0x25];    /* +0x30E t1 UUID ASCII (форматтер доказан
                                 *  байт-точно, UUID2_SOURCE.md) [live 1:1] */
    CHAR   BoardSerial[0x3C];   /* +0x333 serial t2 (ёмкость пэда 0x10) */
    CHAR   BoardVendor[0x50];   /* +0x36F производитель t2 */
    CHAR   BoardModel[0x259];   /* +0x3BF продукт t2 */
    CHAR   SynthGuid[0x28];     /* +0x618 f18 композитный GUID v1-формата:
                                 *  цепочка GetIfEntry2 (find_netio 0x14001f5c8,
                                 *  FNV 0xeff5b62c6320059e, region 487);
                                 *  node = MAC собственного NIC (MIB_IF_ROW2) [dec] */
    UINT16 SecurityState;       /* +0x640 битмаска f20: 0x2001 -> 0xe001
                                 *  между ранами; == staging f20 [dec] */
    UINT16 Reserved642;         /* +0x642 нули */
    UINT32 MacCount;            /* +0x644 сайт store 0x1437a659b [static] */
    UINT32 MacListOfs;          /* +0x648 == AC_HELLO_MACLIST_OFS; сайт
                                 *  store 0x14075fcfb [static] */
    UINT8  Reserved64C;         /* +0x64C ноль */
    CHAR   MachineHash[0x41];   /* +0x64D f21 64 lower-hex (класс sha256);
                                 *  BCrypt-хаб region 7341 0x14024af8e,
                                 *  exit-фраг HashData 0x1402b09e1; вход
                                 *  неидентифицирован [neg ~30k+60M] */
    UINT8  Reserved68E[2];      /* +0x68E нули */
    UINT8  Flag690;             /* +0x690 = 1 в каждом фрейме [unknown] */
    UINT8  Reserved691[3];      /* +0x691 нули */
    UINT32 Uuid2Ofs;            /* +0x694 == AC_HELLO_UUID2_OFS(MacCount)
                                 *  [dec, MATCH в обоих фреймах] */
    UINT8  Reserved698[2];      /* +0x698 нули */
    CHAR   BiosVersion[0x32];   /* +0x69A SMBIOS t0 ("1805") [live] */
    CHAR   BiosVendor[0x32];    /* +0x6CC t0 ("American Megatrends Inc.") */
    CHAR   BiosDate[0x1A];      /* +0x6FE t0 ("10/30/2024") */
    UINT8  Flag718;             /* +0x718 = 1 в каждом фрейме (также выставлен
                                 *  в server manifest контейнере) [unknown] */
    UINT8  Reserved719[7];      /* +0x719 нули */
    CHAR   MacList[AC_HELLO_MAC_MAX][AC_HELLO_MAC_SLOT];
                                /* +0x720 снапшот ARP/neighbor-кэша:
                                 *  GetIpNetTable2 (FNV 0xecd20b3bbdda9a4b),
                                 *  MIB_IPNET_ROW2 stride 0x58, MAC @+0x28,
                                 *  State @+0x4C (Incomplete -> null-слот);
                                 *  форматтер 0x1400477a0, slot sprintf
                                 *  thunk 0x14022fc93 [static+live] */
    /* CHAR Uuid2[0x25];        @ AC_HELLO_UUID2_OFS(MacCount): ASCII
                                 * GUID f22, derived-not-stored (маршаллер
                                 * 0x140282319->@0x14028237c, thunk
                                 * 0x1403891f9) [dec]; стабилен между ранами */
    UINT8  Tail[0xFD0 - 0x720 - AC_HELLO_MAC_MAX * AC_HELLO_MAC_SLOT];
} AC_REC_HELLO, *PAC_REC_HELLO;
#pragma pack(pop)

#define AC_HELLO_FIXED_BYTES (0x720 + AC_HELLO_MAC_MAX * AC_HELLO_MAC_SLOT)

/* --------------------------------------------------------------------------
 * disks (маркер 0x18) -- 8 + count*0x148 байтов [dec: count=2 -> 664B]
 * Продюсер: disks_collector 0x14005ef70 -> хаб 0x1403eaa0a -> классификатор
 * \Device\ 0x14008dc40 -> воркеры 0x14008e3f0/0x14008e944/0x14008f80c;
 * storage_query_hub 0x14017ae1c (IOCTL_STORAGE_QUERY_PROPERTY 0x2d1400),
 * ata_srb_hub 0x1403be16b (SRB_IO_CONTROL 0x4d008 ATA IDENTIFY 0xEC).
 * ------------------------------------------------------------------------ */
#pragma pack(push, 1)
typedef struct _AC_DISK_SLOT {
    CHAR   Id[0xFF];            /* +0x000 serial дескриптора / NVMe ns id */
    CHAR   Model[0x29];         /* +0x0FF IDENTIFY слова 27-46 (swapped) */
    CHAR   Firmware[0x1C];      /* +0x128 IDENTIFY слова 23-26 */
    UINT32 SerialLen;           /* +0x144 = 0x11 (17) [dec] */
    /* serial пишется по slot_base + 0x148 -- т.е. на голову Id СЛЕДУЮЩЕГО
     * слота (оверлей, пусто для SATA) или за конец записи для последнего
     * слота [layout доказан по wire; семантика открыта, BYTE_MAP #3.1] */
} AC_DISK_SLOT, *PAC_DISK_SLOT;
#pragma pack(pop)
#define AC_DISK_SERIAL_OFS      0x148

#pragma pack(push, 1)
typedef struct _AC_REC_DISKS {
    UINT32       Marker;        /* +0x00 = AC_REC_MARK_DISKS */
    UINT32       Count;         /* +0x04 (= 2 на capture-машине) */
    AC_DISK_SLOT Slots[2];      /* +0x08, stride 0x148 */
} AC_REC_DISKS, *PAC_REC_DISKS;
#pragma pack(pop)

/* --------------------------------------------------------------------------
 * ram (маркер 0x19) -- 8 + count*0x163 байтов [dec: count=4 -> 1428B]
 * Продюсер: smbios_ram_collector 0x14004b7a4 -> smbios_hub 0x1401835f8
 * (скан SMBIOS по сырой физпамяти, тот же проход, что hello t0/t1/t2).
 * ------------------------------------------------------------------------ */
#pragma pack(push, 1)
typedef struct _AC_RAM_SLOT {
    CHAR Serial[0xFF];          /* +0x000 serial t17  [live 1:1 WMI] */
    CHAR Vendor[0x32];          /* +0x0FF производитель t17 */
    CHAR PartNumber[0x32];      /* +0x131 part t17 (пэд пробелами) */
} AC_RAM_SLOT, *PAC_RAM_SLOT;

typedef struct _AC_REC_RAM {
    UINT32      Marker;         /* +0x00 = AC_REC_MARK_RAM */
    UINT32      Count;          /* +0x04 (= 4) */
    AC_RAM_SLOT Slots[4];       /* +0x08, stride 0x163 */
} AC_REC_RAM, *PAC_REC_RAM;
#pragma pack(pop)

/* --------------------------------------------------------------------------
 * heartbeat (маркер 0x24) -- 8B [dec]
 * Продюсер: воркер FUN_14001278c (ctx 0x140108d98, KTIMER ~-30s) ->
 * FUN_14000c35c(2); константа типа материализуется как (0x2481b1>>16) [static]
 * ------------------------------------------------------------------------ */
#pragma pack(push, 1)
typedef struct _AC_REC_HEARTBEAT {
    UINT32 Marker;              /* +0x00 = AC_REC_MARK_HEARTBEAT */
    UINT32 Flag;                /* +0x04 in {1,2}: два таймера ~30s, фазовый
                                 *  сдвиг ~4s [dec; семантика unknown] */
} AC_REC_HEARTBEAT, *PAC_REC_HEARTBEAT;
#pragma pack(pop)

/* --------------------------------------------------------------------------
 * proc-attach (маркер 0x0A) -- 32B [dec, фрейм in_0194: pid 0x6a60 = cs2]
 * Продюсер шины FUN_140066b3c пишет {qword 0x0a, qword pid, qword state,
 * qword 0}; wire-экземпляр несёт Flag=1 (вариант attach) [dec/static]
 * ------------------------------------------------------------------------ */
#pragma pack(push, 1)
typedef struct _AC_REC_PROC_ATTACH {
    UINT32 Marker;              /* +0x00 = AC_REC_MARK_PROC_ATTACH */
    UINT32 Zero04;              /* +0x04 = 0 */
    UINT64 Pid;                 /* +0x08 */
    UINT64 State;               /* +0x10 = 0 (шина: значение ячейки 0x140108ba8) */
    UINT32 Flag;                /* +0x18 = 1 (attach) / 0 (вариант reset) */
    UINT32 Zero1C;              /* +0x1C = 0 */
} AC_REC_PROC_ATTACH, *PAC_REC_PROC_ATTACH;
#pragma pack(pop)

/* --------------------------------------------------------------------------
 * записи имён 0x1A / 0x1B / 0x29 -- 0x20C байтов [static; 0x1B dec-проверен]
 * продюсер 0x1B: part_0007.c:470 (ветка verification-fail, очередь enqueue
 * 0x140108e40, NTSTATUS 0xc000009a); фрейм in_0217 = путь DiscordHook64.dll
 * ------------------------------------------------------------------------ */
#pragma pack(push, 1)
typedef struct _AC_REC_NAME {
    UINT32 Marker;              /* +0x00 = 0x1A / 0x1B / 0x29 */
    WCHAR  Path[0x104];         /* +0x04 UTF-16LE z (0x208 байтов) */
} AC_REC_NAME, *PAC_REC_NAME;
#pragma pack(pop)

/* --------------------------------------------------------------------------
 * teardown 0x02 -- 0x10 байтов [static, FUN_140066c18]
 * ------------------------------------------------------------------------ */
#pragma pack(push, 1)
typedef struct _AC_REC_TEARDOWN {
    UINT64 Type;                /* +0x00 = AC_EV_TEARDOWN */
    UINT64 Pid;                 /* +0x08 PsGetCurrentProcessId */
} AC_REC_TEARDOWN, *PAC_REC_TEARDOWN;
#pragma pack(pop)

/* --------------------------------------------------------------------------
 * module-state 0x1E -- 0x210 байтов [static, FUN_14003f0bc]
 * state: 2 = открытие файла не удалось (fallback), 3 = классифицирован
 * ------------------------------------------------------------------------ */
#pragma pack(push, 1)
typedef struct _AC_REC_MODULE_STATE {
    UINT32 Marker;              /* +0x00 = AC_EV_MODULE_STATE */
    UINT32 Pad0;                /* +0x04 */
    WCHAR  Path[0x102];         /* +0x08 UTF-16LE (0x204 байта) */
    UINT8  State;               /* +0x20C */
    UINT8  PadS[3];             /* +0x20D */
} AC_REC_MODULE_STATE, *PAC_REC_MODULE_STATE;
#pragma pack(pop)

/* --------------------------------------------------------------------------
 * module-load 0x26 -- 0x4D8 байтов [static, FUN_14003f78c / FUN_140043414]
 * ------------------------------------------------------------------------ */
#pragma pack(push, 1)
typedef struct _AC_REC_MODULE_LOAD {
    UINT32 Marker;              /* +0x000 = AC_EV_MODULE_LOAD */
    UINT32 Pad0;                /* +0x004 = 0 */
    UINT64 Seq;                 /* +0x008 LOCK xadd 0x140108db8 */
    UINT64 DllBase;             /* +0x010 KLDR +0x10 */
    UINT64 SizeOfImage;         /* +0x018 (dword src +0x20, zero-ext) */
    WCHAR  Path[0x104];         /* +0x020 UTF-16LE (0x208 байтов) */
    UINT8  Reserved228[0x208];  /* +0x228 */
    UINT8  BranchFlag;          /* +0x430 1 (FUN_14003f78c) / 0 (043414) */
    UINT8  Pad431[7];           /* +0x431 */
    UINT64 PidCtx;              /* +0x438 0 или pid (вариант) */
    UINT64 KuserRef;            /* +0x440 = 0xfffff78000000014 (ссылка KUSER) */
    UINT8  ClientCtx[0x48];     /* +0x448 опциональный per-client контекст
                                 *  (FUN_1400062a8; только когда pid ==
                                 *  pid первичного клиента 0x140108750) */
    UINT32 VerifyFlags;         /* +0x490 bit0 = file-open fail; 8 = clean */
    UINT32 Flag494;             /* +0x494 0/1 */
    UINT32 Pad498;              /* +0x498 */
    UINT32 VerdictStatus;       /* +0x49C NTSTATUS пути FUN_140042034 */
    UINT8  Tail[0x38];          /* +0x4A0 */
} AC_REC_MODULE_LOAD, *PAC_REC_MODULE_LOAD;
#pragma pack(pop)

/* --------------------------------------------------------------------------
 * дамп модуля/региона 0x22 -- 0x228 + size байтов [static, ветка FUN_14003f78c]
 * ------------------------------------------------------------------------ */
#pragma pack(push, 1)
typedef struct _AC_REC_MODULE_DUMP {
    UINT32 Marker;              /* +0x00 = AC_EV_MODULE_DUMP */
    UINT32 Pad0;                /* +0x04 */
    UINT64 Base;                /* +0x08 база дампа (AC_EVENT_CHANNEL #1 также
                                 *  числит 0x22 среди seq-событий -> этот qword
                                 *  -- позиция seq в чтении seq; union оставлен
                                 *  одним полем, BYTE_MAP #5) */
    WCHAR  Name[0x108];         /* +0x10 UTF-16LE (0x210 байтов; конец +0x220) */
    UINT32 Size;                /* +0x220 сырое число байтов */
    UINT32 Reason;              /* +0x224 0 = неверифицированный модуль (полный
                                 *        образ), 6 = регион попадания
                                 *        паттерна (<=0x1000) */
    /* UINT8 Raw[Size];         +0x228 */
} AC_REC_MODULE_DUMP, *PAC_REC_MODULE_DUMP;
#pragma pack(pop)
#define AC_DUMP_HDR_SIZE        0x228

/* --------------------------------------------------------------------------
 * детекция 0x12 -- 0x658 байтов [static; подтипы 06/0b/18/43/47]
 * ------------------------------------------------------------------------ */
#pragma pack(push, 1)
typedef struct _AC_REC_DETECTION {
    UINT32 Marker;              /* +0x000 = AC_EV_DETECTION */
    UINT32 Pad0;                /* +0x004 */
    UINT64 Seq;                 /* +0x008 (явный LOCK inc только в
                                 *  подтипе 0x47; возможно VM-сендер
                                 *  в остальных [suspected]) */
    UINT32 Subtype;             /* +0x010 0x06/0x0b/0x18/0x43/0x47 */
    WCHAR  Str1[0x104];         /* +0x014 (0x208B) */
    WCHAR  Str2[0x104];         /* +0x21C (0x208B) */
    WCHAR  Str3[0x104];         /* +0x424 (0x208B, NUL-terminated) */
    UINT32 Flag;                /* +0x62C флаг/ctx */
    UINT32 Pad630;              /* +0x630 */
    UINT32 State;               /* +0x634 (ячейка 0x140108d78) */
    UINT64 Ctx0;                /* +0x638 указатель совпадения */
    UINT64 Ctx1;                /* +0x640 конец региона */
    UINT64 Ctx2;                /* +0x648 значение */
    UINT8  Tail[8];             /* +0x650 */
} AC_REC_DETECTION, *PAC_REC_DETECTION;
#pragma pack(pop)

/* --------------------------------------------------------------------------
 * файл+подпись 0x2B -- база 0x4D4, на wire 0x498 + sigsize
 * [static, FUN_1400713c8; rate-limit дедуп 10/600 FUN_140070e9c]
 * ------------------------------------------------------------------------ */
#pragma pack(push, 1)
typedef struct _AC_SIG_BLOB {
    UINT32 Size;                /* +0x00 размер блоба (вкл. заголовок) */
    UINT32 Status;              /* +0x04 NTSTATUS пути verify */
    /* UINT8 Data[Size-8];      +0x08 Authenticode PKCS#7 (VM 0x140002524) */
} AC_SIG_BLOB, *PAC_SIG_BLOB;

typedef struct _AC_REC_FILE_SIG {
    UINT32 Marker;              /* +0x000 = AC_EV_FILE_SIG */
    UINT32 Pad0;                /* +0x004 */
    UINT64 Seq;                 /* +0x008 LOCK xadd 0x140108db8 */
    UINT64 ObjId[3];            /* +0x010/+0x018/+0x020 */
    UINT64 ChannelId;           /* +0x028 param_2 (id канала/клиента) */
    WCHAR  Path1[0x104];        /* +0x030 из FILE_OBJECT (0x208B) */
    WCHAR  Path2[0x104];        /* +0x238 (0x208B) */
    UINT64 MappedSize;          /* +0x440 */
    UINT64 KuserRef;            /* +0x448 = 0xfffff78000000014 */
    UINT8  Zero450;             /* +0x450 = 0 */
    CHAR   FileHashAscii[0x47]; /* +0x451 hex-фингерпринт файла
                                 *  (FUN_14009be44 VM); дедуп сравнивает
                                 *  0x41 байтов -> 64 hex + NUL (кандидат
                                 *  sha256) [layout доказан] */
    AC_SIG_BLOB Sig;            /* +0x498 опционально; запись на wire =
                                 *  0x498 + sigsize */
} AC_REC_FILE_SIG, *PAC_REC_FILE_SIG;
#pragma pack(pop)
#define AC_FILE_SIG_BASE_SIZE   0x498

/* --------------------------------------------------------------------------
 * S->D push plaintext'ы (для полноты канала; layout'ы [dec],
 * DRIVER_CHANNEL_BYTEMAP #2). Сторона драйвера = AcChannelPush* в channels.c.
 * ------------------------------------------------------------------------ */
#pragma pack(push, 1)
typedef struct _AC_PUSH_SESSION_UUID {  /* IOCTL 0xC3502010, 40B */
    UINT32 Tag;                 /* +0x00 = 0x15 */
    CHAR   Guid[36];            /* +0x04 ASCII uuid аккаунта + NUL */
} AC_PUSH_SESSION_UUID;

typedef struct _AC_PUSH_MATCH_RECORD {  /* IOCTL 0xC3502018, 28B */
    UINT32 Tag;                 /* +0x00 = 0x17 */
    UINT8  Varint[6];           /* +0x04 varint-подобное */
    UINT8  IdPrefix[15];        /* +0x0A префикс id */
    UINT8  Zero[3];             /* +0x19 */
} AC_PUSH_MATCH_RECORD;

typedef struct _AC_PUSH_DRIVER_EVENT {  /* IOCTL 0xC350202C, 24B */
    UINT32 Tag;                 /* +0x00 = 0x14 */
    UINT32 Zero0;               /* +0x04 */
    UINT32 Value;               /* +0x08 */
    UINT32 Zero1;               /* +0x0C */
    UINT32 Code;                /* +0x10 in {0x12 pattern, 0x26 module-load,
                                 *         0x2b file+sig} */
    UINT32 Zero2;               /* +0x14 */
} AC_PUSH_DRIVER_EVENT;

typedef struct _AC_PUSH_CMD {           /* IOCTL 0xC3502050, 12B */
    UINT32 Tag;                 /* +0x00 = 0x27 */
    UINT32 One0;                /* +0x04 = 1 */
    UINT32 One1;                /* +0x08 = 1 (семантика unknown) */
} AC_PUSH_CMD;

typedef struct _AC_PUSH_VENDOR_CN {     /* IOCTL 0xC350203C, 64B */
    CHAR Cn[64];                /* NUL-пэдденый Authenticode vendor CN */
} AC_PUSH_VENDOR_CN;

typedef struct _AC_PUSH_SHA256_HEX {    /* IOCTL 0xC3502040, 65B */
    CHAR Hex[65];               /* 64 lower-hex + NUL */
} AC_PUSH_SHA256_HEX;

typedef struct _AC_PUSH_U64_SET {       /* IOCTL 0xC350205C, 104B (N=12) */
    UINT32 Session;             /* +0x00 per-session поле [unknown] */
    UINT32 Count;               /* +0x04 = 11 (shim56) / 12 (shim72) */
    UINT64 Values[12];          /* +0x08 cross-run константы (первые 11);
                                 * источник за VM [unknown, FNV/sha neg] */
} AC_PUSH_U64_SET;
#pragma pack(pop)

/* --------------------------------------------------------------------------
 * Server-side контейнеры, делящие крипто-канал (атрибуционная справка;
 * это НЕ записи драйвера -- BYTE_MAP #6):
 *   S1 manifest 2000B (вход вердикта обновления server->service)
 *   S2 command 48B (ордер инвентаря kernel-модулей)
 *   S3 keepalive 8B {1,9}
 * ------------------------------------------------------------------------ */
#pragma pack(push, 1)
typedef struct _AC_S1_MANIFEST {        /* 0x7D0 bytes [dec] */
    UINT32 Subtype;             /* +0x000 = 0 */
    UINT32 LatestBuild;         /* +0x004 "latest" сервера (0x67c/0x67d) */
    UINT32 Flags;               /* +0x008 0x100 / 0x101 / 0x01000100 */
    UINT8  Reserved00C[0x70C];  /* +0x00C нули */
    UINT8  Flag718;             /* +0x718 = 1 (та же позиция, что Flag718
                                 *  hello -- общий писатель контейнеров [hyp]) */
    UINT8  Reserved719[0xB7];   /* +0x719 нули */
} AC_S1_MANIFEST;

typedef struct _AC_S2_CMD {             /* 48 байтов [dec] */
    UINT32 Tag;                 /* +0x00 = 3 */
    UINT32 Zero;                /* +0x04 = 0 */
    UINT8  One;                 /* +0x08 = 1 */
    CHAR   Guid[36];            /* +0x09 id глагола/объекта (константа
                                 *  "f6a78d0d-bc4c-4c2f-9100-41286f9c2a7e") */
    UINT8  Pad[3];              /* +0x2D */
} AC_S2_CMD;

typedef struct _AC_S3_KEEPALIVE {       /* 8 байтов [dec] */
    UINT32 Tag;                 /* +0x00 = 1 */
    UINT32 Code;                /* +0x04 = 9 (пинг живости сервера) */
} AC_S3_KEEPALIVE;
#pragma pack(pop)

/* семейство ingame64.dll 0x01 (атрибуционная справка; ключ ee4f7299...) */
#pragma pack(push, 1)
typedef struct _AC_INGAME_SUB4_HDR {    /* {1,4,id,len}{UTF-16LE str} */
    UINT32 Tag;                 /* +0x00 = 1 */
    UINT32 Sub;                 /* +0x04 = 4 */
    UINT32 Id;                  /* +0x08 (0x61 API-имя, 0x5F цифра,
                                 *  0x63/0x33 net-имя, 0x2F/0x31 пусто) */
    UINT32 StrLen;              /* +0x0C UTF-16LE символы (без NUL) */
    /* WCHAR Str[];             +0x10 */
} AC_INGAME_SUB4_HDR;

typedef struct _AC_INGAME_SUB9_HDR {    /* {1,9}{UTF-16LE str @+8} */
    UINT32 Tag;                 /* +0x00 = 1 */
    UINT32 Sub;                 /* +0x04 = 9 (520B: имя GPU; 8B голое: S3) */
    /* WCHAR Str[];             +0x08 */
} AC_INGAME_SUB9_HDR;
#pragma pack(pop)

/* --------------------------------------------------------------------------
 * static assert'ы -- только смещения, доказанные wire-фреймами или
 * дословной статикой
 * ------------------------------------------------------------------------ */
#define AC_SA(name, expr) \
    typedef char ac_sa_##name[(expr) ? 1 : -1]

/* wire-конверт */
AC_SA(box_hdr,    sizeof(AC_WIRE_BOX_HDR) == AC_WIRE_SEAL_OVERHEAD);

/* hello (wire: фреймы hello_2.pt / in_0001.pt) */
AC_SA(hello_size, sizeof(AC_REC_HELLO) == AC_HELLO_SIZE);
AC_SA(hello_build,  offsetof(AC_REC_HELLO, Build) == 0x004);
AC_SA(hello_label1, offsetof(AC_REC_HELLO, LabelSerial) == 0x21E);
AC_SA(hello_sysser, offsetof(AC_REC_HELLO, SystemSerial) == 0x26E);
AC_SA(hello_label2, offsetof(AC_REC_HELLO, LabelProduct) == 0x2AA);
AC_SA(hello_uuid,   offsetof(AC_REC_HELLO, SystemUuid) == 0x30E);
AC_SA(hello_bser,   offsetof(AC_REC_HELLO, BoardSerial) == 0x333);
AC_SA(hello_bven,   offsetof(AC_REC_HELLO, BoardVendor) == 0x36F);
AC_SA(hello_bmod,   offsetof(AC_REC_HELLO, BoardModel) == 0x3BF);
AC_SA(hello_sguid,  offsetof(AC_REC_HELLO, SynthGuid) == 0x618);
AC_SA(hello_f20,    offsetof(AC_REC_HELLO, SecurityState) == 0x640);
AC_SA(hello_count,  offsetof(AC_REC_HELLO, MacCount) == 0x644);
AC_SA(hello_macofs, offsetof(AC_REC_HELLO, MacListOfs) == 0x648);
AC_SA(hello_hash,   offsetof(AC_REC_HELLO, MachineHash) == 0x64D);
AC_SA(hello_f690,   offsetof(AC_REC_HELLO, Flag690) == 0x690);
AC_SA(hello_u2ofs,  offsetof(AC_REC_HELLO, Uuid2Ofs) == 0x694);
AC_SA(hello_biosv,  offsetof(AC_REC_HELLO, BiosVersion) == 0x69A);
AC_SA(hello_biosven,offsetof(AC_REC_HELLO, BiosVendor) == 0x6CC);
AC_SA(hello_biosd,  offsetof(AC_REC_HELLO, BiosDate) == 0x6FE);
AC_SA(hello_f718,   offsetof(AC_REC_HELLO, Flag718) == 0x718);
AC_SA(hello_maclst, offsetof(AC_REC_HELLO, MacList) == 0x720);

/* disks / ram (wire: in_0002.pt / in_0003.pt) */
AC_SA(disk_slot,  sizeof(AC_DISK_SLOT) == 0x148);
AC_SA(disk_id,    offsetof(AC_DISK_SLOT, Id) == 0x000);
AC_SA(disk_model, offsetof(AC_DISK_SLOT, Model) == 0x0FF);
AC_SA(disk_fw,    offsetof(AC_DISK_SLOT, Firmware) == 0x128);
AC_SA(disk_serlen,offsetof(AC_DISK_SLOT, SerialLen) == 0x144);
AC_SA(disks_rec,  sizeof(AC_REC_DISKS) == 0x298);
AC_SA(ram_slot,   sizeof(AC_RAM_SLOT) == 0x163);
AC_SA(ram_vendor, offsetof(AC_RAM_SLOT, Vendor) == 0x0FF);
AC_SA(ram_part,   offsetof(AC_RAM_SLOT, PartNumber) == 0x131);
AC_SA(ram_rec,    sizeof(AC_REC_RAM) == 0x594);

/* события (wire: in_0006/0194/0217; static: layout'ы шины) */
AC_SA(hb_size,    sizeof(AC_REC_HEARTBEAT) == 8);
AC_SA(attach_size,sizeof(AC_REC_PROC_ATTACH) == 0x20);
AC_SA(name_size,  sizeof(AC_REC_NAME) == 0x20C);
AC_SA(td_size,    sizeof(AC_REC_TEARDOWN) == 0x10);
AC_SA(mstate_size,sizeof(AC_REC_MODULE_STATE) == 0x210);
AC_SA(mload_size, sizeof(AC_REC_MODULE_LOAD) == 0x4D8);
AC_SA(mload_path, offsetof(AC_REC_MODULE_LOAD, Path) == 0x020);
AC_SA(mload_branch,offsetof(AC_REC_MODULE_LOAD, BranchFlag) == 0x430);
AC_SA(mload_kuser,offsetof(AC_REC_MODULE_LOAD, KuserRef) == 0x440);
AC_SA(mload_flags,offsetof(AC_REC_MODULE_LOAD, VerifyFlags) == 0x490);
AC_SA(mload_verdict,offsetof(AC_REC_MODULE_LOAD, VerdictStatus) == 0x49C);
AC_SA(dump_hdr,   sizeof(AC_REC_MODULE_DUMP) == AC_DUMP_HDR_SIZE);
AC_SA(det_size,   sizeof(AC_REC_DETECTION) == 0x658);
AC_SA(det_subtype,offsetof(AC_REC_DETECTION, Subtype) == 0x010);
AC_SA(det_str2,   offsetof(AC_REC_DETECTION, Str2) == 0x21C);
AC_SA(det_str3,   offsetof(AC_REC_DETECTION, Str3) == 0x424);
AC_SA(det_flag,   offsetof(AC_REC_DETECTION, Flag) == 0x62C);
AC_SA(det_state,  offsetof(AC_REC_DETECTION, State) == 0x634);
AC_SA(det_ctx2,   offsetof(AC_REC_DETECTION, Ctx2) == 0x648);
AC_SA(fsig_hash,  offsetof(AC_REC_FILE_SIG, FileHashAscii) == 0x451);
AC_SA(fsig_sig,   offsetof(AC_REC_FILE_SIG, Sig) == 0x498);
AC_SA(fsig_base,  offsetof(AC_REC_FILE_SIG, Sig) == AC_FILE_SIG_BASE_SIZE);

/* S->D + server-контейнеры */
AC_SA(uuid_push,  sizeof(AC_PUSH_SESSION_UUID) == 40);
AC_SA(match_push, sizeof(AC_PUSH_MATCH_RECORD) == 28);
AC_SA(event_push, sizeof(AC_PUSH_DRIVER_EVENT) == 24);
AC_SA(cmd_push,   sizeof(AC_PUSH_CMD) == 12);
AC_SA(u64_push,   sizeof(AC_PUSH_U64_SET) == 104);
AC_SA(s1_size,    sizeof(AC_S1_MANIFEST) == 0x7D0);
AC_SA(s1_flag,    offsetof(AC_S1_MANIFEST, Flag718) == 0x718);
AC_SA(s2_size,    sizeof(AC_S2_CMD) == 48);
AC_SA(s3_size,    sizeof(AC_S3_KEEPALIVE) == 8);

/* --------------------------------------------------------------------------
 * бандлы входов билдеров (выходы коллекторов; зеркалят данные
 * hwid.c/smbios.c)
 * ------------------------------------------------------------------------ */
#pragma pack(push, 1)
typedef struct _AC_HWID_DISK_SRC {
    CHAR   Id[0x20];            /* serial дескриптора / NVMe namespace id */
    CHAR   Model[0x29];
    CHAR   Firmware[0x1C];
    UINT32 SerialLen;           /* 0x11 на wire */
    CHAR   Serial[0x20];        /* ATA IDENTIFY w10-19 + суффикс "_00000001." */
} AC_HWID_DISK_SRC;

typedef struct _AC_HWID_RAM_SRC {
    CHAR Serial[0x20];
    CHAR Vendor[0x32];
    CHAR PartNumber[0x32];
} AC_HWID_RAM_SRC;

typedef struct _AC_HELLO_SRC {
    UINT32 Build;               /* билд драйвера (VM-собранный иммедиат) */
    UINT8  Flags[4];            /* per-run флаги; [1] всегда 1 */
    CHAR   SystemSerial[0x3C];  /* SMBIOS t1 */
    CHAR   SystemUuid[0x25];    /* SMBIOS t1 UUID ASCII */
    CHAR   BoardSerial[0x3C];   /* SMBIOS t2 */
    CHAR   BoardVendor[0x50];
    CHAR   BoardModel[0x50];
    CHAR   SynthGuid[0x28];     /* композит f18 (цепочка GetIfEntry2) */
    UINT16 SecurityState;       /* битмаска f20 */
    UINT32 MacCount;            /* строки ARP-кэша */
    CHAR   MacList[AC_HELLO_MAC_MAX][AC_HELLO_MAC_SLOT];
    CHAR   MachineHash[0x41];   /* f21 предвычисленный (BCrypt-хаб 0x14024af8e) */
    CHAR   BiosVersion[0x32];   /* SMBIOS t0 */
    CHAR   BiosVendor[0x32];
    CHAR   BiosDate[0x1A];
    CHAR   Uuid2[0x25];         /* f22 предвычисленный (маршаллер 0x140282319) */
} AC_HELLO_SRC;
#pragma pack(pop)

/* прототипы билдеров */
VOID AcRecBuildHeartbeat(_Out_ PAC_REC_HEARTBEAT Rec, _In_ UINT32 Flag);
VOID AcRecBuildTeardown(_Out_ PAC_REC_TEARDOWN Rec);
VOID AcRecBuildProcAttach(_Out_ PAC_REC_PROC_ATTACH Rec, _In_ UINT64 Pid,
                          _In_ UINT32 Flag);
VOID AcRecBuildName(_Out_ PAC_REC_NAME Rec, _In_ UINT32 Marker,
                    _In_ const WCHAR* Path);
VOID AcRecBuildModuleState(_Out_ PAC_REC_MODULE_STATE Rec,
                           _In_ const WCHAR* Path, _In_ UINT8 State);
VOID AcRecBuildModuleLoad(_Out_ PAC_REC_MODULE_LOAD Rec, _In_ UINT64 DllBase,
                          _In_ UINT64 SizeOfImage, _In_ const WCHAR* Path,
                          _In_ UINT32 VerifyFlags, _In_ UINT32 VerdictStatus);
VOID AcRecBuildModuleDump(
    _Out_writes_bytes_(AC_DUMP_HDR_SIZE + Size) PAC_REC_MODULE_DUMP Rec,
    _In_ UINT64 Base, _In_ const WCHAR* Name, _In_ UINT32 Size,
    _In_ UINT32 Reason, _In_reads_bytes_(Size) const UINT8* Raw);
VOID AcRecBuildFileSig(_Out_ PAC_REC_FILE_SIG Rec, _In_ const UINT64 ObjId[3],
                       _In_ UINT64 ChannelId, _In_ const WCHAR* Path1,
                       _In_ const WCHAR* Path2, _In_ UINT64 MappedSize,
                       _In_ const CHAR* FileHashAscii,
                       _In_opt_ const UINT8* SigBlob, _In_ UINT32 SigBlobSize,
                       _In_ UINT32 SigStatus);
VOID AcRecBuildDisks(_Out_ PAC_REC_DISKS Rec, _In_ UINT32 Count,
                     _In_reads_(Count) const AC_HWID_DISK_SRC* Src);
VOID AcRecBuildRam(_Out_ PAC_REC_RAM Rec, _In_ UINT32 Count,
                   _In_reads_(Count) const AC_HWID_RAM_SRC* Src);
VOID AcRecBuildHello(_Out_ PAC_REC_HELLO Rec, _In_ const AC_HELLO_SRC* Src);

#endif /* AC_RECORDS_H */
