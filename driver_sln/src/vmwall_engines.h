/* ==========================================================================
 * vmwall_engines.h — движки детектов/вердиктов, восстановленные добитием
 * остаточной VM-стены (см. _research_tmp/vmwall/VMWALL_REPORT.md)
 * ========================================================================== */
#ifndef FACEIT_AC_VMWALL_ENGINES_H
#define FACEIT_AC_VMWALL_ENGINES_H

#include <ntddk.h>

/* --- fingerprint (proven-sha256 через CNG; evidence в vmwall_engines.c) --- */
#define AC_FINGERPRINT_HEX_LEN  64      /* 32B дайджест -> 64 hex + NUL */
#define AC_FINGERPRINT_HEX_CAP  65      /* дедуп-сравнение 0x41 байтов */

/* [0x14009bcb4] + [0x140375b79] hex-кодировщик: "%02x" на байт дайджеста
 * (контуры вызывающих фингерпринта: FUN_140045448 запись игрового файла
 * 0x26, FUN_140042034 путь verify модуля, продюсер 0x2B +0x451,
 * ответ USB-handshake 0xC3502048) */
VOID
AcFingerprintHex(
    _In_reads_(32) const UINT8 Digest[32],
    _Out_writes_(AC_FINGERPRINT_HEX_CAP) CHAR Out[AC_FINGERPRINT_HEX_CAP]
    );

/* --- общая геометрия записи 0x12 (BYTE_MAP §5) --- */
#define AC_REC12_SIZE           0x658
#define AC_REC12_OFF_SUBTYPE    0x10
#define AC_REC12_OFF_STR1       0x14
#define AC_REC12_OFF_STR2       0x21c
#define AC_REC12_OFF_STR3       0x424
#define AC_REC12_OFF_F62C       0x62c
#define AC_REC12_OFF_F630       0x630
#define AC_REC12_OFF_F634       0x634
#define AC_REC12_OFF_OFF        0x638
#define AC_REC12_OFF_LEN        0x640
#define AC_REC12_OFF_ALIGNED    0x648
#define AC_REC12_BATCH_MAX      0x0f    /* записи diff-серий на секцию */

/* --- подтипы движка сканов --- */
#define AC_SUBT_SECTION_COMPARE 0x06    /* FUN_14007ac24 */
#define AC_SUBT_SECTION_CMP_B   0x0b    /* FUN_14006ba50 (+ FUN_14006a394) */
#define AC_SUBT_OBJECT_WALK     0x18    /* FUN_1400104ac */
#define AC_SUBT_ADDR_MODULE     0x47    /* FUN_140091e0c */

/* --- биты характеристик секций, используемые движками сравнения --- */
#define AC_SCN_EXEC             0x20000000u
#define AC_SCN_READ             0x40000000u
#define AC_SCN_WRITE            0x80000000u
#define AC_SCN_UNINIT           0x00000080u
#define AC_SCN_DISCARD          0x02000000u

/* --- вердикты minifilter'а (цепочка native_05.c) --- */
typedef enum _AC_MF_VERDICT {
    AcMfPass = 0,                 /* нет совпадения -- разрешить открытие */
    AcMfRecord26Bsp,              /* быстрый путь .bsp (FUN_1400444a8) */
    AcMfRecord26Fingerprint,      /* контент игры (FUN_140045448) */
    AcMfDenyUnnamed,              /* .vpk без нормализуемого имени */
    AcMfDenyVirtualFs             /* .vpk с устройства Dokan/WinFsp/GUID */
} AC_MF_VERDICT;

AC_MF_VERDICT
AcMfClassifyGamePath(
    _In_ PCUNICODE_STRING Path,
    _In_ BOOLEAN NameNormalizable,
    _In_reads_opt_(DevCount) PCUNICODE_STRING DevStack,
    _In_ UINT32 DevCount
    );

/* --- скан паттернов с маской (контракт 0x14009D438) --- */
const UINT8 *
AcFindPatternWildcard(
    _In_ const UINT8 *Start,
    _In_ const UINT8 *End,
    _In_ const UINT8 *Needle,
    _In_ const UINT8 *Mask,
    _In_ SIZE_T Len
    );

/* --- движок сравнения секций (0x06/0x0b) --- */
typedef struct _AC_SCAN_RANGE {
    UINT64 Lo, Hi;
} AC_SCAN_RANGE;

typedef struct _AC_SCAN_CTX {
    AC_SCAN_RANGE Excl[4];        /* исключение IAT/export-dir (0x0b) */
    UINT32 ExclCount;
    AC_SCAN_RANGE RipOk[8];       /* legit RIP-rel адресаты (FUN_14007a300) */
    UINT32 RipOkCount;
    UINT32 HookB50;               /* bRam0000000140108c50 */
    UINT32 HookB51;               /* bRam0000000140108c51 */
    UINT32 StateD78;              /* uRam0000000140108d78 */
} AC_SCAN_CTX;

typedef VOID (NTAPI *AC_REC12_SEND_FN)(
    _In_ const UINT8 *Rec0x658,
    _In_opt_ PVOID UserCtx
    );

UINT32
AcScanCompareSection(
    _In_ const UINT8 *Mem,
    _In_ UINT64 MemVa,
    _In_ const UINT8 *File,
    _In_ UINT64 FileVa,
    _In_ SIZE_T RawLen,
    _In_ SIZE_T Aligned,
    _In_ UINT32 Characteristics,
    _In_ UINT32 Subtype,
    _In_ const CHAR SectName[8],
    _In_ const AC_SCAN_CTX *Ctx,
    _In_ AC_REC12_SEND_FN Send,
    _In_opt_ PVOID UserCtx
    );

/* --- флашер deferred-очереди (0x1400586ec) ---
 * геометрия deferred ctx 0x140108de8: LIST @+0x60, спинлок @+0x70
 * (HWID_DRIVER_COLLECTORS_CODE §6.4); каденс ~30 s KTIMER воркера
 * (DRIVER_CHANNEL_PROTOCOL §4.5), позиция в цепочке: перед drain
 * 0xC3502004 (FULL_CHAIN_IRP_TO_HWID_C §0) */
extern LIST_ENTRY g_AcDeferredQueue;
extern KSPIN_LOCK g_AcDeferredLock;

UINT32
AcChannelFlushDeferred(
    _In_ PLIST_ENTRY Head,
    _In_ AC_REC12_SEND_FN Send,
    _In_opt_ PVOID UserCtx
    );

/* --- атрибуция addr -> module (0x1400010a4 + продюсер 0x140091e0c) --- */
typedef struct _AC_MOD_NODE AC_MOD_NODE, *PAC_MOD_NODE;
struct _AC_MOD_NODE {                   /* layout узла рабочего списка */
    LIST_ENTRY Link;                    /* +0x00 */
    UINT64 Base;                        /* +0x10 */
    UINT32 Size;                        /* +0x20 */
};

PAC_MOD_NODE
AcAddrInModuleList(
    _In_ UINT64 Addr,
    _In_ PLIST_ENTRY Head
    );

/* --- семейство XOR-декодеров строк (k(i) = (i % D) + K) --- */
VOID
AcStrDecWide(
    _Inout_updates_(N) UINT16 *W,
    _In_ UINT32 N,
    _In_ UINT32 D,
    _In_ UINT32 K
    );

/* --- обход object directory (FUN_14000f9c0 + FUN_1400104ac) --- */
#define AC_OBJDIR_BUCKETS  37           /* OBJECT_DIRECTORY.HashBuckets */

#endif /* FACEIT_AC_VMWALL_ENGINES_H */
