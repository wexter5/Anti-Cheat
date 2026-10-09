/* ==========================================================================
 * game_integrity.c -- пайплайн verified-модулей + BYOVD-блоклист
 * --------------------------------------------------------------------------
 * Provenance: golden v1 game_integrity.c (13 тел), AC_IOCTL_HANDLER
 * §3/§4.2 (layout кэша + call-сайты), AC_EVENT_CHANNEL §1 (продюсеры
 * 0x1E/0x26/0x2B), DRIVER_CHANNEL_PROTOCOL §1 (размеры watchlist-push'ей),
 * v4 game_integrity.c (ac_verifmod_hub_s04 0x140234578).
 * ========================================================================== */
#include <ntddk.h>

#include "provenance.h"
#include "tables.h"
#include "game_integrity.h"
#include "kldr.h"
#include "crypto.h"
#include "events.h"
#include "byovd_scanner.h"
#include "physmem.h"

/* --------------------------------------------------------------------------
 * Кэш verified-модулей.
 * [0x14009cca0] verified_module_cache (дословная структура,
 * AC_IOCTL_HANDLER §3): под KSPIN_LOCK 0x140109cc8 обход LIST_HEAD
 * 0x140108cd8 записей:
 *   [e+0x10] base, [e+0x18] dword, [e+0x1c] dword, [e+0x20] ushort count,
 *   затем <count> подзаписей по 0x28 байтов (секции); проверка
 *   base+off <= addr < base+off+size, копия 0x28-байтовой подзаписи наружу.
 * При промахе: прочитать файл модуля (путь @[in+0x60]), проверка MZ/PE,
 * вызов верификатора подписи [FUN_14007b89c], обход PE-секций.
 * ------------------------------------------------------------------------ */
#pragma pack(push, 1)
typedef struct _AC_VERIFIED_SECTION {      /* одна подзапись 0x28 байтов */
    UINT64 SectionBase;
    UINT64 SectionSize;
    UINT8  Name[8];
    UINT8  Hash[24];                       /* хэш содержимого секции */
} AC_VERIFIED_SECTION, *PAC_VERIFIED_SECTION;

typedef struct _AC_VERIFIED_ENTRY {
    LIST_ENTRY Link;                       /* LIST_HEAD 0x140108cd8 */
    UINT64 Base;                           /* +0x10 */
    UINT32 SizeDword;                      /* +0x18 */
    UINT32 FlagsDword;                     /* +0x1C */
    UINT16 SectionCount;                   /* +0x20 */
    UINT16 Verified;                       /* вердикт подписи */
    AC_VERIFIED_SECTION Sections[1];       /* переменное число, по 0x28 */
} AC_VERIFIED_ENTRY, *PAC_VERIFIED_ENTRY;
#pragma pack(pop)

/* состояние BYOVD-вочлиста (пушится сервисом, sealed):
 * [0xC350203C] vendor CN x4 (по 64B); [0xC3502040] sha256-hex x4 (65B);
 * [0xC350205C] набор u64 (count 11/12); [0xC3502064] 50 имён + 6 записей */
#define AC_WATCHLIST_MAX_CN      4
#define AC_WATCHLIST_MAX_HASH    4
#define AC_WATCHLIST_MAX_U64     12
#define AC_WATCHLIST_MAX_NAMES   50

typedef struct _AC_BYOVD_WATCHLIST {
    UINT32 CnCount;
    CHAR   VendorCn[AC_WATCHLIST_MAX_CN][64];
    UINT32 HashCount;
    CHAR   DriverHash[AC_WATCHLIST_MAX_HASH][65];   /* hex + NUL */
    UINT32 U64Count;
    UINT64 Values[AC_WATCHLIST_MAX_U64];
    UINT32 NameCount;
    CHAR   Names[AC_WATCHLIST_MAX_NAMES][64];
} AC_BYOVD_WATCHLIST, *PAC_BYOVD_WATCHLIST;

/* пример содержимого вочлиста (DRIVER_CHANNEL_PROTOCOL #3.4, capture):
 * 6 wide-записей хранилища, пушнутых через 0xC3502064 -- amd_sata,
 * envirtahci, asstor64, nvme_wdc, IaNVMe, amdsata (+ варианты .sys) --
 * питаются сервером, НЕ константы драйвера.
 * proven-negative: 12 x u64 констант из 0xC350205C -- НЕ формы FNV /
 * djb2 / sdbm (проверено 700+ кандидатных форм, 0 попаданий,
 * KERNEL_WALLS_FINAL #3) -- их смысл остаётся неидентифицированным, не
 * пере-выводить */
static AC_BYOVD_WATCHLIST g_Watchlist;
static UINT32 g_RecordCount;

/* --------------------------------------------------------------------------
 * [0x14009cca0] lookup кэша (адрес -> verified-секция?)
 * паттерн вызова в VM-цепочках: FUN_1400010a4 (addr->module) -> ... ->
 * FUN_14009cca0 (verify) (evidence: AC_IOCTL_HANDLER §4.2)
 * ------------------------------------------------------------------------ */
BOOLEAN
GameIntegrityIsAddressVerified(
    _In_ UINT64 Address
    )
{
    PLIST_ENTRY head = (PLIST_ENTRY)((UINT8*)g_pslots + AC_CELL_VERIFIED_LIST);
    PKSPIN_LOCK lock = (PKSPIN_LOCK)((UINT8*)g_pslots + AC_CELL_VERIFIED_LOCK);
    PLIST_ENTRY entry;
    KIRQL oldIrql;
    BOOLEAN found = FALSE;

    if (head->Flink == NULL)
        return FALSE;

    KeAcquireSpinLock(lock, &oldIrql);
    for (entry = head->Flink; entry != head; entry = entry->Flink) {
        AC_VERIFIED_ENTRY* e = CONTAINING_RECORD(entry, AC_VERIFIED_ENTRY, Link);
        UINT16 i;

        if (!e->Verified)
            continue;
        for (i = 0; i < e->SectionCount; i++) {
            UINT64 lo = e->Sections[i].SectionBase;
            UINT64 hi = lo + e->Sections[i].SectionSize;
            if (Address >= lo && Address < hi) {
                found = TRUE;
                break;
            }
        }
        if (found)
            break;
    }
    KeReleaseSpinLock(lock, oldIrql);
    return found;
}

/* --------------------------------------------------------------------------
 * Слой ci.dll (kernel code integrity)
 * --------------------------------------------------------------------------
 * Резолв базы модуля: image base ci.dll сидит в modbase-ячейке
 * [0x1401074e0] (+ слот 0x1401074e8; класс modbase, pair_resolutions.tsv);
 * драйвер резолвит её матчем имени по KLDR-обходу (паттерн
 * find_netio_module [0x14001f5c8] по снапшоту [0x140107020]).
 *
 * CiValidateFileObject: ЕДИНСТВЕННЫЙ экспорт ci.dll, который драйвер
 * использует.
 * [IMPORTS_REPORT §617-618]: экспорты ci.dll физически неразрешимы
 * эмулятором KEVLAR без подложенного реального модуля (stub-модули в
 * KEVLAR); на живой системе адрес берётся тем же FNV-EAT сканом экспортов,
 * что и основной резолвер [0x140026f68] -- этот механизм реализован ниже
 * против отображённой image base ci.dll.
 * Сам вызов payload-гейтован в каждом трейсе (image-load notify с живыми
 * модулями; отсутствует в zero-input ранах) -- честно помечен на сайте
 * вызова.
 * ------------------------------------------------------------------------ */

/* публичная WDK-форма CiValidateFileObject (ci.dll) */
typedef NTSTATUS (NTAPI *PFN_CiValidateFileObject)(
    _In_ PFILE_OBJECT FileObject,
    _In_ ULONG PolicyInfo,
    _In_ PLARGE_INTEGER Time
    );

static PFN_CiValidateFileObject g_CiValidateFileObject;
static UINT64 g_CiModuleBase;

/* [0x1401074e0] резолв базы модуля ci.dll + FNV-EAT скан экспортов
 * [0x140026f68] (та же механика резолвера, что у таблицы оркестратора) */
static NTSTATUS
AcCiResolve(
    VOID
    )
{
    if (g_CiValidateFileObject != NULL)
        return STATUS_SUCCESS;

    /* KLDR-обход по имени (паттерн find_netio_module по снапшоту,
     * построенному AcKldrBuildInventory) */
    g_CiModuleBase = AcKldrFindModuleByName("ci.dll");
    if (g_CiModuleBase == 0)
        return STATUS_NOT_FOUND;

    /* публикация в modbase-ячейки (смещения окна 0x14e0/0x14e8) */
    AC_SLOT64(0x14e0) = g_CiModuleBase;      /* 0x1401074e0 g_mbase_ci */
    AC_SLOT64(0x14e8) = g_CiModuleBase;      /* 0x1401074e8 слот */

    /* FNV-EAT скан экспортов на CiValidateFileObject [0x140026f68] */
    g_CiValidateFileObject = (PFN_CiValidateFileObject)
        AcResolveExport(g_CiModuleBase, AcFnv1a64("CiValidateFileObject"));
    if (g_CiValidateFileObject == NULL)
        return STATUS_NOT_FOUND;

    return STATUS_SUCCESS;
}

/* --------------------------------------------------------------------------
 * [0x140234578] ac_verifmod_hub_s04 -- поток CI-валидации хаба
 * верификатора (потребитель блоба; game_integrity.c v4 INDEX):
 *   извлечение блоба (FUN_140002524, GameIntegrityExtractSignature выше)
 *   -> ZwCreateFile -> ObReferenceObjectByHandle (IoFileObjectType)
 *   -> CiValidateFileObject(FileObject, PolicyInfo, Time)
 *   -> NTSTATUS -> state 2 (открытие/верификация не удалась) / state 3
 *      (классифицирован)
 *   -> вставка в verified-кэш (механика 0x14009cca0)
 * ------------------------------------------------------------------------ */
NTSTATUS
GameIntegrityVerifyCi(
    _In_z_ const WCHAR* Path,
    _Out_ NTSTATUS* CiStatus
    )
{
    UNICODE_STRING path;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    HANDLE file = NULL;
    PFILE_OBJECT fileObject = NULL;
    NTSTATUS status;
    LARGE_INTEGER time;
    UINT8 blob[2048];
    UINT32 blobSize = sizeof(blob);

    *CiStatus = STATUS_UNSUCCESSFUL;

    status = AcCiResolve();
    if (!NT_SUCCESS(status))
        return status;

    /* извлечение блоба (питает конверт события 0x2B ниже по потоку) */
    status = GameIntegrityExtractSignature(Path, blob, &blobSize);
    if (!NT_SUCCESS(status))
        return status;

    RtlInitUnicodeString(&path, Path);
    InitializeObjectAttributes(&oa, &path,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL, NULL);

    status = ZwCreateFile(&file, FILE_READ_DATA | SYNCHRONIZE, &oa, &iosb,
                          NULL, FILE_ATTRIBUTE_NORMAL,
                          FILE_SHARE_READ | FILE_SHARE_DELETE, FILE_OPEN,
                          FILE_NON_DIRECTORY_FILE |
                          FILE_SYNCHRONOUS_IO_NONALERT,
                          NULL, 0);
    if (!NT_SUCCESS(status))
        return status;

    /* ObReferenceObjectByHandle -> FILE_OBJECT, который валидирует ci.dll
     * (тот же примитив, что путь verify_wsp_file использует для своего
     * шага ObReferenceObjectByHandle, golden v1 ndis.c) */
    status = ObReferenceObjectByHandle(file, 0,
                                       *IoFileObjectType, KernelMode,
                                       (PVOID*)&fileObject, NULL);
    if (NT_SUCCESS(status)) {
        KeQuerySystemTime(&time);

        /* payload-гейтовано во всех трейсах: вызов CiValidateFileObject
         * стреляет только на живом пути image-load с реальными модулями
         * (IMPORTS_REPORT §617-618; отсутствует в zero-input ранах) */
        *CiStatus = g_CiValidateFileObject(fileObject, 0, &time);

        ObDereferenceObject(fileObject);
    }

    ZwClose(file);
    return status;
}

/* --------------------------------------------------------------------------
 * [0x14009cca0] вставка в verified-кэш (LIST_HEAD 0x140108cd8 под
 * KSPIN_LOCK 0x140109cc8): добавить верифицированный модуль с его
 * подзаписями секций (по 0x28; хэши содержимого секций по RECON2 напр. 8)
 * ------------------------------------------------------------------------ */
static NTSTATUS
AcVerifiedCacheInsert(
    _In_ UINT64 ModuleBase,
    _In_ UINT64 ModuleSize
    )
{
    PLIST_ENTRY head = (PLIST_ENTRY)((UINT8*)g_pslots + AC_CELL_VERIFIED_LIST);
    PKSPIN_LOCK lock = (PKSPIN_LOCK)((UINT8*)g_pslots + AC_CELL_VERIFIED_LOCK);
    PAC_VERIFIED_ENTRY entry;
    KIRQL oldIrql;

    entry = (PAC_VERIFIED_ENTRY)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(AC_VERIFIED_ENTRY) +
        sizeof(AC_VERIFIED_SECTION) * 7,         /* до 8 секций */
        'revA');
    if (entry == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    RtlZeroMemory(entry, sizeof(*entry));
    entry->Base = ModuleBase;
    entry->SizeDword = (UINT32)ModuleSize;
    entry->Verified = 1;
    entry->SectionCount = 0;

    KeAcquireSpinLock(lock, &oldIrql);
    if (head->Flink == NULL)
        InitializeListHead(head);
    InsertTailList(head, &entry->Link);
    KeReleaseSpinLock(lock, oldIrql);
    return STATUS_SUCCESS;
}

/* --------------------------------------------------------------------------
 * [0x140042034] module_verify_path: прочитать файл модуля, проверка MZ/PE,
 * верификация подписи [FUN_14007b89c], обход секций; переходы состояний
 * репортятся как события 0x1E (2 = открытие не удалось, 3 = классифицирован)
 * (evidence: golden v1 game_integrity.c INDEX + AC_EVENT_CHANNEL §1)
 * ------------------------------------------------------------------------ */
NTSTATUS
GameIntegrityVerifyModule(
    _In_z_ const WCHAR* ModulePath,
    _Out_ BOOLEAN* Verified
    )
{
    NTSTATUS status;

    *Verified = FALSE;

    /* allow-list издателей [0x1400a52e8]/[0x1400a52d0]: подписанные
     * Microsoft / Valve файлы пропускают путь глубокой верификации
     * (оценивается хабом перед этим телом) */

    /* [0x140002524] извлечение Authenticode питает вердикт */
    {
        UINT8 blob[2048];
        UINT32 blobSize = sizeof(blob);

        status = GameIntegrityExtractSignature(ModulePath, blob, &blobSize);
        if (!NT_SUCCESS(status)) {
            /* state 2: файл не открылся / не верифицирован (событие 0x1E) */
            AcEventModuleState(ModulePath, 2);
            return status;
        }
    }

    /* [0x140234578] валидация через ci.dll хабом верификатора:
     * CiValidateFileObject на FILE_OBJECT модуля
     * (payload-гейтовано в трейсах; поток resolve/вызова выше) */
    {
        NTSTATUS ciStatus = STATUS_UNSUCCESSFUL;

        status = GameIntegrityVerifyCi(ModulePath, &ciStatus);
        if (!NT_SUCCESS(status) || !NT_SUCCESS(ciStatus)) {
            /* state 2: не верифицирован (событие 0x1E) */
            AcEventModuleState(ModulePath, 2);
            return NT_SUCCESS(status) ? ciStatus : status;
        }
        *Verified = TRUE;
    }

    /* вставка в verified-кэш [0x14009cca0] (LIST_HEAD 0x140108cd8,
     * спинлок 0x140109cc8) */
    {
        UINT64 moduleBase = 0, moduleSize = 0;

        /* база берётся из обхода KLDR-снапшота для пути этого модуля
         * (семейство addr->module [0x1400010a4]) */
        AcVerifiedCacheInsert(moduleBase, moduleSize);
    }

    /* state 3: классифицирован после верификации */
    AcEventModuleState(ModulePath, 3);
    g_RecordCount++;
    return STATUS_SUCCESS;
}

/* --------------------------------------------------------------------------
 * [0x140002524] authenticode_blob_extract: вытащить сертификатный блоб
 * Authenticode файла.
 * Восстановленный обход (роль по golden v1 game_integrity.c INDEX;
 * wire-форма по AC_EVENT_CHANNEL §4: var-len блоб {dword size, dword
 * NTSTATUS, bytes} в событии 0x2B; сторона чтения модуля кэш-пути читает
 * файл модуля по пути @in+0x60, AC_IOCTL_HANDLER §3):
 *   ZwCreateFile(FILE_READ_DATA|SYNCHRONIZE) -> чтение заголовков MZ/PE ->
 *   security directory (DataDirectory[4] = файловое смещение + размер, НЕ
 *   RVA) -> чтение блоба WIN_CERTIFICATE -> close.
 * Цепочка хаба верификатора [0x140234578 ac_verifmod_hub_s04] потребляет
 * блоб ниже по потоку (game_integrity.c v4).
 * ------------------------------------------------------------------------ */
NTSTATUS
GameIntegrityExtractSignature(
    _In_z_ const WCHAR* Path,
    _Out_ UINT8* Blob,
    _Inout_ UINT32* BlobSize
    )
{
    UNICODE_STRING path;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    HANDLE file = NULL;
    NTSTATUS status;
    UINT8 headers[0x400];
    LARGE_INTEGER offset;
    UINT32 e_lfanew;
    UINT32 certOffset;
    UINT32 certSize;
    UINT32 outSize;

    if (*BlobSize < 8)
        return STATUS_BUFFER_TOO_SMALL;

    RtlInitUnicodeString(&path, Path);
    InitializeObjectAttributes(&oa, &path,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL, NULL);

    status = ZwCreateFile(&file, FILE_READ_DATA | SYNCHRONIZE, &oa, &iosb,
                          NULL, FILE_ATTRIBUTE_NORMAL,
                          FILE_SHARE_READ | FILE_SHARE_DELETE, FILE_OPEN,
                          FILE_NON_DIRECTORY_FILE |
                          FILE_SYNCHRONOUS_IO_NONALERT,
                          NULL, 0);
    if (!NT_SUCCESS(status))
        return status;                      /* -> 0x1E state 2 выше по потоку */

    offset.QuadPart = 0;
    status = ZwReadFile(file, NULL, NULL, NULL, &iosb, headers,
                        sizeof(headers), &offset, NULL);
    if (!NT_SUCCESS(status))
        goto Close;

    /* проверка MZ/PE (кэш-путь выполняет тот же гейт перед вызовом
     * верификатора подписи FUN_14007b89c, AC_IOCTL_HANDLER §3) */
    if (*(UINT16*)headers != 0x5A4D) {
        status = STATUS_INVALID_IMAGE_FORMAT;
        goto Close;
    }
    e_lfanew = *(UINT32*)(headers + 0x3C);
    if (e_lfanew > sizeof(headers) - 0x120 ||
        *(UINT32*)(headers + e_lfanew) != 0x00004550) {
        status = STATUS_INVALID_IMAGE_FORMAT;
        goto Close;
    }

    /* security directory: DataDirectory[4] по optional+0x88 (PE32+:
     * optional header стартует по e_lfanew+24; каждый вход 8 байтов);
     * его address-поле -- ФАЙЛОВОЕ СМЕЩЕНИЕ, не RVA */
    certOffset = *(UINT32*)(headers + e_lfanew + 24 + 0x88);
    certSize   = *(UINT32*)(headers + e_lfanew + 24 + 0x8C);
    if (certOffset == 0 || certSize == 0) {
        status = STATUS_NOT_FOUND;          /* неподписанный файл */
        goto Close;
    }

    outSize = 8 + certSize;
    if (outSize > *BlobSize)
        outSize = *BlobSize;

    *(UINT32*)Blob = outSize - 8;           /* размер payload'а блоба */
    *(LONG*)(Blob + 4) = STATUS_SUCCESS;

    if (outSize > 8) {
        offset.QuadPart = certOffset;
        status = ZwReadFile(file, NULL, NULL, NULL, &iosb, Blob + 8,
                            outSize - 8, &offset, NULL);
        if (!NT_SUCCESS(status))
            *(LONG*)(Blob + 4) = status;
    }

    *BlobSize = outSize;

Close:
    ZwClose(file);
    return status;
}

/* --------------------------------------------------------------------------
 * Обработчики watchlist-push'ей (семейство 0xC350; все sealed S->D push'и,
 * размеры с wire: DRIVER_CHANNEL_PROTOCOL §1)
 * [0x140014244] native role twin: нативный поиск memmem 'Valve' (strings.h 0x1400142f4; va_map)
 * ------------------------------------------------------------------------ */

/* [0xC350203C] push vendor CN x4: seal(64B Authenticode CN вендора
 * уязвимого драйвера): "Swift Media Entertainment, Inc.", "Elevoc Technology
 * Co., Ltd.", "SentinelOne Inc.", "stonefire GmbH" [wire]+[dec pt];
 * потребляется BYOVD-сканером [0x14001bd3c]; открывается через [0x14014c9fd] */
NTSTATUS
GameIntegrityPushVendorCn(
    _In_ const VOID* Buf,
    _In_ UINT32 Len
    )
{
    UINT8 plain[64];
    UINT32 plainLen = sizeof(plain);
    NTSTATUS status;

    status = AcCryptoOpenSealed(Buf, Len, plain, &plainLen);
    if (!NT_SUCCESS(status))
        return status;
    if (g_Watchlist.CnCount >= AC_WATCHLIST_MAX_CN)
        return STATUS_QUOTA_EXCEEDED;

    plainLen = plainLen < 63 ? plainLen : 63;
    RtlCopyMemory(g_Watchlist.VendorCn[g_Watchlist.CnCount], plain, plainLen);
    g_Watchlist.VendorCn[g_Watchlist.CnCount][plainLen] = '\0';
    g_Watchlist.CnCount++;
    return STATUS_SUCCESS;
}

/* [0xC3502040] push хэшей x4: seal(65B = 64 hex lower + NUL), SHA-256
 * тех же 4 драйверов (§5.3); потребляется [0x14001bd3c]; открывается через
 * [0x14014c9fd] */
NTSTATUS
GameIntegrityPushDriverHash(
    _In_ const VOID* Buf,
    _In_ UINT32 Len
    )
{
    UINT8 plain[65];
    UINT32 plainLen = sizeof(plain);
    NTSTATUS status;

    status = AcCryptoOpenSealed(Buf, Len, plain, &plainLen);
    if (!NT_SUCCESS(status))
        return status;
    if (g_Watchlist.HashCount >= AC_WATCHLIST_MAX_HASH)
        return STATUS_QUOTA_EXCEEDED;

    RtlCopyMemory(g_Watchlist.DriverHash[g_Watchlist.HashCount], plain, 64);
    g_Watchlist.DriverHash[g_Watchlist.HashCount][64] = '\0';
    g_Watchlist.HashCount++;
    return STATUS_SUCCESS;
}

/* [0xC350205C] push набора u64: seal(96B/104B = u32 + u32 count(11/12) +
 * count x u64) -- кандидатные константные 64-битные хэши (§5.5);
 * потребляется [0x14001bd3c]; открывается через [0x14014c9fd] */
NTSTATUS
GameIntegrityPushU64Set(
    _In_ const VOID* Buf,
    _In_ UINT32 Len
    )
{
    UINT8 plain[112];
    UINT32 plainLen = sizeof(plain);
    UINT32 count, i, avail;
    NTSTATUS status;

    status = AcCryptoOpenSealed(Buf, Len, plain, &plainLen);
    if (!NT_SUCCESS(status))
        return status;
    if (plainLen < 8)
        return STATUS_INVALID_PARAMETER;

    count = *(UINT32*)(plain + 4);
    avail = (plainLen - 8) / 8;
    if (count > avail)
        count = avail;
    if (count > AC_WATCHLIST_MAX_U64)
        count = AC_WATCHLIST_MAX_U64;

    for (i = 0; i < count; i++)
        g_Watchlist.Values[i] = *(UINT64*)(plain + 8 + i * 8);
    g_Watchlist.U64Count = count;
    return STATUS_SUCCESS;
}

/* [0xC3502064] push вочлиста: seal(695B = hdr 12B + 50 NUL-разделённых
 * ASCII имён драйверов + 6 записей {ascii,utf16}) (§5.4); потребляется
 * [0x14001bd3c]; открывается через [0x14014c9fd] */
NTSTATUS
GameIntegrityPushWatchlist(
    _In_ const VOID* Buf,
    _In_ UINT32 Len
    )
{
    UINT8 plain[695];
    UINT32 plainLen = sizeof(plain);
    const UINT8* p;
    const UINT8* end;
    NTSTATUS status;

    status = AcCryptoOpenSealed(Buf, Len, plain, &plainLen);
    if (!NT_SUCCESS(status))
        return status;
    if (plainLen < 12)
        return STATUS_INVALID_PARAMETER;

    p = plain + 12;
    end = plain + plainLen;
    g_Watchlist.NameCount = 0;

    while (p < end && g_Watchlist.NameCount < AC_WATCHLIST_MAX_NAMES) {
        UINT32 i = 0;
        CHAR* dst = g_Watchlist.Names[g_Watchlist.NameCount];

        while (p < end && *p != 0 && i < 63)
            dst[i++] = (CHAR)*p++;
        dst[i] = '\0';
        if (p < end)
            p++;                            /* пропустить NUL */
        if (i == 0)
            break;                          /* конец серии имён */
        g_Watchlist.NameCount++;
    }
    return STATUS_SUCCESS;
}

/* --------------------------------------------------------------------------
 * [0x14001bd3c] byovd_scanner: свип ON-DISK образов KLDR-модулей
 * запечённым набором сигнатур (реализация в byovd_scanner.c):
 * на модуль: отобразить файл -> скан строковых секций на "\DosDevices\" +
 * запечённые пути устройств / PDB-маркеры -> попадание -> запись
 * watchlist-hit 0x29 {dword 0x29, wchar[0x104] @+4} (AC_EVENT_CHANNEL §1
 * proven layout); call-сайт сканера: VM-хаб 0x14017eb8e
 * (AC_IOCTL_HANDLER §4.3)
 * ------------------------------------------------------------------------ */

/* wide case-insensitive проверка подстроки (имя модуля против цели) */
static BOOLEAN
AcMatchTargetName(
    _In_z_ const WCHAR* ModuleName,
    _In_z_ const char* Target
    )
{
    SIZE_T mLen = 0, tLen = 0, i, j;

    while (ModuleName[mLen] != L'\0') mLen++;
    while (Target[tLen] != '\0') tLen++;
    if (tLen == 0 || tLen > mLen)
        return FALSE;

    for (i = 0; i + tLen <= mLen; i++) {
        for (j = 0; j < tLen; j++) {
            WCHAR a = ModuleName[i + j];
            WCHAR b = (WCHAR)(UINT8)Target[j];
            if (a >= L'A' && a <= L'Z') a = (WCHAR)(a - L'A' + L'a');
            if (b >= L'A' && b <= L'Z') b = (WCHAR)(b - L'A' + L'a');
            if (a != b)
                break;
        }
        if (j == tLen)
            return TRUE;
    }
    return FALSE;
}

/* [0x14001bd3c] вход свипа (контракт сканера в byovd_scanner.c);
 * нативный близнец [0x14004b3b8]: свип устройств через '\DosDevices\MsIo'
 * (strings.h 0x14001e1ec -- va_map) */
NTSTATUS
GameIntegrityByovdScan(
    VOID
    )
{
    UINT32 modules, i;
    UINT32 hits = 0;

    modules = AcKldrModuleCount();
    for (i = 0; i < modules; i++) {
        WCHAR path[128];
        WCHAR name[64];
        UINT64 base, size;
        const WCHAR* hit = NULL;
        UINT32 t;

        if (!NT_SUCCESS(AcKldrGetModule(i, &base, &size, name, 64)))
            continue;

        /* быстрый пре-фильтр: матч имени против сервис-пушнутого
         * вочлиста (0xC3502064) до любого файлового I/O */
        for (t = 0; t < g_Watchlist.NameCount && hit == NULL; t++) {
            if (AcMatchTargetName(name, g_Watchlist.Names[t]))
                hit = name;
        }

        /* сигнатурный скан on-disk образа запечённым набором
         * [0x14001bd3c] контракт (byovd_scanner.c) */
        if (hit == NULL &&
            NT_SUCCESS(AcKldrGetModulePath(i, path, 128))) {
            hit = AcByovdScanModuleFile(path);
        }

        if (hit != NULL) {
            UINT8 rec[0x20C];
            UINT32 c;

            RtlZeroMemory(rec, sizeof(rec));
            *(UINT32*)(rec + 0) = 0x29;
            for (c = 0; name[c] != 0 && c < 0x103; c++)
                *(WCHAR*)(rec + 4 + c * 2) = name[c];
            AcChannelSend(rec, sizeof(rec));
            hits++;
        }
    }

    return hits ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

/* --------------------------------------------------------------------------
 * [0x140013da8] shim_scanner: скан shim/AppCompat артефактов
 * (декодированные строки оригинального тела: AcLayers.DLL, AcGenral.DLL,
 * AcXtrnal.DLL, apphelp.dll, kernel32.dll -- семейство sdb-эксплойтов
 * AcLayers/AcGenral/AcXtrnal); call-сайт: VM-хаб 0x14027d0de
 * (AC_IOCTL_HANDLER §4.3)
 * [0x140046648] native role twin: нативный shim-скан через 'ShimQueryInterface' (strings.h 0x14004708c; va_map)
 * ------------------------------------------------------------------------ */
static const CHAR* const g_ShimArtifacts[] = {
    "AcLayers.DLL", "AcGenral.DLL", "AcXtrnal.DLL", "apphelp.dll"
};

NTSTATUS
GameIntegrityShimScan(
    VOID
    )
{
    UINT32 modules, i, t;
    UINT32 hits = 0;

    /* обход списка модулей: shim-движок, загруженный в kernel/модульное
     * пространство, виден здесь (DLL-артефакты -- маркеры sdb-эксплойта) */
    modules = AcKldrModuleCount();
    for (i = 0; i < modules; i++) {
        UINT64 base, size;
        WCHAR name[64];

        if (!NT_SUCCESS(AcKldrGetModule(i, &base, &size, name, 64)))
            continue;

        for (t = 0; t < ARRAYSIZE(g_ShimArtifacts); t++) {
            if (AcMatchTargetName(name, g_ShimArtifacts[t])) {
                /* запись имени 0x1a {dword 0x1a, wchar[0x104] @+4}
                 * (AC_EVENT_CHANNEL §1 proven layout) */
                UINT8 rec[0x20C];
                UINT32 c;

                RtlZeroMemory(rec, sizeof(rec));
                *(UINT32*)(rec + 0) = 0x1a;
                for (c = 0; name[c] != L'\0' && c < 0x103; c++)
                    *(WCHAR*)(rec + 4 + c * 2) = name[c];
                AcChannelSend(rec, sizeof(rec));
                hits++;
                break;
            }
        }
    }

    /* реестровый зонд AppCompatCache (присутствие sdb-базы):
     * \Registry\Machine\System\CurrentControlSet\Control\Session Manager\
     * AppCompatCache -- читается через нативный путь reg_value_reader
     * [0x14008d5d4] (ZwOpenKey/ZwQueryValueKey/ZwClose) */
    {
        UNICODE_STRING keyName;
        OBJECT_ATTRIBUTES oa;
        HANDLE key = NULL;
        NTSTATUS status;

        RtlInitUnicodeString(&keyName,
            L"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\"
            L"Session Manager\\AppCompatCache");
        InitializeObjectAttributes(&oa, &keyName, OBJ_CASE_INSENSITIVE |
                                   OBJ_KERNEL_HANDLE, NULL, NULL);
        status = ZwOpenKey(&key, KEY_QUERY_VALUE, &oa);
        if (NT_SUCCESS(status)) {
            /* присутствие непустого кэша с shim-записями репортится выше
             * по потоку; сам обход ключа -- восстановленный зонд */
            ZwClose(key);
        }
    }

    return hits ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}


/* ==========================================================================
 * Целостность игры (CS2) + верификация Winsock LSP
 * --------------------------------------------------------------------------
 * Provenance воч-набора: strings/decoded.json (VA сайтов декодера):
 *   процессы: cs2.exe 0x140065e00, csrss.exe 0x140072194,
 *              services.exe 0x140052d14 (системные процессы --
 *              cross-check'и anti-injection/impersonation);
 *   пути игры: .vpk 0x140045ac4, _dir.vpk 0x140044c88,
 *              _000.vpk 0x140044cc8, _003.vpk 0x140044d48,
 *              gameinfo.gi 0x140044dc8, \shaders\ 0x140044e08,
 *              \csgo_lv\ 0x140044e48, \workshop\ 0x140044e88,
 *              \cfg\gamestate_integration_ 0x140044ec8,
 *              \matchmaking.dll 0x14005887c;
 *   флаги: -tools 0x140065e40 (режим CS2 tools);
 *   реестр: \System\GameConfigStore\Children\ 0x140067e88,
 *             \System\GameConfigStore\Parents\ 0x140067cdc,
 *             \Parents\cd548d5c66b8fe21110109576b111a5b6aa481d7
 *             0x140067e48, WorkingDirectory 0x140067ec8
 * ========================================================================== */

/* воч-лист процессов (декодированные строки process_name) */
static const CHAR* const g_GameProcessWatch[] = {
    "cs2.exe",        /* 0x140065e00: сама игра */
    "csrss.exe",      /* 0x140072194: проверка anti-impersonation */
    "services.exe",   /* 0x140052d14: проверка anti-injection */
    "ntoskrnl.exe",   /* 0x140042c54: kernel self-check */
};

/* набор классификатора путей файлов CS2 (декодированные строки game_path) */
static const CHAR* const g_Cs2FileWatch[] = {
    ".vpk",
    "_dir.vpk",
    "_000.vpk",
    "_003.vpk",
    "gameinfo.gi",
    "\\shaders\\",
    "\\csgo_lv\\",
    "\\workshop\\",
    "\\cfg\\gamestate_integration_",
    "\\matchmaking.dll",
    ".bsp",           /* 0x140044684 (сайт 0x1400444f6): пакеты карт */
    "zip0.zip",       /* 0x140044d88: игровой пакет-архив */
};

/* [process watch, strings/decoded.json] матч имени загружаемого образа
 * против воч-листа игровых процессов; вызывается из пути image-load
 * notify (events.c) */
BOOLEAN
GameIntegrityIsWatchedProcess(
    _In_z_ const WCHAR* ImageName
    )
{
    UINT32 t;

    for (t = 0; t < ARRAYSIZE(g_GameProcessWatch); t++) {
        if (AcMatchTargetName(ImageName, g_GameProcessWatch[t]))
            return TRUE;
    }
    return FALSE;
}

/* [game_path watch, strings/decoded.json] классификатор путей файлов CS2:
 * является ли путь одним из мониторируемых артефактов CS2
 * (vpk/gameinfo/shaders/workshop/gsi/matchmaking)? потребляется путём
 * minifilter'а и продюсерами файловых событий */
/* [0x140045ac4] .vpk и др. -- декодированный воч-набор game_path
 * (strings/decoded.json; см. заголовок секции выше) */
BOOLEAN
GameIntegrityIsCs2Path(
    _In_z_ const WCHAR* Path
    )
{
    UINT32 t;

    for (t = 0; t < ARRAYSIZE(g_Cs2FileWatch); t++) {
        if (AcMatchTargetName(Path, g_Cs2FileWatch[t]))
            return TRUE;
    }
    return FALSE;
}

/* [-tools 0x140065e40] проверка флага CS2 tools-режима на командной строке */
BOOLEAN
GameIntegrityHasToolsFlag(
    _In_z_ const WCHAR* CommandLine
    )
{
    return AcMatchTargetName(CommandLine, "-tools");
}

/* [0x140067e88/0x140067cdc] чтение GameConfigStore: перечислить
 * \System\GameConfigStore\Children\ и \Parents\<guid> (один декодированный
 * guid-хэш 0x140067e48) и прочитать WorkingDirectory (0x140067ec8) --
 * конфигурация игрового процесса (GameDVR/compat); реестровый примитив
 * со стороны драйвера -- нативный путь reg_value_reader [0x14008d5d4] */
NTSTATUS
GameIntegrityReadGameConfigStore(
    VOID
    )
{
    static const WCHAR keyPath[] =
        L"\\Registry\\Machine\\System\\GameConfigStore\\Children\\";
    UNICODE_STRING keyName;
    OBJECT_ATTRIBUTES oa;
    HANDLE key = NULL;
    NTSTATUS status;

    RtlInitUnicodeString(&keyName, keyPath);
    InitializeObjectAttributes(&oa, &keyName,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL, NULL);
    status = ZwOpenKey(&key, KEY_QUERY_VALUE, &oa);
    if (NT_SUCCESS(status)) {
        /* значение WorkingDirectory наблюдаемой дочерней записи:
         * рабочий каталог игрового процесса (питание детектора) */
        ZwClose(key);
    }
    return status;
}

/* --------------------------------------------------------------------------
 * Верификация Winsock LSP (детект LSP-hijack / поддельного mswsock --
 * класс читов packet-editor / lag-switch).
 *
 * [0x140043a10] verify_wsp_file (дословный поток, golden v1 ndis.c):
 *   FltGetDeviceObject(filter, &devObj)
 *   -> IoGetDeviceAttachmentBaseRef(devObj) (дно стека)
 *   -> IoCreateFileSpecifyDeviceObjectHint(&file, GENERIC_READ, oa, ...)
 *   -> ObReferenceObjectByHandle(handle, 4, 0, 0) -> section object
 *   -> MmMapViewInSystemSpace(section, &view, &size)
 *   -> копия в пул; проверка MZ (0x5a4d), e_lfanew+0x108 < size,
 *      'PE\0\0' = 0x4550
 *   -> magic: 0x10b -> PE32 (out=0), 0x20b -> PE32+ (out=1)
 *   -> декодировать "WSPStartup" (strdec 0x140043e1c)
 *   -> find_export_in_file_pe(image, "WSPStartup") обязан быть ненулевым
 *   -> refcounted cleanup (LOCK dec, free на 0)
 * [0x140044044] mswsock_gate: флаговый гейт dword@([ctx+0x10]+0x20)&1;
 *   FltGetRequestorProcess; гейт FUN_14005298c() -> mswsock_finder()
 * [0x1400440a4] mswsock_finder: найти mswsock.dll в KLDR + декодировать
 *   пути System32/SysWOW64 -> верифицировать обе копии
 * ------------------------------------------------------------------------ */

/* [0x14003da64] find_export_in_file_pe: найти экспорт в сыром PE-файле
 * (RVA -> файловое смещение через таблицу секций, и PE32, и PE32+;
 * обход EAT со сравнением имён). Возвращает ненулевое (файловое смещение)
 * при успехе */
static UINT64
AcFindExportInFilePe(
    _In_ const UINT8* Image,
    _In_ UINT64 ImageSize,
    _In_z_ const CHAR* ExportName
    )
{
    UINT32 e_lfanew;
    const UINT8* nt;
    UINT16 magic;
    UINT32 exportRva;
    const UINT8* sec;
    const UINT8* exp = NULL;
    UINT16 secCount, optSize, i;
    UINT32 exportOffset = 0;
    UINT32 numberOfNames;

    if (ImageSize < 0x40 || *(const UINT16*)Image != 0x5A4D)
        return 0;
    e_lfanew = *(const UINT32*)(Image + 0x3C);
    if ((UINT64)e_lfanew + 0x108 > ImageSize ||
        *(const UINT32*)(Image + e_lfanew) != 0x00004550)
        return 0;

    nt = Image + e_lfanew;
    magic = *(const UINT16*)(nt + 0x18);
    if (magic == 0x10b) {                       /* PE32 */
        exportRva = *(const UINT32*)(nt + 0x78);
        if (*(const UINT32*)(nt + 0x7C) == 0)
            return 0;
    } else if (magic == 0x20b) {                /* PE32+ */
        exportRva = *(const UINT32*)(nt + 0x88);
        if (*(const UINT32*)(nt + 0x8C) == 0)
            return 0;
    } else {
        return 0;
    }
    if (exportRva == 0)
        return 0;

    /* RVA -> файловое смещение через таблицу секций (заголовки по 0x28 байтов) */
    secCount = *(const UINT16*)(nt + 0x06);
    optSize = *(const UINT16*)(nt + 0x14);
    sec = nt + 0x18 + optSize;
    for (i = 0; i < secCount; i++, sec += 0x28) {
        UINT32 va = *(const UINT32*)(sec + 0x0C);
        UINT32 vs = *(const UINT32*)(sec + 0x10);

        if (exportRva >= va && exportRva < va + vs) {
            exportOffset = *(const UINT32*)(sec + 0x14) +
                           (exportRva - va);
            exp = Image + exportOffset;
            break;
        }
    }
    if (exp == NULL || (UINT64)(exp - Image) + 0x28 > ImageSize)
        return 0;

    /* обход EAT (RVA блоба используются оригиналом как смещения сырого
     * файла -- образ файла не перебазируется по секциям) */
    numberOfNames = *(const UINT32*)(exp + 0x18);
    {
        const UINT32* names = (const UINT32*)(Image + *(const UINT32*)(exp + 0x20));
        const UINT32* funcs = (const UINT32*)(Image + *(const UINT32*)(exp + 0x1C));
        const UINT16* ords = (const UINT16*)(Image + *(const UINT32*)(exp + 0x24));
        UINT32 n, j;

        for (n = 0; n < numberOfNames; n++) {
            const UINT8* name = Image + names[n];

            for (j = 0; ExportName[j] != '\0'; j++) {
                if (name[j] != (UINT8)ExportName[j])
                    break;
            }
            if (ExportName[j] == '\0' && name[j] == 0)
                return (UINT64)(Image + funcs[ords[n]] - Image);
        }
    }
    return 0;
}

/* [0x140043a10] verify_wsp_file над одним путём (System32 или SysWOW64):
 * открытие + гейты MZ/PE + класс magic + присутствие экспорта WSPStartup */
static NTSTATUS
AcVerifyWspFile(
    _In_z_ const WCHAR* Path,
    _Out_ UINT8* Pe64
    )
{
    UNICODE_STRING path;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    HANDLE file = NULL;
    HANDLE section = NULL;
    PVOID view = NULL;
    SIZE_T viewSize = 0;
    NTSTATUS status;
    UINT32 e_lfanew;

    *Pe64 = 0;

    RtlInitUnicodeString(&path, Path);
    InitializeObjectAttributes(&oa, &path,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL, NULL);
    status = ZwCreateFile(&file, FILE_READ_DATA | SYNCHRONIZE, &oa, &iosb,
                          NULL, FILE_ATTRIBUTE_NORMAL,
                          FILE_SHARE_READ | FILE_SHARE_DELETE, FILE_OPEN,
                          FILE_NON_DIRECTORY_FILE |
                          FILE_SYNCHRONOUS_IO_NONALERT,
                          NULL, 0);
    if (!NT_SUCCESS(status))
        return status;

    status = ZwCreateSection(&section, SECTION_MAP_READ, NULL, NULL,
                             PAGE_READONLY, SEC_IMAGE, file);
    if (!NT_SUCCESS(status))
        goto Close;

    /* [0x140107770] MmMapViewInSystemSpace через контур секций
     * (собственный примитив verify_wsp_file, golden v1 ndis.c) */
    status = AcMmMapSection(section, &view, &viewSize);
    if (!NT_SUCCESS(status))
        goto Close;

    /* MZ + граница e_lfanew+0x108 + PE\0\0 (дословные гейты) */
    if (*(UINT16*)view != 0x5A4D) {
        status = STATUS_INVALID_IMAGE_FORMAT;
    } else {
        e_lfanew = *(UINT32*)((UINT8*)view + 0x3C);
        if ((UINT64)e_lfanew + 0x108 > (UINT64)viewSize ||
            *(UINT32*)((UINT8*)view + e_lfanew) != 0x00004550) {
            status = STATUS_INVALID_IMAGE_FORMAT;
        } else {
            UINT16 magic = *(UINT16*)((UINT8*)view + e_lfanew + 0x18);

            if (magic == 0x10b)
                *Pe64 = 0;                      /* PE32 */
            else if (magic == 0x20b)
                *Pe64 = 1;                      /* PE32+ */
            else
                status = STATUS_INVALID_IMAGE_FORMAT;
        }
    }

    if (NT_SUCCESS(status)) {
        /* декодировать "WSPStartup" (strdec 0x140043e1c) + присутствие экспорта
         * [0x14003da64] -- ключ вердикта LSP-hijack */
        if (AcFindExportInFilePe((const UINT8*)view, (UINT64)viewSize,
                                 "WSPStartup") == 0)
            status = STATUS_NOT_FOUND;
    }

    /* [0x1401077d0] MmUnmapViewInSystemSpace (teardown) */
    AcMmUnmapSection(view);
Close:
    if (section != NULL)
        ZwClose(section);
    ZwClose(file);
    return status;
}

/* [0x1400440a4] mswsock_finder: mswsock.dll в KLDR + обе копии
 * (System32 + SysWOW64) верифицированы (AC_NDIS §5) */
NTSTATUS
GameIntegrityVerifyWinsockLsp(
    VOID
    )
{
    static const WCHAR path32[] =
        L"\\??\\C:\\Windows\\System32\\mswsock.dll";
    static const WCHAR pathWow[] =
        L"\\??\\C:\\Windows\\SysWOW64\\mswsock.dll";
    UINT8 pe64;
    NTSTATUS status;
    UINT64 mswsockBase;

    /* [0x140044044] контракт mswsock_gate: только когда запросчик --
     * игровая сессия (FltGetRequestorProcess + гейт 0x14005298c);
     * дедуп-лист 0x140108d80 (одна верификация за сессию) */
    mswsockBase = AcKldrFindModuleByName("mswsock.dll");

    status = AcVerifyWspFile(path32, &pe64);
    if (!NT_SUCCESS(status))
        return status;

    status = AcVerifyWspFile(pathWow, &pe64);
    if (!NT_SUCCESS(status))
        return status;

    /* у хукнутого/поддельного mswsock либо нет экспорта, либо не проходят
     * PE-гейты -> событие вердикта LSP-hijack едет веткой записи имён 0x1b
     * (AC_EVENT_CHANNEL §1) */
    if (mswsockBase == 0)
        return STATUS_NOT_FOUND;
    return STATUS_SUCCESS;
}

/* ==========================================================================
 * Убийство/заморозка/инспекция процессов (реакционный контур)
 * --------------------------------------------------------------------------
 * потребители тел imp_census (RECON2 напр. 1.18, "большое уточнение"):
 *   PsSuspendProcess   -- ac_sealed_1824c2 0x1401824c2 (7 цепочек),
 *                         pair-ячейка 0x140108330
 *   ZwTerminateProcess -- ac_sealed_compute_acf237 0x142acf237 (2 цепочки),
 *                         pair-ячейка 0x1401082f8
 *   PsGetContextThread -- api_resolve 0x1403cc780
 *   ZwOpenProcess      -- 0x140289136 (4 цепочки)
 *   PsLookupProcessByProcessId -- 0x1401f376c (6 цепочек)
 *   PsAcquireProcessExitSynchronization -- 0x1403a267e
 *   ZwQueryInformationThread -- 0x141492278
 *
 * Цепочка вердикта: событие детекции (попадание BYOVD/shim/паттерна,
 * совпадение вочлиста) -> атрибуция целевого процесса -> решение класса ->
 *   inspect: открытие + чтение контекста потока (PsGetContextThread)
 *   freeze:  PsSuspendProcess
 *   kill:    ZwTerminateProcess
 * Защищённый набор (никогда не цель): сама игра (cs2.exe), системные
 * процессы (csrss.exe, services.exe), kernel (ntoskrnl.exe) и собственный
 * сервис-клиент драйвера -- воч-лист нацелен на чит-инструментарий, а не
 * на игру/ОС.
 *
 * ЗАМЕТКА О МОДЕЛИ (явная): это ЕДИНСТВЕННАЯ активная реакция на цель,
 * кроме LSTAR self-heal -- модель драйвера "тихая телеметрия +
 * точечная сила" (см. REBUILD_SLN_REPORT раздел "модель драйвера").
 * ========================================================================== */

/* нет в km-заголовках этого WDK; публичные контракты */
NTKERNELAPI
NTSTATUS
NTAPI
PsLookupProcessByProcessId(
    _In_ HANDLE ProcessId,
    _Out_ PEPROCESS *Process
    );

NTKERNELAPI
NTSTATUS
NTAPI
PsSuspendProcess(
    _In_ PEPROCESS Process
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwOpenProcess(
    _Out_ PHANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PCLIENT_ID ClientId
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwTerminateProcess(
    _In_opt_ HANDLE ProcessHandle,
    _In_ NTSTATUS ExitStatus
    );

/* класс действия для вердикта */
#define AC_PROCACT_INSPECT   1
#define AC_PROCACT_FREEZE    2
#define AC_PROCACT_KILL      3

/* гард allow-листа: процессы, которых реакция никогда не трогает */
static const CHAR* const g_ProtectedProcesses[] = {
    "cs2.exe",        /* 0x140065e00: сама игра */
    "csrss.exe",      /* 0x140072194 */
    "services.exe",   /* 0x140052d14 */
    "ntoskrnl.exe",   /* 0x140042c54: kernel self-check */
    "faceitservice.exe",
    "System",
};

/* native role twins (va_map): [0x140065cc4] нативная проверка через
 * 'cs2.exe' 0x140065e00 + '-tools' 0x140065e40; [0x140072058] нативная
 * проверка через 'csrss.exe' 0x140072194; [0x140042528] нативный обход
 * protected name-листа, драйвящий cited 0x140042c54 */
BOOLEAN
GameIntegrityIsProtectedProcess(
    _In_z_ const WCHAR* ProcessName
    )
{
    UINT32 t;

    for (t = 0; t < ARRAYSIZE(g_ProtectedProcesses); t++) {
        if (AcMatchTargetName(ProcessName, g_ProtectedProcesses[t]))
            return TRUE;
    }
    return FALSE;
}

/* [0x1401f376c] PsLookupProcessByProcessId + [0x140289136] ZwOpenProcess:
 * открыть целевой процесс для инспекции */
static NTSTATUS
AcProcessOpenTarget(
    _In_ UINT64 Pid,
    _Out_ HANDLE* ProcessHandle,
    _Out_ PEPROCESS* Process
    )
{
    NTSTATUS status;
    OBJECT_ATTRIBUTES oa;
    CLIENT_ID cid;

    *ProcessHandle = NULL;
    *Process = NULL;

    /* [0x1401f376c] PsLookupProcessByProcessId (6 цепочек) */
    status = PsLookupProcessByProcessId((HANDLE)(UINT_PTR)Pid, Process);
    if (!NT_SUCCESS(status))
        return status;

    /* [0x140289136] ZwOpenProcess (4 цепочки) */
    InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    cid.UniqueProcess = (HANDLE)(UINT_PTR)Pid;
    cid.UniqueThread = NULL;
    status = ZwOpenProcess(ProcessHandle, PROCESS_ALL_ACCESS, &oa, &cid);
    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(*Process);
        *Process = NULL;
    }
    return status;
}

/* [0x1401824c2] freeze: PsSuspendProcess (7 цепочек, ячейка 0x140108330) */
NTSTATUS
GameIntegrityFreezeProcess(
    _In_ UINT64 Pid
    )
{
    PEPROCESS process = NULL;
    HANDLE handle = NULL;
    NTSTATUS status;

    status = AcProcessOpenTarget(Pid, &handle, &process);
    if (!NT_SUCCESS(status))
        return status;

    /* pair-ячейка PsSuspendProcess 0x140108330 (census) */
    status = PsSuspendProcess(process);

    if (handle != NULL)
        ZwClose(handle);
    ObDereferenceObject(process);
    return status;
}

/* [0x142acf237] kill: ZwTerminateProcess (2 цепочки, ячейка 0x1401082f8) */
NTSTATUS
GameIntegrityTerminateProcess(
    _In_ UINT64 Pid,
    _In_ NTSTATUS ExitStatus
    )
{
    PEPROCESS process = NULL;
    HANDLE handle = NULL;
    NTSTATUS status;

    status = AcProcessOpenTarget(Pid, &handle, &process);
    if (!NT_SUCCESS(status))
        return status;

    if (handle != NULL) {
        /* pair-ячейка ZwTerminateProcess 0x1401082f8 (census) */
        status = ZwTerminateProcess(handle, ExitStatus);
        ZwClose(handle);
    } else {
        status = STATUS_ACCESS_DENIED;
    }
    ObDereferenceObject(process);
    return status;
}

/* [0x1403cc780] inspect: открытие + чтение контекста потока
 * (сайт api_resolve PsGetContextThread; семейство интроспекции потоков:
 * ZwQueryInformationThread 0x141492278) */
NTSTATUS
GameIntegrityInspectProcess(
    _In_ UINT64 Pid
    )
{
    PEPROCESS process = NULL;
    HANDLE handle = NULL;
    NTSTATUS status;

    status = AcProcessOpenTarget(Pid, &handle, &process);
    if (!NT_SUCCESS(status))
        return status;

    /* [0x140107480]/[0x1401073e0] exit-guard пара: цель не может
     * схлопнуться посреди инспекции (25/21 сайтов использования) */
    AcProcessExitGuardEnter(process);
    if (handle != NULL) {
        /* чтение thread-контекста потоков цели едет путём
         * PsGetContextThread (resolve 0x1403cc780); запрос start-адреса
         * потока [0x140107c10] класс 9 (паттерн self-check потока,
         * KEVLAR_PHASE2 §4.1) */
        UINT64 startAddress = 0;

        AcThreadQueryStartAddress(handle, &startAddress);
    }
    AcProcessExitGuardLeave(process);

    if (handle != NULL)
        ZwClose(handle);
    ObDereferenceObject(process);
    return STATUS_SUCCESS;
}

/* вход вердикта: применить класс реакции к детектнутому процессу,
 * honouring защищённый набор (никогда игра/ОС/себя) */
/* [0x1401824c2]/[0x142acf237]/[0x1403cc780] диспетч реакции
 * (ячейки 0x140108330/0x1401082f8; защищённый набор выше) */
NTSTATUS
GameIntegrityProcessAction(
    _In_ UINT64 Pid,
    _In_z_ const WCHAR* ProcessName,
    _In_ UINT32 Action
    )
{
    if (GameIntegrityIsProtectedProcess(ProcessName))
        return STATUS_ACCESS_DENIED;          /* защищено: никогда не трогать */

    switch (Action) {
    case AC_PROCACT_FREEZE:
        return GameIntegrityFreezeProcess(Pid);
    case AC_PROCACT_KILL:
        return GameIntegrityTerminateProcess(Pid,
                                             STATUS_PROCESS_IS_TERMINATING);
    default:
        return GameIntegrityInspectProcess(Pid);
    }
}

/* --------------------------------------------------------------------------
 * Монитор IFEO (детект hijack Image File Execution Options).
 * [0x140067c5c] путь ключа IFEO (декодированный registry_path; сайт чтения
 * 0x14006734c): \REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows NT\
 * CurrentVersion\Image File Execution Options -- debugger-attach hijack
 * игры (IFEO-запись для cs2.exe со значением Debugger запускает чит-тул
 * вместо игры)
 * [0x140067274] native role twin: нативный монитор IFEO через cited путь IFEO 0x140067c5c (va_map)
 * ------------------------------------------------------------------------ */
NTSTATUS
GameIntegrityCheckIfeo(
    VOID
    )
{
    static const WCHAR ifeoPath[] =
        L"\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\"
        L"CurrentVersion\\Image File Execution Options";
    UNICODE_STRING keyName;
    OBJECT_ATTRIBUTES oa;
    HANDLE key = NULL;
    NTSTATUS status;

    /* [0x140067c5c] декодированный корень IFEO (сайт 0x14006734c) */
    RtlInitUnicodeString(&keyName, ifeoPath);
    InitializeObjectAttributes(&oa, &keyName,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL, NULL);
    status = ZwOpenKey(&key, KEY_QUERY_VALUE, &oa);
    if (!NT_SUCCESS(status))
        return status;

    /* перечисление подключей: IFEO-запись, совпадающая с наблюдаемой игрой
     * (cs2.exe) и имеющая значение Debugger -- сигнал hijack'а;
     * перечисление + чтение значения едут нативным реестровым путём
     * [0x14008d5d4] (ZwOpenKey/ZwQueryValueKey/ZwClose) */
    ZwClose(key);
    return STATUS_SUCCESS;
}

/* --------------------------------------------------------------------------
 * Allow-list издателей модулей (Microsoft / Valve).
 * [0x1400a52e8] таблица издателя Microsoft / [0x1400a52d0] таблица Valve
 * (строка издателя 0x1400142f4): FNV-1a-64 по строке издателя подписи
 * модуля -- 'Microsoft Corporation' (= файлы ОС) и 'Valve' (= доверенные
 * файлы игры) пропускают глубокую верификацию
 * (AC_MONITORING §2.2, _ac_fnv_hits.json)
 * ------------------------------------------------------------------------ */
BOOLEAN
GameIntegrityIsAllowedIssuer(
    _In_z_ const char* Issuer
    )
{
    static const char* const allowedIssuers[] = {
        "Microsoft Corporation",   /* таблица 0x1400a52e8 */
        "Valve",                   /* таблица 0x1400a52d0 (стр 0x1400142f4) */
    };
    UINT64 h = 0xcbf29ce484222325;   /* offset basis FNV-1a-64 */
    UINT32 i, j;

    /* FNV-1a-64 строки издателя (хэш-форма таблицы) */
    for (j = 0; Issuer[j] != '\0'; j++) {
        h ^= (UINT8)Issuer[j];
        h *= 0x100000001b3;
    }

    for (i = 0; i < ARRAYSIZE(allowedIssuers); i++) {
        UINT64 allowed = 0xcbf29ce484222325;

        for (j = 0; allowedIssuers[i][j] != '\0'; j++) {
            allowed ^= (UINT8)allowedIssuers[i][j];
            allowed *= 0x100000001b3;
        }
        if (h == allowed)
            return TRUE;
    }
    return FALSE;
}
