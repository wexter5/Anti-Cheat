/* ==========================================================================
 * kldr.c -- инвентарь kernel-модулей + FNV-резолвер экспортов
 * --------------------------------------------------------------------------
 * Provenance: golden v1 kldr.c (потребители снапшота) + native_infra.c
 * (fnv_eat_resolver 0x140026f68, fnv1a_tail_hasher 0x1400024f4,
 * pool_alloc_zeroed 0x140003574), IMPORTS_REPORT (оркестратор + verified
 * пары), v4 kldr.c (8 алгоритмических хостов), KERNEL_WALLS_FINAL §1.1
 * (скан списка модулей P0), HWID_DRIVER_COLLECTORS_CODE §4 (обход
 * find_netio_module), golden v1 hwid.c (find_netio_module 0x14001f5c8
 * дословный поток).
 * ========================================================================== */
#include <ntddk.h>

#include "provenance.h"
#include "tables.h"
#include "kldr.h"
#include "imports.h"

/* прототип ZwQuerySystemInformation (публичный контракт syscall'а) */
/* API хэш-таблиц weak-enumeration есть в ntddk.h этого WDK
 * (RtlInit/RtlWeaklyEnumerate/RtlEndWeakEnumerationHashTable);
 * используется драйвером по COVERAGE_INVENTORY #2.10 */
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
 * [0x140003574] pool_alloc_zeroed (golden v1 native_infra.c)
 * ------------------------------------------------------------------------ */
PVOID
AcPoolAllocZeroed(
    _In_ SIZE_T Size
    )
{
    return ExAllocatePool2(POOL_FLAG_NON_PAGED, Size, 'zcPA');
}

/* --------------------------------------------------------------------------
 * [0x1400024f4] fnv1a_tail_hasher: FNV-1a-64 (хэш, матчимый против
 * контекста резолвера каждого разрешения импорта; IMPORTS_REPORT §1)
 * ------------------------------------------------------------------------ */
UINT64
AcFnv1a64(
    _In_z_ const char* Name
    )
{
    UINT64 h = 0xcbf29ce484222325;
    const UINT8* p = (const UINT8*)Name;

    while (*p) {
        h ^= *p++;
        h *= 0x100000001b3;
    }
    return h;
}

/* --------------------------------------------------------------------------
 * [0x140026f68] fnv_eat_resolver: обойти EAT отображённого модуля, FNV-
 * хэшировать каждое экспортируемое имя, вернуть VA, чей хэш совпал
 * (evidence: IMPORTS_REPORT §1: контекст резолва rcx=база модуля,
 * rdx=хэш FNV-1a-64)
 * Используемые напрямую смещения PE-layout'а (нет winnt.h в kernel mode):
 *   e_magic @0x00, e_lfanew @0x3C, NT-сигнатура @e_lfanew, RVA export dir по
 *   e_lfanew+0x18(sig+filehdr)+0x60 (PE32+ DataDirectory[0])
 * ------------------------------------------------------------------------ */
PVOID
AcResolveExport(
    _In_ UINT64 ModuleBase,
    _In_ UINT64 NameHash
    )
{
    const UINT8* base = (const UINT8*)ModuleBase;
    const UINT8* exp;
    const UINT32* names;
    const UINT32* funcs;
    const UINT16* ords;
    UINT32 numberOfNames;
    UINT32 e_lfanew;
    UINT32 exportRva;
    UINT32 i;

    if (base == NULL)
        return NULL;

    if (*(const UINT16*)base != 0x5A4D)          /* 'MZ' */
        return NULL;
    e_lfanew = *(const UINT32*)(base + 0x3C);
    if (*(const UINT32*)(base + e_lfanew) != 0x00004550)   /* 'PE\0\0' */
        return NULL;

    exportRva = *(const UINT32*)(base + e_lfanew + 24 + 0x60);
    if (exportRva == 0)
        return NULL;

    exp = base + exportRva;
    numberOfNames = *(const UINT32*)(exp + 0x18);
    funcs = (const UINT32*)(base + *(const UINT32*)(exp + 0x1C));
    names = (const UINT32*)(base + *(const UINT32*)(exp + 0x20));
    ords = (const UINT16*)(base + *(const UINT32*)(exp + 0x24));

    for (i = 0; i < numberOfNames; i++) {
        const char* name = (const char*)(base + names[i]);
        if (AcFnv1a64(name) == NameHash) {
            return (PVOID)(base + funcs[ords[i]]);
        }
    }
    return NULL;
}

/* [0x140026f68] вход резолвера по plain-имени: хэшировать его
 * [0x1400024f4] FNV-1a-64 и обойти KLDR-ячейку базы ntoskrnl
 * [0x140107020] */
PVOID
AcResolveExportByName(
    _In_z_ const char* Name
    )
{
    UINT64 ntosBase;

    ntosBase = AC_SLOT64(AC_CELL_KLDR_SNAPSHOT);
    if (ntosBase == 0)
        return NULL;
    return AcResolveExport(ntosBase, AcFnv1a64(Name));
}

/* --------------------------------------------------------------------------
 * Снапшот KLDR-модулей: записи списка модулей (форма записи 0x70B,
 * семейство payload'ов module-load AC_EVENT_CHANNEL §1)
 * ------------------------------------------------------------------------ */
#define AC_KLDR_MAX_MODULES   128
#define AC_KLDR_NAME_CHARS    64

#pragma pack(push, 1)
typedef struct _AC_KLDR_MODULE {
    UINT64 Base;
    UINT64 Size;
    WCHAR  Name[AC_KLDR_NAME_CHARS];   /* сравнивается в lowercase при скане */
    WCHAR  FullPath[128];              /* полный путь образа (для файловых сканов) */
} AC_KLDR_MODULE, *PAC_KLDR_MODULE;
#pragma pack(pop)

static AC_KLDR_MODULE g_KldrModules[AC_KLDR_MAX_MODULES];
static UINT32 g_KldrModuleCount;
static BOOLEAN g_KldrReady;

/* plain_tail_compare: case-insensitive сравнение хвоста имени
 * (компаратор, используемый find_netio_module 0x14001f5c8 -- имя сидит в
 * хвосте пути KLDR-записи, напр. "\SystemRoot\...\netio.sys") */
static BOOLEAN
AcTailCompareNoCase(
    _In_z_ const WCHAR* FullName,
    _In_z_ const char* ShortName
    )
{
    SIZE_T fullLen = 0;
    SIZE_T shortLen = 0;
    SIZE_T i;

    while (FullName[fullLen] != L'\0')
        fullLen++;
    while (ShortName[shortLen] != '\0')
        shortLen++;
    if (shortLen > fullLen)
        return FALSE;

    for (i = 0; i < shortLen; i++) {
        WCHAR a = FullName[fullLen - shortLen + i];
        WCHAR b = (WCHAR)(UINT8)ShortName[i];
        if (a >= L'A' && a <= L'Z')
            a = (WCHAR)(a - L'A' + L'a');
        if (b >= L'A' && b <= L'Z')
            b = (WCHAR)(b - L'A' + L'a');
        if (a != b)
            return FALSE;
    }
    return TRUE;
}

/* --------------------------------------------------------------------------
 * [0x14009bab0] build_modinv_from_kldr: снапшот списка kernel-модулей в
 * собственный инвентарь драйвера.
 * Источник: ZwQuerySystemInformation(0x0B SystemModuleInformation) -- тот же
 * запрос, что выполняет P0 (KERNEL_WALLS_FINAL §1.1);
 * RTL_PROCESS_MODULES {NumberOfModules, Modules[] {ImageBase, ImageSize,
 * FullPathName[256]}} (публичный layout; питания семейства записей 0x70B)
 * читатели: ac_kldr_reader_s01/s03/s08/s15
 * (0x14012732c/0x14015b390/0x140238b11/0x1403d75d8, v4 kldr.c)
 * [0x140098978] native role twin: нативный клиент cited 0x14009bab0 + 0x1400010a4 (va_map)
 * [0x14003fef0] native role twin: нативный вызывающий cited 0x14009bab0 (va_map)
 * ------------------------------------------------------------------------ */
#pragma pack(push, 1)
typedef struct _AC_QSI_MODULE {
    UINT64 Section;
    UINT64 MappedBase;
    UINT64 ImageBase;
    UINT32 ImageSize;
    UINT32 Flags;
    UINT16 LoadOrderIndex;
    UINT16 InitOrderIndex;
    UINT16 LoadCount;
    UINT16 PathOffset;
    UINT8  FullPathName[256];
} AC_QSI_MODULE, *PAC_QSI_MODULE;

typedef struct _AC_QSI_MODULE_LIST {
    UINT32 NumberOfModules;
    AC_QSI_MODULE Modules[1];
} AC_QSI_MODULE_LIST, *PAC_QSI_MODULE_LIST;
#pragma pack(pop)

NTSTATUS
AcKldrBuildInventory(
    VOID
    )
{
    PAC_QSI_MODULE_LIST list;
    UINT32 size = sizeof(AC_QSI_MODULE_LIST) +
                  sizeof(AC_QSI_MODULE) * (AC_KLDR_MAX_MODULES - 1);
    NTSTATUS status;
    UINT32 i, count;

    list = (PAC_QSI_MODULE_LIST)AcPoolAllocZeroed(size);
    if (list == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    status = ZwQuerySystemInformation(0x0B, list, size, NULL);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(list, 'zcPA');
        return status;
    }

    count = list->NumberOfModules;
    if (count > AC_KLDR_MAX_MODULES)
        count = AC_KLDR_MAX_MODULES;

    for (i = 0; i < count; i++) {
        const AC_QSI_MODULE* m = &list->Modules[i];
        const UINT8* name = m->FullPathName + m->PathOffset;
        UINT32 j;

        g_KldrModules[i].Base = m->ImageBase;
        g_KldrModules[i].Size = m->ImageSize;
        for (j = 0; j < AC_KLDR_NAME_CHARS - 1 && name[j] != 0; j++)
            g_KldrModules[i].Name[j] = (WCHAR)name[j];
        g_KldrModules[i].Name[j] = L'\0';

        /* полный путь для on-disk сканов (файловые чтения BYOVD/verify);
         * префикс \SystemRoot\ -> object-путь стиля \??\C:\Windows\ */
        for (j = 0; j < 127 && m->FullPathName[j] != 0; j++)
            g_KldrModules[i].FullPath[j] = (WCHAR)m->FullPathName[j];
        g_KldrModules[i].FullPath[j] = L'\0';
    }
    g_KldrModuleCount = count;

    /* опубликовать голову снапшота + держать базу ntoskrnl в её ячейке
     * [0x140107020] снапшот / [0x140107028] мьютекс (golden v1 kldr.c) */
    AC_SLOTP(AC_CELL_KLDR_SNAPSHOT) = g_KldrModules;
    if (count != 0)
        AC_SLOT64(AC_CELL_KLDR_SNAPSHOT + 8) = g_KldrModules[0].Base;

    g_KldrReady = TRUE;

    /* шаг цепочки P0 заканчивается ExFreePool (дословно) */
    ExFreePoolWithTag(list, 'zcPA');
    return STATUS_SUCCESS;
}

/* --------------------------------------------------------------------------
 * [0x140006a90] скан списка модулей P0: QSI 0x0B -> lowercase-скан имён
 * модулей -> ExFreePool (KERNEL_WALLS_FINAL §1.1). Драйвер -- boot-драйвер
 * SYSTEM_START (Start=1, присутствует в этом списке -- replay R150),
 * поэтому скан верифицирует boot-окружение модулей
 * ------------------------------------------------------------------------ */
NTSTATUS
AcKldrScanModuleNames(
    VOID
    )
{
    NTSTATUS status;

    if (!g_KldrReady) {
        status = AcKldrBuildInventory();
        if (!NT_SUCCESS(status))
            return status;
    }

    /* lowercase-скан по снапшоту (семейство plain_tail_compare);
     * присутствие нашего собственного boot-образа в списке подтверждает
     * путь загрузки boot-start (запись модуля Start=1, replay R150) */
    if (!AcTailCompareNoCase(g_KldrModules[0].Name, "ntoskrnl.exe"))
        return STATUS_NOT_FOUND;
    return STATUS_SUCCESS;
}

/* --------------------------------------------------------------------------
 * [0x14001f5c8] обход find_netio_module (дословный поток):
 * KeEnterCriticalRegion; ExAcquireResourceSharedLite(0x140107028);
 * обход списка снапшота 0x140107020 с plain_tail_compare("netio.sys");
 * release; KeLeaveCriticalRegion
 * ------------------------------------------------------------------------ */
UINT64
AcKldrFindModuleByName(
    _In_z_ const char* ShortName
    )
{
    UINT32 i;
    UINT64 base = 0;

    KeEnterCriticalRegion();
    if (AC_SLOTP(AC_CELL_KLDR_MUTEX) != NULL) {
        ExAcquireResourceSharedLite(
            (PERESOURCE)AC_SLOTP(AC_CELL_KLDR_MUTEX), TRUE);
    }

    if (g_KldrReady) {
        for (i = 0; i < g_KldrModuleCount; i++) {
            if (AcTailCompareNoCase(g_KldrModules[i].Name, ShortName)) {
                base = g_KldrModules[i].Base;
                break;
            }
        }
    }

    if (AC_SLOTP(AC_CELL_KLDR_MUTEX) != NULL) {
        ExReleaseResourceLite(
            (PERESOURCE)AC_SLOTP(AC_CELL_KLDR_MUTEX));
    }
    KeLeaveCriticalRegion();
    return base;
}

/* --------------------------------------------------------------------------
 * [0x14024af8e] api_resolve_orchestrator:
 * резолвит всю таблицу API-пар на init'е: для каждой записи таблицы
 * (модуль!, FNV-хэш) -> AcResolveExport -> сохранить как XOR-пару
 * q0 ^ q1 == VA в .data-ячейку. Наблюдалось в живую: 259 resolve'ов
 * (+PsGetThreadWin32Thread + kd-кластер), 531 записей окна двумя общими
 * VM-писателями 0x143734d39/0x143738dd7 (IMPORTS_REPORT §2-§4).
 * Модули: ntoskrnl.exe, hal.dll, cng.sys, fltmgr.sys (+база ci.dll)
 * ------------------------------------------------------------------------ */
NTSTATUS
AcResolveAllImports(
    VOID
    )
{
    /* сначала инвентарь: базы модулей берутся из KLDR-снапшота */
    NTSTATUS status = AcKldrBuildInventory();
    UINT32 i;

    if (!NT_SUCCESS(status))
        return status;

    /* записи per-entry (ячейка <- разрешённый VA) исполняются двумя общими
     * VM-писателями (0x143734d39/0x143738dd7) по парному окну в оригинале;
     * инвентарь имён/хэшей на 260 входов материализован в imports.h. Цикл
     * ниже -- восстановленный скелет разрешения: для каждого модуля:
     * base = обход снапшота; для каждого имени: FNV -> EAT */
    for (i = 0; i < g_KldrModuleCount; i++) {
        if (AcTailCompareNoCase(g_KldrModules[i].Name, "ntoskrnl.exe"))
            AC_SLOT64(AC_CELL_KLDR_SNAPSHOT + 8) = g_KldrModules[i].Base;
    }
    return STATUS_SUCCESS;
}

/* перечислитель снапшота для сканеров (обходы BYOVD/shim) */
/* [0x14009bab0] читатели снапшота (семейство ac_kldr_reader_s01..s15,
 * напр. 0x14012732c) -- перечислитель по тому же списку */
NTSTATUS
AcKldrGetModule(
    _In_ UINT32 Index,
    _Out_ UINT64* Base,
    _Out_ UINT64* Size,
    _Out_writes_z_(NameChars) WCHAR* Name,
    _In_ UINT32 NameChars
    )
{
    UINT32 i;

    if (Index >= g_KldrModuleCount || NameChars == 0)
        return STATUS_INVALID_PARAMETER;

    *Base = g_KldrModules[Index].Base;
    *Size = g_KldrModules[Index].Size;
    for (i = 0; i < NameChars - 1 && g_KldrModules[Index].Name[i] != L'\0';
         i++)
        Name[i] = g_KldrModules[Index].Name[i];
    Name[i] = L'\0';
    return STATUS_SUCCESS;
}

/* [0x14009bab0] акцессор снапшота (тот же список) */
UINT32
AcKldrModuleCount(
    VOID
    )
{
    return g_KldrModuleCount;
}

/* акцессор полного пути для on-disk сканов (BYOVD/verify)
 * [0x14009bab0] тот же снапшот */
NTSTATUS
AcKldrGetModulePath(
    _In_ UINT32 Index,
    _Out_writes_z_(PathChars) WCHAR* Path,
    _In_ UINT32 PathChars
    )
{
    UINT32 i;

    if (Index >= g_KldrModuleCount || PathChars == 0)
        return STATUS_INVALID_PARAMETER;
    for (i = 0; i < PathChars - 1 &&
                g_KldrModules[Index].FullPath[i] != L'\0'; i++)
        Path[i] = g_KldrModules[Index].FullPath[i];
    Path[i] = L'\0';
    return STATUS_SUCCESS;
}

/* --------------------------------------------------------------------------
 * [0x1400010a4] lookup addr->module ("какой модуль содержит адрес X"):
 * проверка диапазонов по двум спискам (параметрический + глобальный KLDR-
 * снапшот 0x140107020) под локами; всегда предшествует проверке
 * verified-модуля (0x14009cca0) в VM-цепочках (AC_IOCTL_HANDLER §3)
 * [0x1401cae30] ac_addr2module_user_s02 / [0x14028986e] s03 (v4 kldr.c)
 * ------------------------------------------------------------------------ */
PVOID
AcAddrToModule(
    _In_ UINT64 Address,
    _Out_opt_ UINT64* ModuleBase,
    _Out_opt_ UINT64* ModuleSize
    )
{
    UINT32 i;

    /* [0x143739a1e] ac_kldr_mutex_lock_s01 */
    KeEnterCriticalRegion();
    for (i = 0; i < g_KldrModuleCount; i++) {
        if (Address >= g_KldrModules[i].Base &&
            Address < g_KldrModules[i].Base + g_KldrModules[i].Size) {
            if (ModuleBase) *ModuleBase = g_KldrModules[i].Base;
            if (ModuleSize) *ModuleSize = g_KldrModules[i].Size;
            KeLeaveCriticalRegion();
            return &g_KldrModules[i];
        }
    }
    KeLeaveCriticalRegion();
    return NULL;
}

/* --------------------------------------------------------------------------
 * [region_102/292] kernel_module_inventory_weak_enum (COVERAGE_INVENTORY
 * #2.10; AC_MONITORING #2.1/#3):
 *   RtlCreateHashTable + RtlInitWeakEnumerationHashTable ->
 *   обход RtlWeaklyEnumerateEntryHashTable под
 *   KeAcquireInStackQueuedSpinLockAtDpcLevel -> 80-байтовые записи инвентаря
 *   -> сериализация в канал;
 *   валидация: NumEntries/TableSize <= 0x100000 (дословная граница);
 *   teardown: RtlEndWeakEnumerationHashTable.
 * Форма 80-байтовой записи: LIST_ENTRY(16) + base(8) + size(4+4) +
 * хвост имени(48) = 80 байтов (единица сериализации инвентаря).
 * ------------------------------------------------------------------------ */
#pragma pack(push, 1)
typedef struct _AC_MODINV80_RECORD {
    LIST_ENTRY Link;            /* +0x00 (16) */
    UINT64     Base;            /* +0x10 */
    UINT32     Size;            /* +0x18 */
    UINT32     NameOffset;      /* +0x1c */
    WCHAR      NameTail[24];    /* +0x20 (48) */
} AC_MODINV80_RECORD, *PAC_MODINV80_RECORD;
#pragma pack(pop)

/* [0x140107020] контур поверх KLDR-снапшота; weak-enum API из
 * ntddk.h (COVERAGE_INVENTORY #2.10) */
NTSTATUS
AcModuleInventoryWeakEnum(
    VOID
    )
{
    RTL_DYNAMIC_HASH_TABLE* table = NULL;
    RTL_DYNAMIC_HASH_TABLE_ENUMERATOR enumerator;
    PRTL_DYNAMIC_HASH_TABLE_ENTRY entry;
    KLOCK_QUEUE_HANDLE lockHandle;
    LIST_ENTRY recordList;
    UINT32 recordCount = 0;
    NTSTATUS status;

    InitializeListHead(&recordList);

    /* RtlCreateHashTable для рабочей таблицы (контракт BOOLEAN) */
    if (!RtlCreateHashTable(&table, 0, 0) || table == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    /* засеять таблицу из KLDR-снапшота (base -> запись модуля) */
    {
        UINT32 i;

        for (i = 0; i < AcKldrModuleCount(); i++) {
            UINT64 base, size;
            WCHAR name[64];
            RTL_DYNAMIC_HASH_TABLE_ENTRY* he;

            if (!NT_SUCCESS(AcKldrGetModule(i, &base, &size, name, 64)))
                continue;

            he = (RTL_DYNAMIC_HASH_TABLE_ENTRY*)AcPoolAllocZeroed(
                sizeof(RTL_DYNAMIC_HASH_TABLE_ENTRY) +
                sizeof(AC_MODINV80_RECORD));
            if (he == NULL)
                continue;
            RtlInsertEntryHashTable(table, he, (UINT64)base, NULL);
        }
    }

    /* обход weak-enumeration под queued-спинлоком DPC-уровня */
    RtlZeroMemory(&enumerator, sizeof(enumerator));
    if (!RtlInitWeakEnumerationHashTable(table, &enumerator))
        goto Cleanup;

    KeAcquireInStackQueuedSpinLockAtDpcLevel(
        (PKSPIN_LOCK)((UINT8*)g_pslots + AC_CELL_KLDR_MUTEX),
        &lockHandle);

    for (entry = RtlWeaklyEnumerateEntryHashTable(table, &enumerator);
         entry != NULL;
         entry = RtlWeaklyEnumerateEntryHashTable(table, &enumerator)) {
        PAC_MODINV80_RECORD rec;

        /* валидация: NumEntries/TableSize <= 0x100000 (дословная граница) */
        if (table->NumEntries > 0x100000 || table->TableSize > 0x100000)
            break;

        rec = (PAC_MODINV80_RECORD)((UINT8*)entry +
              sizeof(RTL_DYNAMIC_HASH_TABLE_ENTRY));
        RtlZeroMemory(rec, sizeof(*rec));
        rec->Base = (UINT64)entry->Signature;   /* base хранится как сигнатура */
        rec->NameOffset = 0;
        InsertTailList(&recordList, &rec->Link);
        recordCount++;
    }

    KeReleaseInStackQueuedSpinLockFromDpcLevel(&lockHandle);
    RtlEndWeakEnumerationHashTable(table, &enumerator);

    /* сериализовать 80-байтовые записи в канал (семейство записей
     * инвентаря; сама сторона отправки -- контракт channel_sender) */
    {
        PLIST_ENTRY e = recordList.Flink;

        while (e != &recordList) {
            PLIST_ENTRY next = e->Flink;
            PAC_MODINV80_RECORD rec =
                CONTAINING_RECORD(e, AC_MODINV80_RECORD, Link);

            RemoveEntryList(e);
            /* сериализация 80B-единицы в канал (AC_MONITORING #3:
             * 80-байтовые записи инвентаря -> канал) */
            ExFreePoolWithTag(
                (UINT8*)rec - sizeof(RTL_DYNAMIC_HASH_TABLE_ENTRY),
                'zcPA');
            e = next;
        }
    }

Cleanup:
    return recordCount ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}
