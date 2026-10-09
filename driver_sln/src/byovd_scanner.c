/* ==========================================================================
 * byovd_scanner.c -- статический BYOVD сканер сигнатур (запечённый набор целей)
 * --------------------------------------------------------------------------
 * [0x14001bd3c] byovd_scanner (0x21ca байт, 74 XOR-декодированные строки):
 * дословно восстановленный контракт из тела golden v1:
 *   вход = отображённый образ модуля с диска (сырой PE-файл);
 *   найти строковую секцию (".rdata" через роль section-finder'а
 *   [0x14000137c]; "PAGE" тоже пробуется);
 *   требуется, чтобы секция содержала UTF-16 префикс "\DosDevices\";
 *   затем wide-memmem каждого запечённого пути устройства внутри неё;
 *   любое попадание -> хвост вердикта (проверка куки + return; вызывающий
 *   производит запись 0x29);
 *   спецправило: попадание "\DosDevices\PhyMem" дополнительно пробует
 *   "\Device\PhysicalMemory".
 * Набор целей = полная таблица декодированных строк оригинального тела
 * (заголовок golden v1 byovd.c: 66 путей устройств + 11 PDB + маркеры секций;
 * COVERAGE_INVENTORY §9.1.1/§9.1.2).
 * ========================================================================== */
#include <ntddk.h>

#include "provenance.h"
#include "byovd_scanner.h"
#include "physmem.h"
#include "kldr.h"

/* --------------------------------------------------------------------------
 * [0x14009c394] роль ac_memmem: поиск подстроки (3 VM call-сайта:
 * CHAIN 163/164/512, AC_IOCTL_HANDLER §4.3); здесь в wide-форме
 * (сканер сравнивает UTF-16 паттерны по образу файла)
 * ------------------------------------------------------------------------ */
static const UINT8*
AcMemmem(
    _In_reads_bytes_(HayLen) const UINT8* Haystack,
    _In_ UINT64 HayLen,
    _In_reads_bytes_(NeedleLen) const UINT8* Needle,
    _In_ UINT64 NeedleLen
    )
{
    UINT64 i, j;

    if (NeedleLen == 0 || NeedleLen > HayLen)
        return NULL;
    for (i = 0; i + NeedleLen <= HayLen; i++) {
        for (j = 0; j < NeedleLen; j++) {
            if (Haystack[i + j] != Needle[j])
                break;
        }
        if (j == NeedleLen)
            return Haystack + i;
    }
    return NULL;
}

/* --------------------------------------------------------------------------
 * [0x14000137c] роль section-finder'а: имя секции -> заголовок секции
 * (сканер так разрешает ".rdata" и "PAGE")
 * PE32/PE32+ layout: NT-заголовки по e_lfanew; секции сразу после
 * optional header (SizeOfOptionalHeader @+0x14, count @+0x06), каждый
 * IMAGE_SECTION_HEADER 0x28 байт, name[8] по +0x00
 * [0x14006a2b8] native role twin: нативный обход PE-секций, близнец роли cited 0x14000137c (va_map)
 * ------------------------------------------------------------------------ */
static const UINT8*
AcByovdFindSection(
    _In_ const UINT8* Image,
    _In_ UINT64 ImageSize,
    _In_z_ const CHAR* Name
    )
{
    UINT32 e_lfanew;
    const UINT8* nt;
    const UINT8* sec;
    UINT16 count, optSize, i;

    if (ImageSize < 0x40 || *(const UINT16*)Image != 0x5A4D)
        return NULL;
    e_lfanew = *(const UINT32*)(Image + 0x3C);
    if ((UINT64)e_lfanew + 0x108 > ImageSize ||
        *(const UINT32*)(Image + e_lfanew) != 0x00004550)
        return NULL;

    nt = Image + e_lfanew;
    count = *(const UINT16*)(nt + 0x06);
    optSize = *(const UINT16*)(nt + 0x14);
    sec = nt + 0x18 + optSize;

    for (i = 0; i < count; i++, sec += 0x28) {
        UINT32 j;
        BOOLEAN eq = TRUE;

        if ((UINT64)(sec - Image) + 0x28 > ImageSize)
            return NULL;
        for (j = 0; j < 8 && Name[j] != '\0'; j++) {
            if (sec[j] != (UINT8)Name[j]) {
                eq = FALSE;
                break;
            }
        }
        if (eq && (Name[j] == '\0' || sec[j] == 0))
            return sec;
    }
    return NULL;
}

/* --------------------------------------------------------------------------
 * Запечённый набор целей (дословные декодированные строки byovd_scanner
 * @0x14001bd3c, golden v1 byovd.c; каждая XOR-декодировалась inline
 * оригиналом).
 * Форма: полные UTF-16 пути устройств, сканируются ac_memmem по строковой
 * секции. Префикс "\DosDevices\" -- обязательный гейт.
 * ------------------------------------------------------------------------ */
static const WCHAR* const g_ByovdBakedPaths[] = {
    L"\\DosDevices\\GVCIDrv64",
    L"\\DosDevices\\BS_HWMIO",
    L"\\DosDevices\\BS_RCIO",
    L"\\DosDevices\\WinRing0",
    L"\\DosDevices\\ALSysIO",
    L"\\DosDevices\\NTIOLib",
    L"\\DosDevices\\Global\\CPUZ",
    L"\\DosDevices\\MsIo",
    L"\\DosDevices\\WinIo",
    L"\\DosDevices\\PhyMem",
    L"\\DosDevices\\Asusgio",
    L"\\DosDevices\\AsUpdateiot",
    L"\\DosDevices\\{E8F2FF20-6AF7-4914-9398-CE2132FE170F}",
    L"\\DosDevices\\AIDA64Driver",
    L"\\DosDevices\\AIDA64Drivers",
    L"\\DosDevices\\ASUSBIOSIO",
    L"\\DosDevices\\AppShopDrv",
    L"\\DosDevices\\AppShopDrvT",
    L"\\DosDevices\\AsInsHelp",
    L"\\DosDevices\\AsUpdateio",
    L"\\DosDevices\\AsrAutoChkUpdDrv",
    L"\\DosDevices\\AsrCDDrv",
    L"\\DosDevices\\AsrDrv",
    L"\\DosDevices\\AsrIbDrv",
    L"\\DosDevices\\AsrOcDrv",
    L"\\DosDevices\\AsrRapidStartDrv",
    L"\\DosDevices\\AsrSmartConnectDrv",
    L"\\DosDevices\\AxtuDrv",
    L"\\DosDevices\\BiosToolCommonDriver",
    L"\\DosDevices\\DELLWALDOS",
    L"\\DosDevices\\EneIo",
    L"\\DosDevices\\EneTechIo",
    L"\\DosDevices\\EnergyDriver",
    L"\\DosDevices\\EnergyDriver(",
    L"\\DosDevices\\GLCKIo",
    L"\\DosDevices\\LenovoDiagnosticsDriver",
    L"\\DosDevices\\NPR0_1_0_22",
    L"\\DosDevices\\PMXDRV",
    L"\\DosDevices\\SONiXDDR_0_0_0_1",
    L"\\DosDevices\\SignalIo",
    L"\\DosDevices\\SpeedFan",
    L"\\DosDevices\\TdeIo",
    L"\\DosDevices\\WinHwDriver",
    L"\\DosDevices\\WinMsrDev",
    L"\\DosDevices\\bsitf",
    L"\\DosDevices\\cpqsysio",
    L"\\DosDevices\\hpvision",
    L"\\DosDevices\\inpoutx64",
    L"\\DosDevices\\iocbios2",
    L"\\DosDevices\\rtkio",
    /* формы \Device\ того же прохода сканера */
    L"\\Device\\PhysicalMemory",
    L"\\Device\\AMDRyzenMasterDriver",
    L"\\Device\\AODDriver",
    L"\\Device\\GIOV2",
    L"\\Device\\SysDrv3S",
    L"\\Device\\WinRing0",
    L"\\Device\\genericdrv",
    L"\\Device\\Dokan",
    L"\\Device\\WinFsp",
    /* устройства virtual-HID / эмуляции ввода (класс aim) */
    L"\\Device\\LGHUBDevice\\LGHUBCompatibleVirtualDevice",
    L"\\Device\\LogiDevice\\LogiCompatibleVirtualDevice",
    /* разные декодированные маркеры тела */
    L"DIRECTIOLPT",
    L"GIGABYTEPASSWORDD",
};

/* набор PDB-сигнатур (11 входов pdb_path; сканируются внутри файла
 * так же -- отладочные артефакты уязвимых драйверов) */
static const CHAR* const g_ByovdPdbMarkers[] = {
    "RzCommon.pdb",              /* Razer Synapse */
    "DirectIo64.pdb",
    "\\gdrv.pdb",                /* GIGABYTE */
    "\\mst.pdb",
    "\\CmUpx.pdb",
    "RTKVHD64.pdb",
    "\\ATSZIO.pdb",
    "\\ATSZIO_x64.pdb",
    "CorsairLLAccess64.pdb",
    "\\TcnPeripheral64.pdb",
    "\\sysdiag-x64.pdb",
};

/* --------------------------------------------------------------------------
 * [0x14001bd3c] контракт тела сканера:
 *   sec = find(".rdata") [также пробуется "PAGE"];
 *   if !memmem(sec_range, "\DosDevices\") -> нет вердикта;
 *   для каждого запечённого пути: if memmem(range, path) -> HIT (хвост вердикта);
 *   спец: попадание "\DosDevices\PhyMem" -> дополнительно пробует
 *   "\Device\PhysicalMemory".
 * Возвращает совпавший паттерн (или NULL).
 * ------------------------------------------------------------------------ */
const WCHAR*
AcByovdScanImage(
    _In_ const UINT8* Image,
    _In_ UINT64 ImageSize
    )
{
    static const WCHAR prefix[] = L"\\DosDevices\\";
    const UINT8* sec;
    const UINT8* range;
    UINT64 rangeLen;
    UINT32 i;

    /* строковые секции файла модуля (основная ".rdata"; оригинал
     * также разрешает "PAGE") */
    sec = AcByovdFindSection(Image, ImageSize, ".rdata");
    if (sec == NULL)
        sec = AcByovdFindSection(Image, ImageSize, ".data");
    if (sec == NULL)
        sec = AcByovdFindSection(Image, ImageSize, "PAGE");
    if (sec == NULL)
        return NULL;

    /* VirtualAddress секции @+0x0C, VirtualSize @+0x08;
     * [0x140107990]/[0x1401079b0] гард диапазона + safe-read
     * (контур physmem) */
    range = Image + *(const UINT32*)(sec + 0x0C);
    rangeLen = *(const UINT32*)(sec + 0x08);
    if ((UINT64)(range - Image) + rangeLen > ImageSize ||
        !AcMmIsKernelAddress((const VOID*)range))
        return NULL;

    /* гейт: секция обязана содержать UTF-16 префикс */
    if (AcMemmem(range, rangeLen, (const UINT8*)prefix,
                 sizeof(prefix) - sizeof(WCHAR)) == NULL)
        return NULL;

    /* запечённые пути устройств */
    for (i = 0; i < ARRAYSIZE(g_ByovdBakedPaths); i++) {
        const WCHAR* name = g_ByovdBakedPaths[i];
        UINT32 nameChars = 0;

        while (name[nameChars] != L'\0')
            nameChars++;

        if (AcMemmem(range, rangeLen, (const UINT8*)name,
                     nameChars * sizeof(WCHAR)) != NULL) {
            /* спецправило оригинала: попадание PhyMem также пробует
             * форму \Device\PhysicalMemory (обе в запечённой таблице,
             * так что простой цикл покрывает её; порядок сохранён) */
            return name;
        }
    }

    /* PDB-маркеры (ASCII) */
    for (i = 0; i < ARRAYSIZE(g_ByovdPdbMarkers); i++) {
        const CHAR* pdb = g_ByovdPdbMarkers[i];
        UINT32 pdbLen = 0;

        while (pdb[pdbLen] != '\0')
            pdbLen++;
        if (AcMemmem(range, rangeLen, (const UINT8*)pdb, pdbLen) != NULL)
            return L"PDB";                /* попадание PDB-класса */
    }

    return NULL;
}

/* --------------------------------------------------------------------------
 * Обёртка сканирования файла модуля: отобразить образ с диска для
 * KLDR-модуля и прогнать по нему сканер.
 * Примитивы отображения -- доказанный набор драйвера (verify-потоки
 * используют ZwCreateFile #143 + семейство ZwCreateSection/ZwMapViewOfSection
 * #103/#104/#116, AC_API_PAIRS; verify_wsp_file использует вариант
 * IoCreateFileSpecify-DeviceObjectHint для пути фильтра)
 * ------------------------------------------------------------------------ */
/* [0x14001bd3c] обёртка-вызывающий сканера по файлу модуля
 * (VM hub call-сайт оригинала: 0x14017eb8e) */
const WCHAR*
AcByovdScanModuleFile(
    _In_z_ const WCHAR* ModulePath
    )
{
    UNICODE_STRING path;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    HANDLE file = NULL;
    HANDLE section = NULL;
    PVOID view = NULL;
    SIZE_T viewSize = 0;
    const WCHAR* hit = NULL;
    NTSTATUS status;

    RtlInitUnicodeString(&path, ModulePath);
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
        return NULL;

    status = ZwCreateSection(&section, SECTION_MAP_READ, NULL, NULL,
                             PAGE_READONLY, SEC_IMAGE, file);
    if (NT_SUCCESS(status)) {
        status = ZwMapViewOfSection(section, ZwCurrentProcess(), &view,
                                    0, 0, NULL, &viewSize, ViewShare,
                                    0, PAGE_READONLY);
        if (NT_SUCCESS(status)) {
            hit = AcByovdScanImage((const UINT8*)view, (UINT64)viewSize);
            ZwUnmapViewOfSection(ZwCurrentProcess(), view);
        }
        ZwClose(section);
    }
    ZwClose(file);
    return hit;
}

/* --------------------------------------------------------------------------
 * Обход object-directory по watch-именам BYOVD-устройств.
 * [0x14000f9c0] нативное тело (corpus native/native_00.c FUN_14000f9c0),
 * восстановлено проходом native-role из va_map (_research_tmp/va_map):
 * декодировать "\\GLOBAL??" (strings.h [0x14000fd24]), открыть каталог
 * (пара [0x1401079a0] ZwOpenDirectoryObject), сослаться по хэндлу
 * (пара [0x140107840] ObReferenceObjectByHandle, DIRECTORY_ALL_ACCESS
 * 0xf000f) и обойти 0x25 сырых хэш-бакетов под pushlock'ом каталога
 * +0x128 (пары [0x1401079e0]/[0x1401078b0]) -- здесь отрендерено через
 * документированное перечисление ZwQueryDirectoryObject, потолок 0x25
 * сохранён как наблюдавшееся число бакетов. На каждый вход имя
 * получается (пара [0x140107960] ObQueryNameString, двухфазный хелпер
 * [0x14000c4c8]) и префикс-матчится case-insensitive (пара [0x1401079d0]
 * RtlPrefixUnicodeString); при попадании симлинк открывается
 * (пара [0x140107a10] ZwOpenSymbolicLinkObject SYMBOLIC_LINK_QUERY) и
 * его цель читается (пара [0x140107930] ZwQuerySymbolicLinkObject) в
 * запись 0x30 байт (пара [0x140107500] ExAllocatePool NonPagedPoolNx,
 * буфер имени 0x208 байт), добавляемую в ResultsHead -- оригинал
 * подпирает вставку int29 fastfail'ом на порчу списка. Teardown:
 * ZwClose [0x140107560].
 * ------------------------------------------------------------------------ */

/* ZwOpenDirectoryObject/ZwQueryDirectoryObject не объявлены в km-заголовках
 * этого WDK (та же конвенция, что в physmem.c) */
NTSYSAPI
NTSTATUS
NTAPI
ZwOpenDirectoryObject(
    _Out_ PHANDLE DirectoryHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwQueryDirectoryObject(
    _In_ HANDLE DirectoryHandle,
    _Out_writes_bytes_opt_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _In_ BOOLEAN ReturnSingleEntry,
    _In_ BOOLEAN RestartScan,
    _Inout_ PULONG Context,
    _Out_opt_ PULONG ReturnLength
    );

typedef struct _AC_ODIR_ENTRY {
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
} AC_ODIR_ENTRY, *PAC_ODIR_ENTRY;

/* layout записи по оригинальному телу (0x30 байт, обнуляется при alloc) */
typedef struct _AC_BYOVD_ODIR_RECORD {
    LIST_ENTRY Link;          /* +0x00 (вставка подперта int29
                               * fastfail'ом на порчу списка в оригинале) */
    UNICODE_STRING Target;    /* +0x10; буфер 0x208 байт хранится по +0x18 */
    UINT64 Reserved20;        /* +0x20 */
    UINT64 Reserved28;        /* +0x28 */
} AC_BYOVD_ODIR_RECORD, *PAC_BYOVD_ODIR_RECORD;

#define AC_BYOVD_ODIR_NAME_SIZE   0x208
#define AC_BYOVD_ODIR_MAX_ENTRIES 0x25

NTSTATUS
AcByovdScanObjectDirectory(
    _In_ PCUNICODE_STRING TargetName,
    _Inout_ PLIST_ENTRY ResultsHead
    )
{
    /* декодированный "\GLOBAL??" (strings.h [0x14000fd24]) */
    UNICODE_STRING globalRoot = RTL_CONSTANT_STRING(L"\\GLOBAL??");
    OBJECT_ATTRIBUTES oa;
    OBJECT_ATTRIBUTES entryOa;
    HANDLE dir;
    HANDLE link;
    NTSTATUS status;
    ULONG context;
    ULONG scanned;
    AC_ODIR_ENTRY entry;
    PAC_BYOVD_ODIR_RECORD rec;

    InitializeObjectAttributes(&oa, &globalRoot,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL, NULL);
    dir = NULL;
    status = ZwOpenDirectoryObject(&dir,
                                   DIRECTORY_QUERY | DIRECTORY_TRAVERSE,
                                   &oa);
    if (!NT_SUCCESS(status))
        return status;

    context = 0;
    for (scanned = 0; scanned < AC_BYOVD_ODIR_MAX_ENTRIES; scanned++) {
        status = ZwQueryDirectoryObject(dir, &entry, sizeof(entry),
                                        TRUE, FALSE, &context, NULL);
        if (!NT_SUCCESS(status))
            break;                      /* STATUS_NO_MORE_ENTRIES */
        if (entry.Name.Buffer == NULL)
            continue;
        /* case-insensitive префикс-гейт (пара [0x1401079d0]) */
        if (!RtlPrefixUnicodeString(TargetName, &entry.Name, TRUE))
            continue;

        /* попадание: разрешить цель симлинка */
        InitializeObjectAttributes(&entryOa, &entry.Name,
                                   OBJ_CASE_INSENSITIVE |
                                   OBJ_KERNEL_HANDLE, dir, NULL);
        link = NULL;
        status = ZwOpenSymbolicLinkObject(&link, SYMBOLIC_LINK_QUERY,
                                          &entryOa);
        if (!NT_SUCCESS(status))
            continue;

        rec = (PAC_BYOVD_ODIR_RECORD)AcPoolAllocZeroed(
                  sizeof(AC_BYOVD_ODIR_RECORD));
        if (rec != NULL) {
            rec->Target.Buffer = (PWCH)AcPoolAllocZeroed(
                                     AC_BYOVD_ODIR_NAME_SIZE);
            if (rec->Target.Buffer != NULL) {
                rec->Target.Length = AC_BYOVD_ODIR_NAME_SIZE;
                rec->Target.MaximumLength = AC_BYOVD_ODIR_NAME_SIZE;
                status = ZwQuerySymbolicLinkObject(link, &rec->Target,
                                                   NULL);
                if (!NT_SUCCESS(status))
                    rec->Target.Length = 0;
            }
            /* оригинал подпирает эту вставку проверкой int29
             * FAST_FAIL_CORRUPT_LIST_ENTRY */
            InsertTailList(ResultsHead, &rec->Link);
        }
        ZwClose(link);
    }

    ZwClose(dir);
    return STATUS_SUCCESS;
}
