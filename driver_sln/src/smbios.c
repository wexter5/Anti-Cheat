/* ==========================================================================
 * smbios.c -- читатель SMBIOS: MmMapIoSpace -> скан "_SM_"/"_SM3_" -> checksum
 *             -> обход структур (типы 0/1/2/17) -> извлечение строк
 * --------------------------------------------------------------------------
 * Provenance пути (полный разбор трейса в _research_tmp/smbios_path/PATH.md):
 *   [0x14004b7a4] smbios_ram_collector: нативный trampoline в VM-хаб
 *     (evidence: тело golden v1 hwid.c -- вызов UNRECOVERED_JUMPTABLE)
 *   [0x1401835f8] smbios_hub: VM-хаб коллектора (evidence: golden v4
 *     kldr.c, цепочки B_055484; HWID_COLLECTION_PATH §RAM: "MmMapIoSpace
 *     (0xE0000,0x20000) in kernel, parse 0/1/2/17, memcmp anchor
 *     0x1400a43d0, MmUnmap pair 0x1401083f8")
 *   [0x140107ce8/0x140107ce0] import pair-ячейка MmMapIoSpace: адреса
 *     материализуются imul-обфускацией и читаются на исполняемом пути
 *     (evidence: PATH.md шаги 8-11, fb8 корпус ac_sealed_compute_7beadc)
 *   [0xF0000] кандидатный phys-адрес окна якоря: store доказан на трейсе
 *     D_07e99c (ac_sealed_2b71e4, обфускаированная константа 0xF0000 на
 *     0x1403f6c15) -- мёртв на zero-input пути (payload-selected)
 *   Именованные контуры (FULL_CHAIN_IRP_TO_HWID_C): SMBIOS_PARSER_LIFTED и
 *   RAM_EXTRACTORS_C -- поднятые подпути parse/extract этого файла
 *   (экстракторы t0 0x140216e50 / t1 0x1401ed25c / t2 0x1401ee2bc,
 *   читатели строк 0x1401edae4 / 0x1401db946);
 *   smbios_recover (agent-485m): вооружённый ран достигает call-сайта
 *     MmMapIoSpace 0x1402609a6; SMT-модель листа phys-адреса SAT с
 *     input-регистровыми листьями (sage_rcx_result.json) -- конкретный
 *     phys-адрес вооружается живым IOCTL payload'ом, структура полностью
 *     восстановлена.
 * ========================================================================== */
#include <ntddk.h>

#include "provenance.h"
#include "smbios.h"
#include "physmem.h"

/* [0xE0000] физическое окно BIOS/firmware, отображаемое коллектором
 * (evidence: HWID_COLLECTION_PATH §RAM: MmMapIoSpace(0xE0000, 0x20000);
 * покрывает и legacy-область якоря 0xF0000-0xFFFFF, и сегмент 0xE0000) */
#define AC_SMBIOS_PHYS_BASE   0x000E0000
#define AC_SMBIOS_PHYS_SIZE   0x00020000

/* [0xF0000] окно скана якоря (смещение внутри маппинга)
 * (evidence: PATH.md -- кандидат store 0xF0000, область якоря по спеке SMBIOS) */
#define AC_SMBIOS_SCAN_LO     (0x000F0000 - AC_SMBIOS_PHYS_BASE)
#define AC_SMBIOS_SCAN_HI     AC_SMBIOS_PHYS_SIZE

/* якорь EPS (SMBIOS 2.x "_SM_"; 3.x "_SM3_" сравнивается побайтово) */
#define AC_SMBIOS_ANCHOR2     0x5F4D535F   /* "_SM_" */

#pragma pack(push, 1)
/* Entry Point Structure SMBIOS 2.x (якорь "_SM_", len 0x1F) */
typedef struct _AC_SMBIOS_EPS {
    UINT32 Anchor;          /* "_SM_" */
    UINT8  Checksum;        /* суммируется в 0 по EpsLength */
    UINT8  EpsLength;       /* 0x1F */
    UINT8  MajorVersion;
    UINT8  MinorVersion;
    UINT16 MaxStructSize;
    UINT8  Revision;
    UINT8  Formatted[5];
    UINT8  IntAnchor[5];    /* "_DMI_" */
    UINT8  IntChecksum;
    UINT16 TableLength;
    UINT32 TableAddress;    /* физический адрес таблицы структур */
    UINT16 StructCount;
    UINT8  BcdRevision;
} AC_SMBIOS_EPS, *PAC_SMBIOS_EPS;

/* Entry Point Structure SMBIOS 3.x (якорь "_SM3_", len 0x18) */
typedef struct _AC_SMBIOS3_EPS {
    UINT8  Anchor[5];       /* "_SM3_" */
    UINT8  Checksum;
    UINT8  EpsLength;       /* 0x18 */
    UINT8  MajorVersion;
    UINT8  MinorVersion;
    UINT8  DocRev;
    UINT8  Revision;
    UINT8  Reserved;
    UINT32 TableMaxSize;
    UINT64 TableAddress;    /* физический */
} AC_SMBIOS3_EPS, *PAC_SMBIOS3_EPS;

/* заголовок структуры (formatted-секция начинается здесь) */
typedef struct _AC_SMBIOS_HEADER {
    UINT8 Type;
    UINT8 Length;           /* длина formatted-секции */
    UINT16 Handle;
} AC_SMBIOS_HEADER, *PAC_SMBIOS_HEADER;
#pragma pack(pop)

/* --------------------------------------------------------------------------
 * [0x1400a43d0] ac_memcmp -- именованный нативный примитив сравнения
 * памяти, используемый как компаратор якоря (evidence: HWID_COLLECTION_PATH
 * §RAM; семейство mem-примитивов crt_runtime.c)
 * ------------------------------------------------------------------------ */
static INT
AcMemCompare(
    _In_ const VOID* A,
    _In_ const VOID* B,
    _In_ SIZE_T Count
    )
{
    const UINT8* a = (const UINT8*)A;
    const UINT8* b = (const UINT8*)B;
    SIZE_T i;

    for (i = 0; i < Count; i++) {
        if (a[i] != b[i])
            return (INT)a[i] - (INT)b[i];
    }
    return 0;
}

/* checksum EPS: все байты entry point structure суммируются в 0
 * (evidence: спека SMBIOS; шаг верификации checksum -- часть
 * восстановленного пути хаба [0x1401835f8], PATH.md "scan -> checksum ->
 * parse") */
static BOOLEAN
AcSmbiosChecksum(
    _In_ const UINT8* Bytes,
    _In_ UINT32 Length
    )
{
    UINT8 sum = 0;
    UINT32 i;

    for (i = 0; i < Length; i++)
        sum = (UINT8)(sum + Bytes[i]);
    return (BOOLEAN)(sum == 0);
}

/* [0x1401835f8] скан якоря: обход окна 0xF0000 параграф за параграфом
 * в поиске "_SM_" (fallback "_SM3_"), верификация checksum
 * (evidence: кандидат PATH.md 0xF0000 + восстановленная
 * последовательность scan/compare) */
static PVOID
AcSmbiosFindEntryPoint(
    _In_ const UINT8* Area,
    _Out_ BOOLEAN* IsV3
    )
{
    UINT32 off;

    *IsV3 = FALSE;
    for (off = AC_SMBIOS_SCAN_LO; off < AC_SMBIOS_SCAN_HI - 0x20; off += 0x10) {
        const AC_SMBIOS_EPS* eps = (const AC_SMBIOS_EPS*)(Area + off);
        const AC_SMBIOS3_EPS* eps3 = (const AC_SMBIOS3_EPS*)(Area + off);

        if (eps->Anchor == AC_SMBIOS_ANCHOR2 &&
            eps->EpsLength >= 0x1F &&
            AcSmbiosChecksum((const UINT8*)eps, eps->EpsLength)) {
            return (PVOID)eps;
        }
        if (AcMemCompare(eps3->Anchor, "_SM3_", 5) == 0 &&
            eps3->EpsLength >= 0x18 &&
            AcSmbiosChecksum((const UINT8*)eps3, eps3->EpsLength)) {
            *IsV3 = TRUE;
            return (PVOID)eps3;
        }
    }
    return NULL;
}

/* Копировать NUL-терминированную строку string-set'а, ограниченно
 * (шаг извлечения string-set'а парса хаба [0x1401835f8]) */
static VOID
AcSmbiosCopyString(
    _Out_writes_(DestSize) CHAR* Dest,
    _In_ UINT32 DestSize,
    _In_ const UINT8* StringSet,
    _In_ UINT8 Index
    )
{
    UINT8 n;

    if (DestSize == 0)
        return;
    Dest[0] = '\0';
    if (Index == 0)
        return;

    /* дойти до Index-той строки набора */
    for (n = 1; n < Index; n++) {
        while (*StringSet != 0)
            StringSet++;
        StringSet++;
        if (*StringSet == 0)
            return;         /* упёрлись в двойной NUL-терминатор */
    }

    {
        UINT32 i = 0;
        while (StringSet[i] != 0 && i < DestSize - 1) {
            Dest[i] = (CHAR)StringSet[i];
            i++;
        }
        Dest[i] = '\0';
    }
}

/* Распарсить интересующие поля одной структуры (типы 0/1/2/17)
 * (evidence: HWID_COLLECTION_PATH §Board/BIOS/UUID + §RAM: типы 0/1/2/17,
 * поля RAM = serial/vendor/part; шаг парса хаба [0x1401835f8]) */
static VOID
AcSmbiosParseStructure(
    _In_ const AC_SMBIOS_HEADER* Hdr,
    _In_ const UINT8* StringSet,
    _Inout_ PAC_SMBIOS_DATA Data
    )
{
    const UINT8* f = (const UINT8*)Hdr;

    switch (Hdr->Type) {
    case 0:     /* BIOS Information */
        if (Hdr->Length >= 0x12) {
            AcSmbiosCopyString(Data->BiosVendor, sizeof(Data->BiosVendor),
                               StringSet, f[0x04]);
            AcSmbiosCopyString(Data->BiosVersion, sizeof(Data->BiosVersion),
                               StringSet, f[0x05]);
            AcSmbiosCopyString(Data->BiosReleaseDate,
                               sizeof(Data->BiosReleaseDate),
                               StringSet, f[0x08]);
        }
        break;

    case 1:     /* System Information (+UUID по 0x08, 16 сырых байтов) */
        if (Hdr->Length >= 0x19) {
            AcSmbiosCopyString(Data->SysManufacturer,
                               sizeof(Data->SysManufacturer),
                               StringSet, f[0x04]);
            AcSmbiosCopyString(Data->SysProductName,
                               sizeof(Data->SysProductName),
                               StringSet, f[0x05]);
            AcSmbiosCopyString(Data->SysSerialNumber,
                               sizeof(Data->SysSerialNumber),
                               StringSet, f[0x07]);
            RtlCopyMemory(Data->SysUuid, f + 0x08, 16);
        }
        break;

    case 2:     /* Baseboard Information */
        if (Hdr->Length >= 0x08) {
            AcSmbiosCopyString(Data->BoardManufacturer,
                               sizeof(Data->BoardManufacturer),
                               StringSet, f[0x04]);
            AcSmbiosCopyString(Data->BoardProduct, sizeof(Data->BoardProduct),
                               StringSet, f[0x05]);
            AcSmbiosCopyString(Data->BoardSerial, sizeof(Data->BoardSerial),
                               StringSet, f[0x07]);
        }
        break;

    case 17:    /* Memory Device: vendor/serial/part питают запись RAM */
        if (Hdr->Length >= 0x1B &&
            Data->MemoryDeviceCount < AC_SMBIOS_MAX_DEVICES) {
            PAC_SMBIOS_MEMORY_DEVICE dev =
                &Data->MemoryDevices[Data->MemoryDeviceCount];
            UINT16 sizeField = *(const UINT16*)(f + 0x0C);

            if (sizeField == 0 || sizeField == 0xFFFF)
                break;      /* пустой слот */

            dev->SizeMB = sizeField;
            AcSmbiosCopyString(dev->Manufacturer, sizeof(dev->Manufacturer),
                               StringSet, f[0x17]);
            AcSmbiosCopyString(dev->SerialNumber, sizeof(dev->SerialNumber),
                               StringSet, f[0x18]);
            AcSmbiosCopyString(dev->PartNumber, sizeof(dev->PartNumber),
                               StringSet, f[0x1A]);
            dev->Present = 1;
            Data->MemoryDeviceCount++;
        }
        break;

    default:
        break;
    }
}

/* Обход таблицы структур: formatted-секция + string-set, терминированный
 * двойным NUL; стоп на типе 127 (конец таблицы) или исчерпании
 * count/length (evidence: layout таблицы SMBIOS; цикл парса --
 * восстановленная структура хаба smbios_hub 0x1401835f8) */
static VOID
AcSmbiosParseTable(
    _In_ const UINT8* Table,
    _In_ UINT32 TableLength,
    _In_ UINT32 StructCount,
    _Inout_ PAC_SMBIOS_DATA Data
    )
{
    const UINT8* p = Table;
    const UINT8* end = Table + TableLength;
    UINT32 count = 0;

    while (p + sizeof(AC_SMBIOS_HEADER) <= end) {
        const AC_SMBIOS_HEADER* hdr = (const AC_SMBIOS_HEADER*)p;
        const UINT8* stringSet;

        if (hdr->Type == 127)
            break;
        if (hdr->Length < sizeof(AC_SMBIOS_HEADER) ||
            p + hdr->Length > end)
            break;

        AcSmbiosParseStructure(hdr, p + hdr->Length, Data);

        /* пропустить formatted-секцию + string-set (двойной NUL) */
        stringSet = p + hdr->Length;
        while (stringSet + 1 < end &&
               !(stringSet[0] == 0 && stringSet[1] == 0)) {
            stringSet++;
        }
        p = stringSet + 2;

        if (StructCount && ++count >= StructCount)
            break;
    }
}

/* --------------------------------------------------------------------------
 * Вход коллектора: map -> scan -> checksum -> parse -> unmap.
 * [0x1401835f8] smbios_hub (полный provenance в заголовке файла)
 * [0x1401083f8] пара MmUnmapIoSpace (teardown на каждом пути выхода)
 *
 * payload-selected: в zero-input ранах import-пара MmMapIoSpace читается
 * как 0x0, а вызов вооружается живым IOCTL payload'ом (таблица "Actual
 * target" PATH.md; smbios_recover sage_rcx SAT с input-листьями).
 * Реконструкция ниже -- восстановленная структура пути; конкретная
 * константа phys-адреса (окно якоря 0xF0000 внутри маппинга 0xE0000) --
 * кандидат PATH.md, подкреплённый спецификацией SMBIOS.
 * ------------------------------------------------------------------------ */
NTSTATUS
SmbiosCollect(
    _Out_ PAC_SMBIOS_DATA Data
    )
{
    PHYSICAL_ADDRESS phys;
    const UINT8* area = NULL;
    const UINT8* tableArea = NULL;
    PVOID eps;
    BOOLEAN isV3;
    NTSTATUS status = STATUS_NOT_FOUND;

    RtlZeroMemory(Data, sizeof(*Data));

    /* [0x140107ce8^0x140107ce0] MmMapIoSpace(0xE0000, 0x20000, MmCached)
     * -- режим кэширования дословно из bait-replay
     * (HWID_KERNEL_TO_SERVICE §3: rcx=0xE0000, rdx=0x20000, r8=MmCached) */
    phys.QuadPart = AC_SMBIOS_PHYS_BASE;
    area = (const UINT8*)MmMapIoSpace(phys, AC_SMBIOS_PHYS_SIZE, MmCached);
    if (area == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    eps = AcSmbiosFindEntryPoint(area, &isV3);
    if (eps == NULL)
        goto Unmap;

    /* [0x1401082d0] MmGetPhysicalAddress: cross-check физической базы
     * отображённого окна против ожидаемого региона 0xE0000
     * (phys-контурная валидация; EPS обязан сидеть в legacy-области) */
    {
        UINT64 epsPhys = AcMmGetPhysicalAddress(eps);

        if (epsPhys < AC_SMBIOS_PHYS_BASE ||
            epsPhys >= AC_SMBIOS_PHYS_BASE + AC_SMBIOS_PHYS_SIZE)
            goto Unmap;
    }

    if (isV3) {
        /* SMBIOS 3.x: таблица может сидеть вне legacy-окна; отобразить её */
        const AC_SMBIOS3_EPS* eps3 = (const AC_SMBIOS3_EPS*)eps;
        PHYSICAL_ADDRESS tablePhys;
        UINT32 tableSize = eps3->TableMaxSize;

        if (tableSize == 0 || tableSize > 0x10000)
            goto Unmap;
        tablePhys.QuadPart = (UINT64)eps3->TableAddress;
        tableArea = (const UINT8*)MmMapIoSpace(tablePhys, tableSize,
                                               MmCached);
        if (tableArea == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto Unmap;
        }
        AcSmbiosParseTable(tableArea, tableSize, 0, Data);
        status = STATUS_SUCCESS;
    } else {
        /* SMBIOS 2.x: физический адрес DMI-таблицы внутри области BIOS на
         * стандартных платформах (и внутри нашего маппинга, когда это так) */
        const AC_SMBIOS_EPS* eps2 = (const AC_SMBIOS_EPS*)eps;
        UINT64 tableVa;

        if (eps2->TableAddress < AC_SMBIOS_PHYS_BASE ||
            eps2->TableAddress + eps2->TableLength >
                AC_SMBIOS_PHYS_BASE + AC_SMBIOS_PHYS_SIZE)
            goto Unmap;

        tableVa = (UINT64)area +
                  (eps2->TableAddress - AC_SMBIOS_PHYS_BASE);
        AcSmbiosParseTable((const UINT8*)tableVa, eps2->TableLength,
                           eps2->StructCount, Data);
        status = STATUS_SUCCESS;
    }

Unmap:
    /* [0x1401083f8^0x1401083f0] MmUnmapIoSpace на каждом пути выхода */
    if (tableArea != NULL)
        MmUnmapIoSpace((PVOID)tableArea, 0x10000);
    MmUnmapIoSpace((PVOID)area, AC_SMBIOS_PHYS_SIZE);
    return status;
}
