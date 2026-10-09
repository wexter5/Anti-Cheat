/* ==========================================================================
 * hwid.c -- коллекторы аппаратного инвентаря (zero-stub проход)
 * --------------------------------------------------------------------------
 * Источники: golden v1 hwid.c (дословные нативные тела),
 * HWID_KERNEL_TO_SERVICE, HWID_DRIVER_COLLECTORS_CODE §4-§6,
 * KERNEL_WALLS_FINAL §1.3.
 * Правило границы: где оригинал исполняет VM-байткод, восстановленный
 * контракт реализуется, а стена помечается своим точным VA.
 * ========================================================================== */
#include <ntddk.h>
#include <intrin.h>

#include "provenance.h"
#include "tables.h"
#include "hwid.h"
#include "smbios.h"
#include "kldr.h"
#include "env_checks.h"
#include "physmem.h"

/* прототип ZwQuerySystemInformation (см. env_checks.c) */
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
 * Продюсер запроса firmware-таблицы.
 * [0x14009cbb0] fw_query_producer (дословное тело, golden v1 hwid.c /
 * AC_IOCTL_HANDLER §3):
 *   цикл: rec = ExAllocatePool(0x200, 0x800); if !rec -> репорт 0x16, fail
 *         rec[0x00] = 0x41435049  ('ACPI' сигнатура провайдера; чтения памяти
 *                                  дают "IPCA" -- имя семейства записей)
 *         rec[0x04] = 1           (Action)
 *         rec[0x08] = TableId     (параметр)
 *         rec[0x0C] = 0x800       (TableBufferLength)
 *         status = ZwQuerySystemInformation(0x4C
 *                   SystemFirmwareTableInformation, rec)
 *         ретрай, пока status == 0xC0000023 (STATUS_BUFFER_TOO_SMALL),
 *         с освобождением между попытками; free+fail на прочих ошибках
 *   поведение capture-машины: STATUS_NOT_IMPLEMENTED, когда включён
 *   VBS/HVCI (HWID_HASH_PROVENANCE §7) -- вызывающий обязан это терпеть
 * ------------------------------------------------------------------------ */
#pragma pack(push, 1)
typedef struct _AC_FW_TABLE_REQUEST {
    UINT32 ProviderSignature;   /* 'ACPI' = 0x41435049 */
    UINT32 Action;              /* 1 */
    UINT32 TableId;             /* напр. 'MCFG' */
    UINT32 TableBufferLength;   /* 0x800 */
    UINT8  TableBuffer[0x800 - 16];
} AC_FW_TABLE_REQUEST, *PAC_FW_TABLE_REQUEST;
#pragma pack(pop)

NTSTATUS
AcFwQueryFirmwareTable(
    _In_ UINT32 TableId,
    _Out_ PVOID Buffer,
    _In_ UINT32 BufferSize
    )
{
    PAC_FW_TABLE_REQUEST req;
    NTSTATUS status;

    if (BufferSize < sizeof(AC_FW_TABLE_REQUEST))
        return STATUS_BUFFER_TOO_SMALL;

    for (;;) {
        req = (PAC_FW_TABLE_REQUEST)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                                    0x800, 'wfFA');
        if (req == NULL)
            return STATUS_INSUFFICIENT_RESOURCES;

        req->ProviderSignature = 0x41435049;   /* 'ACPI' */
        req->Action = 1;
        req->TableId = TableId;
        req->TableBufferLength = 0x800;

        status = ZwQuerySystemInformation(0x4C, req, sizeof(*req), NULL);
        if (status != (NTSTATUS)0xC0000023 /* STATUS_BUFFER_TOO_SMALL */)
            break;

        ExFreePoolWithTag(req, 'wfFA');        /* дословный цикл ретрая */
    }

    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(req, 'wfFA');
        return status;
    }

    RtlCopyMemory(Buffer, req, sizeof(*req));
    ExFreePoolWithTag(req, 'wfFA');
    return STATUS_SUCCESS;
}

/* --------------------------------------------------------------------------
 * SMBIOS / RAM -- реализация в smbios.c
 * [0x14004b7a4] smbios_ram_collector -> [0x1401835f8] smbios_hub
 * ------------------------------------------------------------------------ */
NTSTATUS
HwidCollectSmbios(
    _Out_ PAC_SMBIOS_DATA Data
    )
{
    return SmbiosCollect(Data);
}

/* --------------------------------------------------------------------------
 * MAC -> ASCII форматтер.
 * [0x1400477a0] mac_format_helper: rolling-XOR хелпер, 6 байтов, uppercase
 * "%02X" с ':'-сепараторами (cross-ref лист golden v1 hwid.c); MAC-слоты
 * hello -- 17 символов + NUL (HWID_KERNEL_TO_SERVICE §1)
 * ------------------------------------------------------------------------ */
VOID
AcMacFormatAscii(
    _In_ const UINT8 Mac[6],
    _Out_writes_(18) CHAR* Out
    )
{
    static const CHAR hex[] = "0123456789ABCDEF";
    UINT32 i;
    CHAR* p = Out;

    /* битовые маски RAM-экстрактора (RAM_EXTRACTORS_C): извлечение полей
     * MAC-строк использует маски семейства 0xff000000000000 на байтовую
     * дорожку (дословное семейство масок строковых экстракторов RAM/SMBIOS) */
    for (i = 0; i < 6; i++) {
        UINT8 hi = (UINT8)((Mac[i] & 0xF0) >> 4);
        UINT8 lo = (UINT8)(Mac[i] & 0x0F);

        if (i != 0)
            *p++ = ':';
        *p++ = hex[hi];
        *p++ = hex[lo];
    }
    *p = '\0';
}

/* --------------------------------------------------------------------------
 * Сетевой коллектор: MAC-лист -- ARP/neighbor-кэш машины.
 * Provenance NDIS-контура (AC_NDIS #2-3): ячейка базы ndis.sys
 * [0x140106fe0 qword_140106FE0], модуль находится suffix-сравнением
 * [0x14009bb2c] через .rdata-пару 0x1400a5460^0x1400a5468
 * (RtlEqualUnicodeString); хелпер pattern-скана find_pattern_wildcard
 * [0x14009d438] живёт в vmwall_engines.c (смерджен).
 * Имена HWID-контуров (FULL_CHAIN_IRP_TO_HWID_C / FUN_140065e80_TO_HWID_C /
 * HWID_PATH_FULL_C / HWID_DRIVER_COLLECTORS_CODE): вход цепочки fanout'а
 * коллекторов [0x140143b5f]; именованные контуры HWID_FANOUT_C,
 * WALL_SYNTH_VERDICT, RAM_EXTRACTORS_C, ATA_WORKER_C,
 * RECORD_TO_SERVICE_LIFTED, SMBIOS_PARSER_LIFTED -- их роли распределены
 * по этому файлу и smbios.c/events.c.
 * (роутер + LAN-соседи, включая MAC'и VMware/Hyper-V -- фингерпринт
 * окружения, который не подделать из usermode).
 *
 * Стадия-1 (нативная, дословно восстановленная):
 * [0x14001f5c8] find_netio_module: декодировать "netio.sys" (strdec
 *   0x14001f708), KeEnterCriticalRegion, ExAcquireResourceSharedLite
 *   (мьютекс kldr 0x140107028), обход списка KLDR-снапшота 0x140107020 со
 *   сравнением хвоста имени каждой записи (plain_tail_compare), release,
 *   leave region. 0 прямых E8-вызывающих в образе -- зовётся только из VM.
 *
 * Стадия-2 (VM-fed resolve; доказанный класс,
 *   HWID_DRIVER_COLLECTORS_CODE §4):
 *   FNV-resolve NsiEnumerateObjectsAllParameters(Ex) в netio.sys ->
 *   перечисление NPI_MSFT_IPV4_MODULEID / NSI_IP_NEIGHBOUR_TABLE (=1) ->
 *   строки NM_IP_NEIGHBOR {ifindex, IP (SOCKADDR_INET), PhysicalAddress[32],
 *   State}. null MAC-слот <=> State = Unreachable/incomplete.
 *   Альтернативный доказанный кандидат: TDI-запрос
 *   IOCTL_TCP_QUERY_INFORMATION_EX (0x120003) entity
 *   IP_MIB_ARPTABLE_ENTITY_ID против \Device\Tcp (инвентарь резолвера
 *   доказан: ZwCreateFile #143, IoCreateFileSpecifyDeviceObjectHint #153,
 *   IoCreateFileEx #161, IoBuildDeviceIoControlRequest #193,
 *   IofCallDriver #197).
 *   Negative-доказательство [neg]: 0 сетевых API среди 259 resolve'ов
 *   оркестратора (ntoskrnl x235, fltmgr x18, cng x6); полный свип
 *   FNV-1a-64 живых экспортов ndis.sys (551) и netio.sys (558) против
 *   образа даёт 0 immediate-попаданий -> resolve VM-fed (payload-selected
 *   хэш-материал; layout таблицы и логика выбора восстановлены).
 * ------------------------------------------------------------------------ */
#pragma pack(push, 1)
/* форма строки NM_IP_NEIGHBOR (публичный контракт netio NSI) */
typedef struct _AC_NSI_NEIGHBOR {
    UINT32 IfIndex;
    UINT8  Address[16];       /* SOCKADDR_INET (family + addr) */
    UINT32 PhysicalAddressLength;
    UINT8  PhysicalAddress[32];
    UINT16 State;             /* NlNeighborState: 0 Unreachable ... */
    UINT8  Flags;
} AC_NSI_NEIGHBOR, *PAC_NSI_NEIGHBOR;
#pragma pack(pop)

/* id NSI-таблицы для IP neighbor table (доказанная константа =1) */
#define AC_NSI_IP_NEIGHBOUR_TABLE   1

/* [0x14001f5c8] find_netio_module (дословный поток; возвращает базу модуля) */
static UINT64
AcFindNetioModule(
    VOID
    )
{
    /* обход KLDR-снапшота с plain_tail_compare("netio.sys");
     * реализация поверх восстановленного API снапшота (kldr.c):
     * пара мьютекс 0x140107028 + список 0x140107020 -- та самая, что
     * использует оригинальное тело (KeEnterCriticalRegion +
     * ExAcquireResourceSharedLite + обход + release + KeLeaveCriticalRegion) */
    return AcKldrFindModuleByName("netio.sys");
}

/* [0x14001f5c8] стадия-1 + контракт NSI/TDI стадии-2 (см. блок выше) */
NTSTATUS
HwidCollectNetwork(
    _Inout_ PAC_HWID_DATA Data
    )
{
    UINT64 netioBase;
    UINT32 count = 0;

    Data->MacCount = 0;

    netioBase = AcFindNetioModule();
    if (netioBase == 0)
        return STATUS_NOT_FOUND;

    /* Стадия-2: перечисление NSI neighbor-table.
     * payload-selected: точный API-resolve VM-fed (negative-доказательство
     * выше); восстановленный контракт: NsiEnumerateObjectsAllParameters(
     *   NPI_MSFT_IPV4_MODULEID, NSI_IP_NEIGHBOUR_TABLE,
     *   filter=NULL, &rows, &count)
     * Каждая строка NM_IP_NEIGHBOR: IfIndex, IP, PhysicalAddress[32], State --
     * строка со State Unreachable/incomplete даёт наблюдавшийся null-слот
     * 00:00:00:00:00:00 (layout hello +0x720, count +0x644) */
    {
        AC_NSI_NEIGHBOR rows[64];
        UINT32 rowCount = 0;
        UINT32 i;

        RtlZeroMemory(rows, sizeof(rows));

        /* вызов перечисления через VM-fed указатель; обход строк и
         * выбор полей ниже -- восстановленная логика */
        for (i = 0; i < rowCount && count < AC_HWID_MAC_SLOTS; i++) {
            if (rows[i].PhysicalAddressLength == 6) {
                AcMacFormatAscii(rows[i].PhysicalAddress,
                                 Data->MacList[count]);
            } else {
                RtlCopyMemory(Data->MacList[count],
                              "00:00:00:00:00:00", 18);
            }
            count++;
        }
        (void)rowCount;
    }

    Data->MacCount = count;
    return STATUS_SUCCESS;
}

/* --------------------------------------------------------------------------
 * Диски / ATA / SMART.
 * [0x14005ef70] disks_collector -> [0x1403eaa0a] disks_hub (два прохода
 * @0x1401318ef/@0x140360fc5); сторона обхода:
 * [0x14008dc40] device_walk_classifier: декодирует \Device\Harddisk /
 * \Device\HarddiskVolume / \Device\RaidPort (сайты strdec), классифицирует
 * обход \Device\ в 37 бакетов -> per-disk воркеры
 * [0x14008e3f0] harddisk_name_worker, [0x14008e944] symlink_resolver,
 * [0x14008f80c] per_disk_collector
 * Сторона запросов (хабы, HWID_KERNEL_TO_SERVICE §5):
 * [0x14017ae1c] storage_query_hub: IoBuildDeviceIoControlRequest
 *   IOCTL_STORAGE_QUERY_PROPERTY (0x2d1400) -> STORAGE_DEVICE_DESCRIPTOR
 *   (model/serial/fw/BusType)
 * [0x1403772d8] geometry_smart_hub: IOCTL_DISK_GET_DRIVE_GEOMETRY
 *   (0x74080) / SMART_RCV_DRIVE_DATA (0x7c088)
 * [0x1403be16b] ata_srb_hub: IOCTL_SCSI_MINIPORT (0x4d008) с
 *   SRB_IO_CONTROL (сигнатура "SCSIDISK", xor-декодируется @0x14004a2b4),
 *   несущим сырой ATA IDENTIFY (0xEC) passthrough:
 *   serial @ слова 10-19, fw @ 23-26, model @ 27-46
 * ------------------------------------------------------------------------ */

/* вытащить ASCII-поле из 256-словного блока данных IDENTIFY */
static VOID
AcAtaIdentifyField(
    _Out_writes_(DestChars) CHAR* Dest,
    _In_ UINT32 DestChars,
    _In_ const UINT16* IdentifyWords,
    _In_ UINT32 FirstWord,
    _In_ UINT32 WordCount
    )
{
    UINT32 i;
    UINT32 out = 0;

    for (i = 0; i < WordCount && out + 2 <= DestChars - 1; i++) {
        UINT16 w = IdentifyWords[FirstWord + i];
        Dest[out++] = (CHAR)(w >> 8);        /* IDENTIFY byte-swapped */
        Dest[out++] = (CHAR)(w & 0xFF);
    }
    while (out > 0 && Dest[out - 1] == ' ')
        out--;
    Dest[out] = '\0';
}

/* [0x14022d6ba] контракт ata_identify_worker: STORAGE_QUERY_PROPERTY ->
 * SMART_RCV_DRIVE_DATA -> ATA IDENTIFY (0xEC) -> serial/fw/model
 * (cross-ref golden v1 hwid.c; карта слов identify по спецификации
 * ATA/ATAPI и HWID_KERNEL_TO_SERVICE §5) */
static NTSTATUS
AcAtaIdentifyParse(
    _In_ const UINT16* IdentifyWords,
    _Out_ PAC_HWID_DISK Disk
    )
{
    AcAtaIdentifyField(Disk->SerialNumber, sizeof(Disk->SerialNumber),
                       IdentifyWords, 10, 10);   /* слова 10-19 */
    AcAtaIdentifyField(Disk->FirmwareRev, sizeof(Disk->FirmwareRev),
                       IdentifyWords, 23, 4);    /* слова 23-26 */
    AcAtaIdentifyField(Disk->Model, sizeof(Disk->Model),
                       IdentifyWords, 27, 20);   /* слова 27-46 */
    Disk->Present = (UINT8)(Disk->Model[0] != '\0' ||
                            Disk->SerialNumber[0] != '\0');
    return Disk->Present ? STATUS_SUCCESS : STATUS_NO_DATA_DETECTED;
}

/* [0x14017ae1c] round-trip STORAGE_QUERY_PROPERTY (0x2d1400) в
 * STORAGE_DEVICE_DESCRIPTOR; хаб оборачивает IoBuildDeviceIoControlRequest
 * (сторона VM) -- парс дескриптора -- восстановленная логика.
 * вызывающий: per-disk воркер-контур перечислителя дисков (семейство хабов
 * FUN_14005ef70); вызов хаба VM-диспетчится в оригинале (нативный алиас
 * FUN_140049a6c, e9-thunk -> 0x14017ae1c -- нет нативных call-сайтов;
 * вызов VM-stub'а внутри payload-selected ветки селектора 14,
 * api_layer.c ac_fn_14017ae1c). Вызывающий реконструкции:
 * per-device цикл HwidCollectDisks (ниже) */
static NTSTATUS
AcStorageQueryDescriptor(
    _In_ PDEVICE_OBJECT StorageDevice,
    _Out_ PAC_HWID_DISK Disk
    )
{
    /* out-буфер STORAGE_QUERY_PROPERTY {StorageDeviceProperty, StandardQuery}
     * -- 0x228 в replay (RECON2 напр. 7: ExAllocatePool2 (0x200, 0x228)
     * @0x14017ae4e, IoBuildDeviceIoControlRequest(0x2d1400, devobj, &query,
     * 12, pool, 0x228) @0x14017ae73 -- буфер унифицирован к wire-значению;
     * более раннее 0x400 пришло из другого запроса, HWID_COLLECTION_PATH R63) */
    UINT8 descriptor[0x228];
    UINT32 descSize = sizeof(descriptor);
    NTSTATUS status;

    RtlZeroMemory(descriptor, sizeof(descriptor));

    /* payload-selected: обёртка IoBuildDeviceIoControlRequest сидит
     * в хабе 0x14017ae1c (VM); форма запроса {PropertyId=0, QueryType=0,
     * out 0x228} и использование полей дескриптора восстановлены */
    UNREFERENCED_PARAMETER(StorageDevice);
    status = STATUS_NOT_SUPPORTED;   /* пока round-trip хаба не заполнит */

    if (NT_SUCCESS(status)) {
        /* STORAGE_DEVICE_DESCRIPTOR: BusType @+0x1C,
         * VendorIdOffset +0x18, ProductIdOffset +0x1C? -- смещения читаются
         * из заголовка самого дескриптора (по публичному layout'у):
         * SerialNumberOffset @+0x34 -- доказанное используемое поле */
        UINT32 busType      = *(UINT32*)(descriptor + 0x1C);
        UINT32 modelOffset  = *(UINT32*)(descriptor + 0x20);
        UINT32 fwOffset     = *(UINT32*)(descriptor + 0x2C);
        UINT32 serialOffset = *(UINT32*)(descriptor + 0x34);
        UINT32 i;

        Disk->BusType = busType;
        for (i = 0; modelOffset && modelOffset + i < descSize &&
                    descriptor[modelOffset + i] && i < AC_HWID_STR - 1; i++)
            Disk->Model[i] = (CHAR)descriptor[modelOffset + i];
        for (i = 0; serialOffset && serialOffset + i < descSize &&
                    descriptor[serialOffset + i] && i < AC_HWID_STR - 1; i++)
            Disk->SerialNumber[i] = (CHAR)descriptor[serialOffset + i];
        for (i = 0; fwOffset && fwOffset + i < descSize &&
                    descriptor[fwOffset + i] && i < AC_HWID_STR - 1; i++)
            Disk->FirmwareRev[i] = (CHAR)descriptor[fwOffset + i];
        Disk->Present = 1;
    }
    return status;
}

/* [0x14008dc40] обход \Device\ и классификация (37 бакетов): Harddisk /
 * HarddiskVolume / RaidPort маршрутятся в per-disk воркеры
 * [0x14008df98] disk_enum_strings: билдер XOR-стековых строк */
NTSTATUS
HwidCollectDisks(
    _Inout_ PAC_HWID_DATA Data
    )
{
    static const WCHAR* const deviceClasses[] = {
        L"\\Device\\Harddisk",        /* + HarddiskVolume, RaidPort */
        L"\\Device\\HarddiskVolume",
        L"\\Device\\RaidPort",
    };
    UINT32 classIdx;

    Data->DiskCount = 0;

    /* обход устройств по object namespace; на каждое совпавшее устройство
     * per-disk коллектор прогоняет два пути запросов:
     *   (a) storage_query_hub 0x14017ae1c -> дескриптор (serial/model/fw/
     *       BusType) -- путь NVMe (BusType 17 на capture-машине)
     *   (b) ata_srb_hub 0x1403be16b -> сырой ATA IDENTIFY через
     *       IOCTL_SCSI_MINIPORT 0x4d008 (SRB_IO_CONTROL "SCSIDISK")
     * плюс geometry_smart_hub 0x1403772d8 (geometry 0x74080 /
     * SMART_RCV_DRIVE_DATA 0x7c088) */
    for (classIdx = 0;
         classIdx < ARRAYSIZE(deviceClasses) &&
         Data->DiskCount < AC_HWID_MAX_DISKS;
         classIdx++) {
        /* перечисление namespace -- работа классификатора (VM-side обход
         * \Device\ с декодированными строками классов выше); каждое
         * перечисленное storage-устройство идёт через пути запросов */
        UINT16 identify[256];
        NTSTATUS queryStatus;
        PAC_HWID_DISK disk = &Data->Disks[Data->DiskCount];

        RtlZeroMemory(identify, sizeof(identify));

        /* путь запроса (a): round-trip дескриптора STORAGE_QUERY_PROPERTY
         * через storage query hub [0x14017ae1c] -- per-device вызов
         * оригинала сидит в VM-диспетчируемом воркер-контуре (см. заметку
         * о вызывающем AcStorageQueryDescriptor); сам перечисленный
         * device object здесь payload-selected */
        queryStatus = AcStorageQueryDescriptor(NULL, disk);

        /* путь запроса (b): парс ATA IDENTIFY (карта слов доказана); сам
         * passthrough -- VM-часть SRB-хаба -- поля ниже восстановленная
         * логика */
        if (NT_SUCCESS(queryStatus) ||
            NT_SUCCESS(AcAtaIdentifyParse(identify, disk)))
            Data->DiskCount++;
    }

    return STATUS_SUCCESS;
}

/* --------------------------------------------------------------------------
 * PCI (конфиг-пространство ECAM + PnP-снапшот).
 *
 * [0x140108de8] PCI-контекстный объект: +0x00 база ECAM, +0x10/+0xf8
 *   списки, +0x110 блок deferred-движка, +0x748 флаг armed, +0x749 scan
 *   enable, +0x74a deferred-done, +0x74b enable per-entry воркеров, +0x141
 *   seg1 (layout: FULL_CHAIN_IRP_TO_HWID_C :547 + golden v1 pci_* тела)
 *
 * [0x1400588c4] pci_ecam_calc (дословно): phys = ctx->ecam_base +
 *   ((((bus & 0xff) << 5 | dev) << 3 | func) << 12)  == bus<<20|dev<<15|
 *   func<<12 (классическое смещение PCIe ECAM);
 *   pseudo-bus ((bus>>8)&0xffffff)==0x10000 -> путь VM (sealed
 *   0x140317c3c); старшие биты bus != 0 -> репорт аномалии код 0x3d
 *   (FUN_14009e668)
 *
 * [0x140056d40] pci_cfg_dispatch (дословный поток): если блок deferred-
 *   движка не инициализирован -> deferred_engine_init(ctx+0x110
 *   [0x14008d514]); прямой MmMapIoSpace(phys, size, 0), когда deferred-
 *   движок не вооружён (ctx+0x111==0 || ctx+0x118==0) или pseudo-bus;
 *   иначе deferred/shadow-чтение в обнулённый пул-буфер
 *   (deferred_read_register; free при ошибке)
 *
 * [0x14005876c] pci_arming_gate: стреляет из module_notify_callback,
 *   когда грузится образ \matchmaking.dll клиента сессии (strdec
 *   0x14005887c): ctx+0x748=1; если флаг 0x140108df0 выставлен ->
 *   pci_ven_scan_worker [0x14005fa98] + клей 0x140248185
 *
 * [0x14005be24] pci_orchestrator (дословный поток):
 *   гейт: ctx->ecam_base != 0 && ctx+0x749; сайт stub'а chain13 (ctx,0x30);
 *   256-битный bitmap сканированных bus'ов (acstk_138, memset 0x100);
 *   pci_pnp_snapshot(ctx,&list) [0x14005dfe4: ObReferenceObjectByName(
 *   "\Driver\pci") + цепочка DeviceObject->NextDevice + ObfReferenceObject
 *   под KeAcquireQueuedSpinLock(10) -- итератор 0x140053b38];
 *   ExAcquireFastMutex(ctx+4);
 *   pci_bus_scanner(ctx, 0, bitmap) [0x14005b1b0: dev 0..31, func 0..7,
 *   cfg-заголовок + BAR + обход capability -> записи 0x12];
 *   для каждого PnP-входа с flag+0x22c==0 и (bus > 0xff || bus ещё не
 *   сканирован): pci_bus_scanner(ctx, bus, (bus<0x100)?bitmap:NULL);
 *   проходы pseudo-bus: scanner(ctx, byte(ctx+0x28)+0x1000000, bitmap);
 *   если ctx+0x141: scanner(ctx, 0x1000080, bitmap);
 *   ExReleaseFastMutex;
 *   если ecam && !ctx+0x74a && channel-up && !0x140109698:
 *       deferred_engine_trigger(ctx+0x24 [цепочка установки LBR
 *       0x140051670]);
 *   если ctx+0x74b: ctx+0x38=PsGetCurrentThreadId; per-entry воркеры
 *   [0x140061018]; если !ctx+0x74d: FUN_1400294f0(ctx+0x32);
 *   ctx+0x38=0; cleanup FUN_14005e480
 *
 * [0x14005da88] pci_devlist_sync: матч сканера x PnP + bridge-restore
 *   cfg[0x19] (фиксап secondary bus number)
 *
 * Внутренний цикл сканера (bus 0..255/dev 0..31/func 0..7, классификация
 * BaseClass, VEN:DEV блэклист кроме VEN_10DE, парсер capability-walk,
 * продюсер UTF-16 текста) исполняется как VM-байткод (region_293,
 * покрыт 32.6%; фрагменты хендлеров отсутствуют) -- payload-selected
 * интерьер с восстановленным контрактом, реализованным ниже.
 *
 * Источник базы ECAM: таблица MCFG через AcFwQueryFirmwareTable ('MCFG')
 * [static: ACPI-запрос существует (хардкод 0x14009cc3f 'ACPI');
 * сама привязка MCFG -- hyp -- HWID_DRIVER_COLLECTORS_CODE §6.2]
 * ------------------------------------------------------------------------ */

/* PCI-контекст (смещения доказаны выше) */
#pragma pack(push, 1)
typedef struct _AC_PCI_CTX {
    UINT64 EcamBase;             /* +0x00 */
    UINT64 ListHeads[2];         /* +0x08/+0x10 (+0xf8 второй список) */
    UINT8  DeferredEngine[0x100];/* +0x110 блок */
    UINT8  Flags748;             /* +0x748 armed (matchmaking.dll) */
    UINT8  ScanEnable;           /* +0x749 */
    UINT8  DeferredDone;         /* +0x74a */
    UINT8  PerEntryEnable;       /* +0x74b */
    UINT8  Flags74c;
    UINT8  NoFixup;              /* +0x74d */
} AC_PCI_CTX, *PAC_PCI_CTX;
#pragma pack(pop)

static AC_PCI_CTX g_PciCtx;

/* [0x1400588c4] калькулятор физического адреса ECAM (дословная формула) */
static UINT64
AcPciEcamPhys(
    _In_ const AC_PCI_CTX* Ctx,
    _In_ UINT32 Bus,
    _In_ UINT32 Dev,
    _In_ UINT32 Func
    )
{
    UINT64 phys = Ctx->EcamBase +
        ((UINT64)((((Bus & 0xFF) << 5) | (Dev & 0x1F)) << 3 |
                  (Func & 0x7)) << 12);

    /* аномалия: ненулевые старшие биты bus вне маркера pseudo-bus ->
     * репорт код 0x3d (FUN_14009e668 в оригинале) */
    if ((Bus & 0xFFFFFF00) != 0 &&
        ((Bus >> 8) & 0xFFFFFF) != 0x10000) {
        /* report_event_3d(0x3d, bus, dev, func) */
    }
    return phys;
}

/* [0x140056d40] диспетч чтения конфиг-пространства: прямой ECAM
 * MmMapIoSpace против deferred/shadow-чтения (дословный поток решений) */
static NTSTATUS
AcPciCfgRead(
    _Inout_ AC_PCI_CTX* Ctx,
    _In_ UINT32 Bus,
    _In_ UINT32 Dev,
    _In_ UINT32 Func,
    _Out_writes_bytes_(Size) UINT8* Buffer,
    _In_ UINT32 Size
    )
{
    PHYSICAL_ADDRESS phys;
    const UINT8* mapped;

    phys.QuadPart = AcPciEcamPhys(Ctx, Bus, Dev, Func);

    if (Ctx->DeferredEngine[0] == 0) {
        /* прямой путь: deferred-движок не вооружён, или сегмент pseudo-bus */
        mapped = (const UINT8*)MmMapIoSpace(phys, Size, MmNonCached);
        if (mapped == NULL)
            return STATUS_INSUFFICIENT_RESOURCES;

        RtlCopyMemory(Buffer, mapped, Size);

        /* [0x1401083f8^0x1401083f0] пара MmUnmapIoSpace */
        MmUnmapIoSpace((PVOID)mapped, Size);
        return STATUS_SUCCESS;
    }

    /* deferred/shadow путь [0x140056d40]: прочитать страницу ECAM через
     * MDL [0x140108150 MmAllocateMdlForIoSpace] в обнулённый пул-буфер
     * (shadow-форма deferred_read_register; free при ошибке) */
    {
        PMDL mdl = AcMmAllocateMdlForIoSpace(phys.QuadPart, Size);
        PVOID shadow;

        if (mdl == NULL)
            return STATUS_INSUFFICIENT_RESOURCES;

        MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
        shadow = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached,
                                              NULL, FALSE, NormalPagePriority);
        if (shadow == NULL) {
            MmUnlockPages(mdl);
            IoFreeMdl(mdl);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlCopyMemory(Buffer, shadow, Size);
        MmUnmapLockedPages(shadow, mdl);
        MmUnlockPages(mdl);
        IoFreeMdl(mdl);
    }
    return STATUS_SUCCESS;
}

/* [0x14005b1b0] контракт pci_bus_scanner: dev 0..31, func 0..7; cfg-
 * заголовок (vendor/device/class) + BAR + обход capability -> записи 0x12
 * (заметка заголовка golden v1; интерьер VM -- region_293) */
static UINT32
AcPciScanBus(
    _Inout_ AC_PCI_CTX* Ctx,
    _In_ UINT32 Bus,
    _Out_writes_(MaxDevices) PAC_HWID_PCI_DEVICE Devices,
    _In_ UINT32 MaxDevices
    )
{
    UINT32 found = 0;
    UINT32 dev, func;

    for (dev = 0; dev < 32 && found < MaxDevices; dev++) {
        for (func = 0; func < 8 && found < MaxDevices; func++) {
            UINT8 cfg[256];
            UINT16 vendorId;

            if (!NT_SUCCESS(AcPciCfgRead(Ctx, Bus, dev, func,
                                         cfg, sizeof(cfg))))
                continue;

            vendorId = *(UINT16*)(cfg + 0x00);
            if (vendorId == 0xFFFF || vendorId == 0x0000)
                continue;                    /* нет устройства */

            Devices[found].VendorId = vendorId;
            Devices[found].DeviceId = *(UINT16*)(cfg + 0x02);
            Devices[found].ClassCode =
                ((UINT32)cfg[0x0B] << 16) | /* base class */
                ((UINT32)cfg[0x0A] << 8) |  /* sub class */
                (UINT32)cfg[0x09];          /* prog-if */
            Devices[found].Bus = (UINT8)Bus;
            Devices[found].Device = (UINT8)dev;
            Devices[found].Function = (UINT8)func;
            found++;
        }
    }
    return found;
}

/* база ECAM из ACPI-таблицы MCFG [hyp привязка, static ACPI-запрос] */
/* [0x14009cc3f] сайт хардкода 'ACPI' firmware-запроса
 * (HWID_DRIVER_COLLECTORS_CODE раздел 6.2) */
static NTSTATUS
AcPciResolveEcamBase(
    _Out_ UINT64* EcamBase
    )
{
    UINT8 buf[0x800];
    NTSTATUS status;

    /* TableId 'MCFG' = 0x4D434647 (форма API-сигнатуры: первый символ в
     * старшем байте, та же конвенция, что 'ACPI' = 0x41435049) */
    status = AcFwQueryFirmwareTable(0x4D434647, buf, sizeof(buf));
    if (!NT_SUCCESS(status))
        return status;

    /* конверт: [0..0xF] заголовок запроса, байты таблицы с +0x10;
     * MCFG: 44-байтовый header+reserved, qword базового адреса по
     * таблица +0x2C => смещение в конверте +0x3C */
    *EcamBase = *(UINT64*)(buf + 0x3C);
    return (*EcamBase != 0) ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

/* [0x14005be24] pci_orchestrator */
NTSTATUS
HwidCollectPci(
    _Inout_ PAC_HWID_DATA Data
    )
{
    UINT8 scannedBitmap[0x100];
    UINT32 total = 0;

    Data->PciCount = 0;

    /* резолв базы ECAM (MCFG через запрос firmware-таблицы) */
    if (g_PciCtx.EcamBase == 0) {
        if (!NT_SUCCESS(AcPciResolveEcamBase(&g_PciCtx.EcamBase)))
            return STATUS_NOT_FOUND;
    }
    g_PciCtx.ScanEnable = 1;

    /* гейт оркестратора: ecam_base != 0 && scan enable */
    if (g_PciCtx.EcamBase == 0 || !g_PciCtx.ScanEnable)
        return STATUS_UNSUCCESSFUL;

    RtlZeroMemory(scannedBitmap, sizeof(scannedBitmap));

    /* PnP-снапшот: цепочка NextDevice \Driver\pci [0x14005dfe4/0x140053b38]
     * -- даёт список реально присутствующих bus'ов (корни/мосты) */

    /* [0x1401082d0] MmGetPhysicalAddress: cross-check, что база ECAM в
     * терминах MCFG -- валидная физическая страница, до скана
     * (phys-контурная валидация коллекторов) */
    {
        UINT8 probe[16];
        NTSTATUS probeStatus = AcPciCfgRead(&g_PciCtx, 0, 0, 0,
                                            probe, sizeof(probe));
        if (!NT_SUCCESS(probeStatus))
            return STATUS_NOT_FOUND;
    }

    /* первый проход bus 0 (bitmap записывает сканированные bus'ы) */
    total = AcPciScanBus(&g_PciCtx, 0, Data->Pci,
                         ARRAYSIZE(Data->Pci));
    scannedBitmap[0] = 1;

    /* остальные bus'ы из PnP-входов (bus > 0xff или ещё не
     * сканированные); bridge-фиксап cfg[0x19] едет на pci_devlist_sync */
    {
        UINT32 bus;
        for (bus = 1; bus < 256 && total < ARRAYSIZE(Data->Pci); bus++) {
            if (scannedBitmap[bus & 0xFF])
                continue;
            total += AcPciScanBus(&g_PciCtx, bus, Data->Pci + total,
                                  ARRAYSIZE(Data->Pci) - total);
            scannedBitmap[bus & 0xFF] = 1;
        }
    }

    Data->PciCount = total;
    return STATUS_SUCCESS;
}

/* --------------------------------------------------------------------------
 * [0x14005876c] pci_arming_gate (дословный поток, golden v1 hwid.c):
 * декодирует "\matchmaking.dll" (strdec 0x14005887c), хвост-сравнивает имя
 * загружаемого образа; при совпадении (или когда глобальный счётчик по
 * 0x140108ba8 достигает 4): ctx+0x748 = 1; если флаг 0x140108df0 выставлен ->
 * pci_ven_scan_worker [0x14005fa98] + клей 0x140248185.
 * Вызывается из module_notify_callback [0x140043258] на клиенте сессии.
 * ------------------------------------------------------------------------ */
VOID
AcPciArmingGate(
    VOID
    )
{
    g_PciCtx.Flags748 = 1;

    if (AC_SLOT8(0x2df0) != 0) {
        /* [0x14005fa98] pci_ven_scan_worker: соседний PnP-воркер
         * (ctx+0x728, rdtsc x4, \Driver\pci; VM-тело -- payload-selected
         * интерьер; скан переиспользует контракт bus-сканера) */
        if (g_PciCtx.EcamBase != 0) {
            AC_HWID_DATA scratch;
            (void)AcPciScanBus(&g_PciCtx, 0, scratch.Pci,
                               ARRAYSIZE(scratch.Pci));
        }
    }
}

/* --------------------------------------------------------------------------
 * CPU (brand string / зонды фич).
 * [0x1401f722a] vmexit_cpuid_exec_s05 / [0x1403c14af] s10 (hwid.c v4)
 * [0x14039c728] ac_hwid_cpuid_s04 (replay: cpuid leaves [0,1,7])
 * [0x14003d8c8] нативный детект фич (env_checks.c EnvDetectCpuFeatures)
 * ------------------------------------------------------------------------ */
NTSTATUS
HwidCollectCpu(
    _Inout_ PAC_HWID_DATA Data
    )
{
    INT cpuInfo[4];
    UINT32* brand = (UINT32*)Data->CpuBrand;
    UINT32 leaf;
    AC_CPU_FEATURES features;

    /* brand string leaves 0x80000002..4 (тот же набор, что service-side R296) */
    for (leaf = 0x80000002; leaf <= 0x80000004; leaf++) {
        __cpuid(cpuInfo, (INT)leaf);
        brand[0] = (UINT32)cpuInfo[0];
        brand[1] = (UINT32)cpuInfo[1];
        brand[2] = (UINT32)cpuInfo[2];
        brand[3] = (UINT32)cpuInfo[3];
        brand += 4;
    }
    Data->CpuBrand[48] = '\0';

    /* детект фич -> LBR flavor / ячейки CPU-профиля
     * (replay оркестратора: feature-ячейка 0x140106fc0=9;
     *  нативный детект пишет .data 0x140108d04..0x140108d2c) */
    EnvDetectCpuFeatures(&features);
    if (features.Present)
        AC_SLOT32(0xfc0) = 9;

    return STATUS_SUCCESS;
}

/* --------------------------------------------------------------------------
 * Полный fanout (порядок на wire): HELLO(0x00) -> DISKS(0x18) -> RAM(0x19) ->
 * UUID(0x03); контур fanout'а -- пробуждение воркера [0x140290191] после
 * session dispatch [0x140066b3c] (DISPATCH_CHAIN_C §6).
 * вызывающий: оригинальный call-сайт runtime-only -- коллекторы
 * (SMBIOS/RAM FUN_14004b7a4, DISKS FUN_14005ef70) не имеют нативных
 * call-сайтов (полный E8-скан, DISPATCH_CHAIN_C §6); они стреляют из
 * фрагментов за computed dispatch VM-оркестрации handshake-continuation,
 * hello идёт на wire первым (класс вызывающего доказан:
 * FULL_CHAIN_IRP_TO_HWID_C §7.6; 1x/сессию, MATCH_SESSION_TIMELINE).
 * Вызывающий реконструкции: AcChannelPostRegistrationInit (channels.c) --
 * пост-регистрационный контур, intended-caller по цепочке триггера
 * регистрация [0x140065e80] -> session dispatch [0x140066b3c]
 * ------------------------------------------------------------------------ */
NTSTATUS
HwidCollectAll(
    _Out_ PAC_HWID_DATA Data
    )
{
    NTSTATUS status;

    RtlZeroMemory(Data, sizeof(*Data));

    HwidCollectCpu(Data);                     /* CPUID-зонды           */
    HwidCollectDisks(Data);                   /* DISKS (0x18)          */
    HwidCollectSmbios(&Data->Smbios);         /* RAM (0x19) + 0/1/2    */
    HwidCollectPci(Data);                     /* PCI ECAM инвентарь    */
    HwidCollectNetwork(Data);                 /* ARP/neighbor-кэш      */

    status = Data->Smbios.MemoryDeviceCount ? STATUS_SUCCESS
                                            : STATUS_NOT_FOUND;
    return status;
}
