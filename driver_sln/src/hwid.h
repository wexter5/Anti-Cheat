/* ==========================================================================
 * hwid.h -- коллекторы аппаратного инвентаря
 * ========================================================================== */
#ifndef FACEIT_AC_HWID_H
#define FACEIT_AC_HWID_H

#include <ntddk.h>
#include "smbios.h"

/* Fanout коллекторов, порядок на wire (hello драйвера): HELLO(0x00) ->
 * DISKS(0x18) -> RAM(0x19) -> UUID(0x03)
 * (evidence: DISPATCH_CHAIN_C §6, DRIVER_CHANNEL_PROTOCOL §1) */
#define AC_HWID_REC_HELLO   0x00
#define AC_HWID_REC_DISKS   0x18
#define AC_HWID_REC_RAM     0x19
#define AC_HWID_REC_UUID    0x03

#define AC_HWID_MAX_DISKS   8
#define AC_HWID_STR         64

#pragma pack(push, 1)
typedef struct _AC_HWID_DISK {
    CHAR SerialNumber[AC_HWID_STR];  /* ATA IDENTIFY слова 10-19 / дескриптор */
    CHAR Model[AC_HWID_STR];         /* ATA IDENTIFY слова 27-46 */
    CHAR FirmwareRev[AC_HWID_STR];   /* ATA IDENTIFY слова 23-26 */
    UINT32 BusType;                  /* STORAGE_BUS_TYPE (17 = BusTypeNvme) */
    UINT8  Present;
} AC_HWID_DISK, *PAC_HWID_DISK;

typedef struct _AC_HWID_PCI_DEVICE {
    UINT16 VendorId;
    UINT16 DeviceId;
    UINT8  Bus;
    UINT8  Device;
    UINT8  Function;
    UINT32 ClassCode;                /* base/sub/progif запакованные */
} AC_HWID_PCI_DEVICE, *PAC_HWID_PCI_DEVICE;

/* MAC-слот MAC-листа hello (+0x720): ASCII, 17 символов + NUL
 * (evidence: HWID_KERNEL_TO_SERVICE §1/§4 [dec]) */
#define AC_HWID_MAC_SLOTS   16
#define AC_HWID_MAC_ASCII   18

typedef struct _AC_HWID_DATA {
    AC_SMBIOS_DATA Smbios;                       /* типы 0/1/2/17 */
    UINT32 DiskCount;
    AC_HWID_DISK Disks[AC_HWID_MAX_DISKS];
    UINT32 PciCount;
    AC_HWID_PCI_DEVICE Pci[64];
    UINT32 MacCount;                             /* hello +0x644 */
    CHAR MacList[AC_HWID_MAC_SLOTS][AC_HWID_MAC_ASCII]; /* hello +0x720 */
    CHAR CpuBrand[49];                           /* CPUID 0x80000002..4 */
} AC_HWID_DATA, *PAC_HWID_DATA;
#pragma pack(pop)

/* [0x14004b7a4]/[0x1401835f8] коллектор SMBIOS+RAM (smbios.c) */
NTSTATUS HwidCollectSmbios(_Out_ PAC_SMBIOS_DATA Data);

/* [0x14005ef70]/[0x1403eaa0a] коллектор дисков (обход + запрос + ATA passthrough) */
NTSTATUS HwidCollectDisks(_Inout_ PAC_HWID_DATA Data);

/* [0x14005be24] pci_orchestrator (ECAM + PnP-снапшот + сканеры) */
NTSTATUS HwidCollectPci(_Inout_ PAC_HWID_DATA Data);

/* [0x14001f5c8] find_netio_module + NSI neighbor table (ARP-кэш) */
NTSTATUS HwidCollectNetwork(_Inout_ PAC_HWID_DATA Data);

/* [0x14003d8c8] детект CPU-фич + [0x1401f722a]/[0x1403c14af] brand */
NTSTATUS HwidCollectCpu(_Inout_ PAC_HWID_DATA Data);

/* [0x14009cbb0] fw_query_producer: запрос firmware-таблицы QSI 0x4C
 * ('ACPI' сигнатура провайдера, ретрай на STATUS_BUFFER_TOO_SMALL) */
NTSTATUS AcFwQueryFirmwareTable(_In_ UINT32 TableId,
                                _Out_ PVOID Buffer,
                                _In_ UINT32 BufferSize);

/* [0x1400477a0] mac_format_helper: MAC 6B -> uppercase ASCII "%02X:" */
VOID AcMacFormatAscii(_In_ const UINT8 Mac[6],
                      _Out_writes_(18) CHAR* Out);

/* [0x14005876c] pci_arming_gate: стреляет при загрузке образа клиента
 * сессии \matchmaking.dll (путь image notify) */
VOID AcPciArmingGate(VOID);

/* полный fanout */
NTSTATUS HwidCollectAll(_Out_ PAC_HWID_DATA Data);

#endif /* FACEIT_AC_HWID_H */
