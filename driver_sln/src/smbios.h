/* ==========================================================================
 * smbios.h -- читатель области firmware SMBIOS (map -> scan -> checksum -> parse)
 * ========================================================================== */
#ifndef FACEIT_AC_SMBIOS_H
#define FACEIT_AC_SMBIOS_H

#include <ntddk.h>

/* Извлечённый набор данных SMBIOS (питает записи hello/HWID драйвера).
 * Provenance набора полей: DRIVER_CHANNEL_PROTOCOL §6 dec hello драйвера
 * (запись RAM 1476B: 4x {serial, vendor, part}; поля board/BIOS/UUID),
 * HWID_COLLECTION_PATH.md §Board/BIOS/UUID (типы 0/1/2). */
#define AC_SMBIOS_STR_MAX      64
#define AC_SMBIOS_MAX_DEVICES  8

#pragma pack(push, 1)
typedef struct _AC_SMBIOS_MEMORY_DEVICE {
    CHAR Manufacturer[AC_SMBIOS_STR_MAX];  /* тип 17, строка 0x17 -> напр. Micron */
    CHAR SerialNumber[AC_SMBIOS_STR_MAX];  /* тип 17, строка 0x18 */
    CHAR PartNumber[AC_SMBIOS_STR_MAX];    /* тип 17, строка 0x1A */
    UINT16 SizeMB;                         /* тип 17, поле 0x0C */
    UINT8  Present;
} AC_SMBIOS_MEMORY_DEVICE, *PAC_SMBIOS_MEMORY_DEVICE;

typedef struct _AC_SMBIOS_DATA {
    /* тип 0 -- BIOS */
    CHAR BiosVendor[AC_SMBIOS_STR_MAX];
    CHAR BiosVersion[AC_SMBIOS_STR_MAX];
    CHAR BiosReleaseDate[AC_SMBIOS_STR_MAX];
    /* тип 1 -- System */
    CHAR SysManufacturer[AC_SMBIOS_STR_MAX];
    CHAR SysProductName[AC_SMBIOS_STR_MAX];
    CHAR SysSerialNumber[AC_SMBIOS_STR_MAX];
    UINT8 SysUuid[16];                     /* тип 1, поле 0x08, сырые байты */
    /* тип 2 -- Baseboard */
    CHAR BoardManufacturer[AC_SMBIOS_STR_MAX];
    CHAR BoardProduct[AC_SMBIOS_STR_MAX];
    CHAR BoardSerial[AC_SMBIOS_STR_MAX];
    /* тип 17 -- Memory Devices */
    UINT32 MemoryDeviceCount;
    AC_SMBIOS_MEMORY_DEVICE MemoryDevices[AC_SMBIOS_MAX_DEVICES];
} AC_SMBIOS_DATA, *PAC_SMBIOS_DATA;
#pragma pack(pop)

/* [0x1401835f8] smbios_hub: map область firmware -> scan -> parse -> unmap */
NTSTATUS
SmbiosCollect(
    _Out_ PAC_SMBIOS_DATA Data
    );

#endif /* FACEIT_AC_SMBIOS_H */
