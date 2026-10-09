/* ==========================================================================
 * byovd_scanner.h -- статический BYOVD сканер сигнатур
 * ========================================================================== */
#ifndef FACEIT_AC_BYOVD_SCANNER_H
#define FACEIT_AC_BYOVD_SCANNER_H

#include <ntddk.h>

/* [0x14001bd3c] контракт сканера: сканировать отображённый образ модуля
 * на запечённый BYOVD-набор; возвращает совпавший паттерн или NULL */
const WCHAR* AcByovdScanImage(_In_ const UINT8* Image,
                              _In_ UINT64 ImageSize);

/* отобразить файл модуля и просканировать его (ZwCreateFile+ZwCreateSection+MapView) */
const WCHAR* AcByovdScanModuleFile(_In_z_ const WCHAR* ModulePath);

/* [0x14000f9c0] обход object-directory по watch-именам BYOVD-устройств:
 * префикс-матч входов \GLOBAL?? и сбор целей их симлинков */
NTSTATUS AcByovdScanObjectDirectory(_In_ PCUNICODE_STRING TargetName,
                                    _Inout_ PLIST_ENTRY ResultsHead);

#endif /* FACEIT_AC_BYOVD_SCANNER_H */
