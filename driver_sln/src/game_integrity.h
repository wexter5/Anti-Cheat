/* ==========================================================================
 * game_integrity.h -- пайплайн verified-модулей + BYOVD-блоклист
 * ========================================================================== */
#ifndef FACEIT_AC_GAME_INTEGRITY_H
#define FACEIT_AC_GAME_INTEGRITY_H

#include <ntddk.h>
#include "ioctl.h"

/* [0x14009cca0] lookup verified_module_cache: находится ли адрес внутри
 * секции подписанного модуля (с кэшем)? */
BOOLEAN GameIntegrityIsAddressVerified(_In_ UINT64 Address);

/* [0x140042034] module_verify_path: полная верификация файла модуля */
NTSTATUS GameIntegrityVerifyModule(_In_z_ const WCHAR* ModulePath,
                                   _Out_ BOOLEAN* Verified);

/* [0x140002524] authenticode_blob_extract: var-len Authenticode-блоб
 * файла (питает событие 0x2B) */
NTSTATUS GameIntegrityExtractSignature(_In_z_ const WCHAR* Path,
                                       _Out_ UINT8* Blob,
                                       _Inout_ UINT32* BlobSize);

/* push-обработчики: питания BYOVD-вочлиста (семейство 0xC350) */
NTSTATUS GameIntegrityPushVendorCn(_In_ const VOID* Buf, _In_ UINT32 Len);
NTSTATUS GameIntegrityPushDriverHash(_In_ const VOID* Buf, _In_ UINT32 Len);
NTSTATUS GameIntegrityPushU64Set(_In_ const VOID* Buf, _In_ UINT32 Len);
NTSTATUS GameIntegrityPushWatchlist(_In_ const VOID* Buf, _In_ UINT32 Len);

/* [0x14001bd3c] byovd_scanner (~90 целевых устройств) */
NTSTATUS GameIntegrityByovdScan(VOID);

/* [0x140013da8] shim_scanner (артефакты AppCompat/shim) */
NTSTATUS GameIntegrityShimScan(VOID);

/* воч-набор целостности игры (CS2) + верификация Winsock LSP */
BOOLEAN GameIntegrityIsWatchedProcess(_In_z_ const WCHAR* ImageName);
BOOLEAN GameIntegrityIsCs2Path(_In_z_ const WCHAR* Path);
BOOLEAN GameIntegrityHasToolsFlag(_In_z_ const WCHAR* CommandLine);
NTSTATUS GameIntegrityReadGameConfigStore(VOID);
NTSTATUS GameIntegrityVerifyWinsockLsp(VOID);

/* убийство/заморозка/инспекция процессов (реакционный контур) */
BOOLEAN GameIntegrityIsProtectedProcess(_In_z_ const WCHAR* ProcessName);
NTSTATUS GameIntegrityFreezeProcess(_In_ UINT64 Pid);
NTSTATUS GameIntegrityTerminateProcess(_In_ UINT64 Pid,
                                       _In_ NTSTATUS ExitStatus);
NTSTATUS GameIntegrityInspectProcess(_In_ UINT64 Pid);
NTSTATUS GameIntegrityProcessAction(_In_ UINT64 Pid,
                                    _In_z_ const WCHAR* ProcessName,
                                    _In_ UINT32 Action);

/* [0x140067c5c] проверка IFEO-hijack */
NTSTATUS GameIntegrityCheckIfeo(VOID);

/* [0x1400a52e8]/[0x1400a52d0] allow-list издателей (Microsoft/Valve) */
BOOLEAN GameIntegrityIsAllowedIssuer(_In_z_ const char* Issuer);

/* [0x140234578]/[0x1401074e0] поток валидации ci.dll
 * (CiValidateFileObject; payload-гейтовано в трейсах) */
NTSTATUS GameIntegrityVerifyCi(_In_z_ const WCHAR* Path,
                               _Out_ NTSTATUS* CiStatus);

#endif /* FACEIT_AC_GAME_INTEGRITY_H */
