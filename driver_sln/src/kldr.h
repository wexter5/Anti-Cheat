/* ==========================================================================
 * kldr.h -- инвентарь kernel-модулей (KLDR-снапшот), lookup addr->module,
 *           FNV-резолвер экспортов, разрешение импортов
 * ========================================================================== */
#ifndef FACEIT_AC_KLDR_H
#define FACEIT_AC_KLDR_H

#include <ntddk.h>

/* [0x140026f68] fnv_eat_resolver: in-image обходчик экспортов, матч FNV-1a-64 */
PVOID AcResolveExport(_In_ UINT64 ModuleBase, _In_ UINT64 NameHash);

/* разрешить экспорт по plain-имени (сначала хэширует fnv1a) */
PVOID AcResolveExportByName(_In_z_ const char* Name);

/* [0x14024af8e] api_resolve_orchestrator: разрешить полную парную таблицу
 * (259 resolve'ов) в .data XOR-pair ячейки */
NTSTATUS AcResolveAllImports(VOID);

/* [0x1400010a4] addr->module: диапазонный lookup по двум спискам
 * (параметрический + глобальный снапшот 0x140107020) под локами */
PVOID AcAddrToModule(_In_ UINT64 Address, _Out_opt_ UINT64* ModuleBase,
                     _Out_opt_ UINT64* ModuleSize);

/* [0x14009bab0] build_modinv_from_kldr: записи инвентаря модулей (0x70B) */
NTSTATUS AcKldrBuildInventory(VOID);

/* [0x140006a90] шаг скана списка модулей P0 (QSI 0x0B + lowercase имена) */
NTSTATUS AcKldrScanModuleNames(VOID);

/* [0x14001f5c8] обход find_netio_module (tail-сравнение, возвращает базу) */
UINT64 AcKldrFindModuleByName(_In_z_ const char* ShortName);

/* перечислитель снапшота (для сканеров): idx < count -> base/size/name */
NTSTATUS AcKldrGetModule(_In_ UINT32 Index, _Out_ UINT64* Base,
                         _Out_ UINT64* Size,
                         _Out_writes_z_(NameChars) WCHAR* Name,
                         _In_ UINT32 NameChars);
UINT32 AcKldrModuleCount(VOID);

/* [region_102/292] kernel_module_inventory_weak_enum: обход weak-enum
 * хэш-таблицы -> записи 80B -> канал (COVERAGE_INVENTORY #2.10) */
NTSTATUS AcModuleInventoryWeakEnum(VOID);

/* [0x14009bab0] полный путь образа модуля снапшота (файловые сканы) */
NTSTATUS AcKldrGetModulePath(_In_ UINT32 Index,
                             _Out_writes_z_(PathChars) WCHAR* Path,
                             _In_ UINT32 PathChars);

/* [0x140003574] pool_alloc_zeroed */
PVOID AcPoolAllocZeroed(_In_ SIZE_T Size);

/* [0x1400024f4] fnv1a_tail_hasher: FNV-1a-64 по имени */
UINT64 AcFnv1a64(_In_z_ const char* Name);

#endif /* FACEIT_AC_KLDR_H */
