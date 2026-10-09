/* ==========================================================================
 * pml4_scan.h -- скан kernel-half PML4 (пост "scan_kernel_page_tables") +
 *                глубокий физический walker таблиц страниц + VAD-сканер
 * --------------------------------------------------------------------------
 * Источник: аудит упущенного agent-515 (AUDIT_MISSED_AC.md §1, §3) +
 * готовые тела sln_candidate_ac_pml4_scan.c. Корпуса: strings.c:7518-7753
 * (per-process сравнение), library_rest.c:22114-22909 (walker/триггер/
 * оркестратор/VAD), thunks.c:531 (MmCopyMemory-thunk). Все VA семейства до
 * аудита были mis-classified (ac_native_crt / ac_hole_dispatch / ЛОЖНЫЙ
 * владелец channels.c:AcChannelDrainEvents у 0x14006eb90); исправлено.
 * ========================================================================== */
#ifndef FACEIT_AC_PML4_SCAN_H
#define FACEIT_AC_PML4_SCAN_H

#include <fltKernel.h>   /* первым: идиома WDK minifilter (как events.c) */
#include <ntddk.h>

/* ---- недокументированные экспорты, использованные оригиналом --------------
 * (объявлены вручную: публичные WDK-заголовки их не несут; сигнатуры --
 * общеизвестные нативные формы) */
typedef struct _AC_HANDLE_TABLE_ENTRY {
    UINT_PTR VolatileLowValue;              /* +0x00 object-биты (>>0x10 & ~0xF) */
    UINT_PTR HighValue;                     /* +0x08 */
} AC_HANDLE_TABLE_ENTRY, *PAC_HANDLE_TABLE_ENTRY;

typedef struct _AC_HANDLE_TABLE {
    UINT8  Opaque[0x30];
    UINT_PTR PushLock;                      /* +0x30 (ExfUnblockPushLock сайт) */
} AC_HANDLE_TABLE, *PAC_HANDLE_TABLE;

typedef BOOLEAN (*PAC_ENUMHANDLE_CALLBACK)(
    PAC_HANDLE_TABLE HandleTable,
    PAC_HANDLE_TABLE_ENTRY HandleTableEntry,
    HANDLE Handle,
    PVOID EnumParameter);

NTKERNELAPI BOOLEAN ExEnumHandleTable(
    PAC_HANDLE_TABLE HandleTable,
    PAC_ENUMHANDLE_CALLBACK Callback,
    PVOID EnumParameter,
    PHANDLE Handle);

NTKERNELAPI PVOID ObGetObjectType(_In_ PVOID Object);

NTKERNELAPI ULONG PsGetProcessSessionId(_In_ PEPROCESS Process);

NTKERNELAPI NTSTATUS PsAcquireProcessExitSynchronization(
    _In_ PEPROCESS Process);

NTKERNELAPI VOID PsReleaseProcessExitSynchronization(
    _In_ PEPROCESS Process);

NTKERNELAPI VOID ExfUnblockPushLock(
    _Inout_ PEX_PUSH_LOCK PushLock,
    _In_opt_ PVOID WaitBlock);

#ifndef AC_MemorySectionName
/* класс 2 ZwQueryVirtualMemory (публичный enum знает только
 * MemoryBasicInformation=0) */
#define AC_MemorySectionName  ((MEMORY_INFORMATION_CLASS)2)
#endif

/* ---- аккумулятор расхождений PT-walk (layout дословно из FUN_14006d584) -- */
typedef struct _AC_PTWALK_ACC {
    UINT8  Active;          /* +0x00 есть незакрытый диапазон */
    UINT8  _pad[7];
    UINT64 Va;              /* +0x08 база диапазона */
    UINT64 Length;          /* +0x10 длина (склеивание соседних) */
    UINT32 Field0;          /* +0x18..+0x20 поля VM-эмиттера (формат отчёта */
    UINT32 Field1;          /*      payload-selected; переносятся дословно) */
    UINT32 Field2;
    UINT64 Field3;          /* +0x28 */
    UINT32 Field4;          /* +0x30 */
    UINT64 Pte;             /* +0x38 сырые биты PTE записи-источника */
} AC_PTWALK_ACC;            /* 0x40 */

/* ---- физическое чтение -------------------------------------------------- */
/* [0x14004fe58] MmCopyMemory-thunk: чтение таблиц ПО ФИЗИКЕ (pfn << 12) */
NTSTATUS AcPhysReadPage(_Out_ VOID* Dst, _In_ UINT64 PhysAddr, _In_ SIZE_T Len);

/* PsProcessType объявлен в ntddk.h (POBJECT_TYPE*) */

/* ---- глубокий физический walker (нижние уровни) -------------------------- */
/* [0x14006dbb0] драйвер рекурсивного обхода: снимок g_Pml4Snapshot[0..0xFF] */
VOID AcPtwalkDeepScan(_In_ PVOID Ctx);
/* [0x14006da00] уровень записей PML4 (страница PDPT; PS -> 1GB лист) */
VOID AcWalkPml4Level(_In_ UINT64 Pfn, _Inout_ UINT32* Pml4IdxIo,
                     _In_ PVOID Ctx, _Inout_ AC_PTWALK_ACC* Acc,
                     _In_ UINT64* ScratchPdpt, _In_ UINT64* ScratchPd,
                     _In_ UINT64* ScratchPt);
/* [0x14006d80c] уровень PDPT (страница PD; PS -> 2MB лист) */
VOID AcWalkPdptLevel(_In_ UINT64 Pfn, _Inout_ UINT32* Pml4IdxIo,
                     _Inout_ UINT32* PdptIdxIo, _In_ PVOID Ctx,
                     _Inout_ AC_PTWALK_ACC* Acc,
                     _In_ UINT64* ScratchPd, _In_ UINT64* ScratchPt);
/* [0x14006d65c] уровень PD/PT (страница PT; сверка 4KB трансляций) */
VOID AcWalkPdLevel(_In_ UINT64 Pfn, _Inout_ UINT32* Pml4IdxIo,
                   _Inout_ UINT32* PdptIdxIo, _Inout_ UINT32* PdIdxIo,
                   _In_ PVOID Ctx, _Inout_ AC_PTWALK_ACC* Acc,
                   _In_ UINT64* ScratchPt);
/* [0x14006d584] аккумулятор: склейка соседних VA-диапазонов */
VOID AcPtwalkAccAdd(_Inout_ AC_PTWALK_ACC* Acc, _In_ UINT64 Va, _In_ UINT64 Len,
                    _In_ UINT32 F0, _In_ UINT32 F1, _In_ UINT32 F2,
                    _In_ UINT64 F3, _In_ UINT32 F4, _In_ const UINT64* PtePtr,
                    _In_ PVOID Ctx);
/* [0x14006d530] flush аккумулятора */
VOID AcPtwalkAccFlush(_Inout_ AC_PTWALK_ACC* Acc, _In_ PVOID Ctx);
/* [0x14006d208] VM-эмиттер отчёта (jumptable -> [0x14018179c]) */
VOID AcPtwalkAccEmit(_In_ UINT64 Va, _In_ UINT64 Len, _In_ UINT32 F0,
                     _In_ UINT32 F1, _In_ UINT32 F2, _In_ UINT64 F3,
                     _In_ UINT32 F4, _In_ UINT64 Pte, _In_ PVOID Ctx);

/* ---- per-process сравнение kernel-half PML4 ------------------------------ */
/* [0x14006eb90] scan_kernel_page_tables: цикл 0x100..0x1FF live vs copy */
VOID AcScanKernelPageTables(_Inout_ PLIST_ENTRY SessionList,
                            _In_ PEPROCESS Process);

/* ---- триггеры ------------------------------------------------------------ */
/* [0x14006f1d0] перебор процессов через ExEnumHandleTable */
VOID AcPml4ScanAllProcesses(VOID);
/* [0x14006f12c] callback хендлов: фильтр PsProcessType -> скан */
BOOLEAN AcPml4ScanHandleCb(_In_ PAC_HANDLE_TABLE HandleTable,
                           _In_ PAC_HANDLE_TABLE_ENTRY HandleTableEntry,
                           _In_ HANDLE Handle, _In_ PVOID EnumParameter);
/* [0x1400687e8] оркестратор тика: image-name -> deep-walk -> VAD-скан */
VOID AcPageTableScanTick(_In_ UINT8 Arg1, _In_ UINT8 Arg2);

/* ---- VAD-сканер ---------------------------------------------------------- */
/* [0x14006ccec] ZwQueryVirtualMemory-цикл по VA текущего процесса */
VOID AcVadScanProcess(_In_ UINT8 Reserved, _In_ UINT8 RecordExecutable,
                      _In_ PVOID Ctx);
/* [0x14006914c] запись подозрительного региона (VM-диспетч) */
VOID AcVadScanRecord(_In_ const VOID* Mbi, _In_ PVOID Ctx);

#endif /* FACEIT_AC_PML4_SCAN_H */
