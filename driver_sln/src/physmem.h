/* ==========================================================================
 * physmem.h -- контур phys/mem/process (FILL_LIST P5)
 * ========================================================================== */
#ifndef FACEIT_AC_PHYSMEM_H
#define FACEIT_AC_PHYSMEM_H

#include <ntddk.h>

/* [0x140107770] pair-ячейка MmMapViewInSystemSpace (83 сайта использования:
 * кластеры @0x141a64ec8/0x140c23d4b/0x140c23d62/0x140bb4c97,
 * census-top 0x140cd7c03) */
NTSTATUS AcMmMapSection(_In_ HANDLE Section, _Out_ PVOID* Base,
                        _Inout_ PSIZE_T ViewSize);

/* [0x1401077d0] pair-ячейка MmUnmapViewInSystemSpace */
VOID AcMmUnmapSection(_In_ PVOID Base);

/* [0x1401082d0] pair-ячейка MmGetPhysicalAddress (30 сайтов:
 * @0x14078fe37/0x140a24e68/0x140a24e9e/0x1412b2788, census-top
 * 0x1403b040a, replay-чтения x14) */
UINT64 AcMmGetPhysicalAddress(_In_ CONST VOID* Va);

/* [0x140107990] pair-ячейка MmSystemRangeStart (24 raw): валидация
 * класса адреса для логики сканов */
BOOLEAN AcMmIsKernelAddress(_In_ CONST VOID* Va);

/* [0x140108150] pair-ячейка MmAllocateMdlForIoSpace (21 сайт:
 * @0x140921170/0x140921a00/0x140921a19, census-top 0x14091f591) */
PMDL AcMmAllocateMdlForIoSpace(_In_ UINT64 PhysAddress, _In_ UINT32 Size);

/* [0x1401079b0] pair-ячейка MmIsAddressValid (15 raw, gt=60): предикат
 * safe-read для сканеров */
BOOLEAN AcMmSafeRead(_In_ CONST VOID* Src, _Out_ PVOID Dst,
                     _In_ UINT32 Size);

/* [0x140107650] pair-ячейка ZwAllocateVirtualMemory (14 сайтов:
 * @0x140876fdb/0x140876ff1, census-top 0x1408751a0) */
NTSTATUS AcZwAllocateVirtualMemory(_In_ UINT64 Size, _Out_ PVOID* Base);

/* [0x140107c10] pair-ячейка ZwQueryInformationThread (30 сайтов:
 * @0x14149c1e3/0x14149b854, census-top 0x141492278) */
NTSTATUS AcThreadQueryStartAddress(_In_ HANDLE Thread,
                                   _Out_ UINT64* StartAddress);

/* [0x140107480] PsAcquireProcessExitSynchronization (25 сайтов:
 * resolve @0x1403a267e, вызовы @0x14211435a/0x1447f447d/0x1447f7b4b)
 * [0x1401073e0] PsReleaseProcessExitSynchronization (21 сайт:
 * @0x14230aa94/0x14230aaa0, census-top 0x1401999d1)
 * exit-guard пара, обрамляющая окна инспекции процесса */
VOID AcProcessExitGuardEnter(_In_ PEPROCESS Process);
VOID AcProcessExitGuardLeave(_In_ PEPROCESS Process);

#endif /* FACEIT_AC_PHYSMEM_H */
