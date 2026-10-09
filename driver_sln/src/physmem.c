/* ==========================================================================
 * physmem.c -- контур phys/mem/process (FILL_LIST P5, все 10)
 * --------------------------------------------------------------------------
 * Ячейки импортов -- разрешённые pair-ячейки 259-таблицы (ячейки в
 * provenance каждой функции; сайты использования по FILL_LIST.md /
 * import_links.jsonl). Каждая обёртка несёт восстановленную роль контура;
 * разводка call-сайтов: маппинг секций (пути verify), трансляция phys
 * (HWID-коллекторы), MDL-маппинг (deferred-чтение PCI ECAM), safe-read
 * (сканеры BYOVD/паттернов), аллокация VM, интроспекция потоков/процессов
 * (реакционный контур).
 * ========================================================================== */
#include <ntddk.h>

#include "provenance.h"
#include "tables.h"
#include "physmem.h"

/* ZwAllocateVirtualMemory отсутствует в km-заголовках этого WDK */
NTSYSAPI
NTSTATUS
NTAPI
ZwAllocateVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _In_ UINT64 ZeroBits,
    _Inout_ PUINT64 RegionSize,
    _In_ UINT32 AllocationType,
    _In_ UINT32 Protect
    );

/* также здесь отсутствуют; публичные контракты */
NTSYSAPI
NTSTATUS
NTAPI
ZwQueryInformationThread(
    _In_ HANDLE ThreadHandle,
    _In_ UINT32 ThreadInformationClass,
    _Out_ PVOID ThreadInformation,
    _In_ UINT32 ThreadInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

NTKERNELAPI
VOID
NTAPI
PsAcquireProcessExitSynchronization(
    _In_ PEPROCESS Process
    );

NTKERNELAPI
VOID
NTAPI
PsReleaseProcessExitSynchronization(
    _In_ PEPROCESS Process
    );

/* --------------------------------------------------------------------------
 * Маппинг секций (system space).
 * [0x140107770] MmMapViewInSystemSpace: verify-потоки отображают файлы
 * модулей через section-объекты в system space (дословный поток
 * verify_wsp_file [0x140043a10] использует ровно этот примитив; другие
 * живые кластеры: @0x141a64ec8, @0x140c23d4b, @0x140c23d62, @0x140bb4c97,
 * census-top 0x140cd7c03 -- 83 сайта использования, FILL_LIST #1)
 * [0x1401077d0] MmUnmapViewInSystemSpace: парный teardown
 * ------------------------------------------------------------------------ */
NTSTATUS
AcMmMapSection(
    _In_ HANDLE Section,
    _Out_ PVOID* Base,
    _Inout_ PSIZE_T ViewSize
    )
{
    *Base = NULL;
    return MmMapViewInSystemSpace(Section, Base, ViewSize);
}

/* [0x1401077d0] pair-ячейка MmUnmapViewInSystemSpace (teardown) */
VOID
AcMmUnmapSection(
    _In_ PVOID Base
    )
{
    if (Base != NULL)
        MmUnmapViewInSystemSpace(Base);
}

/* --------------------------------------------------------------------------
 * Трансляция virtual->physical (HWID-коллекторы).
 * [0x1401082d0] MmGetPhysicalAddress: коллекторы транслируют виртуальные
 * адреса отображённых firmware-структур в физические для шагов маппинга
 * (usage: @0x14078fe37, @0x140a24e68, @0x140a24e9e, @0x1412b2788,
 * census-top 0x1403b040a; replay-чтения x14) -- используется путём SMBIOS
 * для cross-check'а entry-point/базы таблицы и контуром PCI ECAM для
 * валидации базы маппинга
 * ------------------------------------------------------------------------ */
UINT64
AcMmGetPhysicalAddress(
    _In_ CONST VOID* Va
    )
{
    PHYSICAL_ADDRESS phys = MmGetPhysicalAddress((PVOID)Va);
    return (UINT64)phys.QuadPart;
}

/* --------------------------------------------------------------------------
 * Валидация класса адреса.
 * [0x140107990] MmSystemRangeStart (24 raw): указатели, подаваемые в
 * kernel-логику сканов (сканы образов модулей, обходы EAT), обязаны лежать
 * на/выше начала system-диапазона -- граничная проверка сканеров
 * ------------------------------------------------------------------------ */
BOOLEAN
AcMmIsKernelAddress(
    _In_ CONST VOID* Va
    )
{
    return (UINT64)Va >= (UINT64)MmSystemRangeStart;
}

/* --------------------------------------------------------------------------
 * MDL-маппинг I/O-пространства.
 * [0x140108150] MmAllocateMdlForIoSpace: MDL-маппинг физических диапазонов
 * (usage: @0x140921170, @0x140921a00, @0x140921a19, census-top
 * 0x14091f591) -- контур deferred/shadow-чтения PCI ECAM отображает
 * страницу ECAM через MDL вместо обычного MmMapIoSpace, когда deferred-
 * движок вооружён
 * ------------------------------------------------------------------------ */
PMDL
AcMmAllocateMdlForIoSpace(
    _In_ UINT64 PhysAddress,
    _In_ UINT32 Size
    )
{
    MM_PHYSICAL_ADDRESS_LIST list;
    PMDL mdl = NULL;

    list.PhysicalAddress.QuadPart = (INT64)PhysAddress;
    list.NumberOfBytes = Size;

    if (NT_SUCCESS(MmAllocateMdlForIoSpace(&list, 1, &mdl)))
        return mdl;
    return NULL;
}

/* --------------------------------------------------------------------------
 * Предикат safe-read.
 * [0x1401079b0] MmIsAddressValid (15 raw, uses_gt=60): охраняемое
 * копирование для сканеров (скан паттернов BYOVD по диапазонам модулей,
 * обход EAT резолвера) -- страница может быть выгружена под валидно
 * выглядящим указателем; предикат -- гард чтения драйвера
 * ------------------------------------------------------------------------ */
BOOLEAN
AcMmSafeRead(
    _In_ CONST VOID* Src,
    _Out_ PVOID Dst,
    _In_ UINT32 Size
    )
{
    if (!MmIsAddressValid((PVOID)Src) ||
        !MmIsAddressValid((PVOID)((const UINT8*)Src + Size - 1)))
        return FALSE;

    __try {
        RtlCopyMemory(Dst, Src, Size);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
    return TRUE;
}

/* --------------------------------------------------------------------------
 * Аллокация виртуальной памяти.
 * [0x140107650] ZwAllocateVirtualMemory (14 сайтов: @0x140876fdb,
 * @0x140876ff1, census-top 0x1408751a0): приватные VM-аллокации механики
 * (hook-infra контур также резолвит NtAllocateVirtualMemory 0x1401f1e95
 * для той же цели)
 * ------------------------------------------------------------------------ */
NTSTATUS
AcZwAllocateVirtualMemory(
    _In_ UINT64 Size,
    _Out_ PVOID* Base
    )
{
    UINT64 regionSize = Size;

    *Base = NULL;
    return ZwAllocateVirtualMemory(ZwCurrentProcess(), Base, 0,
                                   &regionSize,
                                   MEM_COMMIT | MEM_RESERVE,
                                   PAGE_READWRITE);
}

/* --------------------------------------------------------------------------
 * Интроспекция потоков.
 * [0x140107c10] ZwQueryInformationThread (30 сайтов: @0x14149c1e3,
 * @0x14149b854, census-top 0x141492278): self-check поток воркайтем-
 * механики (KEVLAR_PHASE2 §4.1: PsGetThreadProcessId==4 System,
 * PsIsThreadTerminating, ObOpenObjectByPointer, ZwQueryInformationThread,
 * ZwClose) запрашивает старт-адрес потока (класс
 * ThreadQuerySetWin32StartAddress = 9)
 * ------------------------------------------------------------------------ */
NTSTATUS
AcThreadQueryStartAddress(
    _In_ HANDLE Thread,
    _Out_ UINT64* StartAddress
    )
{
    ULONG retLen = 0;

    *StartAddress = 0;
    return ZwQueryInformationThread(Thread,
                                    9 /* ThreadQuerySetWin32StartAddress */,
                                    StartAddress, sizeof(*StartAddress),
                                    &retLen);
}

/* --------------------------------------------------------------------------
 * Гард-пара process-exit.
 * [0x140107480] PsAcquireProcessExitSynchronization (25 сайтов: resolve
 * @0x1403a267e; вызовы @0x14211435a, @0x1447f447d, @0x1447f7b4b)
 * [0x1401073e0] PsReleaseProcessExitSynchronization (21 сайт:
 * @0x14230aa94, @0x14230aaa0, census-top 0x1401999d1)
 * Пара обрамляет окна инспекции процесса: цель не может схлопнуться
 * посреди инспекции (используется путём inspect/freeze реакционного
 * контура)
 * ------------------------------------------------------------------------ */
VOID
AcProcessExitGuardEnter(
    _In_ PEPROCESS Process
    )
{
    PsAcquireProcessExitSynchronization(Process);
}

/* [0x1401073e0] PsReleaseProcessExitSynchronization (leave-половина
 * exit-guard пары [0x140107480] выше) */
VOID
AcProcessExitGuardLeave(
    _In_ PEPROCESS Process
    )
{
    PsReleaseProcessExitSynchronization(Process);
}
