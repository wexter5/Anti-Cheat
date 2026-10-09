/* ==========================================================================
 * thread_capture.c -- захват контекста потока + phys-guard страницы
 * --------------------------------------------------------------------------
 * Интеграция аудита упущенного (agent-515,
 * _research_tmp/audit_ac_missed/AUDIT_MISSED_AC.md §3).
 *
 * [0x14008846c] -- кейс-образец аудита: внешний пост "capture_thread_information",
 * тело ЕСТЬ в корпусе (library_rest.c:23904-23946), но класс ac_native_crt /
 * тег [dead-native] не пустил его в Reference Reconstruction (va_map
 * mis-classified; исправлено: владелец thread_capture.c). Порт verbatim.
 *
 * [0x1400883b4] -- phys-guard (сосед capture_thread_information,
 * library_rest.c:23868-23901), тоже был ac_native_crt; исправлено.
 * ========================================================================== */
#include <ntddk.h>
#include <intrin.h>

#include "provenance.h"
#include "tables.h"
#include "thread_capture.h"

C_ASSERT(sizeof(AC_THREAD_CTX_SLOT) == AC_THREAD_CTX_SLOT_STRIDE);

/* --------------------------------------------------------------------------
 * [0x14008846c] capture_thread_information (FUN_14008846c,
 * library_rest.c:23907-23946, [dead-native] -- вызывается из sealed VM-
 * фреймов, статически недостижим).
 *
 * Дословная семантика тела:
 *   cpu = KeGetCurrentProcessorNumberEx(NULL);
 *   слот = base + cpu * 0x116 dword'ов (stride 0x458);
 *   если слот->filled != 0 -> return 1 (заполнение только по !filled);
 *   слот->thread    = qword gs:0x188          (KPCR.CurrentThread = ETHREAD);
 *   слот->tid       = PsGetCurrentThreadId();
 *   слот->pid       = PsGetCurrentProcessId();
 *   слот->fA/fB/fC  = qword'ы ETHREAD + build-офсеты [0x14010910c] /
 *                     [0x1401091b0] / [0x1401091b4] (ячейки .data; значения
 *                     вычисляет резолвер офсетов семейства [0x1400640b0] --
 *                     payload-selected значения);
 *   слот->dw80      = dword ETHREAD + 0x80;
 *   слот->cr3       = in_CR3 (CR3 на входе в функцию);
 *   слот->kpcrE0    = dword [qword gs:0x18 (KPCR.SelfPcr) + 0xe0];
 *   uVar4 = ((ULONG_PTR)&frame_end & ~0xFFF) - (ULONG_PTR)&frame;
 *   if (0x400 < uVar4) uVar4 = 0x400;        -- кап глубины дампа;
 *   слот->dumpLen   = uVar4;
 *   ac_memmove(слот->dump, &frame, uVar4);   -- дамп живого стека;
 *   слот->filled    = 1;
 *   LOCK: *base += 1;                        -- счётчик буфера;
 *   return 1;
 * ------------------------------------------------------------------------ */
BOOLEAN
AcThreadContextCapture(
    _Inout_ AC_THREAD_CTX_CAPTURE* Capture
    )
{
    ULONG cpu;
    AC_THREAD_CTX_SLOT* slot;
    UINT8* thread;
    UINT_PTR framePtr;
    UINT64 dumpLen;
    UINT64 kpcrSelf;

    cpu = KeGetCurrentProcessorNumberEx(NULL);
    slot = &Capture->Slots[cpu];

    if (slot->Filled != 0)
        return TRUE;

    /* qword gs:0x188 -- текущий ETHREAD (KPCR.CurrentThread) */
    thread = (UINT8*)KeGetCurrentThread();
    slot->Thread    = (UINT64)thread;
    slot->ThreadId  = (UINT64)PsGetCurrentThreadId();
    slot->ProcessId = (UINT64)PsGetCurrentProcessId();

    /* qword'ы ETHREAD по build-зависимым офсетам из ячеек .data
     * (payload-selected значения: семейство резолвера [0x1400640b0]) */
    slot->EthreadFieldA = *(UINT64*)(thread + AC_SLOT32(AC_CELL_ETHREAD_OFF_A));
    slot->EthreadFieldB = *(UINT64*)(thread + AC_SLOT32(AC_CELL_ETHREAD_OFF_B));
    slot->EthreadFieldC = *(UINT64*)(thread + AC_SLOT32(AC_CELL_ETHREAD_OFF_C));
    slot->EthreadDword80 = *(UINT32*)(thread + 0x80);

    /* in_CR3 -- значение CR3 на входе */
    slot->Cr3 = __readcr3();

    /* dword [gs:0x18 (KPCR.SelfPcr) + 0xe0] -- чтение KPCR */
    kpcrSelf = __readgsqword(0x18);
    slot->KpcrDwordE0 = *(UINT32*)(kpcrSelf + 0xe0);

    /* глубина дампа живого стека, кап 0x400. Дословная арифметика
     * оригинала: ((ULONG_PTR)&frame_end & ~0xFFF) - (ULONG_PTR)&frame,
     * затем min(0x400); для кадра в пределах страницы разность
     * беззнаково «огромна» -> всегда срабатывает кап 0x400 */
    framePtr = (UINT_PTR)&framePtr;
    dumpLen = 0x1000 - (UINT64)(framePtr & 0xFFF);
    if (dumpLen > AC_THREAD_CTX_STACK_CAP)
        dumpLen = AC_THREAD_CTX_STACK_CAP;
    slot->StackDumpLen = dumpLen;
    RtlCopyMemory(slot->StackDump, (const VOID*)framePtr, (SIZE_T)dumpLen);

    slot->Filled = 1;

    /* LOCK-инкремент счётчика буфера (первые 4 байта аллокации) */
    InterlockedIncrement(&Capture->FilledSlots);

    return TRUE;
}

/* --------------------------------------------------------------------------
 * [0x1400883b4] phys-guard идентичности страницы (FUN_1400883b4,
 * library_rest.c:23871-23901). Сверка: VA вне границ собственного образа ->
 * MmGetPhysicalAddress(va & ~0xFFF) == ([0x140108c60] ^ [0x140108c58])
 * (XOR-пара ожидаемого физадреса; пара «вооружена», когда ячейки различны).
 *
 * [0x140109690] дескриптор границ собственного образа {+8 base, +0x10 size}
 * (genuinely live state: 0 писателей по кампании chainstate -- payload-selected
 * содержимое); [0x140107020] голова KLDR-снапшота: +0x30 base, +0x40 size
 * первого модуля (свой драйвер). Опорный адрес якоря возвращает VM-трамп
 * (ac_vmentry_tramp_gs_088c34 -> [0x1403cb2dd]) -- payload-selected;
 * нейтральная форма: якорь отсутствует (0), ветка якоря пропускается.
 * ------------------------------------------------------------------------ */
BOOLEAN
AcPhysPageIdentityCheck(
    _In_ UINT64 Va
    )
{
    const UINT8* bounds;
    UINT64 base;
    UINT32 size;
    UINT64 anchor;
    const UINT8* snap;
    UINT64 ownBase;
    UINT32 ownSize;
    PHYSICAL_ADDRESS phys;

    bounds = (const UINT8*)AC_SLOTP(AC_CELL_FLAVOR_BOUNDS);
    base = (bounds != NULL) ? *(const UINT64*)(bounds + 8) : 0;
    size = (bounds != NULL) ? *(const UINT32*)(bounds + 0x10) : 0;

    if (bounds != NULL && base <= Va && Va < base + size)
        return TRUE;                /* внутри границ -- страница «своя» */

    /* payload-selected: опорный VA от VM-трампа [0x1403cb2dd]; нейтрально 0 */
    anchor = 0;
    if (anchor != 0 && anchor <= Va && Va < anchor + 0x1000) {
        snap = (const UINT8*)AC_SLOTP(AC_CELL_KLDR_SNAPSHOT);
        ownBase = *(const UINT64*)(snap + 0x30);
        ownSize = *(const UINT32*)(snap + 0x40);
        if (anchor < ownBase || ownBase + ownSize < anchor)
            return TRUE;
    }

    if (AC_SLOT64(AC_CELL_PHYS_EXPECT_HI) != AC_SLOT64(AC_CELL_PHYS_EXPECT_LO)) {
        phys = MmGetPhysicalAddress((PVOID)(Va & ~(UINT64)0xFFF));
        if (phys.QuadPart != 0) {
            return (UINT64)phys.QuadPart ==
                   (AC_SLOT64(AC_CELL_PHYS_EXPECT_HI) ^
                    AC_SLOT64(AC_CELL_PHYS_EXPECT_LO));
        }
    }
    return FALSE;
}
