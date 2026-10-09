/* ==========================================================================
 * pml4_scan.c -- скан kernel-half PML4 + глубокий физический walker + VAD
 * --------------------------------------------------------------------------
 * Интеграция аудита упущенного (agent-515, AUDIT_MISSED_AC.md §1/§3).
 * Пост "scan_kernel_page_tables": два указателя (current vs copied PML4),
 * цикл 0x100..0x1FF, PFN-маска 0x0000FFFFFFFFF000, репорт type 0x12
 * (запись 0x658 -- тот же размер, что у session_rec12_producer
 * [0x140073c04]). Совпадение сигнатур поста полное.
 *
 * Карта provenance (тела):
 *   strings.c:7518-7753      FUN_14006eb90  per-process сравнение
 *   library_rest.c:22114-163 FUN_1400687e8  оркестратор
 *   library_rest.c:22395-475 FUN_14006ccec  VAD-сканер
 *   library_rest.c:22478-604 FUN_14006d530/584/65c  аккумулятор + PD/PT
 *   library_rest.c:22608-792 FUN_14006d80c/da00     PDPT/PML4 уровни
 *   library_rest.c:22795-909 FUN_14006dbb0/f12c/f1d0 драйвер + триггер
 *   thunks.c:531             FUN_14004fe58  MmCopyMemory-thunk
 *
 * Наполнение зеркала [0x140108dd8] -- sealed gotovm-фрейм ~0x14354d903
 * (payload-selected инициализация; сам сравниватель нативный).
 * ========================================================================== */
#include "provenance.h"
#include "pml4_scan.h"
#include "tables.h"
#include "channels.h"
#include "events.h"

#ifndef MEM_IMAGE
#define MEM_IMAGE   0x1000000   /* Type: образ (дословная маска из тела) */
#endif
#ifndef MEM_COMMIT
#define MEM_COMMIT  0x1000      /* State: committed */
#endif

#define AC_PML4_TAG  'PML4'

/* [0x140108dd8] зеркало системной PML4 (0x1000 байт = 512 записей).
 * Область частично за пределами захваченного окна g_pslots (0x140106000..
 * 0x140109d58); наполняется sealed gotovm-фреймом ~0x14354d903
 * (payload-selected) -> отдельное хранилище модуля. */
static UINT64 g_AcPml4Snapshot[0x200];

/* VA глобала-зеркала в оригинале (индекс self-map окна считается из него) */
#define AC_PML4_SNAPSHOT_VA  0x140108dd8ULL

/* PFN-маски оригинала */
#define AC_PTE_PFN_MASK   0xFFFFFFFFFULL         /* pfn = entry >> 0xc & mask */
#define AC_PML4_PFN_XOR   0xFFFFFFFFF000ULL      /* (cur ^ old) & mask */

/* helper: pool_alloc_zeroed -- идиома корпуса (FUN_140003574) */
static PVOID
AcPml4AllocZeroed(
    _In_ SIZE_T Size
    )
{
    PVOID p = ExAllocatePool2(POOL_FLAG_NON_PAGED, Size, AC_PML4_TAG);
    if (p != NULL)
        RtlZeroMemory(p, Size);
    return p;
}

/* --------------------------------------------------------------------------
 * [0x14004fe58] AcPhysReadPage (thunks.c:531 = чистый passthrough
 * MmCopyMemory). Walker читает таблицы страниц ПО ФИЗИКЕ:
 * (dst, pfn << 0xc, 0x1000) -- обход виртуальных перехватов.
 * ------------------------------------------------------------------------ */
NTSTATUS
AcPhysReadPage(
    _Out_ VOID* Dst,
    _In_ UINT64 PhysAddr,
    _In_ SIZE_T Len
    )
{
    PHYSICAL_ADDRESS pa;
    MM_COPY_ADDRESS src;
    SIZE_T copied = 0;

    pa.QuadPart = (LONGLONG)PhysAddr;
    src.PhysicalAddress = pa;
    return MmCopyMemory(Dst, src, Len, MM_COPY_MEMORY_PHYSICAL, &copied);
}

/* --------------------------------------------------------------------------
 * payload-selected: VM-хелперы walker'а. Трансляция VA по текущему CR3
 * (сайт ac_vmentry_tramp_06d118 -> [0x14030e625]) и фильтр зоны интереса
 * (сайт ac_vmentry_tramp_09c2a4 -> [0x140173bf4]) -- VM-тела, статически не
 * восстанавливаются. Нейтральные формы: трансляция совпала (расхождения
 * нет), фильтр не срабатывает -- walker не генерирует ложных расхождений.
 * ------------------------------------------------------------------------ */
static BOOLEAN
AcPtwalkVmTranslate(
    _In_ UINT64 Va,
    _Out_ UINT32* F0,
    _Out_ UINT32* F1,
    _Out_ UINT32* F2,
    _Out_ UINT64* F3,
    _Out_ UINT32* F4,
    _Out_ UINT64* Residual
    )
{
    UNREFERENCED_PARAMETER(Va);
    *F0 = 0;
    *F1 = 0;
    *F2 = 0;
    *F3 = 0;
    *F4 = 0;
    *Residual = 0;
    return TRUE;            /* нейтрально: трансляция успешна, остаток 0 */
}

/* payload-selected: фильтр зоны интереса VA (сайт ac_vmentry_tramp_09c2a4
 * -> [0x140173bf4]); нейтральная форма: FALSE */
static BOOLEAN
AcPtwalkVmFilterVa(
    _In_ UINT64 Va
    )
{
    UNREFERENCED_PARAMETER(Va);
    return FALSE;           /* нейтрально: VA вне зоны интереса */
}

/* --------------------------------------------------------------------------
 * [0x14006d208] VM-эмиттер отчёта расхождений PTE (jumptable ->
 * [0x14018179c]; кадр 0x2d8 байт). payload-selected: тело за VM-диспетчом
 * (класс был ac_hole_dispatch); поля переносятся дословно из аккумулятора.
 * ------------------------------------------------------------------------ */
VOID
AcPtwalkAccEmit(
    _In_ UINT64 Va,
    _In_ UINT64 Len,
    _In_ UINT32 F0,
    _In_ UINT32 F1,
    _In_ UINT32 F2,
    _In_ UINT64 F3,
    _In_ UINT32 F4,
    _In_ UINT64 Pte,
    _In_ PVOID Ctx
    )
{
    UNREFERENCED_PARAMETER(Va);
    UNREFERENCED_PARAMETER(Len);
    UNREFERENCED_PARAMETER(F0);
    UNREFERENCED_PARAMETER(F1);
    UNREFERENCED_PARAMETER(F2);
    UNREFERENCED_PARAMETER(F3);
    UNREFERENCED_PARAMETER(F4);
    UNREFERENCED_PARAMETER(Pte);
    UNREFERENCED_PARAMETER(Ctx);
}

/* --------------------------------------------------------------------------
 * [0x14006d530] flush аккумулятора: если диапазон открыт -- эмит и сброс
 * флага (дословно: if (*acc != 0) { emit(...); *acc = 0; })
 * ------------------------------------------------------------------------ */
VOID
AcPtwalkAccFlush(
    _Inout_ AC_PTWALK_ACC* Acc,
    _In_ PVOID Ctx
    )
{
    if (Acc->Active != 0) {
        AcPtwalkAccEmit(Acc->Va, Acc->Length, Acc->Field0, Acc->Field1,
                        Acc->Field2, Acc->Field3, Acc->Field4, Acc->Pte, Ctx);
        Acc->Active = 0;
    }
}

/* --------------------------------------------------------------------------
 * [0x14006d584] аккумулятор расхождений PTE: склеивает соседние VA-
 * диапазоны в одну запись (len += при совпадении всех полей и
 * непрерывности, иначе flush + перезапуск)
 * ------------------------------------------------------------------------ */
VOID
AcPtwalkAccAdd(
    _Inout_ AC_PTWALK_ACC* Acc,
    _In_ UINT64 Va,
    _In_ UINT64 Len,
    _In_ UINT32 F0,
    _In_ UINT32 F1,
    _In_ UINT32 F2,
    _In_ UINT64 F3,
    _In_ UINT32 F4,
    _In_ const UINT64* PtePtr,
    _In_ PVOID Ctx
    )
{
    if (Acc->Active == 0 || Acc->Va + Acc->Length != Va ||
        Acc->Field0 != F0 || Acc->Field1 != F1 || Acc->Field2 != F2 ||
        Acc->Field3 != F3 || Acc->Field4 != F4) {
        AcPtwalkAccFlush(Acc, Ctx);
        Acc->Active = 1;
        Acc->Va     = Va;
        Acc->Length = Len;
        Acc->Pte    = *PtePtr;
        Acc->Field0 = F0;
        Acc->Field1 = F1;
        Acc->Field2 = F2;
        Acc->Field3 = F3;
        Acc->Field4 = F4;
    }
    else {
        Acc->Length += Len;
    }
}

/* --------------------------------------------------------------------------
 * [0x14006d65c] уровень PD/PT (FUN_14006d65c): читает страницу PT по
 * физике; per present-записи с восстановленным VA (классические сдвиги
 * >>0x27/0x1e/0x15/0xc & 0x1ff) повторно транслирует VA через VM-хелпер
 * ([0x14030e625], текущий CR3); при расхождении + проходе фильтра
 * ([0x140173bf4]) записывает 4KB-расхождение (размер 0x1000). Ресинхронизация
 * индексов по транслированному VA (запись могла быть перенесена).
 * ------------------------------------------------------------------------ */
VOID
AcWalkPdLevel(
    _In_ UINT64 Pfn,
    _Inout_ UINT32* Pml4IdxIo,
    _Inout_ UINT32* PdptIdxIo,
    _Inout_ UINT32* PdIdxIo,
    _In_ PVOID Ctx,
    _Inout_ AC_PTWALK_ACC* Acc,
    _In_ UINT64* ScratchPt
    )
{
    NTSTATUS status;
    UINT32 i;

    status = AcPhysReadPage(ScratchPt, Pfn << 0xC, 0x1000);
    if (!NT_SUCCESS(status))
        return;

    i = 0;
    for (;;) {
        UINT64 entry = ScratchPt[i];
        UINT64 va;
        UINT32 f0, f1, f2, f4;
        UINT64 f3, residual;
        UINT64 tva;
        UINT32 newPml4, newPdpt, newPd, newPt;

        if ((entry & 1) == 0 || (INT64)entry < 0)
            goto advance;

        va = ((UINT64)*Pml4IdxIo << 0x27) | ((UINT64)*PdptIdxIo << 0x1E) |
             ((UINT64)*PdIdxIo << 0x15) | ((UINT64)i << 0xC);
        if (!AcPtwalkVmTranslate(va, &f0, &f1, &f2, &f3, &f4, &residual)) {
            if (AcPtwalkVmFilterVa(va)) {
                AcPtwalkAccAdd(Acc, va, 0x1000, f0, f1, f2, f3, f4,
                               &ScratchPt[i], Ctx);
            }
            goto advance;
        }

        /* трансляция успешна: ресинхронизация индексов по факту */
        tva = residual + va;
        newPml4 = (UINT32)(tva >> 0x27) & 0x1FF;
        newPdpt = (UINT32)(tva >> 0x1E) & 0x1FF;
        newPd   = (UINT32)(tva >> 0x15) & 0x1FF;
        newPt   = (UINT32)(tva >> 0xC) & 0x1FF;
        if (*Pml4IdxIo != newPml4 || *PdptIdxIo != newPdpt ||
            *PdIdxIo != newPd) {
            *Pml4IdxIo = newPml4;
            *PdptIdxIo = newPdpt;
            *PdIdxIo   = newPd;
            return;
        }
        if (i != newPt) {
            i = newPt;              /* ресинхронизация без +1 */
        }
        else {
advance:
            i = i + 1;
        }
        if (i > 0x1FF)
            return;
    }
}

/* --------------------------------------------------------------------------
 * [0x14006d80c] уровень PDPT (FUN_14006d80c): страница PD по физике,
 * do..while (idx < 0x200); PS-бит ((char)entry < 0) -> 2MB лист
 * (отчёт размером 0x200000), иначе рекурсия в PD/PT по
 * pfn = entry >> 0xc & 0xFFFFFFFFF
 * ------------------------------------------------------------------------ */
VOID
AcWalkPdptLevel(
    _In_ UINT64 Pfn,
    _Inout_ UINT32* Pml4IdxIo,
    _Inout_ UINT32* PdptIdxIo,
    _In_ PVOID Ctx,
    _Inout_ AC_PTWALK_ACC* Acc,
    _In_ UINT64* ScratchPd,
    _In_ UINT64* ScratchPt
    )
{
    NTSTATUS status;
    UINT32 i;

    status = AcPhysReadPage(ScratchPd, Pfn << 0xC, 0x1000);
    if (!NT_SUCCESS(status))
        return;

    i = 0;
    do {
        UINT32 cur = i;
        UINT64 entry = ScratchPd[cur];

        if ((entry & 1) == 0) {
            i = cur + 1;
            continue;
        }
        {
            UINT32 savedPml4 = *Pml4IdxIo;
            UINT32 savedPdpt = *PdptIdxIo;

            if ((CHAR)(UINT8)entry < 0) {
                /* PS -> 2MB лист */
                UINT64 va = ((UINT64)savedPdpt << 0x1E) |
                            ((UINT64)savedPml4 << 0x27) | ((UINT64)cur << 0x15);
                if ((INT64)entry >= 0) {
                    UINT32 f0, f1, f2, f4;
                    UINT64 f3, residual, tva;
                    UINT32 newPml4, newPdpt, newPd;

                    if (!AcPtwalkVmTranslate(va, &f0, &f1, &f2, &f3, &f4,
                                             &residual)) {
                        if (AcPtwalkVmFilterVa(va)) {
                            AcPtwalkAccAdd(Acc, va, 0x200000, f0, f1, f2, f3,
                                           f4, &ScratchPd[cur], Ctx);
                        }
                    }
                    else {
                        tva = residual + va;
                        newPml4 = (UINT32)(tva >> 0x27) & 0x1FF;
                        newPdpt = (UINT32)(tva >> 0x1E) & 0x1FF;
                        newPd   = (UINT32)(tva >> 0x15) & 0x1FF;
                        i = newPd;
                        if (*Pml4IdxIo != newPml4 || *PdptIdxIo != newPdpt) {
                            *Pml4IdxIo = newPml4;
                            *PdptIdxIo = newPdpt;
                            return;
                        }
                        if (cur != newPd)
                            continue;           /* ресинхронизация без +1 */
                    }
                }
                i = cur + 1;
            }
            else {
                AcWalkPdLevel((entry >> 0xC) & AC_PTE_PFN_MASK, Pml4IdxIo,
                              PdptIdxIo, &i, Ctx, Acc, ScratchPt);
                if (savedPml4 != *Pml4IdxIo)
                    return;
                if (savedPdpt != *PdptIdxIo)
                    return;
                if (cur == i)
                    i = cur + 1;
                /* иначе индекс уже переписан ресинхронизацией */
            }
        }
    } while (i < 0x200);
}

/* --------------------------------------------------------------------------
 * [0x14006da00] уровень записей PML4 (FUN_14006da00): страница PDPT по
 * физике (AcPhysReadPage(buf, pfn<<12, 0x1000)), цикл 512 записей:
 * P = entry & 1; PS = (char)entry < 0 (bit7) -> 1GB-лист (отчёт размером
 * 0x40000000); иначе рекурсия в PDPT по pfn = entry >> 0xc & 0xFFFFFFFFF
 * ------------------------------------------------------------------------ */
VOID
AcWalkPml4Level(
    _In_ UINT64 Pfn,
    _Inout_ UINT32* Pml4IdxIo,
    _In_ PVOID Ctx,
    _Inout_ AC_PTWALK_ACC* Acc,
    _In_ UINT64* ScratchPdpt,
    _In_ UINT64* ScratchPd,
    _In_ UINT64* ScratchPt
    )
{
    NTSTATUS status;
    UINT32 i;

    status = AcPhysReadPage(ScratchPdpt, Pfn << 0xC, 0x1000);
    if (!NT_SUCCESS(status))
        return;

    i = 0;
    for (;;) {
        UINT32 cur = i;
        UINT64 entry = ScratchPdpt[cur];

        if ((entry & 1) == 0) {
            i = cur + 1;
        }
        else {
            UINT32 savedPml4 = *Pml4IdxIo;

            if ((CHAR)(UINT8)entry < 0) {
                /* PS -> 1GB лист */
                UINT64 va = ((UINT64)savedPml4 << 0x27) | ((UINT64)cur << 0x1E);
                if ((INT64)entry >= 0) {
                    UINT32 f0, f1, f2, f4;
                    UINT64 f3, residual, tva;
                    UINT32 newPml4, newPdpt;

                    if (!AcPtwalkVmTranslate(va, &f0, &f1, &f2, &f3, &f4,
                                             &residual)) {
                        AcPtwalkAccAdd(Acc, va, 0x40000000ULL, f0, f1, f2, f3,
                                       f4, &ScratchPdpt[cur], Ctx);
                    }
                    else {
                        tva = residual + va;
                        newPdpt = (UINT32)(tva >> 0x1E) & 0x1FF;
                        newPml4 = (UINT32)(tva >> 0x27) & 0x1FF;
                        if (*Pml4IdxIo != newPml4) {
                            *Pml4IdxIo = newPml4;
                            return;
                        }
                        if (cur != newPdpt) {
                            i = newPdpt;        /* ресинхронизация без +1 */
                            goto check;
                        }
                    }
                }
                i = cur + 1;
            }
            else {
                AcWalkPdptLevel((entry >> 0xC) & AC_PTE_PFN_MASK, Pml4IdxIo,
                                &i, Ctx, Acc, ScratchPd, ScratchPt);
                if (savedPml4 != *Pml4IdxIo)
                    return;
                if (cur == i)
                    i = cur + 1;
                /* иначе индекс уже переписан ресинхронизацией */
            }
        }
check:
        if (i > 0x1FF)
            return;
    }
}

/* --------------------------------------------------------------------------
 * [0x14006dbb0] драйвер рекурсивного обхода (FUN_14006dbb0): три scratch-
 * страницы (0x1000 каждая), итерация снимка g_AcPml4Snapshot записей
 * [0..0xFF] (НИЖНЯЯ половина PML4; per-process сравнение ниже ходит верхнюю
 * 0x100..0x1FF), per present-записи рекурсия от её PFN; в конце flush
 * аккумулятора
 * ------------------------------------------------------------------------ */
VOID
AcPtwalkDeepScan(
    _In_ PVOID Ctx
    )
{
    UINT64* scratchPdpt;
    UINT64* scratchPd;
    UINT64* scratchPt;
    AC_PTWALK_ACC acc;
    UINT32 idx;

    scratchPdpt = (UINT64*)AcPml4AllocZeroed(0x1000);
    scratchPd   = (UINT64*)AcPml4AllocZeroed(0x1000);
    scratchPt   = (UINT64*)AcPml4AllocZeroed(0x1000);

    if (scratchPdpt != NULL && scratchPd != NULL && scratchPt != NULL) {
        RtlZeroMemory(&acc, sizeof(acc));
        idx = 0;
        do {
            UINT64 entry = g_AcPml4Snapshot[idx];
            if ((entry & 1) != 0) {
                AcWalkPml4Level((entry >> 0xC) & AC_PTE_PFN_MASK, &idx, Ctx,
                                &acc, scratchPdpt, scratchPd, scratchPt);
            }
            idx++;
        } while (idx < 0x100);
        AcPtwalkAccFlush(&acc, Ctx);
    }

    if (scratchPt != NULL)
        ExFreePoolWithTag(scratchPt, AC_PML4_TAG);
    if (scratchPd != NULL)
        ExFreePoolWithTag(scratchPd, AC_PML4_TAG);
    if (scratchPdpt != NULL)
        ExFreePoolWithTag(scratchPdpt, AC_PML4_TAG);
}

/* --------------------------------------------------------------------------
 * helper: ограниченная копия wide-строки из UNICODE_STRING -- идиома
 * [0x14000c428] (та же, что AcCopyWideString в events.c)
 * ------------------------------------------------------------------------ */
static VOID
AcPml4CopyWideString(
    _Out_writes_(DestChars) WCHAR* Dest,
    _In_ UINT32 DestChars,
    _In_ PCUNICODE_STRING Src
    )
{
    UINT32 i = 0;
    UINT32 chars;

    if (DestChars == 0)
        return;
    chars = Src->Length / sizeof(WCHAR);
    while (i < chars && i < DestChars - 1) {
        Dest[i] = Src->Buffer[i];
        i++;
    }
    Dest[i] = L'\0';
}

/* --------------------------------------------------------------------------
 * [0x14006eb90] scan_kernel_page_tables (FUN_14006eb90, strings.c:7523-7751).
 * Per-process сравнение kernel-half PML4: per-session узел 0x1018 байт
 * (LIST_ENTRY + dword SessionId + копия PML4 0x1000); при создании узла --
 * снимок зеркала (ac_memmove(node+0x18, [0x140108dd8], 0x1000)); далее под
 * PsAcquireProcessExitSynchronization + KeStackAttachProcess цикл
 * 0x100..0x1FF: skip self-map окно (индекс из VA зеркала) и слот процесса;
 * live [0x140108dd8][i] vs копия: обе present и
 * ((cur ^ old) & 0xFFFFFFFFF000) != 0 -> PFN сменился -> репорт 0x12
 * размером 0x658 (subtype 0x38, image-name, pid, session, build) через
 * channel_sender [0x14000bfa0]. Оригинал обёрнут в SEH (__try/__finally по
 * scope-таблицам UNK_14006ecf6..) -- парирование attach/detach сохранено.
 * Build-зависимый офсет EPROCESS: [0x140108d78] < 0x47bc -> 0x500; >= ->
 * 0x680; > 0x65b7 -> 0x400 (та же таблица билдов, что у семейства
 * [0x1400640b0]); цепочка +0x10 -> +0x38 дословно -- слот PML4-индекса
 * процесса (его индекс пропускается).
 * ------------------------------------------------------------------------ */
VOID
AcScanKernelPageTables(
    _Inout_ PLIST_ENTRY SessionList,
    _In_ PEPROCESS Process
    )
{
    typedef struct _AC_PML4_SESSION_NODE {
        LIST_ENTRY Link;                /* +0x00 */
        UINT32 SessionId;               /* +0x10 */
        UINT32 _pad;
        UINT64 Pml4Copy[0x200];         /* +0x18 снимок PML4 (0x1000) */
    } AC_PML4_SESSION_NODE;             /* итого 0x1018 */

    AC_PML4_SESSION_NODE* node;
    UINT64 procSlot;
    UINT32 build, epOff;
    NTSTATUS status;
    KAPC_STATE apcState;
    BOOLEAN attached;
    UINT32 selfMapIdx;
    UINT32 i;

    /* build-зависимый офсет EPROCESS -> слот процесса (дословно) */
    build = AC_SLOT32(AC_CELL_OS_BUILD);        /* [0x140108d78] */
    if (build < 0x47BC) {
        epOff = 0x500;
    }
    else {
        epOff = 0x680;
        if (build > 0x65B7)
            epOff = 0x400;
    }
    procSlot = *(UINT64*)(*(UINT64*)((UINT8*)Process + epOff + 0x10) + 0x38);

    /* per-session узел: создаётся при пустом списке (оригинал не ищет по
     * session-id -- берёт голову; дословно) */
    node = (AC_PML4_SESSION_NODE*)SessionList->Flink;
    if (SessionList->Flink == SessionList) {
        node = (AC_PML4_SESSION_NODE*)AcPml4AllocZeroed(0x1018);
        if (node == NULL) {
            AcEventReportFailure(0x70, 0);      /* alloc-fail (дословно) */
            return;
        }
        node->SessionId = PsGetProcessSessionId(Process);
        RtlCopyMemory(node->Pml4Copy, g_AcPml4Snapshot, 0x1000);
        /* оригинал страхует вставку int29-гейтом целостности списка */
        InsertTailList(SessionList, &node->Link);
    }

    /* индекс self-map окна из VA зеркала оригинала (0x140108dd8 >> 0x27) &
     * 0x1ff == 0 -- для цикла 0x100..0x1FF ветка не срабатывает (дословно) */
    selfMapIdx = (UINT32)(AC_PML4_SNAPSHOT_VA >> 0x27) & 0x1FF;

    status = PsAcquireProcessExitSynchronization(Process);
    if (!NT_SUCCESS(status))
        return;

    attached = FALSE;
    __try {
        KeStackAttachProcess((PRKPROCESS)Process, &apcState);
        attached = TRUE;

        for (i = 0x100; i < 0x200; i++) {
            UINT64 cur, old;
            UINT8* rec;

            if (i == selfMapIdx)
                continue;
            if (procSlot != 0 &&
                i == ((UINT32)(procSlot >> 0x27) & 0x1FF))
                continue;

            cur = g_AcPml4Snapshot[i];          /* live-зеркало */
            old = node->Pml4Copy[i];            /* копия сессии */
            if ((cur & 1) == 0 || (old & 1) == 0)
                continue;
            if (((cur ^ old) & AC_PML4_PFN_XOR) == 0)
                continue;

            /* PFN PML4E сменился для этого процесса -> репорт */
            rec = (UINT8*)AcPml4AllocZeroed(0x658);
            if (rec == NULL) {
                AcEventReportFailure(0x2B, 0);  /* alloc-fail (дословно) */
            }
            else {
                PUNICODE_STRING imageName = NULL;

                *(UINT32*)(rec + 0x000) = AC_EV_DETECTION;  /* type 0x12 */
                *(UINT32*)(rec + 0x010) = 0x38;             /* subtype */

                /* +0x14: строка-заголовок через декодер [0x14006f0ec] +
                 * _snwprintf (cap 0x104 wchar); содержимое декодируемой
                 * строки payload-selected (decoder cluster k(i)=(i%58)+0x70)
                 * -- оставлено нулями */

                /* +0x21c: basename образа текущего процесса
                 * (SeLocateProcessImageName; скан '\\'/'/' с конца) */
                status = SeLocateProcessImageName(IoGetCurrentProcess(),
                                                  &imageName);
                if (NT_SUCCESS(status) && imageName != NULL) {
                    UNICODE_STRING baseName;
                    PCUNICODE_STRING useName = imageName;

                    baseName.Length = 0;
                    baseName.MaximumLength = 0;
                    baseName.Buffer = NULL;
                    if (imageName->Length >= 2) {
                        UINT16 k = (UINT16)(imageName->Length / 2 - 1);
                        while (k != 0) {
                            WCHAR c = imageName->Buffer[k];
                            if (c == L'\\' || c == L'/') {
                                baseName.Buffer = imageName->Buffer + k + 1;
                                baseName.Length = (USHORT)(imageName->Length -
                                                  (k + 1) * sizeof(WCHAR));
                                baseName.MaximumLength = baseName.Length;
                                break;
                            }
                            k--;
                        }
                    }
                    if (baseName.Length != 0)
                        useName = &baseName;
                    AcPml4CopyWideString((WCHAR*)(rec + 0x21C), 0x104,
                                         useName);
                    ExFreePoolWithTag(imageName, 0);
                }

                *(UINT32*)(rec + 0x62C) =
                    (UINT32)(UINT64)PsGetProcessId(Process);
                *(UINT32*)(rec + 0x630) = PsGetProcessSessionId(Process);
                *(UINT32*)(rec + 0x634) = AC_SLOT32(AC_CELL_OS_BUILD);

                AcChannelSend(rec, 0x658);      /* channel_sender [0x14000bfa0] */
            }
            if (rec != NULL)
                ExFreePoolWithTag(rec, AC_PML4_TAG);
        }
    }
    __finally {
        if (attached)
            KeUnstackDetachProcess(&apcState);
        PsReleaseProcessExitSynchronization(Process);
    }
}

/* --------------------------------------------------------------------------
 * [0x14006f12c] callback перечисления хендлов (FUN_14006f12c):
 * object = (*entry >> 0x10) & ~0xF; ObGetObjectType(object) == *PsProcessType
 * -> AcScanKernelPageTables(EnumParameter, object). LOCK-инкремент младшего
 * байта записи + ExfUnblockPushLock(HandleTable+0x30) -- дословно.
 * Вызывается из sealed-фрейма (sealed_decompiled.c:723494/3776981).
 * ------------------------------------------------------------------------ */
BOOLEAN
AcPml4ScanHandleCb(
    _In_ PAC_HANDLE_TABLE HandleTable,
    _In_ PAC_HANDLE_TABLE_ENTRY HandleTableEntry,
    _In_ HANDLE Handle,
    _In_ PVOID EnumParameter
    )
{
    UINT64 object;
    BOOLEAN handled = FALSE;

    UNREFERENCED_PARAMETER(Handle);

    object = (HandleTableEntry->VolatileLowValue >> 0x10) & ~(UINT64)0xF;
    if (ObGetObjectType((PVOID)object) == (PVOID)*PsProcessType) {
        AcScanKernelPageTables((PLIST_ENTRY)EnumParameter,
                               (PEPROCESS)object);
        handled = TRUE;                 /* дословно: возврат 1 на процессе */
    }

    /* LOCK: младший байт записи хендла += 1 (дословно) */
    (*(volatile CHAR*)HandleTableEntry)++;

    if (HandleTable->PushLock != 0)
        ExfUnblockPushLock((PEX_PUSH_LOCK)&HandleTable->PushLock, 0);

    return handled;
}

/* --------------------------------------------------------------------------
 * [0x14006f1d0] триггер перебора процессов (FUN_14006f1d0):
 * ExEnumHandleTable(g_HandleTable, FUN_14006f12c, &ctx, 0); нулевая таблица
 * -> репорт 0x71. После перечисления узлы per-tick списка выключаются и
 * освобождаются (int29-гейт целостности в оригинале; RemoveHeadList здесь)
 * ------------------------------------------------------------------------ */
VOID
AcPml4ScanAllProcesses(
    VOID
    )
{
    LIST_ENTRY sessionList;
    PAC_HANDLE_TABLE table;

    table = (PAC_HANDLE_TABLE)AC_SLOTP(AC_CELL_HANDLE_TABLE);
    if (table == NULL) {
        AcEventReportFailure(0x71, 0);          /* дословно: репорт 0x71 */
        return;
    }

    InitializeListHead(&sessionList);
    ExEnumHandleTable(table, AcPml4ScanHandleCb, &sessionList, NULL);

    while (!IsListEmpty(&sessionList)) {
        PLIST_ENTRY e = RemoveHeadList(&sessionList);
        ExFreePoolWithTag(e, AC_PML4_TAG);
    }
}

/* --------------------------------------------------------------------------
 * payload-selected: VM-трампы оркестратора (ретаргеты glue-сайтов
 * ac_vmentry_tramp_gs_06ced4/06cfcc/06c8f8). Тела за VM -- статически не
 * восстанавливаются; точки вызова и аргументы дословны.
 * ------------------------------------------------------------------------ */
static VOID
AcScanVmTrampA(
    _Inout_ PUNICODE_STRING Name
    )
{
    UNREFERENCED_PARAMETER(Name);   /* [0x14023f52b] через tramp_gs_06ced4 */
}

/* payload-selected: VM-трамп оркестратора [0x1401ca70a] (сайт
 * ac_vmentry_tramp_gs_06cfcc) */
static VOID
AcScanVmTrampB(
    _Inout_ PUNICODE_STRING Name
    )
{
    UNREFERENCED_PARAMETER(Name);   /* [0x1401ca70a] через tramp_gs_06cfcc */
}

/* payload-selected: VM-трамп оркестратора [0x14021db5b] (сайт
 * ac_vmentry_tramp_gs_06c8f8) */
static VOID
AcScanVmTrampC(
    _In_ UINT64 Zero,
    _Inout_ PUNICODE_STRING Name
    )
{
    UNREFERENCED_PARAMETER(Zero);   /* [0x14021db5b] через tramp_gs_06c8f8 */
    UNREFERENCED_PARAMETER(Name);
}

/* --------------------------------------------------------------------------
 * [0x1400687e8] оркестратор тика скана (FUN_1400687e8):
 * SeLocateProcessImageName(IoGetCurrentProcess) -> basename -> 2 VM-трампа
 * -> AcPtwalkDeepScan(ctx=basename) -> VAD-скан -> VM-трамп; освобождение
 * строки. Вызов из sealed-фреймов (нативных call-сайтов нет)
 * ------------------------------------------------------------------------ */
VOID
AcPageTableScanTick(
    _In_ UINT8 Arg1,
    _In_ UINT8 Arg2
    )
{
    PUNICODE_STRING imageName = NULL;
    UNICODE_STRING baseName;
    NTSTATUS status;

    baseName.Length = 0;
    baseName.MaximumLength = 0;
    baseName.Buffer = NULL;

    status = SeLocateProcessImageName(IoGetCurrentProcess(), &imageName);
    if (NT_SUCCESS(status) && imageName != NULL) {
        if (imageName->Length >= 2) {
            UINT16 k = (UINT16)(imageName->Length / 2 - 1);
            while (k != 0) {
                WCHAR c = imageName->Buffer[k];
                if (c == L'\\' || c == L'/') {
                    baseName.Buffer = imageName->Buffer + k + 1;
                    baseName.Length = (USHORT)(imageName->Length -
                                      (k + 1) * sizeof(WCHAR));
                    baseName.MaximumLength = baseName.Length;
                    goto haveName;
                }
                k--;
            }
        }
        baseName = *imageName;          /* слэш не найден -- строка целиком */
    }

haveName:
    AcScanVmTrampA(&baseName);
    AcScanVmTrampB(&baseName);
    AcPtwalkDeepScan(&baseName);
    AcVadScanProcess(Arg1, Arg2, &baseName);
    AcScanVmTrampC(0, &baseName);

    if (imageName != NULL)
        ExFreePoolWithTag(imageName, 0);
}

/* --------------------------------------------------------------------------
 * [0x14006914c] запись подозрительного VAD-региона (FUN_14006914c) --
 * VM-диспетч стаб: «Could not recover jumptable at 0x14027a1f8», тело за
 * VM (класс был ac_hole_dispatch). payload-selected: семантика записи не
 * восстанавливается статикой; точка вызова и аргументы (mbi, ctx) дословны.
 * ------------------------------------------------------------------------ */
VOID
AcVadScanRecord(
    _In_ const VOID* Mbi,
    _In_ PVOID Ctx
    )
{
    UNREFERENCED_PARAMETER(Mbi);
    UNREFERENCED_PARAMETER(Ctx);
}

/* --------------------------------------------------------------------------
 * payload-selected: фильтр VAD-региона [0x14009c1c8] (addr, regionSize) --
 * «real code at target, never executed (payload)» (rewire-v4), в корпусах
 * стаб; нейтральная форма: FALSE (регион не подозрительный).
 * VM-ветки section-name: fail -> [0x14020c3f7] (tramp_gs_068d04), ok ->
 * [0x140372cef] (tramp_068efc).
 * ------------------------------------------------------------------------ */
static BOOLEAN
AcVadRegionFilter(
    _In_ UINT64 Addr,
    _In_ UINT64 RegionSize
    )
{
    UNREFERENCED_PARAMETER(Addr);
    UNREFERENCED_PARAMETER(RegionSize);
    return FALSE;
}

/* payload-selected: VM-ветка fail section-name query [0x14020c3f7]
 * (сайт ac_vmentry_tramp_gs_068d04) */
static VOID
AcVadVmSectionFail(
    _In_ UINT64 Zero,
    _In_ PVOID Base,
    _In_ NTSTATUS Status,
    _In_ UINT64 Eight
    )
{
    UNREFERENCED_PARAMETER(Zero);   /* [0x14020c3f7] через tramp_gs_068d04 */
    UNREFERENCED_PARAMETER(Base);
    UNREFERENCED_PARAMETER(Status);
    UNREFERENCED_PARAMETER(Eight);
}

/* payload-selected: VM-ветка успеха section-name query [0x140372cef]
 * (сайт ac_vmentry_tramp_068efc) */
static VOID
AcVadVmSectionOk(
    VOID
    )
{                                   /* [0x140372cef] через tramp_068efc */
}

/* --------------------------------------------------------------------------
 * [0x14006ccec] VAD-сканер (FUN_14006ccec): ZwQueryVirtualMemory(-1, addr,
 * MemoryBasicInformation) цикл по VA; флаги MEM_IMAGE/PRIVATE/MAPPED,
 * регион 0x1000 (MEM_COMMIT) -> фильтр + запись; image-регионы: пропуск
 * дубликатов по AllocationBase + ZwQueryVirtualMemory класс 2
 * (MemorySectionName, буфер 0x218) -> VM-ветки. param_1 не используется в
 * теле (дословно; сохранён как Reserved)
 * ------------------------------------------------------------------------ */
VOID
AcVadScanProcess(
    _In_ UINT8 Reserved,
    _In_ UINT8 RecordExecutable,
    _In_ PVOID Ctx
    )
{
    MEMORY_BASIC_INFORMATION mbi;
    UINT64 addr = 0;
    NTSTATUS status;
    BOOLEAN keepGoing = TRUE;

    UNREFERENCED_PARAMETER(Reserved);

    status = ZwQueryVirtualMemory((HANDLE)-1, NULL, MemoryBasicInformation,
                                  &mbi, sizeof(mbi), NULL);
    if (!NT_SUCCESS(status))
        return;

    do {
        PVOID allocBase = mbi.AllocationBase;

        if ((mbi.Type & MEM_IMAGE) == 0) {
            if ((mbi.Protect & 0xF0) == 0) {
                /* неисполняемый регион: MEM_COMMIT + фильтр -> запись */
                if (mbi.State == MEM_COMMIT &&
                    AcVadRegionFilter(addr, (UINT64)mbi.RegionSize)) {
                    AcVadScanRecord(&mbi, Ctx);
                }
            }
            else if (RecordExecutable == 0) {
                AcVadScanRecord(&mbi, Ctx);
            }
            addr += mbi.RegionSize;
            status = ZwQueryVirtualMemory((HANDLE)-1, (PVOID)addr,
                                          MemoryBasicInformation, &mbi,
                                          sizeof(mbi), NULL);
            if (!NT_SUCCESS(status))
                break;
        }
        else {
            /* image-регион: пропуск записей с тем же AllocationBase */
            do {
                addr += mbi.RegionSize;
                status = ZwQueryVirtualMemory((HANDLE)-1, (PVOID)addr,
                                              MemoryBasicInformation, &mbi,
                                              sizeof(mbi), NULL);
                if (!NT_SUCCESS(status)) {
                    keepGoing = FALSE;
                    break;
                }
            } while (mbi.AllocationBase == allocBase);

            /* section-name по СТАРОМУ base (дословно: ветка выполняется и
             * после неудачи внутреннего цикла) */
            {
                UINT8 nameBuf[0x218];

                status = ZwQueryVirtualMemory((HANDLE)-1, allocBase,
                                              AC_MemorySectionName, nameBuf,
                                              sizeof(nameBuf), NULL);
                if (!NT_SUCCESS(status))
                    AcVadVmSectionFail(0, allocBase, status, 8);
                else
                    AcVadVmSectionOk();
            }
        }
    } while (keepGoing);
}
