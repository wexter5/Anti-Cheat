/* ==========================================================================
 * thread_capture.h -- захват контекста потока (per-CPU слоты) + phys-guard
 *                     идентичности физической страницы
 * --------------------------------------------------------------------------
 * Источник: аудит упущенного agent-515
 * (_research_tmp/audit_ac_missed/AUDIT_MISSED_AC.md §3, строки таблицы
 * "0x1400883b4" / "0x14008846c"); тела: library_rest.c:23868-23946.
 * Оба VA до аудита были mis-classified в ac_native_crt (va_map); исправлено.
 * ========================================================================== */
#ifndef FACEIT_AC_THREAD_CAPTURE_H
#define FACEIT_AC_THREAD_CAPTURE_H

#include <ntddk.h>

/* stride per-CPU слота: 0x116 dword'ов = 0x458 байт (дословно из тела) */
#define AC_THREAD_CTX_SLOT_STRIDE   0x458
/* кап глубины дампа стека (дословно: if (0x400 < uVar4) uVar4 = 0x400) */
#define AC_THREAD_CTX_STACK_CAP     0x400

/* [0x14008846c] per-CPU слот захвата: заполняется один раз (Filled == 0),
 * поля по смещениям из тела FUN_14008846c */
typedef struct _AC_THREAD_CTX_SLOT {
    UINT64 Reserved0;           /* +0x000 */
    UINT64 Thread;              /* +0x008 ETHREAD (дословно: qword gs:0x188) */
    UINT64 ThreadId;            /* +0x010 PsGetCurrentThreadId */
    UINT64 ProcessId;           /* +0x018 PsGetCurrentProcessId */
    UINT8  Filled;              /* +0x020 флаг заполнения (гейт записи) */
    UINT8  _pad0[7];
    UINT64 EthreadFieldA;       /* +0x028 ETHREAD + офсет [0x14010910c] */
    UINT64 EthreadFieldB;       /* +0x030 ETHREAD + офсет [0x1401091b0] */
    UINT64 EthreadFieldC;       /* +0x038 ETHREAD + офсет [0x1401091b4] */
    UINT32 EthreadDword80;      /* +0x040 dword ETHREAD+0x80 */
    UINT32 _pad1;
    UINT64 Cr3;                 /* +0x048 CR3 на входе (in_CR3) */
    UINT32 KpcrDwordE0;         /* +0x050 dword KPCR(через gs:0x18 SelfPcr)+0xe0 */
    UINT32 _pad2;
    UINT64 StackDumpLen;        /* +0x058 глубина дампа (<= 0x400) */
    UINT8  StackDump[AC_THREAD_CTX_SLOT_STRIDE - 0x60]; /* +0x060 байты стека */
} AC_THREAD_CTX_SLOT;           /* итого 0x458 */

/* заголовок буфера захвата: счётчик + слоты по процессорам.
 * Дословно: LOCK-инкремент *param_1 (первые 4 байта аллокации) после
 * заполнения слота. */
typedef struct _AC_THREAD_CTX_CAPTURE {
    volatile LONG FilledSlots;  /* +0x00 Interlocked-инкремент счётчика буфера */
    UINT32 _pad0;
    AC_THREAD_CTX_SLOT Slots[1];/* +0x08 per-CPU слоты (stride 0x458) */
} AC_THREAD_CTX_CAPTURE;

/* [0x14008846c] capture_thread_information (кейс-образец аудита) */
BOOLEAN AcThreadContextCapture(_Inout_ AC_THREAD_CTX_CAPTURE* Capture);

/* [0x1400883b4] phys-guard: сверка физической страницы VA с XOR-парой
 * [0x140108c60]^[0x140108c58] (сосед capture_thread_information) */
BOOLEAN AcPhysPageIdentityCheck(_In_ UINT64 Va);

#endif /* FACEIT_AC_THREAD_CAPTURE_H */
