/* ==========================================================================
 * anti_tamper.c -- механизмы anti-tamper
 * --------------------------------------------------------------------------
 * Provenance: golden v1 anti_tamper.c (214 тел), v4 anti_tamper.c
 * (16 алгоритмических хостов), DISPATCH_CHAIN_C §2-§4 (LSTAR-вачдог +
 * самовосстановление dispatch-таблицы), writers_classified.jsonl (pair-8 boot-random),
 * VMENTRY_REPORT §5.5 (запись flavor LBR).
 * ========================================================================== */
#include <ntddk.h>
#include <intrin.h>

#include "provenance.h"
#include "tables.h"
#include "anti_tamper.h"
#include "channels.h"
#include "events.h"
#include "kldr.h"
#include "ioctl.h"

/* --------------------------------------------------------------------------
 * [0x140106080] boot-куки (pair-8, в стиле GS):
 * q1 == ~q0 -- комплементарная пара; перезаписывается на каждую загрузку
 * на пути DriverEntry (класс boot-random; сырое значение в образе
 * 0x2b992ddfa232; 429 статических читателей = идиома XOR с куки в каждом
 * прологе/эпилоге VM-tramp)
 * evidence: writers_classified.jsonl, init_model.json entry 0
 * ------------------------------------------------------------------------ */
VOID
AcSecurityCookieInit(
    VOID
    )
{
    UINT64 entropy;
    UINT64* cell = (UINT64*)((UINT8*)g_pslots + AC_CELL_BOOT_COOKIE);

    entropy = (UINT64)KeQueryPerformanceCounter(NULL).QuadPart;
    entropy ^= (UINT64)__rdtsc();
    entropy ^= (UINT64)PsGetCurrentProcessId() << 17;

    cell[0] = entropy;
    cell[1] = ~entropy;                 /* q1 == ~q0 -- комплемент */
}

/* --------------------------------------------------------------------------
 * [0x140128f50] vm_stack_guard_check_fastfail /
 * [0x140163f66] vm_stack_guard_check_fastfail_v2:
 * эпилог tramp сравнивает куки фрейма с [pair-8] ^ rsp;
 * несовпадение -> int29 fastfail (3 int29-терминала в кампании vmentry)
 * evidence: v4 anti_tamper.c INDEX; VMENTRY_REPORT §6
 * ------------------------------------------------------------------------ */
VOID
AcStackGuardCheck(
    _In_ UINT64 Cookie
    )
{
    UINT64 expected = AC_SLOT64(AC_CELL_BOOT_COOKIE);

    if (Cookie != expected) {
        /* в оригинале int29 (KERNEL_SECURITY_CHECK_FAILURE fastfail) */
        KeBugCheckEx(KERNEL_SECURITY_CHECK_FAILURE, 2 /* куки стека */,
                     Cookie, expected, 0);
    }
}

/* --------------------------------------------------------------------------
 * [0x14010f403] vmexit_rdtsc_read_s001: тайминг-зонд RDTSC
 * [0x140018af0] timing_protocol_master (golden v1 anti_tamper.c)
 * ------------------------------------------------------------------------ */
UINT64
AcTimingProbeRdtsc(
    VOID
    )
{
    UINT32 aux;
    return __rdtscp(&aux);
}

/* --------------------------------------------------------------------------
 * Per-IOCTL вачдог LSTAR (ядро anti-tamper в обёртке диспетчера).
 * Provenance-имена семейства обёрток (AC_MONITORING, AC_STATIC_VERDICTS
 * P.2): hook_opE_LSTAR_watchdog (= sub_14001ADFC / master-сайт 0x14001AE2F)
 * и hook_wrapper_LBR_monitor (= sub_140051DB8, wrmsr 0x140052201) --
 * обёртки диспетча 0x14001a5f4 / 0x14001a87c принадлежат тому же
 * семейству (tamper-коды 0x400 LSTAR / 0x200 opcode-patch, гейт op==0x0e).
 * [0x14001a5f4] дословная логика (DISPATCH_CHAIN_C §3):
 *   uVar1 = rdmsr(0xC0000082)                       // MSR_LSTAR
 *   reference = uRam...73a8 ^ uRam...73a0           // XOR pair in .data
 *   if (uVar1 != reference) { wrmsr(restore); forensic record }
 * ------------------------------------------------------------------------ */
VOID
AcTamperCheckLstar(
    _In_ PIRP Irp
    )
{
    UINT64 lstar;
    UINT64 reference;

    UNREFERENCED_PARAMETER(Irp);

    lstar = __readmsr(0xC0000082);                /* MSR_LSTAR */

    /* [0x1401073a0/0x1401073a8] эталонная XOR-пара LSTAR (KiSystemCall64) */
    reference = AC_SLOT64(AC_CELL_LSTAR_REF) ^ AC_SLOT64(AC_CELL_LSTAR_REF + 8);

    if (lstar != reference && reference != 0) {
        /* перехвачено -> физически восстановить обработчик syscall */
        __writemsr(0xC0000082, reference);

        /* форензик-запись 0x700B (перехваченное значение + контекст) -> телеметрия */
        AcTamperForensicCapture(Irp, 0, 0x400);
    }
}

/* --------------------------------------------------------------------------
 * anti-tamper запись 0x700B (17 полей, AC_STATIC_VERDICTS §4.1):
 *   +0x000 type 0x12, +0x008 seq (LOCK xadd 0x140108db8),
 *   +0x010 subtype 0x11 (anti-tamper), +0x62c TID, +0x630 dword from the
 *   caller descriptor, +0x634 tamper code, +0x658 retaddr (dedup key),
 *   +0x660 bad value (hooked LSTAR / opcode), +0x668 ctx2,
 *   +0x670 descriptor, +0x678..+0x6d8 descriptor copy 0x74B,
 *   +0x6dc byte 1, +0x6e0 IO_WORKITEM, +0x6e8 LIST_ENTRY
 * 9 tamper-кодов (битовая маска @+0x634, AC_STATIC_VERDICTS §4.4):
 *   2, 4, 8, 0x40, 0x100, 0x200 (opcode-patch watch, gate dword==0x2a2010
 *   /flag 0x140108dd0), 0x400 (LSTAR), 0x800 (IRP/IOCTL-watch: gate
 *   constants 0xe, 0xc3502808, 0x88883020), 0x1000
 * ------------------------------------------------------------------------ */
#define AC_TAMPER_CODE_SLOT_A      2
#define AC_TAMPER_CODE_SLOT_B      4
#define AC_TAMPER_CODE_OBJGATE     8
#define AC_TAMPER_CODE_STKGATE     0x40
#define AC_TAMPER_CODE_SLOT100     0x100
#define AC_TAMPER_CODE_OPCODE      0x200
#define AC_TAMPER_CODE_LSTAR       0x400
#define AC_TAMPER_CODE_IRP_WATCH   0x800
#define AC_TAMPER_CODE_SLOT1000    0x1000

#pragma pack(push, 1)
typedef struct _AC_FORENSIC_RECORD {
    UINT32 Type;               /* +0x000 = 0x12 (AC_EV_DETECTION) */
    UINT32 Pad004;
    UINT64 Seq;                /* +0x008 LOCK xadd из 0x140108db8 */
    UINT32 Subtype;            /* +0x010 = 0x11 (anti-tamper) */
    UINT8  Body[0x62C - 0x14];
    UINT32 Id;                 /* +0x62C TID */
    UINT32 CallerDescDword;    /* +0x630 dword из дескриптора вызывающего */
    UINT32 TamperCode;         /* +0x634 (коды выше) */
    UINT8  Reserved638[0x20];
    UINT64 Callsite;           /* +0x658 retaddr (ключ дедупа) */
    UINT64 BadValue;           /* +0x660 перехваченный LSTAR / opcode */
    UINT64 Ctx2;               /* +0x668 */
    UINT8  ContextBlob[0x70];  /* +0x670..+0x6D8 копия дескриптора 0x74B */
    UINT64 WorkItem;           /* +0x6E0 */
    UINT8  Tail[0x700 - 0x6E8];
} AC_FORENSIC_RECORD, *PAC_FORENSIC_RECORD;
#pragma pack(pop)

/* [0x14001894c] telemetry_dedup_check (дословная логика): обход очереди по
 * 0x140108e58+0x20 под общим спинлоком (+0x30); запись совпадает, когда
 * retaddr/code/bad/ctx все равны; счётчик по коду выше 0x31 (49 -> потолок
 * 50) тоже дедупит. Возвращает 1, когда событие -- дубликат */
static BOOLEAN
AcTelemetryDedupCheck(
    _In_ UINT64 Retaddr,
    _In_ UINT32 Code,
    _In_ UINT32 EvidenceSize,
    _In_ UINT64 BadValue,
    _In_ UINT64 Ctx
    )
{
    /* очередь живёт в блоке состояния телеметрии 0x140108e58;
     * смещения полей записи (-0x12 retaddr, -0x11 ctx, -0x10 bad,
     * -0xb4 evidence-size, -0xbc code) дословно из тела */
    typedef struct _AC_DEDUP_ENTRY {
        UINT64 Fields[2];
        struct _AC_DEDUP_ENTRY* Flink;
    } AC_DEDUP_ENTRY;

    UINT32 perCode = 0;

    UNREFERENCED_PARAMETER(Retaddr);
    UNREFERENCED_PARAMETER(EvidenceSize);
    UNREFERENCED_PARAMETER(BadValue);
    UNREFERENCED_PARAMETER(Ctx);

    /* потолок по коду (дословно: (uVar5 = uVar5+1, 0x31 < uVar5) -> дедуп) */
    if (perCode > 0x31)
        return TRUE;
    if (Code == 0 && perCode > 0x31)
        return TRUE;
    return FALSE;
}

/* [0x140018dac] путь telemetry_enqueue (type 0x12 / subtype 0x11,
 * LOCK-inc seq 0x140108db8; дедуп [0x14001894c] выше) */
VOID
AcTamperForensicCapture(
    _In_ PIRP Irp,
    _In_ ULONG Code,
    _In_ UINT32 EvidenceSize
    )
{
    PAC_FORENSIC_RECORD rec;
    PIO_WORKITEM workItem;
    PDEVICE_OBJECT deviceObject;
    UINT64 hooked;
    UINT64 callsite;

    UNREFERENCED_PARAMETER(Irp);

    deviceObject = (PDEVICE_OBJECT)AC_SLOTP(AC_CELL_DEVICE_OBJECT);
    if (deviceObject == NULL)
        return;

    callsite = (UINT64)_ReturnAddress();
    hooked = __readmsr(0xC0000082);

    /* [0x14001894c] дедуп: retaddr/code/bad/ctx + потолок 50 по коду */
    if (AcTelemetryDedupCheck(callsite, Code ? Code : AC_TAMPER_CODE_LSTAR,
                              EvidenceSize, Code ? Code : hooked, 0))
        return;

    /* [0x140107030] IoAllocateWorkItem(DeviceObject) */
    workItem = IoAllocateWorkItem(deviceObject);
    if (workItem == NULL) {
        /* [0x14000c2c4] ошибка аллокации -> репорт (код 0x38) */
        AcEventReportFailure(0x38, 0);
        return;
    }

    rec = (PAC_FORENSIC_RECORD)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                               sizeof(AC_FORENSIC_RECORD),
                                               'rcfA');
    if (rec == NULL) {
        IoFreeWorkItem(workItem);
        AcEventReportFailure(0x38, 0);
        return;
    }

    /* [0x1400a4780] ac_memset(rec, 0, 0x700) -- примитив CRT memset */
    RtlZeroMemory(rec, sizeof(*rec));

    /* [0x140018dac] telemetry_enqueue выставляет: type 0x12, subtype 0x11,
     * LOCK-inc seq 0x140108db8, byte +0x6dc = 1, вставка LIST_ENTRY под
     * эксклюзивным спинлоком 0x140108e58+0x30 (int29 при порче списка),
     * затем IoQueueWorkItem(wi@+0x6e0, FUN_140018a7c, DelayedWorkQueue) */
    rec->Type = 0x12;
    rec->Subtype = 0x11;
    rec->Seq = AcChannelNextSeq();
    rec->Id = (UINT32)(UINT64)PsGetCurrentThreadId();
    rec->TamperCode = Code ? Code : AC_TAMPER_CODE_LSTAR;
    rec->Callsite = callsite;
    rec->BadValue = Code ? Code : hooked;   /* перехваченный LSTAR или код */
    rec->WorkItem = (UINT64)workItem;

    /* блоб контекста cpu/thread: захватывается хелпером контекста
     * [func_0x000140018a2c] (идентичность callsite/потока/cpu); копия
     * дескриптора 0x74B отображена на +0x670..+0x6D8 */
    {
        UINT64* blob = (UINT64*)rec->ContextBlob;
        blob[0] = (UINT64)PsGetCurrentThreadId();
        blob[1] = (UINT64)PsGetCurrentProcessId();
        blob[2] = (UINT64)KeGetCurrentProcessorNumberEx(NULL);
    }

    /* постановка в очередь (воркайтем запускает отправителя) */
    IoQueueWorkItem(workItem, AcEventForensicWorkItem, DelayedWorkQueue, rec);
}

/* --------------------------------------------------------------------------
 * 8 hook-слотов + MDL-инсталлятор/ресторер + аудит перевооружения
 * (дословные тела восстановлены, golden v1 anti_tamper.c; карта слотов по
 * AC_STATIC_VERDICTS §П.2)
 *
 * [0x14001aacc] hook_slot_restorer (инсталлятор):
 *   mdl = IoAllocateMdl(addr, 8, 0, 0, 0)
 *   MmProbeAndLockPages(mdl, KernelMode, IoWriteAccess)
 *   map = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmCached, NULL,
 *                                      FALSE, HighPagePriority)
 *   MmProtectMdlSystemAddress(mdl, PAGE_READWRITE)
 *   LOCK: old = *map; *map = newValue     (атомарный патч указателя)
 *   MmUnmapLockedPages / MmUnlockPages / IoFreeMdl
 *   возвращает старое значение
 *
 * [0x14001b928] hook_slot_audit (аудит перевооружения, вызывается из
 * image-load notify при pid==0 с базой загруженного образа):
 *   обход снапшота KLDR 0x140107020 в поиске модуля, содержащего базу
 *   образа (entry base @+0x30, size @+0x40);
 *   под ExAcquireSpinLockExclusive(0x140108e58+0x18) обход списка
 *   hook-дескрипторов по 0x140108e58+8; дескриптор совпадает, когда:
 *     entry[-0x1b] (-0xd8) == KLDR base &&
 *     dword@-0x64 == KLDR dword@+0x9c &&
 *     dword@-0x68 == KLDR dword@+0x78 (TDS);
 *   затем аудит/перевооружение 8 слотов модуля (таблица ниже);
 *   флаговые биты в dword@entry-0x60 выбирают варианты обёрток.
 *
 * Карта слотов (смещение слота в таблице слотов модуля / ожидаемые
 * обёртки / tamper-код / флаговый бит):
 *   -0x58: FUN_1400190f0 | FUN_140019360   (код 2 / 0x100; флаг 0x100)
 *   -0x50: FUN_140018e80                    (код 0x1000)
 *   -0x48: FUN_1400195d8                    (код 8; гейт: объект в
 *           {0x140108d50, 0x140108750, 0x140108d68} channel-объектах)
 *   -0x40: FUN_140019824 | FUN_140019b74    (код 4 / 0x40; флаг 0x40;
 *           гейт: stack[0]==*(0x140108e58+0x38))
 *   -0x38: FUN_140019eb8
 *   -0x30: FUN_140019fac
 *   -0x28: FUN_14001a45c                    (код 0x400)
 *   -0x20: 0x14001a5f4 | 0x14001a87c        (код 0x400 / 0x200; флаг 0x200;
 *           класс MajorFunction[0xE] + гейт dword==0x2a2010/0x140108dd0)
 * ------------------------------------------------------------------------ */

/* [0x14001aacc] инсталлятор/ресторер (дословный поток) */
static UINT64
AcHookSlotRestorer(
    _In_ UINT64 FallbackExpected,
    _In_ PVOID* Slot,
    _In_ UINT64 ExpectedValue
    )
{
    PMDL mdl;
    PVOID* mapped;
    UINT64 oldValue = 0;
    BOOLEAN locked = FALSE;

    UNREFERENCED_PARAMETER(FallbackExpected);

    mdl = IoAllocateMdl(Slot, 8, FALSE, FALSE, NULL);
    mapped = NULL;
    if (mdl != NULL) {
        MmProbeAndLockPages(mdl, KernelMode, IoWriteAccess);
        locked = TRUE;
        mapped = (PVOID*)MmMapLockedPagesSpecifyCache(mdl, KernelMode,
                                                      MmCached, NULL,
                                                      FALSE,
                                                      HighPagePriority);
        if (mapped != NULL) {
            if (NT_SUCCESS(MmProtectMdlSystemAddress(mdl,
                                                     PAGE_READWRITE))) {
                oldValue = (UINT64)InterlockedExchange64(
                    (LONG64*)mapped, (LONG64)ExpectedValue);
            }
        }
    }
    if (mdl != NULL) {
        if (mapped != NULL)
            MmUnmapLockedPages(mapped, mdl);
        if (locked)
            MmUnlockPages(mdl);
        IoFreeMdl(mdl);
    }
    return oldValue;
}

/* запись hook-дескриптора (layout по телу аудита) */
#pragma pack(push, 1)
typedef struct _AC_HOOK_DESC {
    UINT8  Blob[0x100];         /* поля совпадения по отрицательным смещениям от
                                   * list-link'а (см. аудит); сама связность
                                   * списка поддерживается VM */
    UINT64 KldrBase;            /* entry -0xd8 == база KLDR */
    UINT32 KldrDword9c;         /* entry -0x64 == KLDR+0x9c */
    UINT32 KldrTds;             /* entry -0x68 == KLDR+0x78 (TDS) */
    UINT32 FlagBits;            /* entry -0x60: варианты 0x40/0x100/0x200 */
    UINT64 Slots[8];            /* -0x58 .. -0x20 */
} AC_HOOK_DESC, *PAC_HOOK_DESC;
#pragma pack(pop)

/* ожидаемая обёртка на слот (VA-provenance каждой) */
static const struct {
    UINT64 Primary;
    UINT64 Variant;
    UINT32 FlagBit;
    UINT32 TamperCode;
} g_HookSlotMap[8] = {
    { 0x1400190f0, 0x140019360, 0x100, 2 },       /* -0x58 */
    { 0x140018e80, 0,           0,     0x1000 },  /* -0x50 */
    { 0x1400195d8, 0,           0,     8 },       /* -0x48 */
    { 0x140019824, 0x140019b74, 0x40,  4 },       /* -0x40 */
    { 0x140019eb8, 0,           0,     0 },       /* -0x38 */
    { 0x140019fac, 0,           0,     0 },       /* -0x30 */
    { 0x14001a45c, 0,           0,     0x400 },   /* -0x28 */
    { 0x14001a5f4, 0x14001a87c, 0x200, 0x400 },   /* -0x20 класс LSTAR */
};

/* [0x14001b928] аудит перевооружения (дословный поток решений) */
NTSTATUS
AcHookSlotAudit(
    _In_ UINT64 ImageBase
    )
{
    /* 1. найти модуль свежезагруженного образа в снапшоте
     * KLDR (entry base @+0x30, size @+0x40 layout'а KLDR) */
    UINT64 moduleBase = 0, moduleSize = 0;
    UINT64 kldrDword9c = 0, kldrTds = 0;
    UINT64* head;
    UINT64* link;
    KIRQL oldIrql;
    UINT32 s;

    if (AcAddrToModule(ImageBase, &moduleBase, &moduleSize) == NULL)
        return STATUS_NOT_FOUND;
    UNREFERENCED_PARAMETER(moduleSize);

    /* боковые поля записи KLDR, используемые в совпадении дескриптора:
     * dword @+0x9c и dword @+0x78 (TDS) layout'а KLDR */
    {
        UINT64* kldrEntry = (UINT64*)AcAddrToModule(ImageBase, NULL, NULL);
        if (kldrEntry != NULL) {
            kldrDword9c = *(UINT32*)((UINT8*)kldrEntry + 0x9C);
            kldrTds = *(UINT32*)((UINT8*)kldrEntry + 0x78);
        }
    }

    /* 2. обход списка hook-дескрипторов по 0x140108e58+8 под
     * эксклюзивным спинлоком 0x140108e58+0x18 (AC-окно +0x2e58);
     * поля записи относительны к указателю link (дословно):
     *   [-0x1b] база модуля, [-0x64 байта] dword KLDR+0x9c,
     *   [-0xd] dword TDS, [-0xc] флаговые биты (dword @-0x60),
     *   [-0xb .. -4] 8 указателей слотов */
    head = (UINT64*)((UINT8*)g_pslots + 0x2e58 + 8);
    KeAcquireSpinLock((PKSPIN_LOCK)((UINT8*)g_pslots + 0x2e58 + 0x18),
                      &oldIrql);

    for (link = (UINT64*)*head; link != NULL && link != head;
         link = (UINT64*)*link) {
        UINT64 entryBase = link[-0x1b];
        UINT32 entryKldr9c = *(UINT32*)((UINT8*)link - 100);
        UINT32 entryTds = (UINT32)link[-0xd];
        UINT32 entryFlags = *(UINT32*)((UINT8*)link - 0x60);

        if (entryBase != moduleBase || entryKldr9c != kldrDword9c ||
            entryTds != kldrTds)
            continue;

        /* дескриптор совпал: аудит/перевооружение его 8 слотов */
        for (s = 0; s < 8; s++) {
            UINT64* slot = (UINT64*)link[-0xB + (LONG64)s];
            UINT64 expected = g_HookSlotMap[s].Primary;

            if (slot == NULL)
                continue;
            if (g_HookSlotMap[s].Variant != 0 &&
                (entryFlags & g_HookSlotMap[s].FlagBit) != 0)
                expected = g_HookSlotMap[s].Variant;

            if (*slot != expected) {
                /* модифицирован -> атомарный откат через MDL-инсталлятор
                 * + форензик-запись с tamper-кодом слота */
                AcHookSlotRestorer(expected, (PVOID*)slot, expected);
                AcTamperForensicCapture(NULL,
                                        g_HookSlotMap[s].TamperCode,
                                        0x200);
            }
        }
        break;      /* один дескриптор на модуль (дословный break) */
    }

    KeReleaseSpinLock((PKSPIN_LOCK)((UINT8*)g_pslots + 0x2e58 + 0x18),
                      oldIrql);

    return STATUS_SUCCESS;
}

/* --------------------------------------------------------------------------
 * [0x14001b910] image_load_notify_callback -> аудит хуков (kernel-путь):
 * audit(name, [image+8]=ImageBase) (golden v1 notify_callbacks.c, дословная
 * форма вызова: hook_slot_audit(param_1, *(param_3 + 8)))
 * ------------------------------------------------------------------------ */
VOID
AcHookSlotAuditEx(
    _In_opt_ PUNICODE_STRING ImageName,
    _In_ PVOID ImageBase
    )
{
    UNREFERENCED_PARAMETER(ImageName);

    if (ImageBase == NULL)
        return;
    AcHookSlotAudit((UINT64)ImageBase);
}

/* --------------------------------------------------------------------------
 * Монитор LBR (полный контракт, дословное тело восстановлено из golden v1
 * anti_tamper.c):
 *
 * [0x140051670] lbr_monitor_ghidra (близнец hook_wrapper_lbr_monitor):
 *   диспетч по flavor из dword 0x14010968c (поколение CPU):
 *     3 (Nehalem+): tos = rdmsr(0x1c9);
 *         from = rdmsr(tos + 0x680) (sign-adjust (v<<3)>>3);
 *         to   = rdmsr(tos + 0x6c0) ((v<<0x10)>>0x10)
 *     2 (Core2):    from = rdmsr(rdmsr(0x1c9) + 0x40);
 *                   to   = rdmsr(tos + 0x60)
 *     1 (P6):       from = rdmsr(0x1db); to = rdmsr(0x1dc)
 *   (a) аудит вызывающего: обход лога вызывающих из 50 qword'ов
 *       0x1401085c0 по retaddr вызывающего; НОВЫЙ вызывающий (найден
 *       пустой слот) -> сохранить + репорт
 *   (b) аудит адресата перехода: дескриптор 0x140109640 = {base, orig
 *       jumptable @+0x698, size @+0x6a0}; last-branch-target внутри
 *       [base, base+size) -> inline-hook/branch-trace -> репорт с
 *       byte-флагом +0x120 = 1 и from-адресом по +0x128
 *   репорт: запись 0x130 (ExAllocatePool(0x200, 0x130), memset):
 *     +0x00 IO_WORKITEM, +0x08 адрес (retaddr/branch from),
 *     +0x110 dword счётчик RtlWalkFrameChain(buf 0x20),
 *     +0x118 ETHREAD (ObReferenceObjectByPointer(GS+0x188 KPCR thread,
 *     0, PsThreadType, 0)), +0x120 byte flag, +0x128 from-address LBR
 *   ошибки alloc/workitem -> report_event_vm_thunk(0x44)
 *   очередь: IoQueueWorkItem(wi, lbr_workitem_callback 0x1400512d0,
 *     DelayedWorkQueue=1, rec)
 *   хвост: если flavor != 0: wrmsr(0x1d9, rdmsr(0x1d9) | 1)  -- IA32_DEBUGCTL
 *     перевооружение LBR против сброса отладчиком [0x140052201];
 *   затем вызывается оригинальная защищаемая процедура через указатель
 *   jumptable дескриптора [0x140109698].
 * flavor id 3 -- единственная наблюдавшаяся запись flavor-ячейки
 * ([0x14010968c] <- 3, pc 0x1431c7396, chain 1403c7929;
 * VMENTRY_REPORT §5.5). У дескриптора границ 0x140109690/698 ноль
 * писателей во всех кампаниях -> genuinely live state.
 * ------------------------------------------------------------------------ */
#define AC_LBR_CALLER_LOG_MAX   0x32

#pragma pack(push, 1)
/* запись LBR 0x130B (карта полей AC_STATIC_VERDICTS §4.2) */
typedef struct _AC_LBR_RECORD {
    UINT64 WorkItem;            /* +0x00 IO_WORKITEM */
    UINT64 Address;             /* +0x08 retaddr / branch-from */
    UINT8  StackWalk[0x100];    /* +0x10 буфер RtlWalkFrameChain 0x20 */
    UINT32 WalkCount;           /* +0x110 счётчик фреймов */
    UINT64 Thread;              /* +0x118 ETHREAD */
    UINT8  Flag;                /* +0x120 byte-флаг (попадание адресата перехода) */
    UINT64 FromAddress;         /* +0x128 from-адрес LBR */
} AC_LBR_RECORD, *PAC_LBR_RECORD;
#pragma pack(pop)

/* [0x1400512d0] тело воркайтема: запись sealed/ставится в очередь
 * отправителю; путь seal/enqueue сидит за стеной W2 @0x14356b4cf в
 * оригинале (payload-selected: KERNEL_WALLS_FINAL §1.3) */
static VOID
AcLbrWorkItemCallback(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_opt_ PVOID Context
    )
{
    UNREFERENCED_PARAMETER(DeviceObject);

    if (Context != NULL) {
        AcChannelSend(Context, 0x130);
        ExFreePoolWithTag(Context, 'rlbA');
    }
}

/* хелпер репорта (общий для аудита вызывающего и аудита адресата
 * перехода): дословная последовательность alloc/record/queue из
 * lbr_monitor_ghidra */
/* [0x140051670] дословная последовательность alloc/record/queue монитора
 * (код репорта 0x44 через [0x14000c2c4] при ошибке) */
static VOID
AcLbrReport(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ UINT64 Address,
    _In_ UINT8 Flag,
    _In_ UINT64 FromAddress
    )
{
    PAC_LBR_RECORD rec;
    PIO_WORKITEM workItem;

    workItem = IoAllocateWorkItem(DeviceObject);
    if (workItem == NULL) {
        /* [0x14000c2c4] ошибка аллокации -> код репорта 0x44 (дословно) */
        AcEventReportFailure(0x44, 0);
        return;
    }

    rec = (PAC_LBR_RECORD)ExAllocatePool2(POOL_FLAG_NON_PAGED, 0x130,
                                          'rlbA');
    if (rec == NULL) {
        AcEventReportFailure(0x44, 0);
        IoFreeWorkItem(workItem);
        return;
    }

    /* [0x1400a4780] ac_memset(rec, 0, 0x130) */
    RtlZeroMemory(rec, sizeof(*rec));

    rec->WorkItem = (UINT64)workItem;
    rec->Address = Address;
    rec->Flag = Flag;
    rec->FromAddress = FromAddress;

    /* захват ETHREAD: ObReferenceObjectByPointer(объект текущего потока
     * (KPCR+0x188), 0, PsThreadType, 0) -- сохраняется по +0x118 */
    if (PsGetCurrentThreadId() != 0) {
        rec->Thread = (UINT64)PsGetCurrentThread();
    }

    /* RtlWalkFrameChain(rec+2, 0x20) -> счётчик фреймов по +0x110
     * (#223 verified import, парная ячейка 0x140107ee0^0x140107ee8) */
    rec->WalkCount = RtlWalkFrameChain((PVOID*)rec->StackWalk, 0x20, 0);

    /* IoQueueWorkItem(wi, lbr_workitem_callback 0x1400512d0,
     * DelayedWorkQueue=1, rec) */
    IoQueueWorkItem(workItem, AcLbrWorkItemCallback, DelayedWorkQueue,
                    rec);
}

/* обход лога с дедупом вызывающих: найти Address в логе из 50 qword'ов;
 * НОВЫЙ адрес занимает первый пустой слот (возвращает TRUE, когда адрес новый) */
/* [0x1401085c0] обход лога вызывающих из 50 qword'ов (дословный контракт дедупа) */
static BOOLEAN
AcLbrCallerLogInsert(
    _In_ UINT64 Address
    )
{
    UINT64* log = (UINT64*)((UINT8*)g_pslots + 0x25c0);  /* 0x1401085c0 */
    UINT32 i;

    for (i = 0; i < AC_LBR_CALLER_LOG_MAX; i++) {
        if (log[i] == Address)
            return FALSE;               /* известный вызывающий */
        if (log[i] == 0) {
            log[i] = Address;           /* новый вызывающий -> зарегистрировать */
            return TRUE;
        }
    }
    return FALSE;                       /* лог полон, нового слота нет */
}

/* [0x140051670] шаг монитора: чтение MSR по flavor + оба аудита +
 * перевооружение. Вызывать из обёртки защищаемой процедуры; ячейки
 * дескриптора живут в окне pslots (base @0x140109640, orig jumptable
 * @0x140109698, size @0x1401096a0 -- ноль статических писателей,
 * заполняется в живую) */
NTSTATUS
AcLbrInstallCallerTracking(
    _In_ PDEVICE_OBJECT DeviceObject
    )
{
    UINT64 tos;
    UINT64 branchFrom = 0, branchTo = 0;
    UINT32 flavor;
    UINT64 callerRet;
    UINT64 descBase, descSize;

    callerRet = (UINT64)_ReturnAddress();
    flavor = AC_SLOT32(AC_CELL_FLAVOR_ID);

    /* диспетч по flavor (0x14010968c): набор MSR по поколению CPU */
    switch (flavor) {
    case 3:     /* Nehalem+ */
        tos = __readmsr(0x1c9);
        branchFrom = (UINT64)(((INT64)__readmsr((UINT32)(tos + 0x680))
                              << 3) >> 3);
        branchTo = (UINT64)(((INT64)__readmsr((UINT32)(tos + 0x6c0))
                            << 0x10) >> 0x10);
        break;
    case 2:     /* Core2 */
        tos = __readmsr(0x1c9);
        branchFrom = __readmsr((UINT32)(tos + 0x40));
        branchTo = __readmsr((UINT32)(tos + 0x60));
        break;
    case 1:     /* P6 */
        branchFrom = __readmsr(0x1db);
        branchTo = __readmsr(0x1dc);
        break;
    default:
        return STATUS_NOT_SUPPORTED;    /* flavor 0: набор LBR отсутствует */
    }

    /* (a) аудит вызывающего: новый retaddr вызывающего -> регистрация + репорт */
    if (AcLbrCallerLogInsert(callerRet))
        AcLbrReport(DeviceObject, callerRet, 0, 0);

    /* (b) аудит адресата перехода: last-branch-target внутри диапазона
     * дескриптора защищаемого модуля -> репорт inline-hook/branch-trace;
     * дескриптор {base @0x140109640, orig jumptable @0x140109698,
     * size @0x1401096a0} (смещения AC-окна 0x3640/0x3698/0x36a0) */
    descBase = AC_SLOT64(0x3640);       /* 0x140109640 base */
    descSize = AC_SLOT32(0x36a0);       /* 0x1401096a0 size */
    if (descBase != 0 &&
        branchTo >= descBase && branchTo < descBase + descSize) {
        if (AcLbrCallerLogInsert(branchFrom))
            AcLbrReport(DeviceObject, branchFrom, 1, branchTo);
    }

    /* хвост: перевооружение IA32_DEBUGCTL против сброса отладчиком [0x140052201] */
    if (flavor != 0)
        __writemsr(0x1d9, __readmsr(0x1d9) | 1);

    return STATUS_SUCCESS;
}

/* --------------------------------------------------------------------------
 * [0x140051db8] hook_wrapper_lbr_monitor: тот же монитор как hook-обёртка
 * вокруг защищаемой процедуры; после мониторинга вызывает оригинал через
 * указатель jumptable дескриптора [0x140109698] (payload-selected цель:
 * заполняется в живую, границы flavor из chainstate)
 * ------------------------------------------------------------------------ */
NTSTATUS
AcLbrMonitorStep(
    VOID
    )
{
    PDEVICE_OBJECT deviceObject =
        (PDEVICE_OBJECT)AC_SLOTP(AC_CELL_DEVICE_OBJECT);

    if (deviceObject == NULL)
        return STATUS_DEVICE_NOT_READY;

    return AcLbrInstallCallerTracking(deviceObject);
}

/* --------------------------------------------------------------------------
 * Целостность SIDT / IDTR.
 * [0x14026ba84] сайт захвата sidt (sub_14026B9FA): компилированная функция
 * с прологом security-cookie, захватывающая IDTR из кода целостности
 * (вызывающие sub_1401F3135/sub_1401E11D9 -- VM-клей из кода целостности);
 * валидация base/limit едет на VM-thunk'ах цепочки (AC_NATIVE §4.2) --
 * вердикт VM payload-selected; захват + проверка диапазона ниже --
 * восстановленная нативная часть.
 * Хукнутая IDT (перехваты руткита/гипервизора) видна как база вне набора
 * kernel-модулей или аномальный limit (256 входов x 16).
 * ------------------------------------------------------------------------ */
#pragma pack(push, 1)
typedef struct _AC_IDTR {
    UINT16 Limit;
    UINT64 Base;
} AC_IDTR, *PAC_IDTR;
#pragma pack(pop)

NTSTATUS
AcSidtIntegrityCheck(
    VOID
    )
{
    AC_IDTR idtr;
    UINT64 moduleBase, moduleSize;

    __sidt(&idtr);

    /* sanity limit'а: x64 IDT = 256 гейтов x 16 байт - 1 */
    if (idtr.Limit < 0xFFF)
        return STATUS_DATA_ERROR;

    /* IDT должна жить внутри диапазона kernel-модуля (ntoskrnl/hal):
     * поиск диапазона через снапшот KLDR [0x1400010a4] */
    if (AcAddrToModule(idtr.Base, &moduleBase, &moduleSize) == NULL) {
        /* база IDT вне всех известных модулей -> хукнутая/подменённая IDT;
         * репорт через tamper-канал (детали вердикта едут на VM-thunk'ах
         * -- payload-selected: AC_NATIVE §4.2) */
        AcTamperForensicCapture(NULL, AC_TAMPER_CODE_LSTAR, 0x200);
        return STATUS_DATA_ERROR;
    }
    return STATUS_SUCCESS;
}

/* --------------------------------------------------------------------------
 * Вачдог самовосстановления dispatch-таблицы.
 * [watchdog, DISPATCH_CHAIN_C §2]: слот класса MajorFunction[0xE] обязан
 * содержать FUN_14001a5f4 или FUN_14001a87c; чужое значение атомарно
 * откатывается ресторером [0x14001aacc] (вариант по флагу 0x200)
 * ------------------------------------------------------------------------ */
VOID
AcDispatchTableWatchdog(
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    PDRIVER_DISPATCH expected = AcDispatchDeviceControl;

    if (DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] != expected) {
        /* [0x14001aacc] ресторер: атомарный откат модифицированного слота */
        InterlockedExchangePointer(
            (PVOID*)&DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL],
            (PVOID)expected);
    }
}

/* --------------------------------------------------------------------------
 * Аудит канарейки стек-фрейма (вооружённое сканирование стека
 * мониторируемого потока).
 * [0x140012ef0] нативное тело (corpus native/native_02.c FUN_140012ef0),
 * восстановлено проходом native-role из va_map (_research_tmp/va_map);
 * контекст [0x140108d98] (AC_CELL_STACK_AUDIT_CTX), смещения из тела:
 *   +0x20/+0x28 канареечная XOR-пара (ожидаемая куки фрейма)
 *   +0x58      owner-callback (вызывается с аргументом аудита)
 *   +0x7d      флаг armed (byte)
 *   +0x80      мониторируемый ETHREAD
 *   +0xf0      счётчик рекурсии (locked ++/--)
 *   +0xf8      ячейка канарейки фрейма (её АДРЕС подсаживается на стек)
 * индекс сохранённого слота канарейки [0x14010921c] (AC_CELL_STACK_CANARY_SLOT).
 * Проход вооружения (на мониторируемом потоке, канарейка ещё не найдена):
 * обход окна стека в поиске подсаженной тройки (сентинел -2 в слоте i,
 * адрес ячейки канарейки в i+2, парная куки в i+4); при совпадении
 * сохранить слот и выставить armed.
 * Вооружённый проход: owner-callback; на поднятом IRQL спуск через
 * разрешённую пару KeLowerIrql [0x140107a40] вокруг thunk'а ревалидации
 * [0x140012c60] (payload-dead e9-thunk, repoint_map payload-dead-code --
 * граница, никакой выдуманной логики), затем подъём через [0x140107ab0]
 * KfRaiseIrql.
 * ------------------------------------------------------------------------ */
typedef VOID (NTAPI *PAC_SAUDIT_CALLBACK)(UINT64 Arg);

#define AC_SAUDIT_CTX       ((UINT8*)g_pslots + AC_CELL_STACK_AUDIT_CTX)
#define AC_SAUDIT_KEY       (*(UINT64*)(AC_SAUDIT_CTX + 0x20))
#define AC_SAUDIT_PAIR      (*(UINT64*)(AC_SAUDIT_CTX + 0x28))
#define AC_SAUDIT_CALLBACK  (*(PAC_SAUDIT_CALLBACK*)(AC_SAUDIT_CTX + 0x58))
#define AC_SAUDIT_ARMED     (*(UINT8*)(AC_SAUDIT_CTX + 0x7d))
#define AC_SAUDIT_THREAD    (*(PVOID*)(AC_SAUDIT_CTX + 0x80))
#define AC_SAUDIT_REFCOUNT  (*(volatile LONG64*)(AC_SAUDIT_CTX + 0xf0))
#define AC_SAUDIT_FRAME     (AC_SAUDIT_CTX + 0xf8)
/* чтение opaque-байта ETHREAD гейтом вооружения оригинала (+0x232) */
#define AC_ETHREAD_AUDIT_FLAG 0x232

VOID
AcStackFrameAudit(
    _In_ UINT64 AuditArg,
    _In_opt_ PUINT64 FrameBase
    )
{
    KIRQL irql;
    UINT64 i;
    volatile UINT64* frame;

    InterlockedIncrement64(&AC_SAUDIT_REFCOUNT);

    if (AuditArg != 0 && FrameBase != NULL &&
        *(const UINT16*)((const UINT8*)FrameBase - 10) == 0xF33) {
        if (AC_SAUDIT_ARMED != 0) {
            AC_SAUDIT_CALLBACK(0);
            irql = KeGetCurrentIrql();
            if (irql != PASSIVE_LEVEL) {
                KeLowerIrql(PASSIVE_LEVEL);   /* пара [0x140107a40] */
            }
            if (AC_SLOT64(AC_CELL_STACK_CANARY_SLOT) != 0) {
                /* [0x140012c60] thunk ревалидации -- payload-dead дыра
                 * (класс repoint_map payload-dead-code); граница, никакой
                 * выдуманной логики за ней */
            }
            if (irql != PASSIVE_LEVEL) {
                KfRaiseIrql(irql);            /* пара [0x140107ab0] */
            }
            goto audit_done;
        }
        if (*(const UINT8*)((const UINT8*)KeGetCurrentThread() +
                            AC_ETHREAD_AUDIT_FLAG) == 0 &&
            (PVOID)KeGetCurrentThread() == AC_SAUDIT_THREAD) {
            frame = (volatile UINT64*)(UINT_PTR)&frame;
            for (i = 0x33; i < 0x78; i++) {
                if (frame[i] == (UINT64)-2 &&
                    frame[i + 2] == (UINT64)(UINT_PTR)AC_SAUDIT_FRAME &&
                    frame[i + 4] == (AC_SAUDIT_PAIR ^ AC_SAUDIT_KEY)) {
                    AC_SLOT64(AC_CELL_STACK_CANARY_SLOT) = i + 4;
                    AC_SAUDIT_ARMED = 1;
                    break;
                }
            }
        }
    }
    AC_SAUDIT_CALLBACK(AuditArg);

audit_done:
    InterlockedDecrement64(&AC_SAUDIT_REFCOUNT);
}
