/* ==========================================================================
 * tables.h -- layout .data pair/scratch-окна FACEIT_AC.sys
 * --------------------------------------------------------------------------
 * [0x140106000..0x140109d58] 1963 qword'а. Provenance layout'а:
 *   _research_tmp/rebuild/corpus/de_tables.c        (post-writer значения)
 *   _research_tmp/chainstate/writers_classified.jsonl (per-cell класс)
 *   _research_tmp/chainstate/trigger_snapshot.json   (KEVLAR snapshot)
 * Именованные ячейки ниже несут байтовое смещение внутри окна.
 * ========================================================================== */
#ifndef FACEIT_AC_TABLES_H
#define FACEIT_AC_TABLES_H

#include <ntddk.h>

#define AC_PSLOTS_BASE   0x140106000
#define AC_PSLOTS_COUNT  1963

extern UINT64 g_pslots[AC_PSLOTS_COUNT];

/* ---- именованные ячейки (байтовое смещение от AC_PSLOTS_BASE) ---- */

/* [0x140106080] boot-куки / pair-8 в стиле GS: q1 == ~q0, перезаписывается
 * per-boot энтропией DriverEntry; XOR'ится с rsp в каждом прологе/эпилоге
 * tramp. класс: boot-random (writers_classified.jsonl) */
#define AC_CELL_BOOT_COOKIE        0x080

/* [0x140107020] голова снапшота списка KLDR-модулей (kernel-модули) */
#define AC_CELL_KLDR_SNAPSHOT      0x1020
/* [0x140107028] мьютекс KLDR-снапшота */
#define AC_CELL_KLDR_MUTEX         0x1028

/* [0x140107030] ячейка собственного DEVICE_OBJECT (используется IoAllocateWorkItem) */
#define AC_CELL_DEVICE_OBJECT      0x1030

/* [0x140107268] собственный публичный ключ X25519 драйвера (BSS в файле; live-only) */
#define AC_CELL_OWN_PK             0x1268
/* [0x140107338] собственный секретный ключ X25519 драйвера (BSS в файле; live-only) */
#define AC_CELL_OWN_SK             0x1338

/* [0x1401073a0/0x1401073a8] эталонная XOR-пара LSTAR (KiSystemCall64) */
#define AC_CELL_LSTAR_REF          0x13a0

/* [0x1401083f8] pair-ячейка MmUnmapIoSpace (teardown SMBIOS) */
#define AC_CELL_MMUNMAP            0x23f8

/* [0x140108750] id зарегистрированного клиента (канал) */
#define AC_CELL_CLIENT_ID          0x2750
/* [0x140108cd8] LIST_HEAD кэша verified-модулей (game_integrity) */
#define AC_CELL_VERIFIED_LIST      0x2cd8
/* [0x140108d50] ячейка гейта channel-up ("канал поднят") */
#define AC_CELL_CHANNEL_UP         0x2d50
/* [0x140108db8] счётчик seq событий (LOCK xadd) */
#define AC_CELL_EVENT_SEQ          0x2db8
/* [0x140108e58] спинлок телеметрии (используется +0x18) */
#define AC_CELL_TELEMETRY_LOCK     0x2e58

/* [0x14010968c] id flavor LBR (dword; наблюдалась запись значения 3, каскад) */
#define AC_CELL_FLAVOR_ID          0x368c
/* [0x140109690/0x140109698] дескриптор границ flavor / указатель jumptable
 * (0 писателей по всей кампании 327 цепочек -> genuinely live state) */
#define AC_CELL_FLAVOR_BOUNDS      0x3690

/* [0x140109cc8] KSPIN_LOCK кэша verified-модулей */
#define AC_CELL_VERIFIED_LOCK      0x3cc8

/* ---- дополнительные именованные ячейки (gapcheck 3.9; роли по AC_CHAINS
 * #2.1, AC_REPLAY_BASE, RECON2_INVENTORY, COVERAGE_INVENTORY) ---- */

/* [0x140107040] голова очереди исходящих записей (AC_CHAINS #2.1) */
#define AC_CELL_QUEUE_LIST         0x1040

/* алиасы идентов AC_CHAINS #2.1: channel_primary_obj = AC_CELL_CHANNEL_UP,
 * channel_secondary_obj = AC_CELL_CHANNEL_SECONDARY,
 * event_seq_counter = AC_CELL_EVENT_SEQ */

/* [0x140108d50] первичный объект канала (гейт-объект "channel up";
 * та же ячейка, что AC_CELL_CHANNEL_UP -- алиас оставлен для паритета
 * с отчётами) */
#define AC_CELL_CHANNEL_PRIMARY    AC_CELL_CHANNEL_UP

/* [0x140108d68] вторичный объект канала (FNV-гейт ожидает, что
 * клиентский объект -- именно ЭТОТ канал, для регистрации type-1,
 * AC_FNV_GATE #2 сайт-1) */
#define AC_CELL_CHANNEL_SECONDARY  0x2d68

/* [0x140108c00] сохранённый PID клиента (слот регистрации type-1) */
#define AC_CELL_CHANNEL_PID_SAVED  0x2c00

/* [0x1401091fc] флаг ранней фазы (=1 наблюдалось записанным, RECON2 #3) */
#define AC_CELL_FLAG_1091FC        0x31fc

/* [0x14010936c] счётчик cpuid тайминг-детектора VM-exit
 * (AC_NATIVE алиас ячейки 0x1401093bc; обе формы процитированы) */
#define AC_CELL_TIMING_CPUID_CTR   0x33bc

/* [0x140109370] флаг окна тайминг-детектора VM-exit
 * (AC_NATIVE алиас ячейки 0x1401093c0) */
#define AC_CELL_TIMING_WINDOW_FLAG 0x33c0

/* [0x140106FE0] image base ndis.sys (AC_NDIS #2, qword_140106FE0) */
#define AC_CELL_NDIS_BASE          0xfe0

/* [0x140108d98] контекст anti-tamper аудита стека (AcStackFrameAudit;
 * +0x20/+0x28 пара канарейки, +0x58 owner callback, +0x7d armed, +0x80
 * мониторируемый ETHREAD, +0xf0 refcount, +0xf8 канарейка фрейма) */
#define AC_CELL_STACK_AUDIT_CTX    0x2d98
/* [0x14010921c] сохранённый индекс слота канарейки аудита стека */
#define AC_CELL_STACK_CANARY_SLOT  0x321c

/* ---- ячейки аудита упущенного (agent-515, AUDIT_MISSED_AC.md) ---- */

/* [0x14010910c]/[0x1401091b0]/[0x1401091b4] build-зависимые офсеты qword-полей
 * ETHREAD, читаемые thread-capture [0x14008846c] (значения вычисляет
 * резолвер офсетов семейства [0x1400640b0] -- payload-selected) */
#define AC_CELL_ETHREAD_OFF_A      0x310c
#define AC_CELL_ETHREAD_OFF_B      0x31b0
#define AC_CELL_ETHREAD_OFF_C      0x31b4

/* [0x140108c58]/[0x140108c60] XOR-пара ожидаемого физадреса страницы
 * (phys-guard [0x1400883b4]: пара вооружена, когда значения различны) */
#define AC_CELL_PHYS_EXPECT_LO     0x2c58
#define AC_CELL_PHYS_EXPECT_HI     0x2c60

/* [0x140108d78] номер билда ОС (dword; гейты 0x4564/0x47bc/0x65b7 --
 * таблица офсетов EPROCESS/ETHREAD по билду, семейство [0x1400640b0]) */
#define AC_CELL_OS_BUILD           0x2d78

/* [0x140108ec8] указатель на системную таблицу хендлов (HandleTableListHead
 * снапшот; читается триггером PML4-скана [0x14006f1d0]) */
#define AC_CELL_HANDLE_TABLE       0x2ec8

/* Inline-аксессоры (окно -- массив UINT64; sub-qword ячейки кастуются). */
#define AC_SLOT64(off)   (*(UINT64*)((UINT8*)g_pslots + (off)))
#define AC_SLOT32(off)   (*(UINT32*)((UINT8*)g_pslots + (off)))
#define AC_SLOT8(off)    (*(UINT8*)((UINT8*)g_pslots + (off)))
#define AC_SLOTP(off)    (*(PVOID*)((UINT8*)g_pslots + (off)))

#endif /* FACEIT_AC_TABLES_H */
