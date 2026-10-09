/* ==========================================================================
 * hook_io.c -- телеметрия перехваченных вызовов (hook-IO)
 * --------------------------------------------------------------------------
 * Интеграция аудита упущенного (agent-515, AUDIT_MISSED_AC.md §3).
 * ========================================================================== */
#include <ntddk.h>

#include "provenance.h"
#include "tables.h"
#include "hook_io.h"

/* --------------------------------------------------------------------------
 * [0x14001a078] AcHookedCallTelemetry -- обёртка телеметрии перехваченных
 * вызовов (FUN_14001a078, library_rest.c:2016-2169).
 *
 * [dead-native]: настоящая логика, но статически НЕДОСТИЖИМА -- вызывается
 * только из sealed VM-фреймов (методический вывод аудита §5.2:
 * «[dead-native] != мёртвое»). Интегрирована СТАБОМ с provenance по
 * заданию аудита; тело сохранено в корпусе (library_rest.c:2016-2169).
 *
 * Доказанные по телу факты (для протокола, не реализуются здесь):
 *   ExAcquireSpinLockShared глобала [0x140108e58]+0x18 (тот же блок
 *   состояния телеметрии, что у anti_tamper.c:AcTelemetryDedupCheck);
 *   вызов перехваченных fn-ptr'ов (pcVar12/pcVar13 из func_0x000140018a2c);
 *   статусы 0xC3520808 / 0x88883020 (ветки ответа перехвата);
 *   telemetry_dedup_check(status, retaddr, pid, 0x800);
 *   IoAllocateWorkItem([0x140107030]) + рекорд 0x700 байт
 *   (type 0x800 @+0x634, status @+0x660, retaddr @+0x658, pid @+0x62c,
 *   wi @+0x6e0); ошибки аллокации -> report 0x38 [0x14000c2c4].
 * ------------------------------------------------------------------------ */
VOID
AcHookedCallTelemetry(
    _In_ UINT64 Arg1,
    _In_ UINT64 Arg2,
    _In_ UINT64 Arg3,
    _In_ UINT64 Arg4,
    _In_ UINT64 Arg5
    )
{
    UNREFERENCED_PARAMETER(Arg1);
    UNREFERENCED_PARAMETER(Arg2);
    UNREFERENCED_PARAMETER(Arg3);
    UNREFERENCED_PARAMETER(Arg4);
    UNREFERENCED_PARAMETER(Arg5);
}
