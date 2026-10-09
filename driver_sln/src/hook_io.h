/* ==========================================================================
 * hook_io.h -- телеметрия перехваченных вызовов (hook-IO)
 * --------------------------------------------------------------------------
 * Источник: аудит упущенного agent-515 (AUDIT_MISSED_AC.md §3, запасные).
 * ========================================================================== */
#ifndef FACEIT_AC_HOOK_IO_H
#define FACEIT_AC_HOOK_IO_H

#include <ntddk.h>

/* [0x14001a078] обёртка телеметрии перехваченных вызовов [dead-native] */
VOID AcHookedCallTelemetry(_In_ UINT64 Arg1, _In_ UINT64 Arg2,
                           _In_ UINT64 Arg3, _In_ UINT64 Arg4,
                           _In_ UINT64 Arg5);

#endif /* FACEIT_AC_HOOK_IO_H */
