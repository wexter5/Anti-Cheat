/* ==========================================================================
 * anti_tamper.h -- LSTAR-вачдог, GS-куки, RDTSC-зонды, мониторинг LBR,
 *                  самовосстановление dispatch-таблицы, аудит hook-слотов
 * ========================================================================== */
#ifndef FACEIT_AC_ANTI_TAMPER_H
#define FACEIT_AC_ANTI_TAMPER_H

#include <ntddk.h>

/* [0x140106080] init boot-куки (boot-random пара, q1=~q0) */
VOID AcSecurityCookieInit(VOID);

/* [0x14001a5f4] per-IOCTL проверка LSTAR */
VOID AcTamperCheckLstar(_In_ PIRP Irp);

/* [0x14001a5f4]/[0x14001a87c] форензик-захват (запись 0x700 + воркайтем) */
VOID AcTamperForensicCapture(_In_ PIRP Irp, _In_ ULONG Code,
                             _In_ UINT32 EvidenceSize);

/* [0x140128f50]/[0x140163f66] страж стека: int29 fastfail при несовпадении */
VOID AcStackGuardCheck(_In_ UINT64 Cookie);

/* [0x14010f403] тайминг-зонд RDTSC */
UINT64 AcTimingProbeRdtsc(VOID);

/* [0x14001b928] hook_slot_audit (аудит перевооружения 8 слотов) */
NTSTATUS AcHookSlotAudit(_In_ UINT64 ImageBase);

/* [0x14001b910] вход image-load notify: аудит с именем+базой образа */
VOID AcHookSlotAuditEx(_In_opt_ PUNICODE_STRING ImageName,
                       _In_ PVOID ImageBase);

/* [0x14026ba84] проверка целостности SIDT/IDTR */
NTSTATUS AcSidtIntegrityCheck(VOID);

/* [0x140051db8] обёртка монитора LBR (MSR 0x1c9 DEBUGCTL + 0x680/0x6c0) */
NTSTATUS AcLbrMonitorStep(VOID);

/* [0x140051670] установка трекинга вызывающих LBR (идиома отсрочки) */
NTSTATUS AcLbrInstallCallerTracking(_In_ PDEVICE_OBJECT DeviceObject);

/* [0x14001aacc watchdog] самовосстановление dispatch-таблицы */
VOID AcDispatchTableWatchdog(_In_ PDRIVER_OBJECT DriverObject);

/* [0x140012ef0] аудит канарейки стек-фрейма (восстановление va_map native-role) */
VOID AcStackFrameAudit(_In_ UINT64 AuditArg, _In_opt_ PUINT64 FrameBase);

#endif /* FACEIT_AC_ANTI_TAMPER_H */
