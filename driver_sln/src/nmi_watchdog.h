/* ==========================================================================
 * nmi_watchdog.h -- контур NMI-вачдога
 * ========================================================================== */
#ifndef FACEIT_AC_NMI_WATCHDOG_H
#define FACEIT_AC_NMI_WATCHDOG_H

#include <ntddk.h>

/* [0x1402b1c16]/[0x1403bd850] регистрация KeRegisterNmiCallback */
NTSTATUS AcNmiWatchdogRegister(VOID);

/* [0x1402b1c24] KeDeregisterNmiCallback (путь unload) */
VOID AcNmiWatchdogUnregister(VOID);

/* [0x1402b1bfa]/[0x1402a78bf] cross-CPU NMI-свип + EOI */
VOID AcNmiWatchdogSweepAllCpus(VOID);

/* флаги NMI-аномалий для passive-level воркеров */
UINT32 AcNmiWatchdogConsumeFlags(VOID);

/* [0x14012afb2] контур HalReturnToFirmware (граница) */
NTSTATUS AcNmiWatchdogFirmwareReset(VOID);

#endif /* FACEIT_AC_NMI_WATCHDOG_H */
