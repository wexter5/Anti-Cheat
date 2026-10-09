/* ==========================================================================
 * driver_ts_blacklist.h -- таймстамп-блэклист читерских драйверов
 *                          (TimeDateStamp denylist, 41 значение)
 * --------------------------------------------------------------------------
 * Источник: аудит упущенного agent-515 (AUDIT_MISSED_AC.md §2) +
 * sln_candidate_ac_driver_ts_blacklist.c. Ручной лифтинг по сырым байтам:
 * регион НЕ лифтился ни одним корпусом («Could not recover jumptable at
 * 0x14004069c») -- GAP лифтинга, НЕ sealed.
 * ========================================================================== */
#ifndef FACEIT_AC_DRIVER_TS_BLACKLIST_H
#define FACEIT_AC_DRIVER_TS_BLACKLIST_H

#include <ntddk.h>

/* [0x140040a00] denylist-проверка TimeDateStamp (FALSE = в блэклисте) */
BOOLEAN AcIsNotBlacklistedTimestamp(_In_ UINT32 TimeDateStamp);

/* [0x140042278] PE-валидатор (кластер 0x140042278..0x140042528;
 * сайт вызова цепочки 0x1400423ee) */
VOID AcValidateModulePe(_In_ const UINT8* ImageBase,
                        _Inout_ UINT8* ModuleState);

#endif /* FACEIT_AC_DRIVER_TS_BLACKLIST_H */
