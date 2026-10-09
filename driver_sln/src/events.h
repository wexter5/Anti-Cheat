/* ==========================================================================
 * events.h -- шина событий: heartbeat, module-load, детекция, файл+подпись,
 *             push'и событий драйвера, notify-callback'и
 * ========================================================================== */
#ifndef FACEIT_AC_EVENTS_H
#define FACEIT_AC_EVENTS_H

#include <ntddk.h>

/* [0x14000c35c] heartbeat_producer: запись 0x24 каждые ~30s, два таймера
 * со сдвигом 4s (живость D->S) */
VOID AcEventHeartbeat(VOID);

/* [0x14003f78c]/[0x140043258] продюсер 0x26 module-load (0x4D8) */
NTSTATUS AcEventModuleLoad(_In_ UINT64 Base, _In_ UINT64 Size,
                           _In_z_ const WCHAR* Path, _In_ UINT32 Flags,
                           _In_ NTSTATUS VerifyStatus);

/* [0x14003f0bc] событие состояния модуля 0x1E (0x210): state 2/3 */
NTSTATUS AcEventModuleState(_In_z_ const WCHAR* Path, _In_ UINT8 State);

/* [0x1400713c8] событие файл+подпись 0x2B (0x4D4 + размер подписи) */
NTSTATUS AcEventFileSignature(_In_z_ const WCHAR* Path,
                              _In_ const UINT8* SignatureBlob,
                              _In_ UINT32 SignatureSize);

/* [0x140073c04] сессионный продюсер записей 0x12 (0x658) */
VOID AcEventSessionRecord(_In_ UINT64 ClientId);

/* [0x140052268] шаг проверки code-integrity сессионной цепочки */
VOID AcEventCodeIntegrityCheck(VOID);

/* [0xC350202C] обработчик push'а событий драйвера (всплески игры) */
NTSTATUS AcEventDriverEvent(_In_ const VOID* Buf, _In_ UINT32 Len);

/* [0x140070e9c] rate_limit_dedup: 10 на окно 600s */
BOOLEAN AcEventRateLimitAllow(_In_ UINT32 EventKind);

/* [0x14000c2c4] внутренний репортёр ошибок/живости (коды 0x13/0x14/0x26/0x38) */
VOID AcEventReportFailure(_In_ UINT32 Code, _In_ UINT64 Context);

/* [0xC350201C] match-over: сброс match-состояния (MATCH_SESSION_TIMELINE #0.1) */
NTSTATUS AcEventMatchOver(VOID);

/* воркайтем-процедура для форензик-телеметрии (постановка в anti_tamper.c) */
IO_WORKITEM_ROUTINE AcEventForensicWorkItem;

/* [0x14001b910] image_load_notify_callback (kernel-путь -> аудит хуков)
 * [0x140043258] module_notify_callback (продюсер 0x26 + вооружение PCI) */
NTSTATUS AcRegisterNotifyCallbacks(VOID);

#endif /* FACEIT_AC_EVENTS_H */
