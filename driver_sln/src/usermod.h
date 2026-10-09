/* ==========================================================================
 * usermod.h -- user-mode module introspection из ядра: PEB/Wow64 обходы
 *              списков модулей + резолв экспортов
 * --------------------------------------------------------------------------
 * Источник: аудит упущенного agent-515 (AUDIT_MISSED_AC.md §3, строка 10).
 * Тела: library_rest.c:22954-23060 (0x140072908), 25098-25359
 * (0x14009c558/0x14009c6cc/0x14009c8a4), 1133-1167 (0x140016fa0),
 * fullbody6 native_00.c (0x140001288/0x140001314). Все четыре VA до аудита
 * были mis-classified в ac_native_crt (va_map); исправлено.
 * ========================================================================== */
#ifndef FACEIT_AC_USERMOD_H
#define FACEIT_AC_USERMOD_H

#include <fltKernel.h>   /* первым: идиома WDK minifilter (как events.c) */
#include <ntddk.h>

/* недокументированные экспорты (объявлены вручную; сигнатуры -- общеизвестные
 * нативные формы): возвращают PEB64 / PEB32 текущего процесса */
NTKERNELAPI PVOID PsGetProcessPeb(_In_ PEPROCESS Process);
NTKERNELAPI PVOID PsGetProcessWow64Process(_In_ PEPROCESS Process);

NTKERNELAPI NTSTATUS PsAcquireProcessExitSynchronization(
    _In_ PEPROCESS Process);

NTKERNELAPI VOID PsReleaseProcessExitSynchronization(
    _In_ PEPROCESS Process);

#ifndef AC_MemorySectionName
/* класс 2 ZwQueryVirtualMemory (публичный enum знает только
 * MemoryBasicInformation=0) */
#define AC_MemorySectionName  ((MEMORY_INFORMATION_CLASS)2)
#endif

/* [0x14009c558] резолв экспорта по имени из таблицы экспорта модуля
 * (гейты MmUserProbeAddress; форвардеры -> 0) */
UINT64 AcUsermodResolveExport(_In_ UINT64 ModuleBase, _In_z_ const CHAR* Name,
                              _In_ const UINT32* ExportDir);

/* [0x14009c6cc] модуль по адресу: обход InLoadOrder (Wow64 PEB32 первым,
 * когда Wow64Only == 0); возвращает базу и имя модуля */
NTSTATUS AcUsermodFindByAddr(_In_ UINT64 Addr, _Out_ UINT64* OutBase,
                             _Out_ PUNICODE_STRING OutName,
                             _In_ UINT8 Wow64Only);

/* [0x14009c8a4] модуль по имени: RtlEqualUnicodeString (case-insensitive)
 * по InLoadOrder обоих миров; тег-фильтр MatchTag (0 = без фильтра) */
NTSTATUS AcUsermodFindByName(_In_ PCUNICODE_STRING Name, _Out_ UINT64* OutBase,
                             _In_ UINT8 Wow64Only, _In_ UINT64 MatchTag);

/* [0x140072908] обход InInitializationOrder целевого процесса (под attach
 * по PID): совпадение подстроки имени -> section-name query + VM-трамп */
VOID AcUsermodPebWalk(_In_ UINT64 Reserved, _In_ UINT64 TargetPid,
                      _In_ PCUNICODE_STRING Needle);

#endif /* FACEIT_AC_USERMOD_H */
