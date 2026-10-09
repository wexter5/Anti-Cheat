/* ==========================================================================
 * usermod.c -- user-mode module introspection из ядра (PEB/Wow64)
 * --------------------------------------------------------------------------
 * Интеграция аудита упущенного (agent-515, AUDIT_MISSED_AC.md §3 #10).
 * Обход InLoadOrder/InInitializationOrder списков модулей 64- и 32-битного
 * (Wow64) PEB, резолв экспортов по имени с гейтами MmUserProbeAddress,
 * RtlEqualUnicodeString-сравнения. Офсеты структур -- дословно из тел
 * (комментарии по публичным layout'ам PEB/LDR).
 * ========================================================================== */
#include "provenance.h"
#include "usermod.h"
#include "tables.h"

#define AC_STATUS_NOT_IMPLEMENTED  0xC0000002L   /* оба PEB отсутствуют */
#define AC_STATUS_NOT_FOUND        0xC0000225L   /* модуль не найден */

/* --------------------------------------------------------------------------
 * [0x140001288] attach-хелпер (fullbody6 native_00.c:145): кладёт
 * STATUS_PENDING (0xC0000001+... дословно -0x3fffffff), затем
 * PsLookupProcessByProcessId -> PsAcquireProcessExitSynchronization ->
 * KeStackAttachProcess; флаги +0x40 attached / +0x41 referenced
 * ------------------------------------------------------------------------ */
typedef struct _AC_USERMOD_ATTACH {
    NTSTATUS Status;                /* +0x00 */
    UINT32 _pad0;
    PEPROCESS Process;              /* +0x08 */
    KAPC_STATE ApcState;            /* +0x10 (0x30) */
    UINT8 Attached;                 /* +0x40 */
    UINT8 Referenced;               /* +0x41 */
} AC_USERMOD_ATTACH;

static VOID
AcUsermodAttachTarget(
    _Out_ AC_USERMOD_ATTACH* Ctx,
    _In_ UINT64 TargetPid
    )
{
    Ctx->Status = (NTSTATUS)0xC0000001L;    /* дословно: -0x3fffffff */
    Ctx->Attached = 0;
    Ctx->Referenced = 0;
    Ctx->Process = NULL;

    Ctx->Status = PsLookupProcessByProcessId((HANDLE)TargetPid,
                                             &Ctx->Process);
    if (NT_SUCCESS(Ctx->Status)) {
        Ctx->Referenced = 1;
        Ctx->Status = PsAcquireProcessExitSynchronization(Ctx->Process);
        if (NT_SUCCESS(Ctx->Status)) {
            Ctx->Attached = 1;
            KeStackAttachProcess((PRKPROCESS)Ctx->Process, &Ctx->ApcState);
        }
    }
}

/* --------------------------------------------------------------------------
 * [0x140001314] detach-хелпер (native_00.c:174): KeUnstackDetachProcess +
 * PsReleaseProcessExitSynchronization (по флагу attached), затем
 * ObfDereferenceObject (по флагу referenced)
 * ------------------------------------------------------------------------ */
static VOID
AcUsermodDetachTarget(
    _Inout_ AC_USERMOD_ATTACH* Ctx
    )
{
    if (Ctx->Attached != 0) {
        KeUnstackDetachProcess(&Ctx->ApcState);
        PsReleaseProcessExitSynchronization(Ctx->Process);
    }
    if (Ctx->Process != NULL && Ctx->Referenced != 0)
        ObfDereferenceObject(Ctx->Process);
}

/* --------------------------------------------------------------------------
 * [0x140016fa0] поиск подстроки в UNICODE_STRING (library_rest.c:1136):
 * RtlCompareUnicodeStrings скользящим окном длиной needle; возврат индекса
 * (в символах) первого совпадения, 0xFFFFFFFF когда нет, 0xC000000D на
 * нулевых аргументах; вызывающие проверяют (INT32)rc >= 0 (дословно:
 * `-1 < iVar4`). param_3 = CaseInsensitive
 * ------------------------------------------------------------------------ */
static UINT32
AcUsermodFindSubstring(
    _In_ PCUNICODE_STRING Haystack,
    _In_ PCUNICODE_STRING Needle,
    _In_ UINT8 CaseInsensitive
    )
{
    UINT16 needleLen, haystackLen;
    UINT16 i;

    if (Haystack == NULL || Needle == NULL ||
        Haystack->Buffer == NULL || Needle->Buffer == NULL)
        return 0xC000000D;

    needleLen = Needle->Length;
    haystackLen = Haystack->Length;
    if (needleLen <= haystackLen) {
        i = 0;
        do {
            if (RtlCompareUnicodeStrings(Haystack->Buffer + i,
                                         needleLen / sizeof(WCHAR),
                                         Needle->Buffer,
                                         needleLen / sizeof(WCHAR),
                                         CaseInsensitive) == 0)
                return i;
            i++;
        } while (i <= (UINT16)(haystackLen - needleLen) / sizeof(WCHAR));
    }
    return 0xFFFFFFFF;
}

/* --------------------------------------------------------------------------
 * [0x14009c558] резолв экспорта по имени (FUN_14009c558,
 * library_rest.c:25101-25152): ExportDir = {RVA, size}; все вычисленные
 * user-указатели гейтятся MmUserProbeAddress; перебор AddressOfNames,
 * ordinal из AddressOfNameOrdinals, RVA из AddressOfFunctions; форвардер
 * (RVA внутри диапазона директории) -> 0
 * ------------------------------------------------------------------------ */
UINT64
AcUsermodResolveExport(
    _In_ UINT64 ModuleBase,
    _In_z_ const CHAR* Name,
    _In_ const UINT32* ExportDir
    )
{
    UINT64 dirVa, namesVa, ordVa, funcsVa, probe;
    UINT32 count, i;

    probe = (UINT64)MmUserProbeAddress;

    if (ExportDir[0] == 0)
        return 0;

    dirVa = ModuleBase + ExportDir[0];
    if (dirVa >= probe)
        return 0;
    count = *(const UINT32*)(dirVa + 0x18);         /* NumberOfNames */
    if (count == 0)
        return 0;
    namesVa = ModuleBase + *(const UINT32*)(dirVa + 0x20); /* AddrOfNames */
    if (namesVa >= probe)
        return 0;

    for (i = 0; i < count; i++) {
        const CHAR* entryName;
        const CHAR* a;
        const CHAR* b;
        UINT16 ordinal;
        UINT32 funcRva;
        UINT64 result;

        entryName = (const CHAR*)(ModuleBase +
                                  *(const UINT32*)(namesVa + i * 4));
        if ((UINT64)entryName >= probe)
            continue;

        /* дословное посимвольное сравнение (до NUL включительно) */
        a = Name;
        for (;;) {
            CHAR ca = *a;
            CHAR cb = entryName[(SIZE_T)(a - Name)];
            if (ca != cb)
                break;
            a++;
            if (cb == '\0') {
                /* совпало: ordinal -> функция */
                ordVa = ModuleBase + *(const UINT32*)(dirVa + 0x24) + i * 2;
                if (ordVa >= probe)
                    return 0;
                ordinal = *(const UINT16*)ordVa;
                funcsVa = ModuleBase + *(const UINT32*)(dirVa + 0x1C) +
                          ordinal * 4;
                if (funcsVa >= probe)
                    return 0;
                funcRva = *(const UINT32*)funcsVa;
                result = ModuleBase + funcRva;
                /* форвардер: внутри диапазона export-директории -> 0 */
                if (ExportDir[0] < result &&
                    result < (UINT64)ExportDir[1] + ExportDir[0])
                    return 0;
                return result;
            }
        }
    }
    return 0;
}

/* --------------------------------------------------------------------------
 * [0x14009c6cc] модуль по адресу (FUN_14009c6cc,
 * library_rest.c:25177-25268): Wow64 PEB32 (PsGetProcessWow64Process ->
 * PEB32; Ldr по +0xC, гейт Initialized байт Ldr+4) обходится первым, когда
 * Wow64Only == 0; затем PEB64 (Ldr по +0x18, InLoadOrder по +0x10).
 * Офсеты записей дословно: x86 DllBase +0x18 / SizeOfImage +0x20 /
 * BaseDllName.Buffer +0x30; x64 DllBase +0x30 / SizeOfImage +0x40 /
 * BaseDllName.Buffer +0x60. Имя возвращается УКАЗАТЕЛЕМ на буфер записи
 * (длина в символах*2, кап 0xFFFC), без копии
 * ------------------------------------------------------------------------ */
NTSTATUS
AcUsermodFindByAddr(
    _In_ UINT64 Addr,
    _Out_ UINT64* OutBase,
    _Out_ PUNICODE_STRING OutName,
    _In_ UINT8 Wow64Only
    )
{
    const UINT8* wow64;
    const UINT8* peb;

    wow64 = (const UINT8*)PsGetProcessWow64Process(IoGetCurrentProcess());
    peb   = (const UINT8*)PsGetProcessPeb(IoGetCurrentProcess());

    if (peb == NULL && wow64 == NULL)
        return AC_STATUS_NOT_IMPLEMENTED;

    if (wow64 != NULL && Wow64Only == 0) {
        UINT32 ldr = *(const UINT32*)(wow64 + 0xC);      /* PEB32->Ldr */
        UINT32 head, link;

        if (*(const CHAR*)(UINT_PTR)(ldr + 4) == '\0')   /* Ldr->Initialized */
            return AC_STATUS_NOT_IMPLEMENTED;

        head = ldr + 0xC;                /* InLoadOrderModuleList (x86) */
        link = *(const UINT32*)(UINT_PTR)head;
        while (link != head) {
            const UINT32* e = (const UINT32*)(UINT_PTR)link;
            UINT32 base = e[6];          /* +0x18 DllBase */
            if (base < Addr && Addr < (UINT64)base + e[8] /* +0x20 Size */) {
                UINT32 nameBuf = e[0xC]; /* +0x30 BaseDllName.Buffer */
                UINT64 bytes = 0;
                if (nameBuf == 0) {
                    OutName->Length = 0;
                    OutName->MaximumLength = 0;
                }
                else {
                    while (((const WCHAR*)(UINT_PTR)nameBuf)[bytes / 2] !=
                           L'\0')
                        bytes += 2;
                    if (bytes > 0xFFFC)
                        bytes = 0xFFFC;
                    OutName->Length = (USHORT)bytes;
                    OutName->MaximumLength = (USHORT)(bytes + 2);
                }
                OutName->Buffer = (WCHAR*)(UINT_PTR)nameBuf;
                *OutBase = base;
                return STATUS_SUCCESS;
            }
            link = e[0];
        }
    }

    if (peb != NULL) {
        const UINT8* ldr = *(const UINT8* const*)(peb + 0x18); /* PEB->Ldr */
        const UINT64* head;
        const UINT64* link;

        if (*(const CHAR*)(ldr + 4) == '\0')               /* Initialized */
            return AC_STATUS_NOT_IMPLEMENTED;

        head = (const UINT64*)(ldr + 0x10);  /* InLoadOrderModuleList (x64) */
        for (link = (const UINT64*)*head; link != head;
             link = (const UINT64*)*link) {
            UINT64 base = link[6];                       /* +0x30 DllBase */
            if (base < Addr &&
                Addr < base + *(const UINT32*)(link + 8) /* +0x40 Size */) {
                UINT64 nameBuf = link[0xC];   /* +0x60 BaseDllName.Buffer */
                UINT64 bytes = 0;
                if (nameBuf == 0) {
                    OutName->Length = 0;
                    OutName->MaximumLength = 0;
                }
                else {
                    while (((const WCHAR*)nameBuf)[bytes / 2] != L'\0')
                        bytes += 2;
                    if (bytes > 0xFFFC)
                        bytes = 0xFFFC;
                    OutName->Length = (USHORT)bytes;
                    OutName->MaximumLength = (USHORT)(bytes + 2);
                }
                OutName->Buffer = (WCHAR*)nameBuf;
                *OutBase = base;
                return STATUS_SUCCESS;
            }
        }
    }
    return AC_STATUS_NOT_FOUND;
}

/* --------------------------------------------------------------------------
 * [0x14009c8a4] модуль по имени (FUN_14009c8a4,
 * library_rest.c:25274-25357): RtlEqualUnicodeString(case-insensitive) по
 * BaseDllName записей; MatchTag != 0 -- дополнительная сверка тега записи
 * (+0x60 x86 / +0xB8 x64 LDR; дословно): при mismatch поиск продолжается,
 * первый совпавший base запоминается (ветка «found, но тег не тот»)
 * ------------------------------------------------------------------------ */
NTSTATUS
AcUsermodFindByName(
    _In_ PCUNICODE_STRING Name,
    _Out_ UINT64* OutBase,
    _In_ UINT8 Wow64Only,
    _In_ UINT64 MatchTag
    )
{
    const UINT8* wow64;
    const UINT8* peb;
    BOOLEAN found32 = FALSE;

    wow64 = (const UINT8*)PsGetProcessWow64Process(IoGetCurrentProcess());
    peb   = (const UINT8*)PsGetProcessPeb(IoGetCurrentProcess());

    if (peb == NULL && wow64 == NULL)
        return AC_STATUS_NOT_IMPLEMENTED;

    if (wow64 != NULL && Wow64Only == 0) {
        UINT32 ldr = *(const UINT32*)(wow64 + 0xC);
        UINT32 head, link;

        if (*(const CHAR*)(UINT_PTR)(ldr + 4) == '\0')
            return AC_STATUS_NOT_IMPLEMENTED;

        head = ldr + 0xC;
        link = *(const UINT32*)(UINT_PTR)head;
        while (link != head) {
            const UINT32* e = (const UINT32*)(UINT_PTR)link;
            UINT32 nameBuf = e[0xC];             /* +0x30 BaseDllName.Buffer */
            UNICODE_STRING entryName;
            UINT64 bytes = 0;

            if (nameBuf == 0) {
                entryName.Length = 0;
                entryName.MaximumLength = 0;
                entryName.Buffer = NULL;
            }
            else {
                while (((const WCHAR*)(UINT_PTR)nameBuf)[bytes / 2] !=
                       L'\0')
                    bytes += 2;
                if (bytes > 0xFFFC)
                    bytes = 0xFFFC;
                entryName.Length = (USHORT)bytes;
                entryName.MaximumLength = (USHORT)(bytes + 2);
                entryName.Buffer = (WCHAR*)(UINT_PTR)nameBuf;
            }
            if (RtlEqualUnicodeString(&entryName, Name, TRUE)) {
                *OutBase = e[6];                         /* +0x18 DllBase */
                found32 = TRUE;
                if (MatchTag == 0 || (UINT32)MatchTag == e[0x18] /* +0x60 */)
                    return STATUS_SUCCESS;
            }
            link = e[0];
        }
        if (found32)
            return STATUS_SUCCESS;
    }

    if (peb != NULL) {
        const UINT8* ldr = *(const UINT8* const*)(peb + 0x18);
        const UINT64* head;
        const UINT64* link;
        BOOLEAN found = FALSE;

        if (*(const CHAR*)(ldr + 4) == '\0')
            return AC_STATUS_NOT_IMPLEMENTED;

        head = (const UINT64*)(ldr + 0x10);
        for (link = (const UINT64*)*head; link != head;
             link = (const UINT64*)*link) {
            /* BaseDllName записи x64: +0x58 (UNICODE_STRING целиком) */
            if (RtlEqualUnicodeString((PCUNICODE_STRING)(link + 0xB),
                                      Name, TRUE)) {
                *OutBase = link[6];                      /* +0x30 DllBase */
                found = TRUE;
                if (MatchTag == 0 || MatchTag == link[0x17] /* +0xB8 */)
                    return STATUS_SUCCESS;
            }
        }
        return found ? STATUS_SUCCESS : AC_STATUS_NOT_FOUND;
    }
    return AC_STATUS_NOT_FOUND;
}

/* --------------------------------------------------------------------------
 * payload-selected: VM-трамп section-информации (сайт
 * ac_vmentry_tramp_gs_0724e0 -> [0x1403d4d87]); аргументы готовятся в
 * кадре вызывающего (размер образа), тело за VM
 * ------------------------------------------------------------------------ */
static VOID
AcUsermodVmSection(
    _In_ UINT64 ModuleBase,
    _In_ UINT32 ModuleSize
    )
{
    UNREFERENCED_PARAMETER(ModuleBase);
    UNREFERENCED_PARAMETER(ModuleSize);
}

/* --------------------------------------------------------------------------
 * [0x140072908] обход InInitializationOrder целевого процесса
 * (FUN_140072908, library_rest.c:22959-23058): attach по PID
 * ([0x140001288]/[0x140001314]), чтение PEB/Wow64 ПОД прикреплённым
 * адресным пространством; per записи -- подстрока имени ([0x140016fa0]),
 * при совпадении ZwQueryVirtualMemory класс 2 (section-name, буфер 0x218)
 * на DllBase + VM-трамп с размером образа. param_1 не используется в теле
 * (дословно; сохранён как Reserved)
 * ------------------------------------------------------------------------ */
VOID
AcUsermodPebWalk(
    _In_ UINT64 Reserved,
    _In_ UINT64 TargetPid,
    _In_ PCUNICODE_STRING Needle
    )
{
    AC_USERMOD_ATTACH attach;
    const UINT8* wow64;
    const UINT8* peb;

    UNREFERENCED_PARAMETER(Reserved);

    AcUsermodAttachTarget(&attach, TargetPid);
    if (!NT_SUCCESS(attach.Status))
        return;

    wow64 = (const UINT8*)PsGetProcessWow64Process(IoGetCurrentProcess());
    peb   = (const UINT8*)PsGetProcessPeb(IoGetCurrentProcess());

    if (peb != NULL || wow64 != NULL) {
        if (wow64 == NULL) {
            if (peb != NULL) {
                const UINT8* ldr = *(const UINT8* const*)(peb + 0x18);
                const UINT64* head;
                const UINT64* link;

                if (*(const CHAR*)(ldr + 4) == '\0') {
                    AcUsermodDetachTarget(&attach);
                    goto done;
                }
                /* Ldr + 0x30: InInitializationOrderModuleList (x64);
                 * звено = entry + 0x20 */
                head = (const UINT64*)(ldr + 0x30);
                for (link = (const UINT64*)*head; link != head;
                     link = (const UINT64*)*link) {
                    /* +0x38 от звена = BaseDllName записи (entry+0x58) */
                    UINT32 rc = AcUsermodFindSubstring(
                        Needle, (PCUNICODE_STRING)(link + 7), 1);
                    if ((INT32)rc >= 0) {
                        UINT8 nameBuf[0x218];
                        NTSTATUS qs;

                        qs = ZwQueryVirtualMemory(
                            (HANDLE)-1, (PVOID)link[2] /* +0x10: DllBase */,
                            AC_MemorySectionName, nameBuf, sizeof(nameBuf),
                            NULL);
                        if (NT_SUCCESS(qs)) {
                            AcUsermodVmSection(
                                link[2],
                                *(const UINT32*)(link + 4) /* +0x20 Size */);
                        }
                    }
                }
            }
        }
        else {
            UINT32 ldr = *(const UINT32*)(wow64 + 0xC);    /* PEB32->Ldr */
            UINT32 head, link;

            if (*(const CHAR*)(UINT_PTR)(ldr + 4) == '\0') {
                AcUsermodDetachTarget(&attach);
                goto done;
            }
            /* Ldr + 0x1C: InInitializationOrderModuleList (x86);
             * звено = entry + 0x10 */
            head = ldr + 0x1C;
            link = *(const UINT32*)(UINT_PTR)head;
            while (link != head) {
                const UINT32* e = (const UINT32*)(UINT_PTR)link;
                UINT32 namePtr = e[8];        /* +0x20: BaseDllName.Buffer */
                UNICODE_STRING entryName;
                UINT64 bytes = 0;
                UINT32 rc;

                if (namePtr == 0) {
                    entryName.Length = 0;
                    entryName.MaximumLength = 0;
                    entryName.Buffer = NULL;
                }
                else {
                    while (((const WCHAR*)(UINT_PTR)namePtr)[bytes / 2] !=
                           L'\0')
                        bytes += 2;
                    if (bytes > 0xFFFC)
                        bytes = 0xFFFC;
                    entryName.Length = (USHORT)bytes;
                    entryName.MaximumLength = (USHORT)(bytes + 2);
                    entryName.Buffer = (WCHAR*)(UINT_PTR)namePtr;
                }
                rc = AcUsermodFindSubstring(Needle, &entryName, 1);
                if ((INT32)rc >= 0) {
                    UINT8 nameBuf[0x218];
                    NTSTATUS qs;

                    qs = ZwQueryVirtualMemory(
                        (HANDLE)-1, (PVOID)(UINT_PTR)e[2] /* +0x08: DllBase */,
                        AC_MemorySectionName, nameBuf, sizeof(nameBuf),
                        NULL);
                    if (NT_SUCCESS(qs)) {
                        AcUsermodVmSection(
                            (UINT64)e[2],
                            e[4] /* +0x10: SizeOfImage */);
                    }
                }
                link = e[0];
            }
        }
    }
    AcUsermodDetachTarget(&attach);
done:
    ;
}
