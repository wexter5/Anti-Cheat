/* ==========================================================================
 * vmwall_engines.c — движки детектов/вердиктов, восстановленные добитием
 * остаточной VM-стены (зона: _research_tmp/vmwall/)
 * --------------------------------------------------------------------------
 * Все функции несут provenance-VA оригинала. Источники доказательств:
 * корпус faceitkernel_deobf_c_v4 (native_*.c, SIMD-stub комментарии),
 * трассы _research_tmp/vmentry/mass/*, AC_NDIS.md, BYTE_MAP.md,
 * SEALED_SEMANTICS.md; полный разбор — _research_tmp/vmwall/VMWALL_REPORT.md.
 * KAT-прогоны логики: _research_tmp/vmwall/candidates (8/8 ALL PASS).
 * ========================================================================== */
#include <ntddk.h>

#include "provenance.h"
#include "tables.h"
#include "vmwall_engines.h"

/* ==========================================================================
 * 1. FINGERPRINT -- вердикт proven-sha256 (CNG-делегированный)
 * --------------------------------------------------------------------------
 * [0x140375b79] VM-тело fingerprint (FUN_14009be44 e9-thunk):
 *  - имя алгоритма "SHA256\0" собрано wide-иммедиатами @0x1400122e9
 *    (gap2_02.c:24250-24256; api_layer.c:42800-42806, 43980-43986;
 *    gap2_01.c:47524-47530);
 *  - BCryptOpenAlgorithmProvider(phAlg=0x140109210, "SHA256", NULL, 1)
 *    @0x1401d7125 -- исполняется внутри цепочек фингерпринта
 *    A_0116e4/D_07bb20 (трассы mass/1402c19fc + 1403db34f: api_resolve
 *    BCryptOpenAlgorithmProvider FNV 0x1e7273483b28159d, BCryptGetProperty
 *    0xded8482b3d5effb4);
 *  - поток: IoCreateFileEx (пара 0x1401075d0) -> ZwCreateSection (пара
 *    0x140107730) -> map -> CNG hash -> hex;
 *  - нативный sibling FUN_14009bcb4 (native_13.c:1943): тот же CNG-поток с
 *    дайджестом 0x14 байтов (провайдер 0x140109208 через FUN_1400120ac);
 *  - hex: цикл FUN_1400471d4 с fmt g_unk_1400a49f0 = "%02x" (raw 0xa3df0);
 *  - negative: константы SHA-256 K-table/SHA-1/MD5 = 0 попаданий во всём
 *    образе; dword-попадания "H0" по raw 0xabfc4.. = 4 копии BLAKE2b IV
 *    @0x1400acfc0/0x1400ad000/+0x40/+0x80 (qword'ы SHA-512 IV) -- коллизия
 *    dword-уровня, программного SHA-256 в образе не существует.
 * Вызывающие: FUN_140045448 (путь игровых файлов minifilter, out rec+0x448),
 * FUN_140042034 (путь verify модуля, out obj+0x448).
 * Реконструкция делегирует CNG точно как оригинал.
 * ------------------------------------------------------------------------ */

/* [0x14009bcb4] + [0x140375b79] hex-кодировщик: "%02x" на байт дайджеста
 * (драйвер форматирует _vsnprintf_s; kernel-форма эквивалента).
 * вызывающий: потребители фингерпринта -- FUN_140045448 (запись игрового
 * файла 0x26, out rec+0x448) и FUN_140042034 (путь verify модуля, out
 * obj+0x448) зовут тело фингерпринта; продюсер 0x2B заполняет своё поле
 * +0x451 из того же пути (FUN_14009be44(map, size, out), AC_EVENT_CHANNEL
 * §4), а ответ USB-handshake 0xC3502048 несёт тот же класс hex64.
 * Вызывающие реконструкции: AcEventFileSignature (events.c) и
 * AcChannelBuildUsbResponse (channels.c) */
VOID
AcFingerprintHex(
    _In_reads_(32) const UINT8 Digest[32],
    _Out_writes_(AC_FINGERPRINT_HEX_CAP) CHAR Out[AC_FINGERPRINT_HEX_CAP]
    )
{
    static const CHAR h[] = "0123456789abcdef";
    UINT32 i;

    for (i = 0; i < 32; i++) {
        Out[i * 2 + 0] = h[Digest[i] >> 4];
        Out[i * 2 + 1] = h[Digest[i] & 15];
    }
    Out[AC_FINGERPRINT_HEX_LEN] = '\0';
}

/* ==========================================================================
 * 2. find_pattern_wildcard -- masked memmem
 * --------------------------------------------------------------------------
 * [0x14009D438] сигнатура доказана 68 call-сайтами (AC_NDIS §3):
 * scan(start=rcx, end=rdx, needle=r8, mask=r9, len=[rsp+0x28]);
 * mask[i]==0 -> wildcard; возвращает первое совпадение / 0.
 * Тело: зашифрованная .text-дыра (те же байты в оригинале и devirt-образе,
 * raw 0x9c838; нет в списках devirt-остатков) -- x86-тело статически не
 * читается (runtime-ключ протектора; класс genuinely-live). Контракт ниже
 * доказан call-сайтами; KAT: candidates/scan_pattern_wildcard.c.
 * ------------------------------------------------------------------------ */
const UINT8 *
AcFindPatternWildcard(
    _In_ const UINT8 *Start,
    _In_ const UINT8 *End,
    _In_ const UINT8 *Needle,
    _In_ const UINT8 *Mask,
    _In_ SIZE_T Len
    )
{
    const UINT8 *p;
    SIZE_T i;

    if (Len == 0 || (SIZE_T)(End - Start) < Len)
        return NULL;
    for (p = Start; p + Len <= End; p++) {
        for (i = 0; i < Len; i++) {
            if (Mask[i] != 0 && p[i] != Needle[i])
                break;
        }
        if (i == Len)
            return p;
    }
    return NULL;
}

/* ==========================================================================
 * 3. Движок тампера сравнения секций 0x12/0x06 + 0x12/0x0b
 * --------------------------------------------------------------------------
 * [0x14007ac24] продюсер 0x06 (native_10.c:1082-1529): фильтр секций
 * (EXECUTE | (READ & !WRITE)) & !UNINIT; пропуск имён "PAGEwx3"/"INITKDBG"
 * (декодеры func_0x00014007b6ac k=(i%51)+0x5f / func_0x00014007b6e4
 * k=(i%51)+0x5b); DISCARDABLE page-гранулярный пропуск нулевых серий;
 * overlay-allowlist puRam0000000140109690; legit-diff FUN_14007a300
 * (RIP-rel таблицы 0x140108cd0/0x140108cb0/0x140108c90) + FUN_14007a728
 * (декод инструкций FUN_14004f4c8, REX lookback); паттерн syscall-хука
 * 4C 8B 15 .. .. .. E8|E9 гейтован bRam0000000140108c50/51 ->
 * FUN_1400796a0 апплаер фиксапов (type3 кастомный якорь 0x140108e88,
 * type4 PE base-reloc).
 * Запись: str1 "%x %.8hs %wZ" (k=(i%51)+0x49; err "%x %.8hs %wZ %x"
 * +0x4c), str2/str3 "%02x " дампы file/mem (k=(i%51)+0x2f/+0x33),
 * +0x62c b50, +0x630 b51, +0x634 state, +0x638 off, +0x640 len,
 * +0x648 aligned; хвостовой дамп -> 0x22 reason=6 (native_10.c:1488).
 * [0x14006ba50] вариант 0x0b (native_09.c:955-1316): добавляет диапазоны
 * исключения IAT (data-dir [12]) и Export (data-dir [0]); legit-фильтры
 * FUN_14006a394 (разрешатель указателей дескриптора) + FUN_14006b088
 * (вайтлист +6); финалайзер FUN_14006b510 (сентинел ".rsrc" k=(i%58)+0x46).
 * [0x14006a394] репортёр цепочек указателей: str1 "%wZ %x %.8hs %wZ"
 * (k=(i%58)+0x3c), элементы цепочки "-> %llx" (k=(i%58)+0x29 / " -> %llx"
 * +0x06), имена ZwQueryObject класс 2, коды ошибок iVar*0x100+{5,6,7}
 * @+0x630.
 * ------------------------------------------------------------------------ */

static BOOLEAN
AcRangeHit(
    _In_ UINT64 V,
    _In_reads_(N) const AC_SCAN_RANGE *R,
    _In_ UINT32 N,
    _Out_opt_ UINT32 *Index
    )
{
    UINT32 i;

    for (i = 0; i < N; i++) {
        if (R[i].Lo <= V && V < R[i].Hi) {
            if (Index != NULL)
                *Index = i;
            return TRUE;
        }
    }
    return FALSE;
}

/* [0x14007a300] + [0x14007a728] legit-diff: инструкция с операндом rel32,
 * покрывающим diff-байт; ожидаемый (file-side) адресат внутри известных
 * диапазонов модулей -> пропустить длину инструкции */
static UINT32
AcRipLegitSkip(
    _In_ const UINT8 *M,
    _In_ const UINT8 *F,
    _In_ UINT64 Fva,
    _In_ const AC_SCAN_CTX *Ctx
    )
{
    INT back;

    for (back = 0; back <= 6; back++) {
        const UINT8 *mi = M - back;
        const UINT8 *fi = F - back;
        UINT32 op = mi[0];
        INT32 rel;
        UINT64 tgt;

        if (back > 0 && (mi[-1] & 0xf0) == 0x40) {   /* REX lookback */
            mi--; fi--;
        }
        if (op == 0xe8 || op == 0xe9) {                /* call/jmp rel32 */
            if (back < 1 || back > 4)
                continue;
            rel = (INT32)((UINT32)fi[1] | ((UINT32)fi[2] << 8) |
                          ((UINT32)fi[3] << 16) | ((UINT32)fi[4] << 24));
            tgt = Fva - back + 5 + rel;
            if (AcRangeHit(tgt, Ctx->RipOk, Ctx->RipOkCount, NULL))
                return (UINT32)(5 - back);
        } else if (op == 0x8b || op == 0x89 || op == 0x8d) {
            if ((mi[1] & 0xc7) != 0x05)                /* modrm rip-rel */
                continue;
            if (back < 2 || back > 5)
                continue;
            rel = (INT32)((UINT32)fi[2] | ((UINT32)fi[3] << 8) |
                          ((UINT32)fi[4] << 16) | ((UINT32)fi[5] << 24));
            tgt = Fva - back + 6 + rel;
            if (AcRangeHit(tgt, Ctx->RipOk, Ctx->RipOkCount, NULL))
                return (UINT32)(6 - back);
        }
    }
    return 0;
}

/* helper: wide-допись "%02x " (формат доказан декодером 0x14006b9d0; twin
 * сайта формата [0x14004df48] "%02x", strings.h 0x14004e14c -- va_map) */
static VOID
AcRec12HexDump(
    _Inout_ PWCH Str,
    _In_ UINT32 CapChars,
    _In_reads_(N) const UINT8 *B,
    _In_ SIZE_T N
    )
{
    static const WCHAR h[] = L"0123456789abcdef";
    UINT32 w = 0;
    SIZE_T i;

    while (w < CapChars && Str[w] != L'\0')
        w++;
    for (i = 0; i < N && w + 3 < CapChars; i++) {
        Str[w++] = h[B[i] >> 4];
        Str[w++] = h[B[i] & 15];
        Str[w++] = L' ';
    }
    if (w < CapChars)
        Str[w] = L'\0';
}

/* [0x14007ac24] + [0x14006ba50] ядро compare+batch: одна секция,
 * <= 0xf записей (по одной на diff-серию); геометрия записи AC_REC12_OFF_*
 * нативные близнецы (va_map): [0x14006b088] хелпер legit-фильтра варианта
 * 0x0b (вайтлист +6, вызывает cited 0x14006b9d0/0x14006ba50);
 * [0x140074a2c] близнец сравнения секций через '.text' (strings.h
 * 0x140074bbc) */
UINT32
AcScanCompareSection(
    _In_ const UINT8 *Mem,
    _In_ UINT64 MemVa,
    _In_ const UINT8 *File,
    _In_ UINT64 FileVa,
    _In_ SIZE_T RawLen,
    _In_ SIZE_T Aligned,
    _In_ UINT32 Characteristics,
    _In_ UINT32 Subtype,
    _In_ const CHAR SectName[8],
    _In_ const AC_SCAN_CTX *Ctx,
    _In_ AC_REC12_SEND_FN Send,
    _In_opt_ PVOID UserCtx
    )
{
    UINT8 rec[AC_REC12_SIZE];
    SIZE_T i = 0;
    UINT32 batch = 0;

    UNREFERENCED_PARAMETER(MemVa);
    UNREFERENCED_PARAMETER(Characteristics);

    RtlZeroMemory(rec, sizeof rec);
    *(UINT32 *)(rec) = 0x12;
    *(UINT32 *)(rec + AC_REC12_OFF_SUBTYPE) = Subtype;
    *(UINT32 *)(rec + AC_REC12_OFF_F62C) = Ctx->HookB50;
    *(UINT32 *)(rec + AC_REC12_OFF_F630) = Ctx->HookB51;
    *(UINT32 *)(rec + AC_REC12_OFF_F634) = Ctx->StateD78;

    while (i < RawLen && batch < AC_REC12_BATCH_MAX) {
        UINT32 skip;
        SIZE_T run, n;
        UINT32 exclIdx;

        if (Mem[i] == File[i]) {
            i++;
            continue;
        }
        if (AcRangeHit(FileVa + i, Ctx->Excl, Ctx->ExclCount, &exclIdx)) {
            i = (SIZE_T)(Ctx->Excl[exclIdx].Hi - FileVa);
            continue;
        }
        skip = AcRipLegitSkip(Mem + i, File + i, FileVa + i, Ctx);
        if (skip != 0) {
            i += skip;
            continue;
        }
        run = i;
        n = 0;
        while (i < RawLen && Mem[i] != File[i] && n < 64) {
            i++;
            n++;
        }
        /* одна запись 0x12 на diff-серию */
        *(UINT64 *)(rec + AC_REC12_OFF_OFF) = (UINT64)run;
        *(UINT64 *)(rec + AC_REC12_OFF_LEN) = (UINT64)RawLen;
        *(UINT64 *)(rec + AC_REC12_OFF_ALIGNED) = (UINT64)Aligned;
        /* str1 "%x %.8hs %wZ" -- rva + 8-символьное имя секции (US модуля
         * дописывается caller-side хабом записей, сайт FUN_140001030) */
        {
            PWCH s1 = (PWCH)(rec + AC_REC12_OFF_STR1);
            UINT32 w = 0, k;
            UINT64 v = FileVa + run;
            static const WCHAR h[] = L"0123456789abcdef";
            INT sh;

            for (sh = 60; sh >= 0 && w < 0x100; sh -= 4) {
                WCHAR c = h[(v >> sh) & 15];
                if (c != L'0' || w != 0)
                    s1[w++] = c;
            }
            if (w == 0)
                s1[w++] = L'0';
            s1[w++] = L' ';
            for (k = 0; k < 8 && SectName[k] != '\0' && w < 0x102; k++)
                s1[w++] = (WCHAR)SectName[k];
            s1[w] = L'\0';
        }
        RtlZeroMemory(rec + AC_REC12_OFF_STR2, 0x104 * sizeof(WCHAR));
        RtlZeroMemory(rec + AC_REC12_OFF_STR3, 0x104 * sizeof(WCHAR));
        AcRec12HexDump((PWCH)(rec + AC_REC12_OFF_STR2), 0x104, File + run, n);
        AcRec12HexDump((PWCH)(rec + AC_REC12_OFF_STR3), 0x104, Mem + run, n);
        Send(rec, UserCtx);
        batch++;
        RtlZeroMemory(rec + AC_REC12_OFF_STR1, 0x104 * sizeof(WCHAR));
    }
    return batch;
}

/* ==========================================================================
 * 4. атрибуция addr -> module 0x12/0x47
 * --------------------------------------------------------------------------
 * [0x1400010a4] addr_to_module_lookup (native_00.c:60): быстрый путь --
 * рабочий список по param_2+8, узел {+0x10 base, +0x20 size(u32)}; медленный
 * путь -- KLDR-снапшот 0x140107020 под парами локов, запись {+0x30
 * DllBase, +0x40 SizeOfImage} -> FUN_14009b8ac.
 * [0x140091e0c] продюсер (native_12.c:1325): аудит process-handle на
 * первичном клиенте 0x140108750; PreviousMode==1 пропускается; access в
 * {0x10 VM_READ, 0x20 VM_WRITE, 0x40 DUP_HANDLE, 0x80 CREATE_PROCESS} или
 * флаг 0x1000000 -> запись {0x12, 0x47, seq LOCK xadd 0x140108db8, str2
 * "%wZ+%x" (k=(i%54)+0x75) или "%p" (k=(i%54)+0x7a)}; pass-through пара
 * 0x140108d98.
 * [0x14000118c] FNV-1a-64 резолвер имён модулей (basis
 * 0xcbf29ce484222325, prime 0x100000001b3, rolling (c ^ h) * p).
 * [0x1400796a0] native role twin: обход атрибуции, драйвящий cited 0x1400010a4 (va_map)
 * ------------------------------------------------------------------------ */
PAC_MOD_NODE
AcAddrInModuleList(
    _In_ UINT64 Addr,
    _In_ PLIST_ENTRY Head
    )
{
    PLIST_ENTRY e;

    for (e = Head->Flink; e != Head; e = e->Flink) {
        AC_MOD_NODE *n = CONTAINING_RECORD(e, AC_MOD_NODE, Link);
        if (n->Base <= Addr && Addr < n->Base + n->Size)
            return n;
    }
    return NULL;
}

/* ==========================================================================
 * 5. Семейство XOR-декодеров строк
 * --------------------------------------------------------------------------
 * Шаблон (дизассемблирован из .text; делители доказаны magic-константами):
 * w[i] ^= ((i % D) + K). Доказанные экземпляры -- см. таблицу
 * strdec_family.c:
 * "%wZ %x %.8hs %wZ" (0x14006afc8 D58 K3c; 0x14006c3a4 K16),
 * "-> %llx"/" -> %llx" (0x14006b008 K29; 0x14006b048 K06),
 * ".rsrc" (0x14006b928 K46), "%02x " (0x14006b9d0 K78; 0x14007b71c D51
 * K2f; 0x14007b75c K33), "PAGEwx3" (0x14007b6ac D51 K5f), "INITKDBG"
 * (0x14007b6e4 K5b), "%x %.8hs %wZ" (0x14007b79c K49), "%x %.8hs %wZ %x"
 * (0x14007b7dc K4c), "%wZ+%x" (0x1400921cc D54 K75), "%p" (0x140092214
 * K7a), ".vpk" (0x140045ac4 D51 K68), "%wZ %wZ" (0x140045b04 K3f),
 * "%d %d %d - %04hx:%04hx - %d" (0x14005df54/0x14005df9c D55 K38/K43),
 * "%wZ %p %.8hs %wZ" (0x14006ba10 D58 K7c).
 * ------------------------------------------------------------------------ */
VOID
AcStrDecWide(
    _Inout_updates_(N) UINT16 *W,
    _In_ UINT32 N,
    _In_ UINT32 D,
    _In_ UINT32 K
    )
{
    UINT32 i;

    for (i = 0; i < N; i++)
        W[i] ^= (UINT16)((i % D) + K);
}

/* ==========================================================================
 * 6. Классификатор игровых файлов minifilter'а
 * --------------------------------------------------------------------------
 * [0x140044f08] гейт: первичный клиент 0x140108750 -> [0x140045714]
 * pre-create (FltGetFileNameInformationUnsafe пара 0x107828).
 * [0x1400444a8] суффикс .bsp (ac_strdec_044684) -> быстрая запись 0x26.
 * [0x1400446c4] классификатор: суффикс (FUN_14009b828 CI tail-матч, пара
 * 0x107a08): "_dir.vpk"(044c88), "_000.vpk"(044cc8), "_00N.vpk"
 * (FUN_140044d08 payload stub), "_003.vpk"(044d48), "gameinfo.gi"(044dc8),
 * "zip0.zip"(044d88); подстрока (ac_memmem): "\shaders\"(044e08),
 * "\csgo_lv\"(044e48), "\cfg\gamestate_integration_"(044ec8); NEGATIVE
 * "\workshop\"(044e88) -> FUN_140045448: секция+map -> FUN_14009be44
 * (SHA-256 содержимого @+0x448) -> дедуп по фингерпринту -> 0x26.
 * [0x140044f6c] проверка device-стека: "\Device\Dokan"(045388),
 * "\Device\WinFsp"(0453c8),
 * "\Device\{066B0CB8-ADD8-4d50-ACE4-AFA10257284E}-" префикс(045408)
 * (пара 0x1079d8) -> ACCESS_DENIED; per-driver кэш 0x1401093d0.
 * Ненормализуемый .vpk (пара 0x108178 fail): ZwQueryInformationFile
 * (пара 0x1084e8) -> 0xc0000022 + 0x26 "%wZ %wZ" (func_0x000140045b04
 * k=(i%51)+0x3f).
 * ------------------------------------------------------------------------ */

typedef struct _AC_CI_PAT {
    PCWSTR Pat;
    UINT32 Len;                     /* символы, без NUL */
} AC_CI_PAT;

static const WCHAR kSufDirVpk[]   = L"_dir.vpk";
static const WCHAR kSuf000Vpk[]   = L"_000.vpk";
static const WCHAR kSuf001Vpk[]   = L"_001.vpk";
static const WCHAR kSuf002Vpk[]   = L"_002.vpk";
static const WCHAR kSuf003Vpk[]   = L"_003.vpk";
static const WCHAR kSufGameInfo[] = L"gameinfo.gi";
static const WCHAR kSufZip0[]     = L"zip0.zip";
static const WCHAR kSubShaders[]  = L"\\shaders\\";
static const WCHAR kSubCsgoLv[]   = L"\\csgo_lv\\";
static const WCHAR kSubGsi[]      = L"\\cfg\\gamestate_integration_";
static const WCHAR kSubWorkshop[] = L"\\workshop\\";
static const WCHAR kSufBsp[]      = L".bsp";
static const WCHAR kSufVpk[]      = L".vpk";
static const WCHAR kDevDokan[]    = L"\\Device\\Dokan";
static const WCHAR kDevWinFsp[]   = L"\\Device\\WinFsp";
static const WCHAR kDevGuid[] =
    L"\\Device\\{066B0CB8-ADD8-4d50-ACE4-AFA10257284E}-";

static const AC_CI_PAT kSuffixes[] = {
    { kSufDirVpk,   ARRAYSIZE(kSufDirVpk) - 1 },
    { kSuf000Vpk,   ARRAYSIZE(kSuf000Vpk) - 1 },
    { kSuf001Vpk,   ARRAYSIZE(kSuf001Vpk) - 1 },
    { kSuf002Vpk,   ARRAYSIZE(kSuf002Vpk) - 1 },
    { kSuf003Vpk,   ARRAYSIZE(kSuf003Vpk) - 1 },
    { kSufGameInfo, ARRAYSIZE(kSufGameInfo) - 1 },
    { kSufZip0,     ARRAYSIZE(kSufZip0) - 1 },
};
static const AC_CI_PAT kSubstrs[] = {
    { kSubShaders,  ARRAYSIZE(kSubShaders) - 1 },
    { kSubCsgoLv,   ARRAYSIZE(kSubCsgoLv) - 1 },
    { kSubGsi,      ARRAYSIZE(kSubGsi) - 1 },
};
static const AC_CI_PAT kDevPrefixes[] = {
    { kDevDokan,    ARRAYSIZE(kDevDokan) - 1 },
    { kDevWinFsp,   ARRAYSIZE(kDevWinFsp) - 1 },
    { kDevGuid,     ARRAYSIZE(kDevGuid) - 1 },
};

/* [0x14009b828] матч суффикса, case-insensitive (US-хвост +
 * контракт RtlEqualUnicodeString CI) */
static BOOLEAN
AcSuffixCi(
    _In_ PCUNICODE_STRING Path,
    _In_ const AC_CI_PAT *Suf
    )
{
    UINT32 pathChars = Path->Length / sizeof(WCHAR);
    UINT32 i;

    if (Suf->Len > pathChars)
        return FALSE;
    for (i = 0; i < Suf->Len; i++) {
        WCHAR a = Path->Buffer[pathChars - Suf->Len + i];
        WCHAR b = Suf->Pat[i];
        if (a >= L'A' && a <= L'Z')
            a = (WCHAR)(a - L'A' + L'a');
        if (b >= L'A' && b <= L'Z')
            b = (WCHAR)(b - L'A' + L'a');
        if (a != b)
            return FALSE;
    }
    return TRUE;
}

/* helper: подстрока ac_memmem (case-sensitive, как в оригинале) */
static BOOLEAN
AcContainsW(
    _In_ PCUNICODE_STRING Path,
    _In_ const AC_CI_PAT *Sub
    )
{
    UINT32 pathChars = Path->Length / sizeof(WCHAR);
    UINT32 i, j;

    if (Sub->Len > pathChars)
        return FALSE;
    for (i = 0; i + Sub->Len <= pathChars; i++) {
        for (j = 0; j < Sub->Len; j++) {
            if (Path->Buffer[i + j] != Sub->Pat[j])
                break;
        }
        if (j == Sub->Len)
            return TRUE;
    }
    return FALSE;
}

/* helper: сравнение префикса для проверки device-стека */
static BOOLEAN
AcPrefixW(
    _In_ PCUNICODE_STRING Name,
    _In_ const AC_CI_PAT *Prefix
    )
{
    UINT32 i;

    if (Prefix->Len > Name->Length / sizeof(WCHAR))
        return FALSE;
    for (i = 0; i < Prefix->Len; i++) {
        if (Name->Buffer[i] != Prefix->Pat[i])
            return FALSE;
    }
    return TRUE;
}

/* [0x1400446c4] + [0x1400444a8] + [0x140044f6c] предикат вердикта */
AC_MF_VERDICT
AcMfClassifyGamePath(
    _In_ PCUNICODE_STRING Path,
    _In_ BOOLEAN NameNormalizable,
    _In_reads_opt_(DevCount) PCUNICODE_STRING DevStack,
    _In_ UINT32 DevCount
    )
{
    UINT32 i;

    if (AcSuffixCi(Path, &(AC_CI_PAT){ kSufBsp, ARRAYSIZE(kSufBsp) - 1 }))
        return AcMfRecord26Bsp;

    if (AcSuffixCi(Path, &(AC_CI_PAT){ kSufVpk, ARRAYSIZE(kSufVpk) - 1 })) {
        if (!NameNormalizable)
            return AcMfDenyUnnamed;
        if (DevStack != NULL) {
            UINT32 d;
            for (d = 0; d < DevCount; d++) {
                for (i = 0; i < ARRAYSIZE(kDevPrefixes); i++) {
                    if (AcPrefixW(&DevStack[d], &kDevPrefixes[i]))
                        return AcMfDenyVirtualFs;
                }
            }
        }
    }

    if (!AcContainsW(Path,
                     &(AC_CI_PAT){ kSubWorkshop,
                                   ARRAYSIZE(kSubWorkshop) - 1 })) {
        for (i = 0; i < ARRAYSIZE(kSuffixes); i++) {
            if (AcSuffixCi(Path, &kSuffixes[i]))
                return AcMfRecord26Fingerprint;
        }
        for (i = 0; i < ARRAYSIZE(kSubstrs); i++) {
            if (AcContainsW(Path, &kSubstrs[i]))
                return AcMfRecord26Fingerprint;
        }
    }
    return AcMfPass;
}

/* ==========================================================================
 * 7. Геометрия deferred-очереди + узлов сендера (только layout-assert'ы)
 * --------------------------------------------------------------------------
 * [0x140237308] VM-тело сендера (цепочка D_06ced4; hole-executed -- VM-тело
 * не поднято; трасса mass/14023f52b: ExAllocatePool2 (0x140415432) ->
 * ac_sealed_compute_75a3c7 (IoGetCurrentProcess/PsGetProcessId x2,
 * PID-штамп) -> sealed 482fa1/30c569/47d963/a7d416/cab82a/dd4341/2936ff
 * (оркестрация seal 0x14014c9fd + вставка в очередь); адресаты ext_call
 * вычисляются в живую -- граница).
 * [0x1400586ec] флашер (native_07.c:487): узел {links +0x00, byte sent
 * +0x24, record +0x28 (0x658)}; обход под локом +0x70 (пара
 * 0x1077f8/0x107788); неотправленное переотправляется через
 * FUN_14000bfa0(node+0x28, 0x658).
 * [0x14005be24] обход flush-классов (native_07.c:819): входы {u32 class
 * +0x44, byte flag2 +0x22c}, 256-битный bitmap классов.
 * ------------------------------------------------------------------------ */
typedef struct _AC_DEF_NODE {
    LIST_ENTRY Link;                    /* +0x00 */
    UINT64 _10, _18;
    UINT8 _20, _21, _22, _23;
    UINT8 Sent;                         /* +0x24 */
    UINT8 _25[3];
    UINT8 Record[AC_REC12_SIZE];        /* +0x28 */
} AC_DEF_NODE;

typedef struct _AC_WATCH_ENT {
    UINT8 _00[0x44];
    UINT32 ClassMarker;                 /* +0x44 */
    UINT8 _48[0x1e4];
    UINT8 Flag2;                        /* +0x22c */
} AC_WATCH_ENT;

C_ASSERT(FIELD_OFFSET(AC_DEF_NODE, Sent) == 0x24);
C_ASSERT(FIELD_OFFSET(AC_DEF_NODE, Record) == 0x28);
C_ASSERT(FIELD_OFFSET(AC_WATCH_ENT, ClassMarker) == 0x44);
C_ASSERT(FIELD_OFFSET(AC_WATCH_ENT, Flag2) == 0x22c);

/* голова/лок deferred-очереди драйвера (геометрия ctx 0x140108de8:
 * LIST @+0x60, спинлок @+0x70, HWID_DRIVER_COLLECTORS_CODE §6.4);
 * продюсеры ставят записи 0x658 из VM-контура PCI/сендера
 * [0x140237308] (payload-selected, цепочка D_06ced4) */
LIST_ENTRY g_AcDeferredQueue = {&g_AcDeferredQueue, &g_AcDeferredQueue};
KSPIN_LOCK g_AcDeferredLock;

/* [0x1400586ec] контракт флашера: переотправить узлы с Sent == 0.
 * вызывающий: VM-сайты 0x14017c466/0x140209d30 (FULL_CHAIN_IRP_TO_HWID_C
 * §7.4 -- в оригинале тоже нет нативных call-сайтов, VM-диспетч);
 * вызывающий реконструкции: ветка таймера AcPollWorkerBody
 * (driver_entry.c, каденс ~30 s KTIMER, DRIVER_CHANNEL_PROTOCOL §4.5;
 * intended-caller по порядку цепочки "flusher -> drain 0xC3502004",
 * FULL_CHAIN §0) */
UINT32
AcChannelFlushDeferred(
    _In_ PLIST_ENTRY Head,
    _In_ AC_REC12_SEND_FN Send,
    _In_opt_ PVOID UserCtx
    )
{
    PLIST_ENTRY e;
    UINT32 n = 0;

    for (e = Head->Flink; e != Head; e = e->Flink) {
        AC_DEF_NODE *node = CONTAINING_RECORD(e, AC_DEF_NODE, Link);
        if (node->Sent == 0) {
            Send(node->Record, UserCtx);
            n++;
        }
    }
    return n;
}
