/* ==========================================================================
 * boxout_records.c -- билдеры потока записей box_out.bin
 *                     (входы seal телеметрии/аттестации со стороны сервиса).
 * --------------------------------------------------------------------------
 * Стиль следует wiremap/records.c (agent-493, 7/7 MATCH): каждое поле
 * несёт свой provenance; входы за стеной сервисной VM (фактические
 * значения рана/сессии) берутся как параметры -- никогда не выдумываются.
 *
 * НАПОМИНАНИЕ О ГРАНИЦЕ: эти записи строит faceitservice.exe (VM-билдер,
 * SERVER_PROTOCOL #2.1), а не FACEIT_AC.sys. Драйвер лишь opaque-хранит
 * A-фрейм, когда тот приходит по IOCTL 0xC3502008
 * (AcCryptoStoreBootstrap, crypto.c) -- он его никогда не открывает и не
 * строит.
 *
 * Пополевой evidence:
 *   telemetry : box_out.bin [0x000..0x450), 52 записи, 4 цикла [capture]
 *   attest A/B: box_out.bin [0x450..0x2C7C), 8 пар (A,B) [capture]
 *   A == bootstrap 0xC3502008 pt (_enc_tmp/boxout/pt_604.bin), кроме
 *        двух per-run полей u32 (4 байта) [dec cross-check]
 *   logs      : 4x 'service has not been started' (Win32 1062) в telemetry,
 *               2x2 Qt network errors в хвосте [capture;
 *               SERVER_PROTOCOL #2.1/#2.2]
 * ========================================================================== */
#include "boxout_records.h"

/* --------------------------------------------------------------------------
 * маленький строковый хелпер (без CRT)
 * ------------------------------------------------------------------------ */
/* helper: no-CRT wide strlen для билдера логов */
static UINT32
AcBoxOutStrLenW(
    _In_ const WCHAR* S
    )
{
    UINT32 n = 0;
    while (S[n] != L'\0')
        n++;
    return n;
}

/* --------------------------------------------------------------------------
 * состояние {1,0,N} [сервисный VM-билдер; capture: N in {1,3,4}]
 * ------------------------------------------------------------------------ */
/* payload-selected: запись со стороны сервиса (capture-proven;
 * service VA [0x1405f53b0] tap входа seal) */
VOID
AcBoxOutBuildState(
    _Out_ PAC_BOXOUT_STATE Rec,
    _In_ UINT32 State
    )
{
    Rec->Tag   = AC_BOXOUT_TAG_STATE;
    Rec->Sub   = AC_BOXOUT_SUB_STATE;
    Rec->State = State;
}

/* --------------------------------------------------------------------------
 * параметр {1,10,A,B} [сервисный VM-билдер; capture: A=1, B=1]
 * ------------------------------------------------------------------------ */
/* payload-selected: запись со стороны сервиса (capture-proven) */
VOID
AcBoxOutBuildParam(
    _Out_ PAC_BOXOUT_PARAM Rec,
    _In_ UINT32 A,
    _In_ UINT32 B
    )
{
    Rec->Tag = AC_BOXOUT_TAG_PARAM;
    Rec->Sub = AC_BOXOUT_SUB_PARAM;
    Rec->A   = A;
    Rec->B   = B;
}

/* --------------------------------------------------------------------------
 * прогресс {1,4,double} [сервисный VM-билдер; capture: ~0.02 -> 1.0]
 * Биты копируются, а не вычисляются, поэтому любой double проходит
 * туда-обратно байт-точно.
 * payload-selected: запись со стороны сервиса (capture-proven layout)
 * ------------------------------------------------------------------------ */
VOID
AcBoxOutBuildProgress(
    _Out_ PAC_BOXOUT_PROGRESS Rec,
    _In_ double Fraction
    )
{
    Rec->Tag = AC_BOXOUT_TAG_PROGRESS;
    Rec->Sub = AC_BOXOUT_SUB_PROGRESS;
    RtlCopyMemory(&Rec->FractionBits, &Fraction, sizeof(Fraction));
}

/* --------------------------------------------------------------------------
 * лог-запись {3,3}{16 zeros}{UTF-16LE z}
 * [service VA FUN_1402720b0 = источник текста FormatMessageW,
 * SERVER_PROTOCOL #2.1]. Возвращает полный размер записи
 * (0x18 + 2*(wstrlen+1)), 0 при недостаточной ёмкости.
 * ------------------------------------------------------------------------ */
/* [0x1402720b0] источник текста (service FormatMessageW,
 * SERVER_PROTOCOL #2.1); layout capture-proven */
UINT32
AcBoxOutBuildLog(
    _Out_writes_bytes_(Cap) PAC_BOXOUT_LOG_HDR Rec,
    _In_ UINT32 Cap,
    _In_ const WCHAR* Text
    )
{
    UINT32 chars  = AcBoxOutStrLenW(Text);
    UINT32 total  = AC_BOXOUT_LOG_HDR_SIZE + (chars + 1) * sizeof(WCHAR);
    WCHAR* out;

    if (Cap < total)
        return 0;

    Rec->Tag = AC_BOXOUT_TAG_LOG;
    Rec->Sub = AC_BOXOUT_SUB_LOG;
    RtlZeroMemory(Rec->Zero, sizeof(Rec->Zero));

    out = (WCHAR*)((UINT8*)Rec + AC_BOXOUT_LOG_HDR_SIZE);
    RtlCopyMemory(out, Text, chars * sizeof(WCHAR));
    out[chars] = L'\0';
    return total;
}

/* --------------------------------------------------------------------------
 * A-фрейм аттестации 604B [сервисный VM-билдер; == courier-блоб bootstrap
 * 0xC3502008, кроме Run1/Run2, dec cross-check против pt_604.bin]
 * MachineId: 64 lower-hex ASCII = SHA256(faceit-ingame64.dll) машины
 * (INFODAT_CRYPTO #3); вычисляется на стороне сервиса, передаётся
 * предвычисленным -- здесь никогда не выдумывается.
 * ------------------------------------------------------------------------ */
/* [0x1405f53b0] потребитель seal-entry (service tap);
 * layout capture-proven */
VOID
AcBoxOutBuildAttestA(
    _Out_ PAC_BOXOUT_ATTEST_A Rec,
    _In_ UINT32 Run1,
    _In_ UINT32 Run2,
    _In_ const CHAR MachineId[AC_BOXOUT_MACHINEID_LEN]
    )
{
    RtlZeroMemory(Rec, sizeof(*Rec));
    Rec->Zero00 = 0;
    Rec->Run1   = Run1;
    Rec->Zero08 = 0;
    Rec->Run2   = Run2;
    RtlCopyMemory(Rec->MachineId, MachineId, AC_BOXOUT_MACHINEID_LEN);
}

/* --------------------------------------------------------------------------
 * B-фрейм аттестации 616B = {1,0,1} + A дословно [capture pair-diff:
 * тело B байт-идентично A-фрейму той же пары (Run1,Run2)];
 * потребитель seal-entry [0x1405f53b0] (service tap)
 * ------------------------------------------------------------------------ */
VOID
AcBoxOutBuildAttestB(
    _Out_ PAC_BOXOUT_ATTEST_B Rec,
    _In_ UINT32 Run1,
    _In_ UINT32 Run2,
    _In_ const CHAR MachineId[AC_BOXOUT_MACHINEID_LEN]
    )
{
    Rec->One00  = 1;
    Rec->Zero04 = 0;
    Rec->One08  = 1;
    AcBoxOutBuildAttestA(&Rec->Body, Run1, Run2, MachineId);
}

/* --------------------------------------------------------------------------
 * заметка по wire: каждая запись выше -- ОДИН plaintext-вход
 * crypto_box_seal entry сервиса [0x1405f53b0] (rdx=buf, r8=len tap,
 * REPORT_BUILDER_TAP #3). Хвостовые всплески ошибок в capture -- три
 * ОТДЕЛЬНЫХ входа -- B-фрейм, затем две standalone лог-записи {3,3}
 * (616+132+130 = 878B подряд в tap); отдельного типа записи
 * "ERR frame" не существует [tiling proven, d1_boxout_full.tsv].
 * ------------------------------------------------------------------------ */
