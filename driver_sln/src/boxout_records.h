/* ==========================================================================
 * boxout_records.h -- байт-точные layout'ы потока записей box_out.bin
 *                     (входы seal телеметрии/аттестации faceitservice.exe).
 * --------------------------------------------------------------------------
 * ГРАНИЦА: это записи стороны СЕРВИСА, НЕ драйвера (FACEIT_AC.sys).
 * box_out.bin -- tap plaintext-входов crypto_box_seal entry сервиса
 * [0x1405f53b0 svc] (REPORT_BUILDER_TAP #3). Билдеры записей
 * виртуализованы в сервисе (SERVER_PROTOCOL #2.1:
 * "Построитель записей виртуализован (VM)"), поэтому provenance здесь --
 * capture-proven layout + именованные service VA, где отчёты их дают.
 * Единственная точка касания со стороны ДРАЙВЕРА -- courier-store
 * bootstrap'а A-фрейма (IOCTL 0xC3502008 -> AcCryptoStoreBootstrap,
 * crypto.c).
 *
 * Evidence (всё оффлайн, никакого живого кода):
 *   client/dynamic/box_out.bin            11388B capture [wire tap]
 *   _research_tmp/wiremap_boxout/d1_boxout_full.tsv   карта полей (этот таск)
 *   _enc_tmp/boxout/pt_604.bin            bootstrap 0xC3502008 pt (cross-ref)
 *   SERVER_PROTOCOL #2.1/#2.2, INFODAT_CRYPTO #3, DRIVER_CHANNEL_BYTEMAP #2.1
 *   PROTOCOL_OUTGOING #B1/B4, REPORT_BUILDER_TAP #3
 * ========================================================================== */
#ifndef AC_BOXOUT_RECORDS_H
#define AC_BOXOUT_RECORDS_H

#include <ntddk.h>
#include <stddef.h>

/* --------------------------------------------------------------------------
 * Семейство записей 1: телеметрия {tag=1}/{tag=3} (52 записи в capture,
 * 4 идентичных цикла; SERVER_PROTOCOL #2.1).
 * Все поля little-endian. Самосегментирующиеся: длина следует из (tag,sub).
 * ------------------------------------------------------------------------ */
#define AC_BOXOUT_TAG_STATE     1   /* +0x00, sub 0  -> AC_BOXOUT_STATE    */
#define AC_BOXOUT_TAG_PROGRESS  1   /* +0x00, sub 4  -> AC_BOXOUT_PROGRESS */
#define AC_BOXOUT_TAG_PARAM     1   /* +0x00, sub 10 -> AC_BOXOUT_PARAM    */
#define AC_BOXOUT_TAG_LOG       3   /* +0x00, sub 3  -> AC_BOXOUT_LOG_HDR  */

#define AC_BOXOUT_SUB_STATE     0
#define AC_BOXOUT_SUB_PROGRESS  4
#define AC_BOXOUT_SUB_PARAM     10
#define AC_BOXOUT_SUB_LOG       3

#pragma pack(push, 1)

/* {1,0,N} 12B -- состояние операции; N in {1 begin, 3 fail-path, 4 end} в
 * capture (4 цикла x {1,3,4}); семейство B4-beacon из PROTOCOL_OUTGOING
 * (коды 0/1/11/16 на игровом пайпе) [capture; N-enum hyp, SERVER_PROTOCOL
 * #8.3 unknown] */
typedef struct _AC_BOXOUT_STATE {
    UINT32 Tag;                 /* +0x00 = 1 */
    UINT32 Sub;                 /* +0x04 = 0 */
    UINT32 State;               /* +0x08 N (варьируется по событию) */
} AC_BOXOUT_STATE, *PAC_BOXOUT_STATE;

/* {1,4,double} 16B -- доля прогресса, монотонно ~0.02 -> 1.0 внутри
 * цикла (финальная запись каждого цикла ровно 1.0) [capture] */
typedef struct _AC_BOXOUT_PROGRESS {
    UINT32 Tag;                 /* +0x00 = 1 */
    UINT32 Sub;                 /* +0x04 = 4 */
    UINT64 FractionBits;        /* +0x08 биты IEEE-754 double (варьируются по
                                 *  событию; хранятся как биты для байт-точности) */
} AC_BOXOUT_PROGRESS, *PAC_BOXOUT_PROGRESS;

/* {1,10,A,B} 16B -- параметрическое событие; наблюдалось только A=1,B=1
 * (4x) [capture; семантика hyp, SERVER_PROTOCOL #8.3 unknown] */
typedef struct _AC_BOXOUT_PARAM {
    UINT32 Tag;                 /* +0x00 = 1 */
    UINT32 Sub;                 /* +0x04 = 10 */
    UINT32 A;                   /* +0x08 = 1 в capture */
    UINT32 B;                   /* +0x0C = 1 в capture */
} AC_BOXOUT_PARAM, *PAC_BOXOUT_PARAM;

/* {3,3}{16 zeros}{UTF-16LE z} -- текстовая запись лога/ошибки,
 * standalone-вход seal. Строка из Win32 FormatMessageW (service VA
 * FUN_1402720b0, SERVER_PROTOCOL #2.1) / тексты ошибок Qt-сокета (#2.2).
 * Полный размер = 0x18 + 2*(wstrlen+1). */
typedef struct _AC_BOXOUT_LOG_HDR {
    UINT32 Tag;                 /* +0x00 = 3 */
    UINT32 Sub;                 /* +0x04 = 3 */
    UINT8  Zero[16];            /* +0x08..+0x17 нули [capture] */
    /* WCHAR Text[];            +0x18 UTF-16LE, NUL-терминированная (NUL внутри
                                 *  записи) */
} AC_BOXOUT_LOG_HDR, *PAC_BOXOUT_LOG_HDR;
#define AC_BOXOUT_LOG_HDR_SIZE  0x18

/* --------------------------------------------------------------------------
 * Семейство записей 2: фреймы аттестации ("hex64" семейство,
 * SERVER_PROTOCOL #2.2; именование следует wiremap/BYTE_MAP #7: A=604B,
 * B=616B -- заметь, в legacy-отчёте буквы были переставлены).
 *
 * A-фрейм 604B == courier-блоб bootstrap'а IOCTL 0xC3502008 байт в байт,
 * кроме двух per-run полей u32 [dec cross-check против
 * _enc_tmp/boxout/pt_604.bin: отличаются ровно +0x04/+0x05 и +0x0C/+0x0D].
 * Сервис seal'ит его под сессионный ключ СЕРВЕРА и передаёт драйверу,
 * который хранит его OPAQUE (модель courier/hold,
 * DRIVER_CHANNEL_PROTOCOL #2.2; хранилище драйвера:
 * AcCryptoStoreBootstrap / механизм [0x14014c9fd], crypto.c).
 * ------------------------------------------------------------------------ */
#define AC_BOXOUT_ATTEST_A_SIZE   604   /* 0x25C [wire: 604->652 sealed] */
#define AC_BOXOUT_ATTEST_B_SIZE   616   /* 0x268 [wire: 616->664 sealed] */
#define AC_BOXOUT_MACHINEID_OFS_A 0x219 /* смещение machine-id в A [dec] */
#define AC_BOXOUT_MACHINEID_OFS_B 0x225 /* == 0x0C + 0x219 [dec] */
#define AC_BOXOUT_MACHINEID_LEN   64    /* 32B хэш как lower-hex ASCII */

typedef struct _AC_BOXOUT_ATTEST_A {
    UINT32 Zero00;              /* +0x000 = 0 */
    UINT32 Run1;                /* +0x004 per-run; только младший u16 ненулевой
                                 *  в каждом capture [unknown: uptime-ms/seq/
                                 *  random; IPv4-edge hyp med-low,
                                 *  SERVER_PROTOCOL #2.2] */
    UINT32 Zero08;              /* +0x008 = 0 */
    UINT32 Run2;                /* +0x00C per-run (тот же класс, что Run1) */
    UINT8  Zero10[0x209];       /* +0x010..+0x218 нули */
    CHAR   MachineId[AC_BOXOUT_MACHINEID_LEN];
                                /* +0x219 d521bf49...73b3 = SHA256 содержимого
                                 *  файла faceit-ingame64.dll
                                 *  (INFODAT_CRYPTO #3, пересчитан); билд-маркер
                                 *  ingame-модуля, НЕ HWID; константа во всех
                                 *  16 фреймах [dec] */
    UINT8  Zero259[3];          /* +0x259..+0x25B нули */
} AC_BOXOUT_ATTEST_A, *PAC_BOXOUT_ATTEST_A;

/* B-фрейм 616B = {u32 1}{u32 0}{u32 1} + A-фрейм дословно (так что
 * dword B по +0x0C -- ведущий нуль A). A_k и B_k одной пары несут одинаковые
 * (Run1,Run2) -- 8 пар в capture [dec, доказано pair-diff]. */
typedef struct _AC_BOXOUT_ATTEST_B {
    UINT32 One00;               /* +0x000 = 1 */
    UINT32 Zero04;              /* +0x004 = 0 */
    UINT32 One08;               /* +0x008 = 1 */
    AC_BOXOUT_ATTEST_A Body;    /* +0x00C целый A-фрейм */
} AC_BOXOUT_ATTEST_B, *PAC_BOXOUT_ATTEST_B;

#pragma pack(pop)

/* --------------------------------------------------------------------------
 * static assert'ы -- смещения доказаны картами ненулевых байтов capture
 * и точным тайлингом хвоста (8*604 + 8*616 + 2*132 + 2*130 == 0x282C)
 * ------------------------------------------------------------------------ */
#define AC_BO_SA(name, expr) \
    typedef char ac_bo_sa_##name[(expr) ? 1 : -1]

AC_BO_SA(state_size,    sizeof(AC_BOXOUT_STATE) == 12);
AC_BO_SA(progress_size, sizeof(AC_BOXOUT_PROGRESS) == 16);
AC_BO_SA(param_size,    sizeof(AC_BOXOUT_PARAM) == 16);
AC_BO_SA(loghdr_size,   sizeof(AC_BOXOUT_LOG_HDR) == AC_BOXOUT_LOG_HDR_SIZE);
AC_BO_SA(attesta_size,  sizeof(AC_BOXOUT_ATTEST_A) == AC_BOXOUT_ATTEST_A_SIZE);
AC_BO_SA(attesta_run1,  offsetof(AC_BOXOUT_ATTEST_A, Run1) == 0x004);
AC_BO_SA(attesta_run2,  offsetof(AC_BOXOUT_ATTEST_A, Run2) == 0x00C);
AC_BO_SA(attesta_mid,   offsetof(AC_BOXOUT_ATTEST_A, MachineId) ==
                        AC_BOXOUT_MACHINEID_OFS_A);
AC_BO_SA(attestb_size,  sizeof(AC_BOXOUT_ATTEST_B) == AC_BOXOUT_ATTEST_B_SIZE);
AC_BO_SA(attestb_body,  offsetof(AC_BOXOUT_ATTEST_B, Body) == 0x00C);
AC_BO_SA(attestb_mid,   offsetof(AC_BOXOUT_ATTEST_B, Body) +
                        offsetof(AC_BOXOUT_ATTEST_A, MachineId) ==
                        AC_BOXOUT_MACHINEID_OFS_B);

/* --------------------------------------------------------------------------
 * билдеры (boxout_records.c). Каждый воспроизводит одну запись seal-входа
 * байт в байт из её переменных входов; константные поля пишутся билдером,
 * никогда не берутся у вызывающего.
 * ------------------------------------------------------------------------ */
VOID AcBoxOutBuildState(_Out_ PAC_BOXOUT_STATE Rec, _In_ UINT32 State);
VOID AcBoxOutBuildParam(_Out_ PAC_BOXOUT_PARAM Rec, _In_ UINT32 A,
                        _In_ UINT32 B);
VOID AcBoxOutBuildProgress(_Out_ PAC_BOXOUT_PROGRESS Rec,
                           _In_ double Fraction);
UINT32 AcBoxOutBuildLog(_Out_writes_bytes_(Cap) PAC_BOXOUT_LOG_HDR Rec,
                        _In_ UINT32 Cap, _In_ const WCHAR* Text);
VOID AcBoxOutBuildAttestA(_Out_ PAC_BOXOUT_ATTEST_A Rec, _In_ UINT32 Run1,
                          _In_ UINT32 Run2,
                          _In_ const CHAR MachineId[AC_BOXOUT_MACHINEID_LEN]);
VOID AcBoxOutBuildAttestB(_Out_ PAC_BOXOUT_ATTEST_B Rec, _In_ UINT32 Run1,
                          _In_ UINT32 Run2,
                          _In_ const CHAR MachineId[AC_BOXOUT_MACHINEID_LEN]);

#endif /* AC_BOXOUT_RECORDS_H */
