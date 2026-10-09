/* ==========================================================================
 * fnv_vendor_table.c -- данные FNV-1a-64 allow-таблицы вендоров/издателей
 * --------------------------------------------------------------------------
 * [0x1400a5220..0x1400a57a8] .rdata-таблица из 177 qword-хэшей
 * (AC_STRINGS.md #FNV-vendor: 13 словарно-разрешённых plaintext'ов;
 * остальные 164 qword'а не разрешены -- словари: экспорты ntoskrnl,
 * имена BYOVD-драйверов, hw/sw-вендоры).
 * Семантика: allow-list издателей/имён драйверов, проверяемый по
 * FNV-1a-64 (case-sensitive) -- вендорская сторона политики верификации
 * модулей (game_integrity.c GameIntegrityIsAllowedIssuer использует пару
 * Microsoft/Valve именно этой таблицы: слоты 0x1400a52e8 =
 * "Microsoft Corporation" и 0x1400a52d0 = "Valve").
 * Константы гейта T1/T2/T3 сидят рядом по
 * 0x1400a52f8/0x1400a5300/0x1400a5308 (те же константы, что imm-формы
 * гейта -- AC_FNV_GATE #1).
 * ========================================================================== */
#include <ntddk.h>

#include "provenance.h"
#include "fnv_vendor_table.h"

const AC_FNV_VENDOR_ENTRY g_AcFnvVendorResolved[13] = {
    /* [0x1400a52d0] */ { 0x1400a52d0, 0x41fbfca46d433a81ULL, "Valve" },
    /* [0x1400a52d8] */ { 0x1400a52d8, 0x0e38d89f1b363debULL, "Valve Corp." },
    /* [0x1400a52e0] */ { 0x1400a52e0, 0x8c8679068850646aULL, "Microsoft Windows" },
    /* [0x1400a52e8] */ { 0x1400a52e8, 0xe9051c47abbb5169ULL, "Microsoft Corporation" },
    /* [0x1400a5348] */ { 0x1400a5348, 0xbb481a3308b59748ULL, "NVIDIA CORPORATION" },
    /* [0x1400a5350] */ { 0x1400a5350, 0x9fd7a94869a35f88ULL, "NVIDIA Corporation" },
    /* [0x1400a5398] */ { 0x1400a5398, 0x4d8f2ec4ed5a8668ULL, "Advanced Micro Devices" },
    /* [0x1400a5488] */ { 0x1400a5488, 0xc06292e081502a39ULL, "Intel Corporation" },
    /* [0x1400a54b8] */ { 0x1400a54b8, 0xb94582ea994f8d1eULL, "ASUSTeK Computer Inc." },
    /* [0x1400a54c0] */ { 0x1400a54c0, 0xdbc4b0d57c60c876ULL, "Lenovo" },
    /* [0x1400a54f8] */ { 0x1400a54f8, 0x28091c759ed66e94ULL, "Giga-Byte Technology" },
    /* [0x1400a55b0] */ { 0x1400a55b0, 0x8aa2594116fb2310ULL, "Acer Incorporated" },
    /* [0x1400a55c0] */ { 0x1400a55c0, 0x60267f75c50e2a71ULL, "HP Inc." },
};

/* [0x1400a5220] lookup по разрешённому срезу (словарно-доказанное
 * подмножество таблицы из 177 qword'ов) */
const CHAR*
AcFnvVendorLookup(
    _In_ UINT64 Hash
    )
{
    UINT32 i;

    for (i = 0; i < 13; i++) {
        if (g_AcFnvVendorResolved[i].Hash == Hash)
            return g_AcFnvVendorResolved[i].Plaintext;
    }
    return NULL;
}
