/* ==========================================================================
 * fnv_vendor_table.h -- FNV-1a-64 allow-таблица вендоров/издателей
 * (.rdata 0x1400a5220..0x1400a57a8, 177 qword)
 * ========================================================================== */
#ifndef FACEIT_AC_FNV_VENDOR_TABLE_H
#define FACEIT_AC_FNV_VENDOR_TABLE_H

#include <ntddk.h>

/* одна запись таблицы: VA qword-слота + разрешённый plaintext (13 из 177) */
typedef struct _AC_FNV_VENDOR_ENTRY {
    UINT64 SlotVa;          /* VA qword-слота в образе */
    UINT64 Hash;            /* FNV-1a-64 (case-sensitive) имени */
    const CHAR* Plaintext;  /* разрешённое имя (словарное попадание) */
} AC_FNV_VENDOR_ENTRY, *PAC_FNV_VENDOR_ENTRY;

extern const AC_FNV_VENDOR_ENTRY g_AcFnvVendorResolved[13];

/* полный спан таблицы (177 qword); остальные 164 слота не разрешены
 * (словари: экспорты ntoskrnl, имена BYOVD-драйверов, hw/sw-вендоры) */
#define AC_FNV_VENDOR_TABLE_BASE  0x1400a5220
#define AC_FNV_VENDOR_TABLE_END   0x1400a57a8
#define AC_FNV_VENDOR_TABLE_COUNT 177

/* константы FNV-1a-64 гейта T1/T2/T3 (соседние слоты
 * 0x1400a52f8/0x1400a5300/0x1400a5308 -- те же константы, что imm-формы
 * гейта, AC_FNV_GATE #1) */
#define AC_FNV_GATE_T1  0x8C47A233E34F55B0ULL  /* "ESL FACEIT Group Ltd." */
#define AC_FNV_GATE_T2  0x80B9E5A0501A80EAULL  /* "ESL Gaming GmbH" */
#define AC_FNV_GATE_T3  0xAE362F535AAF8BD7ULL  /* "FACE IT LIMITED" */

/* lookup хэша по разрешённым записям */
const CHAR* AcFnvVendorLookup(_In_ UINT64 Hash);

#endif /* FACEIT_AC_FNV_VENDOR_TABLE_H */
