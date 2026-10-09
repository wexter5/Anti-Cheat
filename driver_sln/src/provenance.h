/* ==========================================================================
 * provenance.h -- конвенция provenance-аннотаций реконструкции
 * --------------------------------------------------------------------------
 * Каждая функция/блок в этой реконструкции несёт комментарий вида:
 *
 *   /* [0x140XXXXX] <что делает> (evidence: <chain|parity|report>) * /
 *
 * где 0x140XXXXX -- виртуальный адрес в оригинальном FACEIT_AC.sys
 * (imagebase 0x140000000). Макросы ниже делают аннотацию доступной
 * тулингу без влияния на codegen. Адреса также эмитятся в объектный файл
 * через строку AC_VA_SECTION, когда определён AC_EMBED_PROVENANCE
 * (по умолчанию выключено: держит бинарь чистым).
 *
 * Маркер границы для genuinely payload-selected путей (доказанно
 * статически невосстановимых, никогда не выдумывается):
 *
 *   /* payload-selected: path not statically recoverable --
 *      see <report> for the proof * /
 * ========================================================================== */
#ifndef FACEIT_AC_PROVENANCE_H
#define FACEIT_AC_PROVENANCE_H

#define AC_STR2(x) #x
#define AC_STR(x)  AC_STR2(x)

/* Аннотация уровня функции: VA оригинала + короткая роль + evidence-тэг. */
#define AC_PROVENANCE(va, what, evidence) \
    __pragma(message("AC-VA " AC_STR(va) " : " what " | " evidence))

/* Маркер границы (payload-selected путь; никакого выдуманного кода за ним). */
#define AC_PAYLOAD_BOUNDARY(why) \
    __pragma(message("AC-PAYLOAD-BOUNDARY: " why))

#endif /* FACEIT_AC_PROVENANCE_H */
