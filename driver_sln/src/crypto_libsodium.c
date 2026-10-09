/* ==========================================================================
 * crypto_libsodium.c -- СМЕРДЖЕННЫЕ крипто-кандидаты (agent-492, 33/33 KAT PASS)
 * --------------------------------------------------------------------------
 * Kernel-форма мержа _research_tmp/sealed_semantics/candidates/:
 *   crypto_xsalsa20.c  (HSalsa20/Salsa20/XSalsa20)
 *   crypto_x25519.c    (X25519 ladder, ref10 51-битные лимбы)
 *   crypto_blake2b.c   (BLAKE2b + правило nonce BLAKE2b-192)
 *   crypto_poly1305.c  (Poly1305 donna-32)
 *   crypto_box_seal_compose.c (wire-композиция seal/open)
 * KAT: RFC7748 (7/7), RFC8439 (5/5), BLAKE2b (6/6), HSalsa/Salsa (11/11),
 * compose 179B=131B+48 (4/4) -- _research_tmp/sealed_semantics/KAT_RESULTS.txt
 * Evidence идентификации: _research_tmp/sealed_semantics/SEALED_SEMANTICS.md
 *
 * VA-карта нативных примитивов драйвера (константы+структура доказаны):
 *   FUN_14002d7a8  HSalsa20 core        FUN_14002dc70  Salsa20 block (ff)
 *   FUN_14003a15c  crypto_stream_salsa20 (vtable 0x140106f78)
 *   FUN_140035b88  X25519 ladder        FUN_14003630c  scalarmult_base
 *   FUN_140034cd8  blake2b_init_param   FUN_140034de4/-4f04 update/final
 *   FUN_1400350b4  poly1305_init        FUN_140035254/-57cc/-55a4 blocks/up/fin
 *   FUN_1400358ac  poly1305 oneshot     FUN_140035950  verify wrapper
 *   FUN_14002ac48  seal compose         FUN_14002ad5c  open compose
 *   FUN_14002abb8  правило nonce (BLAKE2b-192)  FUN_14002ae18 box_beforenm
 *   FUN_140036520/-3674c secretbox seal/open
 * RNG: FUN_140027044 = seed KeQueryPerformanceCounter (пара
 *   0x140107548^0x140107540) + поток RtlRandomEx (пара
 *   0x140107538^0x140107530) -- **НЕ CSPRNG** (детерминированный RtlRandomEx
 *   от QPC-сида; документированная структурная слабость драйвера,
 *   SEALED_SEMANTICS #1.4). Реализован как AcLsRandomBytes ниже.
 * ========================================================================== */
#include <ntddk.h>
#include <intrin.h>
#include <stddef.h>
#include "crypto_libsodium.h"

/* fixed-width типы, которые используют userspace-кандидаты (в km-заголовках
 * нет lowercase-написаний) */
typedef UINT8  uint8_t;
typedef UINT16 uint16_t;
typedef UINT32 uint32_t;
typedef UINT64 uint64_t;
typedef INT32  int32_t;
typedef INT64  int64_t;

/* shim'ы userspace-lib (кандидаты используют libc memset/memcpy/size_t) */
static void* ac_ls_memset(void* d, int c, size_t n)
{
    if (n) RtlFillMemory(d, n, (UINT8)c);
    return d;
}
static void* ac_ls_memcpy(void* d, const void* s, size_t n)
{
    if (n) RtlCopyMemory(d, s, n);
    return d;
}
#define memset  ac_ls_memset
#define memcpy  ac_ls_memcpy

/* RtlRandomEx -- verified импорт 259-таблицы, но его нет в km-заголовках
 * этого WDK; публичный контракт */
NTKERNELAPI
ULONG
NTAPI
RtlRandomEx(
    _Inout_ PULONG Seed
    );

/* ---------------- арифметика поля: fe = uint64_t[5], 51-битные лимбы --- */
#define FE_MASK 0x7ffffffffffffULL

typedef uint64_t fe[5];

static uint64_t load64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= (uint64_t) p[i] << (8 * i);
    return v;
}

static void store64(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++) p[i] = (uint8_t) (v >> (8 * i));
}

static void fe_frombytes(fe h, const uint8_t *s)
{
    uint8_t t[32];
    memcpy(t, s, 32);
    t[31] &= 0x7f;             /* decodeUCoordinate: маскировать бит 255 */
    h[0] = load64(t) & FE_MASK;
    h[1] = (load64(t + 6) >> 3) & FE_MASK;
    h[2] = (load64(t + 12) >> 6) & FE_MASK;
    h[3] = (load64(t + 19) >> 1) & FE_MASK;
    h[4] = (load64(t + 24) >> 12) & FE_MASK;
}

static void fe_carry(fe h)
{
    uint64_t c;
    c = h[0] >> 51; h[0] &= FE_MASK; h[1] += c;
    c = h[1] >> 51; h[1] &= FE_MASK; h[2] += c;
    c = h[2] >> 51; h[2] &= FE_MASK; h[3] += c;
    c = h[3] >> 51; h[3] &= FE_MASK; h[4] += c;
    c = h[4] >> 51; h[4] &= FE_MASK; h[0] += 19 * c;
    c = h[0] >> 51; h[0] &= FE_MASK; h[1] += c;
}

static void fe_tobytes(uint8_t *s, const fe f)
{
    static const uint64_t P[5] = {
        0x7ffffffffffedULL, 0x7ffffffffffffULL, 0x7ffffffffffffULL,
        0x7ffffffffffffULL, 0x7ffffffffffffULL
    };
    uint64_t h[5], d[5];
    uint64_t mask, borrow;
    int i;

    for (i = 0; i < 5; i++) h[i] = f[i];
    fe_carry(h);
    fe_carry(h);

    /* условное вычитание p через явную borrow-цепочку (constant-time) */
    borrow = 0;
    for (i = 0; i < 5; i++) {
        uint64_t sub = P[i] + borrow;
        if (h[i] >= sub) { d[i] = h[i] - sub; borrow = 0; }
        else { d[i] = (h[i] + (1ULL << 51)) - sub; borrow = 1; }
    }
    /* borrow == 1 -> h < p -> оставить h; borrow == 0 -> h >= p -> взять d */
    mask = borrow - 1;
    for (i = 0; i < 5; i++)
        h[i] = (h[i] & ~mask) | (d[i] & mask);

    store64(s + 0,  h[0] | (h[1] << 51));
    store64(s + 8,  (h[1] >> 13) | (h[2] << 38));
    store64(s + 16, (h[2] >> 26) | (h[3] << 25));
    store64(s + 24, (h[3] >> 39) | (h[4] << 12));
}

/* fe_mul (роль FUN_14002ae74): школьное умножение по uniform radix 2^51 с
 * заворотом 2^255 == 19. 128-битные аккумуляторы на лимб (по 5 произведений,
 * <= 5*19*2^104 < 2^111, безопасно); цепочка MSVC _umul128 + _addcarry_u64. */
#if defined(_MSC_VER)
#include <intrin.h>
#endif

typedef struct { uint64_t lo, hi; } u128_t;

static void u128_add_mul(u128_t *acc, uint64_t x, uint64_t y)
{
#if defined(_MSC_VER)
    uint64_t h, l = _umul128(x, y, &h);
    unsigned char c = _addcarry_u64(0, acc->lo, l, &acc->lo);
    _addcarry_u64(c, acc->hi, h, &acc->hi);
#else
    unsigned __int128 m = (unsigned __int128) x * y;
    acc->lo += (uint64_t) m;
    acc->hi += (uint64_t) (m >> 64) + (acc->lo < (uint64_t) m);
#endif
}

static void u128_add_mul19(u128_t *acc, uint64_t x, uint64_t y)
{
#if defined(_MSC_VER)
    uint64_t h, l = _umul128(x, y, &h);
    /* 128-битное произведение * 19: результат < 2^107 */
    uint64_t h2, l2 = _umul128(l, 19, &h2);
    unsigned char c;
    h2 += h * 19;
    c = _addcarry_u64(0, acc->lo, l2, &acc->lo);
    _addcarry_u64(c, acc->hi, h2, &acc->hi);
#else
    unsigned __int128 m = 19 * (unsigned __int128) x * y;
    acc->lo += (uint64_t) m;
    acc->hi += (uint64_t) (m >> 64) + (acc->lo < (uint64_t) m);
#endif
}

/* извлечение переносов из 128-битных аккумуляторов в редуцированные
 * 51-битные лимбы с распространением переполнения между лимбами; оставляет
 * все лимбы < 2^51 + маленький запас (на это опирается 2p-смещение fe_sub) */
static void fe_from_u128s(fe h, u128_t t[5])
{
    uint64_t c;
    h[0] = t[0].lo & FE_MASK;
    c = (t[0].lo >> 51) | (t[0].hi << 13);
#if defined(_MSC_VER)
    {
        unsigned char cf = _addcarry_u64(0, t[1].lo, c, &t[1].lo);
        t[1].hi += cf;
    }
#else
    t[1].lo += c; t[1].hi += (t[1].lo < c);
#endif
    h[1] = t[1].lo & FE_MASK;
    c = (t[1].lo >> 51) | (t[1].hi << 13);
#if defined(_MSC_VER)
    {
        unsigned char cf = _addcarry_u64(0, t[2].lo, c, &t[2].lo);
        t[2].hi += cf;
    }
#else
    t[2].lo += c; t[2].hi += (t[2].lo < c);
#endif
    h[2] = t[2].lo & FE_MASK;
    c = (t[2].lo >> 51) | (t[2].hi << 13);
#if defined(_MSC_VER)
    {
        unsigned char cf = _addcarry_u64(0, t[3].lo, c, &t[3].lo);
        t[3].hi += cf;
    }
#else
    t[3].lo += c; t[3].hi += (t[3].lo < c);
#endif
    h[3] = t[3].lo & FE_MASK;
    c = (t[3].lo >> 51) | (t[3].hi << 13);
#if defined(_MSC_VER)
    {
        unsigned char cf = _addcarry_u64(0, t[4].lo, c, &t[4].lo);
        t[4].hi += cf;
    }
#else
    t[4].lo += c; t[4].hi += (t[4].lo < c);
#endif
    h[4] = t[4].lo & FE_MASK;
    c = (t[4].lo >> 51) | (t[4].hi << 13);
    h[0] += 19 * c;                  /* c <= 2^58 -> 19c влезает в u64 */
    /* полная carry-цепочка, чтобы все лимбы стали < 2^51 + маленький запас */
    c = h[0] >> 51; h[0] &= FE_MASK; h[1] += c;
    c = h[1] >> 51; h[1] &= FE_MASK; h[2] += c;
    c = h[2] >> 51; h[2] &= FE_MASK; h[3] += c;
    c = h[3] >> 51; h[3] &= FE_MASK; h[4] += c;
    c = h[4] >> 51; h[4] &= FE_MASK; h[0] += 19 * c;
    c = h[0] >> 51; h[0] &= FE_MASK; h[1] += c;
}

static void fe_mul(fe h, const fe f, const fe g)
{
    u128_t t[5] = {{0, 0}, {0, 0}, {0, 0}, {0, 0}, {0, 0}};
    for (int i = 0; i < 5; i++)
        for (int j = 0; j < 5; j++) {
            if (i + j < 5) u128_add_mul(&t[i + j], f[i], g[j]);
            else u128_add_mul19(&t[i + j - 5], f[i], g[j]);
        }
    fe_from_u128s(h, t);
}

static void fe_sq(fe h, const fe f) { fe_mul(h, f, f); }  /* FUN_14002b744 */

/* a24 = 121665 = (A-2)/4 (аранжировка RFC 7748). Ladder драйвера,
 * производный от ref10, использует эквивалентную аранжировку 121666; sealed
 * VM-тело ac_sealed_compute_cf60cf несёт 0x1DB41 = 121665 в своём frame-пуле. */
static void fe_mul121665(fe h, const fe f)
{
    u128_t t[5] = {{0, 0}, {0, 0}, {0, 0}, {0, 0}, {0, 0}};
    for (int i = 0; i < 5; i++) u128_add_mul(&t[i], f[i], 121665);
    fe_from_u128s(h, t);
}

/* ref10 fe_mul121666: множитель (A+2)/4 виден inline в native_04.c:818
 * (оставлен для полноты provenance; ladder ниже использует форму RFC) */
static void fe_mul121666(fe h, const fe f)
{
    u128_t t[5] = {{0, 0}, {0, 0}, {0, 0}, {0, 0}, {0, 0}};
    for (int i = 0; i < 5; i++) u128_add_mul(&t[i], f[i], 121666);
    fe_from_u128s(h, t);
}

static void fe_add(fe h, const fe f, const fe g)
{ for (int i = 0; i < 5; i++) h[i] = f[i] + g[i]; }

static void fe_sub(fe h, const fe f, const fe g)
{
    /* держать лимбы неотрицательными: добавить 2p (2 * (2^255-19) в
     * 51-битных лимбах: limb0 = 2^52-38, limbs 1..4 = 2^52-2) */
    h[0] = (f[0] + 0xfffffffffffdaULL) - g[0];
    h[1] = (f[1] + 0xffffffffffffeULL) - g[1];
    h[2] = (f[2] + 0xffffffffffffeULL) - g[2];
    h[3] = (f[3] + 0xffffffffffffeULL) - g[3];
    h[4] = (f[4] + 0xffffffffffffeULL) - g[4];
}

/* структура FUN_140035994: constant-time условный swap, mask = -bit */
static void fe_cswap(fe f, fe g, int b)
{
    uint64_t mask = (uint64_t) (-(int64_t) b);
    for (int i = 0; i < 5; i++) {
        uint64_t x = (f[i] ^ g[i]) & mask;
        f[i] ^= x;
        g[i] ^= x;
    }
}

static void fe_inv(fe out, const fe z)
{
    /* z^(p-2), p = 2^255-19; square-and-multiply от старшего бита */
    fe res, base;
    res[0] = 1; res[1] = res[2] = res[3] = res[4] = 0;
    for (int i = 0; i < 5; i++) base[i] = z[i];
    for (int bit = 254; bit >= 0; bit--) {
        /* экспонента 2^255-21: биты 254..5 = 1, биты 4..0 = 01011 */
        int ebit = (bit >= 5) ? 1 : (int) ((0x0b >> bit) & 1);
        fe_sq(res, res);
        if (ebit) fe_mul(res, res, base);
    }
    for (int i = 0; i < 5; i++) out[i] = res[i];
}

/* ---------------- X25519 (RFC 7748 раздел 5) -------------------------- */
void ac_x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t u[32])
{
    uint8_t k[32];
    fe x1, x2, z2, x3, z3;
    int swap = 0;
    int pos;

    memcpy(k, scalar, 32);
    k[0] &= 248;                 /* clamp (RFC 7748 decodeScalar25519) */
    k[31] &= 127;
    k[31] |= 64;

    fe_frombytes(x1, u);
    x2[0] = 1; x2[1] = x2[2] = x2[3] = x2[4] = 0;
    z2[0] = z2[1] = z2[2] = z2[3] = z2[4] = 0;
    for (int i = 0; i < 5; i++) x3[i] = x1[i];
    z3[0] = 1; z3[1] = z3[2] = z3[3] = z3[4] = 0;

    for (pos = 254; pos >= 0; pos--) {
        int kt = (k[pos >> 3] >> (pos & 7)) & 1;
        fe A, AA, B, BB, E, C, D, DA, CB, t0, t1;
        swap ^= kt;
        fe_cswap(x2, x3, swap);
        fe_cswap(z2, z3, swap);
        swap = kt;

        fe_add(A, x2, z2);       /* A  = x2 + z2 */
        fe_sq(AA, A);            /* AA = A^2 */
        fe_sub(B, x2, z2);       /* B  = x2 - z2 */
        fe_sq(BB, B);            /* BB = B^2 */
        fe_sub(E, AA, BB);       /* E  = AA - BB */
        fe_add(C, x3, z3);       /* C  = x3 + z3 */
        fe_sub(D, x3, z3);       /* D  = x3 - z3 */
        fe_mul(DA, D, A);        /* DA = D*A */
        fe_mul(CB, C, B);        /* CB = C*B */
        fe_add(t0, DA, CB);
        fe_sq(x3, t0);           /* x3 = (DA+CB)^2 */
        fe_sub(t1, DA, CB);
        fe_sq(t1, t1);
        fe_mul(z3, x1, t1);      /* z3 = x1*(DA-CB)^2 */
        fe_mul(x2, AA, BB);      /* x2 = AA*BB */
        /* z2 = E*(AA + a24*E), a24 = 121665 (RFC 7748 arrangement) */
        {
            fe a24E;
            fe_mul121665(a24E, E);
            fe_add(a24E, AA, a24E);
            fe_mul(z2, E, a24E);
        }
    }
    fe_cswap(x2, x3, swap);
    fe_cswap(z2, z3, swap);

    fe_inv(z3, z2);
    fe_mul(x2, x2, z3);
    fe_tobytes(out, x2);
}

void ac_x25519_base(uint8_t out[32], const uint8_t scalar[32])
{
    uint8_t nine[32];
    memset(nine, 0, 32);
    nine[0] = 9;                 /* базовая точка u = 9 */
    ac_x25519(out, scalar, nine);
}

/* ============================== KAT ===================================== */

static uint32_t rotl32(uint32_t v, int n) { return (v << n) | (v >> (32 - n)); }

static uint32_t ld32(const uint8_t *p)
{
    return (uint32_t) p[0] | ((uint32_t) p[1] << 8) |
           ((uint32_t) p[2] << 16) | ((uint32_t) p[3] << 24);
}

static void st32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t) v;       p[1] = (uint8_t) (v >> 8);
    p[2] = (uint8_t) (v >> 16); p[3] = (uint8_t) (v >> 24);
}

/* 20 раундов Salsa20; ff=1 применяет feed-forward (блочная функция).
 * Зеркалит раундовую структуру FUN_14002d7a8 (ff=0) / FUN_14002dc70 (ff=1):
 * 8 quarterround'ов на doubleround, ротации 7/9/13/18. */
static void salsa20_rounds(uint32_t x[16], const uint32_t in[16], int ff)
{
    int i;
    for (i = 0; i < 16; i++) x[i] = in[i];
    for (i = 0; i < 10; i++) {          /* 10 doubleround'ов = 20 раундов */
        /* columnround */
        x[ 4] ^= rotl32(x[ 0] + x[12],  7); x[ 8] ^= rotl32(x[ 4] + x[ 0],  9);
        x[12] ^= rotl32(x[ 8] + x[ 4], 13); x[ 0] ^= rotl32(x[12] + x[ 8], 18);
        x[ 9] ^= rotl32(x[ 5] + x[ 1],  7); x[13] ^= rotl32(x[ 9] + x[ 5],  9);
        x[ 1] ^= rotl32(x[13] + x[ 9], 13); x[ 5] ^= rotl32(x[ 1] + x[13], 18);
        x[14] ^= rotl32(x[10] + x[ 6],  7); x[ 2] ^= rotl32(x[14] + x[10],  9);
        x[ 6] ^= rotl32(x[ 2] + x[14], 13); x[10] ^= rotl32(x[ 6] + x[ 2], 18);
        x[ 3] ^= rotl32(x[15] + x[11],  7); x[ 7] ^= rotl32(x[ 3] + x[15],  9);
        x[11] ^= rotl32(x[ 7] + x[ 3], 13); x[15] ^= rotl32(x[11] + x[ 7], 18);
        /* rowround */
        x[ 1] ^= rotl32(x[ 0] + x[ 3],  7); x[ 2] ^= rotl32(x[ 1] + x[ 0],  9);
        x[ 3] ^= rotl32(x[ 2] + x[ 1], 13); x[ 0] ^= rotl32(x[ 3] + x[ 2], 18);
        x[ 6] ^= rotl32(x[ 5] + x[ 4],  7); x[ 7] ^= rotl32(x[ 6] + x[ 5],  9);
        x[ 4] ^= rotl32(x[ 7] + x[ 6], 13); x[ 5] ^= rotl32(x[ 4] + x[ 7], 18);
        x[11] ^= rotl32(x[10] + x[ 9],  7); x[ 8] ^= rotl32(x[11] + x[10],  9);
        x[ 9] ^= rotl32(x[ 8] + x[11], 13); x[10] ^= rotl32(x[ 9] + x[ 8], 18);
        x[12] ^= rotl32(x[15] + x[14],  7); x[13] ^= rotl32(x[12] + x[15],  9);
        x[14] ^= rotl32(x[13] + x[12], 13); x[15] ^= rotl32(x[14] + x[13], 18);
    }
    if (ff)
        for (i = 0; i < 16; i++) x[i] += in[i];
}

/* ---- FUN_14002d7a8: HSalsa20 core --------------------------------------
 * out32 = HSalsa20(key32, nonce16); без feed-forward;
 * пишет слова x[0],x[5],x[10],x[15],x[6],x[7],x[8],x[9] (NaCl-спека). */
void ac_hsalsa20(uint8_t out[32], const uint8_t nonce[16],
                 const uint8_t key[32])
{
    static const uint32_t sig[4] = {
        0x61707865u, 0x3320646eu, 0x79622d32u, 0x6b206574u
    };
    uint32_t in[16], x[16];

    in[0]  = sig[0];           /* x[0]  = sigma0 */
    in[1]  = ld32(key + 0);    /* x[1..4] = key[0..15] */
    in[2]  = ld32(key + 4);
    in[3]  = ld32(key + 8);
    in[4]  = ld32(key + 12);
    in[5]  = sig[1];           /* x[5]  = sigma1 */
    in[6]  = ld32(nonce + 0);  /* x[6..9] = nonce16 */
    in[7]  = ld32(nonce + 4);
    in[8]  = ld32(nonce + 8);
    in[9]  = ld32(nonce + 12);
    in[10] = sig[2];           /* x[10] = sigma2 */
    in[11] = ld32(key + 16);   /* x[11..14] = key[16..31] */
    in[12] = ld32(key + 20);
    in[13] = ld32(key + 24);
    in[14] = ld32(key + 28);
    in[15] = sig[3];           /* x[15] = sigma3 */

    salsa20_rounds(x, in, 0);

    st32(out + 0,  x[0]);      /* карта вывода NaCl crypto_core_hsalsa20 */
    st32(out + 4,  x[5]);
    st32(out + 8,  x[10]);
    st32(out + 12, x[15]);
    st32(out + 16, x[6]);
    st32(out + 20, x[7]);
    st32(out + 24, x[8]);
    st32(out + 28, x[9]);
}

/* ---- FUN_14002dc70: Salsa20-блок с feed-forward ------------------------
 * out64 = Salsa20_block(key32, nonce8, counter64, sigma) */
void ac_salsa20_block(uint8_t out[64], const uint8_t key[32],
                      const uint8_t nonce[8], uint64_t counter)
{
    static const uint32_t sig[4] = {
        0x61707865u, 0x3320646eu, 0x79622d32u, 0x6b206574u
    };
    uint32_t in[16], x[16];
    int i;

    in[0]  = sig[0];
    in[1]  = ld32(key + 0);
    in[2]  = ld32(key + 4);
    in[3]  = ld32(key + 8);
    in[4]  = ld32(key + 12);
    in[5]  = sig[1];
    in[6]  = ld32(nonce + 0);
    in[7]  = ld32(nonce + 4);
    in[8]  = (uint32_t) counter;          /* счётчик -> x[8],x[9] */
    in[9]  = (uint32_t) (counter >> 32);
    in[10] = sig[2];
    in[11] = ld32(key + 16);
    in[12] = ld32(key + 20);
    in[13] = ld32(key + 24);
    in[14] = ld32(key + 28);
    in[15] = sig[3];

    salsa20_rounds(x, in, 1);
    for (i = 0; i < 16; i++) st32(out + 4 * i, x[i]);
}

/* ---- поток XSalsa20 (форма FUN_14003a15c поверх двух ядер) -------------
 * keystream из msglen байтов для XSalsa20(key32, nonce24). */
void ac_xsalsa20_stream(uint8_t *out, size_t msglen,
                        const uint8_t nonce[24], const uint8_t key[32])
{
    uint8_t subkey[32];
    uint8_t block[64];
    uint64_t counter = 0;
    size_t off = 0;

    ac_hsalsa20(subkey, nonce, key);       /* nonce[0..15] */
    while (off < msglen) {
        size_t take = (msglen - off < 64) ? msglen - off : 64;
        size_t i;
        ac_salsa20_block(block, subkey, nonce + 16, counter++);
        for (i = 0; i < take; i++) out[off + i] = block[i];
        off += take;
    }
    memset(subkey, 0, sizeof subkey);
    memset(block, 0, sizeof block);
}

/* ============================== KAT ===================================== */

static const uint64_t AC_B2B_IV[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

/* перестановки sigma (12 x 16), RFC 7693 раздел 3.1 */
static const uint8_t AC_B2B_SIGMA[12][16] = {
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15},
    {14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3},
    {11, 8,12, 0, 5, 2,15,13,10,14, 3, 6, 7, 1, 9, 4},
    { 7, 9, 3, 1,13,12,11,14, 2, 6, 5,10, 4, 0,15, 8},
    { 9, 0, 5, 7, 2, 4,10,15,14, 1,11,12, 6, 8, 3,13},
    { 2,12, 6,10, 0,11, 8, 3, 4,13, 7, 5,15,14, 1, 9},
    {12, 5, 1,15,14,13, 4,10, 0, 7, 6, 3, 9, 2, 8,11},
    {13,11, 7,14,12, 1, 3, 9, 5, 0,15, 4, 8, 6, 2,10},
    { 6,15,14, 9,11, 3, 0, 8,12, 2,13, 7, 1, 4,10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5,15,11, 9,14, 3,12,13, 0},
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15},
    {14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3}
};

typedef struct {
    uint64_t h[8];
    uint64_t t[2];
    uint64_t f[2];
    uint8_t  buf[128];
    size_t   buflen;
    uint32_t outlen;
    int      last_node;
} ac_blake2b_state;

static uint64_t rotr64(uint64_t v, int n) { return (v >> n) | (v << (64 - n)); }

static uint64_t p1305_load64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= (uint64_t) p[i] << (8 * i);
    return v;
}

static void p1305_store64(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++) p[i] = (uint8_t) (v >> (8 * i));
}

/* ---- FUN_14002f104: compress -------------------------------------------
 * Ротации G 32/24/16/63 точно как восстановлено в теле драйвера. */
#define B2B_G(a, b, c, d, mx, my)                    \
    do {                                             \
        v[a] = v[a] + v[b] + (mx);                   \
        v[d] = rotr64(v[d] ^ v[a], 32);              \
        v[c] = v[c] + v[d];                          \
        v[b] = rotr64(v[b] ^ v[c], 24);              \
        v[a] = v[a] + v[b] + (my);                   \
        v[d] = rotr64(v[d] ^ v[a], 16);              \
        v[c] = v[c] + v[d];                          \
        v[b] = rotr64(v[b] ^ v[c], 63);              \
    } while (0)

static void ac_blake2b_compress(ac_blake2b_state *S, const uint8_t block[128])
{
    uint64_t m[16], v[16];
    int i, r;

    for (i = 0; i < 16; i++) m[i] = p1305_load64(block + 8 * i);
    for (i = 0; i < 8; i++) v[i] = S->h[i];
    for (i = 0; i < 8; i++) v[i + 8] = AC_B2B_IV[i];
    v[12] ^= S->t[0];
    v[13] ^= S->t[1];
    v[14] ^= S->f[0];
    v[15] ^= S->f[1];

    for (r = 0; r < 12; r++) {
        const uint8_t *s = AC_B2B_SIGMA[r];
        B2B_G(0, 4,  8, 12, m[s[ 0]], m[s[ 1]]);
        B2B_G(1, 5,  9, 13, m[s[ 2]], m[s[ 3]]);
        B2B_G(2, 6, 10, 14, m[s[ 4]], m[s[ 5]]);
        B2B_G(3, 7, 11, 15, m[s[ 6]], m[s[ 7]]);
        B2B_G(0, 5, 10, 15, m[s[ 8]], m[s[ 9]]);
        B2B_G(1, 6, 11, 12, m[s[10]], m[s[11]]);
        B2B_G(2, 7,  8, 13, m[s[12]], m[s[13]]);
        B2B_G(3, 4,  9, 14, m[s[14]], m[s[15]]);
    }
    for (i = 0; i < 8; i++) S->h[i] ^= v[i] ^ v[i + 8];
}

/* ---- FUN_140034cd8: init_param (блок параметров XOR'ится в IV) -------- */
static void ac_blake2b_init(ac_blake2b_state *S, uint32_t outlen)
{
    /* блок параметров драйвера (FUN_140034d84): {0x18,0,1,1} -> 0x01010018 */
    uint64_t param = 0x01010000ULL | (uint64_t) outlen;
    int i;
    memset(S, 0, sizeof *S);
    for (i = 0; i < 8; i++) S->h[i] = AC_B2B_IV[i];
    S->h[0] ^= param;
    S->outlen = outlen;
}

/* ---- FUN_140034de4: update --------------------------------------------- */
static void ac_blake2b_update(ac_blake2b_state *S, const uint8_t *in,
                              size_t len)
{
    while (len > 0) {
        size_t room = sizeof S->buf - S->buflen;
        if (len <= room) {
            memcpy(S->buf + S->buflen, in, len);
            S->buflen += len;
            return;
        }
        memcpy(S->buf + S->buflen, in, room);
        S->t[0] += 128;
        if (S->t[0] < 128) S->t[1]++;
        ac_blake2b_compress(S, S->buf);
        S->buflen = 0;
        in += room;
        len -= room;
    }
}

/* ---- FUN_140034f04: final ---------------------------------------------- */
static void ac_blake2b_final(ac_blake2b_state *S, uint8_t *out)
{
    uint8_t full[64];
    S->t[0] += (uint64_t) S->buflen;
    if (S->t[0] < S->buflen) S->t[1]++;
    if (S->last_node) S->f[1] = ~0ULL;
    S->f[0] = ~0ULL;                          /* флаг последнего блока (драйвер:
                                               * param_1[10] = ~0) */
    memset(S->buf + S->buflen, 0, sizeof S->buf - S->buflen);
    ac_blake2b_compress(S, S->buf);
    for (int i = 0; i < 8; i++) p1305_store64(full + 8 * i, S->h[i]);
    memcpy(out, full, S->outlen);
    memset(S, 0, sizeof *S);                  /* wipe состояния (драйвер трёт
                                               * 0x40 + 0x100 байтов) */
}

/* one-shot helper: правило nonce BLAKE2b-192 wire-протокола
 * (FUN_14002abb8: update(eph_pk,32), update(recip_pk,32), final) */
void ac_blake2b_192(uint8_t out[24], const uint8_t *in, size_t len)
{
    ac_blake2b_state S;
    ac_blake2b_init(&S, 24);
    ac_blake2b_update(&S, in, len);
    ac_blake2b_final(&S, out);
}

/* ============================== KAT ===================================== */

typedef struct {
    uint32_t r[5];          /* clamp'нутые r-лимбы (26-битные) */
    uint32_t h[5];          /* аккумулятор */
    uint32_t s[4];          /* s (вторая половина ключа) */
    uint32_t pad[1];        /* (держится неявным; hibit обрабатывается по блокам) */
    uint8_t  buf[16];
    size_t   buflen;
} ac_poly1305_state;

/* ---- FUN_1400350b4: init (clamp + s) ----------------------------------- */
static void ac_poly1305_init(ac_poly1305_state *st, const uint8_t key[32])
{
    uint32_t t0 = (uint32_t) key[0] | ((uint32_t) key[1] << 8) |
                  ((uint32_t) key[2] << 16) | ((uint32_t) key[3] << 24);
    uint32_t t1 = (uint32_t) key[4] | ((uint32_t) key[5] << 8) |
                  ((uint32_t) key[6] << 16) | ((uint32_t) key[7] << 24);
    uint32_t t2 = (uint32_t) key[8] | ((uint32_t) key[9] << 8) |
                  ((uint32_t) key[10] << 16) | ((uint32_t) key[11] << 24);
    uint32_t t3 = (uint32_t) key[12] | ((uint32_t) key[13] << 8) |
                  ((uint32_t) key[14] << 16) | ((uint32_t) key[15] << 24);

    /* clamp: r &= 0x0ffffffc0ffffffc0ffffffc0fffffff (форма 26-битных лимбов) */
    st->r[0] = t0 & 0x3ffffff;
    st->r[1] = ((t0 >> 26) | (t1 << 6)) & 0x3ffff03;
    st->r[2] = ((t1 >> 20) | (t2 << 12)) & 0x3ffc0ff;
    st->r[3] = ((t2 >> 14) | (t3 << 18)) & 0x3f03fff;
    st->r[4] = (t3 >> 8) & 0x00fffff;

    for (int i = 0; i < 5; i++) st->h[i] = 0;
    for (int i = 0; i < 4; i++)
        st->s[i] = (uint32_t) key[16 + 4 * i] | ((uint32_t) key[17 + 4 * i] << 8) |
                   ((uint32_t) key[18 + 4 * i] << 16) |
                   ((uint32_t) key[19 + 4 * i] << 24);
    st->buflen = 0;
}

/* ---- FUN_140035254: blocks ----------------------------------------------
 * 16-байтовые блоки; hibit = 2^128 добавляется для полных блоков
 * (pad==0 -> финальный частичный блок: без hibit -- форма драйвера
 * ~-(flag!=0) & 0x1000000). */
static void ac_poly1305_blocks(ac_poly1305_state *st, const uint8_t *m,
                               size_t bytes, uint32_t hibit)
{
    const uint32_t r0 = st->r[0], r1 = st->r[1], r2 = st->r[2],
                   r3 = st->r[3], r4 = st->r[4];
    const uint32_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
    uint32_t h0 = st->h[0], h1 = st->h[1], h2 = st->h[2],
             h3 = st->h[3], h4 = st->h[4];
    uint64_t d0, d1, d2, d3, d4;
    uint32_t c;

    while (bytes >= 16) {
        uint32_t t0 = (uint32_t) m[0] | ((uint32_t) m[1] << 8) |
                      ((uint32_t) m[2] << 16) | ((uint32_t) m[3] << 24);
        uint32_t t1 = (uint32_t) m[4] | ((uint32_t) m[5] << 8) |
                      ((uint32_t) m[6] << 16) | ((uint32_t) m[7] << 24);
        uint32_t t2 = (uint32_t) m[8] | ((uint32_t) m[9] << 8) |
                      ((uint32_t) m[10] << 16) | ((uint32_t) m[11] << 24);
        uint32_t t3 = (uint32_t) m[12] | ((uint32_t) m[13] << 8) |
                      ((uint32_t) m[14] << 16) | ((uint32_t) m[15] << 24);

        h0 += t0 & 0x3ffffff;
        h1 += ((t0 >> 26) | (t1 << 6)) & 0x3ffffff;
        h2 += ((t1 >> 20) | (t2 << 12)) & 0x3ffffff;
        h3 += ((t2 >> 14) | (t3 << 18)) & 0x3ffffff;
        h4 += (t3 >> 8) | hibit;

        d0 = (uint64_t) h0 * r0 + (uint64_t) h1 * s4 + (uint64_t) h2 * s3 +
             (uint64_t) h3 * s2 + (uint64_t) h4 * s1;
        d1 = (uint64_t) h0 * r1 + (uint64_t) h1 * r0 + (uint64_t) h2 * s4 +
             (uint64_t) h3 * s3 + (uint64_t) h4 * s2;
        d2 = (uint64_t) h0 * r2 + (uint64_t) h1 * r1 + (uint64_t) h2 * r0 +
             (uint64_t) h3 * s4 + (uint64_t) h4 * s3;
        d3 = (uint64_t) h0 * r3 + (uint64_t) h1 * r2 + (uint64_t) h2 * r1 +
             (uint64_t) h3 * r0 + (uint64_t) h4 * s4;
        d4 = (uint64_t) h0 * r4 + (uint64_t) h1 * r3 + (uint64_t) h2 * r2 +
             (uint64_t) h3 * r1 + (uint64_t) h4 * r0;

        c = (uint32_t) (d0 >> 26); h0 = (uint32_t) d0 & 0x3ffffff;
        d1 += c; c = (uint32_t) (d1 >> 26); h1 = (uint32_t) d1 & 0x3ffffff;
        d2 += c; c = (uint32_t) (d2 >> 26); h2 = (uint32_t) d2 & 0x3ffffff;
        d3 += c; c = (uint32_t) (d3 >> 26); h3 = (uint32_t) d3 & 0x3ffffff;
        d4 += c; c = (uint32_t) (d4 >> 26); h4 = (uint32_t) d4 & 0x3ffffff;
        h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff;
        h1 += c;

        m += 16;
        bytes -= 16;
    }

    st->h[0] = h0; st->h[1] = h1; st->h[2] = h2;
    st->h[3] = h3; st->h[4] = h4;
}

/* ---- FUN_1400357cc: update --------------------------------------------- */
static void ac_poly1305_update(ac_poly1305_state *st, const uint8_t *m,
                               size_t len)
{
    if (st->buflen != 0) {
        size_t take = 16 - st->buflen;
        if (take > len) take = len;
        memcpy(st->buf + st->buflen, m, take);
        st->buflen += take;
        m += take;
        len -= take;
        if (st->buflen == 16) {
            ac_poly1305_blocks(st, st->buf, 16, 1u << 24);
            st->buflen = 0;
        }
    }
    if (len >= 16) {
        size_t blocks = len & ~(size_t) 15;
        ac_poly1305_blocks(st, m, blocks, 1u << 24);
        m += blocks;
        len -= blocks;
    }
    if (len != 0) {
        memcpy(st->buf, m, len);
        st->buflen = len;
    }
}

/* ---- FUN_1400355a4 [0x1400355a4]: finish ----------------------------------
 * (аудит agent-515 §3: VA был mis-classified в ac_native_crt (va_map);
 * владелец -- этот модуль, класс ac_crypto_primitive; НЕ дубль: это и есть
 * порт poly1305_finish, 26-битные лимбы, >>0x1a, *5) ----------------------- */
static void ac_poly1305_finish(ac_poly1305_state *st, uint8_t mac[16])
{
    uint32_t h0, h1, h2, h3, h4;
    uint32_t c, mask;
    uint32_t g0, g1, g2, g3, g4;
    uint64_t f;

    if (st->buflen != 0) {
        st->buf[st->buflen++] = 1;
        memset(st->buf + st->buflen, 0, 16 - st->buflen);
        ac_poly1305_blocks(st, st->buf, 16, 0);   /* без hibit: финальный блок */
    }

    h0 = st->h[0]; h1 = st->h[1]; h2 = st->h[2];
    h3 = st->h[3]; h4 = st->h[4];

    /* полный перенос */
    c = h1 >> 26; h1 &= 0x3ffffff; h2 += c;
    c = h2 >> 26; h2 &= 0x3ffffff; h3 += c;
    c = h3 >> 26; h3 &= 0x3ffffff; h4 += c;
    c = h4 >> 26; h4 &= 0x3ffffff; h0 += c * 5;
    c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;

    /* выбрать h, если h < p, иначе h - p  (драйвер: трюк сравнения +0xfc000000) */
    g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
    g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    g4 = h4 + c - (1u << 26);

    mask = (g4 >> 31) - 1;      /* 0, если h >= p (g4 без borrow), ~0 иначе */
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0; h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2; h3 = (h3 & mask) | g3;
    h4 = (h4 & mask) | g4;

    /* схлопнуть 26-битные лимбы в четыре 32-битных слова, затем
     * h = (h + s) mod 2^128 (порядок finish donna-32: сначала pack, потом +s) */
    {
        uint32_t w0 = (uint32_t) ((h0) | (h1 << 26));
        uint32_t w1 = (uint32_t) ((h1 >> 6) | (h2 << 20));
        uint32_t w2 = (uint32_t) ((h2 >> 12) | (h3 << 14));
        uint32_t w3 = (uint32_t) ((h3 >> 18) | (h4 << 8));

        f = (uint64_t) w0 + st->s[0];             w0 = (uint32_t) f;
        f = (uint64_t) w1 + st->s[1] + (f >> 32); w1 = (uint32_t) f;
        f = (uint64_t) w2 + st->s[2] + (f >> 32); w2 = (uint32_t) f;
        f = (uint64_t) w3 + st->s[3] + (f >> 32); w3 = (uint32_t) f;

        mac[0] = (uint8_t) w0;  mac[1] = (uint8_t) (w0 >> 8);
        mac[2] = (uint8_t) (w0 >> 16); mac[3] = (uint8_t) (w0 >> 24);
        mac[4] = (uint8_t) w1;  mac[5] = (uint8_t) (w1 >> 8);
        mac[6] = (uint8_t) (w1 >> 16); mac[7] = (uint8_t) (w1 >> 24);
        mac[8] = (uint8_t) w2;  mac[9] = (uint8_t) (w2 >> 8);
        mac[10] = (uint8_t) (w2 >> 16); mac[11] = (uint8_t) (w2 >> 24);
        mac[12] = (uint8_t) w3; mac[13] = (uint8_t) (w3 >> 8);
        mac[14] = (uint8_t) (w3 >> 16); mac[15] = (uint8_t) (w3 >> 24);
    }

    memset(st, 0, sizeof *st);     /* wipe состояния 0x58 байтов в драйвере */
}

/* ---- FUN_1400358ac: one-shot ------------------------------------------- */
void ac_poly1305(uint8_t mac[16], const uint8_t *m, size_t len,
                 const uint8_t key[32])
{
    ac_poly1305_state st;
    ac_poly1305_init(&st, key);
    ac_poly1305_update(&st, m, len);
    ac_poly1305_finish(&st, mac);
}

/* constant-time verify (форма FUN_140035950) */
int ac_poly1305_verify(const uint8_t mac[16], const uint8_t *m, size_t len,
                       const uint8_t key[32])
{
    uint8_t calc[16];
    uint8_t diff = 0;
    ac_poly1305(calc, m, len, key);
    for (int i = 0; i < 16; i++) diff |= (uint8_t) (calc[i] ^ mac[i]);
    return diff == 0;
}

/* ============================== KAT ===================================== */

#define AC_SEAL_OVERHEAD 48

/* crypto_box_beforenm: k = HSalsa20(X25519(sk, pk), zero16) */
static void ac_box_beforenm(uint8_t k[32], const uint8_t pk[32],
                            const uint8_t sk[32])
{
    static const uint8_t zero16[16] = {0};   /* g_unk_1400a57a8 = 00*16 */
    uint8_t shared[32];
    ac_x25519(shared, sk, pk);
    ac_hsalsa20(k, zero16, shared);
    memset(shared, 0, sizeof shared);
}

/* crypto_secretbox_easy_afternm: c = tag16 || ct
 * (конструкция NaCl: stream[0:32] -> poly-ключ; stream[32:] XOR m) */
static void ac_secretbox(uint8_t *c, const uint8_t *m, size_t mlen,
                         const uint8_t nonce[24], const uint8_t k[32])
{
    uint8_t subkey[32], stream[64], polykey[32];
    uint64_t cur_blk = 0;
    size_t pos;

    ac_hsalsa20(subkey, nonce, k);
    /* ключ poly1305 = первые 32 байта потока (счётчик блоков 0) */
    ac_salsa20_block(stream, subkey, nonce + 16, 0);
    memcpy(polykey, stream, 32);

    /* байт i plaintext'а XOR'ится с байтом потока 32 + i */
    for (pos = 0; pos < mlen; pos++) {
        uint64_t soff = 32 + pos;
        uint64_t blk = soff / 64;
        if (blk != cur_blk) {
            ac_salsa20_block(stream, subkey, nonce + 16, blk);
            cur_blk = blk;
        }
        c[16 + pos] = m[pos] ^ stream[soff % 64];
    }
    ac_poly1305(c, c + 16, mlen, polykey);

    memset(polykey, 0, sizeof polykey);
    memset(subkey, 0, sizeof subkey);
    memset(stream, 0, sizeof stream);
}

static int ac_secretbox_open(uint8_t *m, const uint8_t *c, size_t clen,
                             const uint8_t nonce[24], const uint8_t k[32])
{
    uint8_t subkey[32], stream[64], polykey[32];
    uint64_t cur_blk = 0;
    size_t pos;
    int ok;

    if (clen < 16) return -1;
    ac_hsalsa20(subkey, nonce, k);
    ac_salsa20_block(stream, subkey, nonce + 16, 0);
    memcpy(polykey, stream, 32);

    /* сначала MAC, constant-time (драйвер FUN_14003674c: verify, затем decrypt) */
    ok = ac_poly1305_verify(c, c + 16, clen - 16, polykey);
    memset(polykey, 0, sizeof polykey);
    if (!ok) {
        memset(subkey, 0, sizeof subkey);
        memset(stream, 0, sizeof stream);
        return -1;
    }
    for (pos = 0; pos < clen - 16; pos++) {
        uint64_t soff = 32 + pos;
        uint64_t blk = soff / 64;
        if (blk != cur_blk) {
            ac_salsa20_block(stream, subkey, nonce + 16, blk);
            cur_blk = blk;
        }
        m[pos] = c[16 + pos] ^ stream[soff % 64];
    }
    memset(subkey, 0, sizeof subkey);
    memset(stream, 0, sizeof stream);
    return 0;
}

/* crypto_box_seal: wire = eph_pk || secretbox(nonce24, k) */
/* [0x14002ac48] seal compose (цепочка вызовов в заголовке файла) */
VOID
AcLsBoxSeal(uint8_t *wire, const uint8_t *m, size_t mlen,
                        const uint8_t recipient_pk[32],
                        const uint8_t eph_sk[32])
{
    uint8_t nonce_in[64], nonce[24], k[32];
    ac_x25519_base(wire, eph_sk);                 /* wire[0:32] = eph_pk */
    memcpy(nonce_in, wire, 32);
    memcpy(nonce_in + 32, recipient_pk, 32);
    ac_blake2b_192(nonce, nonce_in, 64);          /* правило FUN_14002abb8 */
    ac_box_beforenm(k, recipient_pk, eph_sk);     /* правило FUN_14002ae18 */
    ac_secretbox(wire + 32, m, mlen, nonce, k);   /* tag||ct по wire[32:] */
    memset(k, 0, sizeof k);
}

/* [0x14002ad5c] open compose (цепочка вызовов в заголовке файла) */
INT
AcLsBoxSealOpen(uint8_t *m, const uint8_t *wire, size_t wirelen,
                            const uint8_t own_pk[32], const uint8_t own_sk[32])
{
    uint8_t nonce_in[64], nonce[24], k[32];
    int rc;
    if (wirelen < AC_SEAL_OVERHEAD) return -1;
    memcpy(nonce_in, wire, 32);
    memcpy(nonce_in + 32, own_pk, 32);
    ac_blake2b_192(nonce, nonce_in, 64);
    ac_box_beforenm(k, wire /*eph_pk*/, own_sk);
    rc = ac_secretbox_open(m, wire + 32, wirelen - 32, nonce, k);
    memset(k, 0, sizeof k);
    return rc;
}

/* ============================== KAT ===================================== */


/* ---- FUN_140027044: собственный RNG драйвера (НЕ CSPRNG) -----------------
 * seed = KeQueryPerformanceCounter (пара 0x140107548^0x140107540);
 * поток = RtlRandomEx (пара 0x140107538^0x140107530), послойное извлечение
 * байтов (native_03.c; RtlRandomEx -- verified импорт 259-таблицы).
 * Структурная слабость (документированная, SEALED_SEMANTICS #1.4):
 * детерминированный RtlRandomEx от QPC-сида -- воспроизводим любым, кто
 * угадает счётчик на boot'е. Оставлен как фактический механизм драйвера;
 * НЕ "апгрейдить" его молча (conformance с оригиналом важнее). */
VOID
AcLsRandomBytes(
    _Out_ UINT8* Buffer,
    _In_ UINT32 Size
    )
{
    ULONG seed = (ULONG)KeQueryPerformanceCounter(NULL).QuadPart;
    UINT32 i;

    for (i = 0; i < Size; i++) {
        if ((i & 3) == 0)
            seed = RtlRandomEx(&seed);
        Buffer[i] = (UINT8)(seed >> ((i & 3) * 8));
    }
}

/* ---- заметка о call-chain драйвера (provenance композиции) ---------------
 * seal: FUN_14002ac48 (RNG FUN_14003d608 -> eph sk; scalarmult_base через
 *       vtable 0x140106f68+8; nonce FUN_14002abb8 по ячейкам 0x140107300
 *       server pk; beforenm FUN_14002ae18; box FUN_140036520)
 * open: FUN_14002ad5c (nonce по own pk-ячейке 0x1401072a8; beforenm с
 *       own sk-ячейкой 0x140107378; unbox FUN_14003674c)
 * ------------------------------------------------------------------------ */
