/* ==========================================================================
 * crypto_libsodium.h -- смердженные крипто-кандидаты (agent-492, 33/33 KAT)
 * ========================================================================== */
#ifndef FACEIT_AC_CRYPTO_LIBSODIUM_H
#define FACEIT_AC_CRYPTO_LIBSODIUM_H

#include <ntddk.h>

/* ---- примитивы (VA-карта в заголовке crypto_libsodium.c) --------------- */

/* [FUN_14002d7a8] HSalsa20 core: out32 = HSalsa20(key32, nonce16) */
void ac_hsalsa20(UINT8* out /*[32]*/, const UINT8* nonce /*[16]*/,
                 const UINT8* key /*[32]*/);

/* [FUN_14002dc70] Salsa20-блок с feed-forward */
void ac_salsa20_block(UINT8* out /*[64]*/, const UINT8* key /*[32]*/,
                      const UINT8* nonce /*[8]*/, UINT64 counter);

/* [FUN_14003a15c] keystream XSalsa20 (key32, nonce24) */
void ac_xsalsa20_stream(UINT8* out, size_t msglen,
                        const UINT8* nonce /*[24]*/,
                        const UINT8* key /*[32]*/);

/* [FUN_140035b88] X25519 ladder: out32 = X25519(scalar, u) */
void ac_x25519(UINT8* out /*[32]*/, const UINT8* scalar /*[32]*/,
               const UINT8* u /*[32]*/);

/* [FUN_14003630c] умножение X25519 на базовую точку */
void ac_x25519_base(UINT8* out /*[32]*/, const UINT8* scalar /*[32]*/);

/* [FUN_14002abb8] BLAKE2b-192 one-shot (правило nonce wire) */
void ac_blake2b_192(UINT8* out /*[24]*/, const UINT8* in, size_t len);

/* [FUN_1400358ac] Poly1305 one-shot */
void ac_poly1305(UINT8* mac /*[16]*/, const UINT8* m, size_t len,
                 const UINT8* key /*[32]*/);

/* [FUN_140035950] Poly1305 verify (constant-time) */
int ac_poly1305_verify(const UINT8* mac /*[16]*/, const UINT8* m,
                       size_t len, const UINT8* key /*[32]*/);

/* ---- wire-композиция ---------------------------------------------------- */

/* [FUN_14002ac48] crypto_box_seal: wire = eph_pk(32) || tag(16) || ct
 * (вызывающий даёт эфемерный секретный ключ, на кадр) */
VOID AcLsBoxSeal(_Out_ UINT8* wire, _In_ const UINT8* m, _In_ size_t mlen,
                 _In_ const UINT8* recipient_pk,
                 _In_ const UINT8* eph_sk);

/* [FUN_14002ad5c] crypto_box_seal_open: возвращает 0 при валидном MAC */
INT AcLsBoxSealOpen(_Out_ UINT8* m, _In_ const UINT8* wire,
                    _In_ size_t wirelen, _In_ const UINT8* own_pk,
                    _In_ const UINT8* own_sk);

/* [FUN_140027044] собственный RNG драйвера: QPC-seed + поток RtlRandomEx
 * (НЕ CSPRNG -- документированная слабость, SEALED_SEMANTICS #1.4) */
VOID AcLsRandomBytes(_Out_ UINT8* Buffer, _In_ UINT32 Size);

#endif /* FACEIT_AC_CRYPTO_LIBSODIUM_H */
