/* ==========================================================================
 * crypto.h -- криптография телеметрии/канала: sealed-боксы (X25519 +
 *             XSalsa20-Poly1305), BLAKE2, BCrypt-хаб
 * --------------------------------------------------------------------------
 * Provenance: golden v1 crypto.c (62 тела: telemetry_crypto + нативные
 * оркестраторы), DRIVER_CHANNEL_PROTOCOL §2 (примитив + wire-layout),
 * AC_NATIVE §2 (ячейки собственной пары, вызывающие crypto_box_seal_open).
 * ========================================================================== */
#ifndef FACEIT_AC_CRYPTO_H
#define FACEIT_AC_CRYPTO_H

#include <ntddk.h>
#include <intrin.h>
#include "channels.h"

/* [0x1401d7125 контур] источник энтропии (lazy-слой ksecdd BCrypt) */
VOID AcCryptoRandomBytes(_Out_ UINT8* Buffer, _In_ UINT32 Size);

/* [0x14024af8e] хаб machine-hash (BCrypt 259-таблица) */
NTSTATUS AcCryptoMachineHash(_In_ const UINT8* Data, _In_ UINT32 DataSize,
                             _Out_ UINT8 HashOut[32]);

/* [0x14002abb8] правило nonce (BLAKE2b-192 по eph_pk || recipient_pk) */
VOID AcCryptoDeriveNonce(_In_ const UINT8 EphPk[32],
                         _In_ const UINT8 RecipPk[32],
                         _Out_ UINT8 Nonce[24]);

/* wire-layout (DRIVER_CHANNEL_PROTOCOL §2.1, [wire]+[dec]):
 *   wire = eph_pk(32) || MAC(16) || ct
 *   nonce = BLAKE2b-192(eph_pk || recipient_pk)
 *   overhead 48B (65->113, 96->144, 695->743, 604->652 все сходятся) */
#define AC_CRYPTO_EPH_PK_SIZE   32
#define AC_CRYPTO_MAC_SIZE      16
#define AC_CRYPTO_SEAL_OVERHEAD (AC_CRYPTO_EPH_PK_SIZE + AC_CRYPTO_MAC_SIZE)
#define AC_CRYPTO_KEY_SIZE      32

/* [0x14014c9fd] crypto_vm_orchestrator: диспетч seal/open
 * (evidence: golden v1 crypto.c INDEX) */
NTSTATUS
AcCryptoBoxSeal(
    _In_ const UINT8* Plaintext,
    _In_ UINT32 PlaintextLen,
    _In_ const UINT8 RecipientPk[AC_CRYPTO_KEY_SIZE],
    _Out_ UINT8* Wire,
    _Inout_ UINT32* WireLen
    );

/* нативный crypto_box_seal_open (14 VM-stub вызывающих, AC_NATIVE §2);
 * собственная пара: pk-ячейка 0x140107268 / sk-ячейка 0x140107338 (BSS,
 * live-only: 0 писателей по кампании 327-цепочек -- генерация на boot'е) */
NTSTATUS
AcCryptoBoxSealOpen(
    _In_ const UINT8* Wire,
    _In_ UINT32 WireLen,
    _Out_ UINT8* Plaintext,
    _Inout_ UINT32* PlaintextLen
    );

/* [0xC3502034] обработчик key-exchange: in = 32B pk сервиса, out = 32B
 * свежего эфемерного pk драйвера (пара X25519: randombytes(32) +
 * scalarmult_base)
 * (evidence: DRIVER_CHANNEL_PROTOCOL §1 [wire]+[static R13]) */
NTSTATUS
AcCryptoKeyExchange(
    _In_ const UINT8 ServicePk[AC_CRYPTO_KEY_SIZE],
    _Out_ UINT8 DriverPkOut[AC_CRYPTO_KEY_SIZE]
    );

/* открыть входящий sealed-push (S->D); получатель = собственный ключ драйвера */
NTSTATUS
AcCryptoOpenSealed(
    _In_ const VOID* Wire,
    _In_ UINT32 WireLen,
    _Out_ UINT8* Plaintext,
    _Inout_ UINT32* PlaintextLen
    );

/* [0xC3502008] хранилище bootstrap-блоба (модель courier: sealed под
 * СЕРВЕРНЫЙ сессионный ключ, драйвер его никогда не открывает) */
NTSTATUS
AcCryptoStoreBootstrap(
    _In_ const VOID* Buf,
    _In_ UINT32 Len
    );

/* путь сендера: seal под session pk сервиса + постановка в очередь на drain */
NTSTATUS
AcCryptoSealAndQueue(
    _Inout_ PAC_CHANNEL_STATE Channel,
    _In_ const VOID* Buf,
    _In_ UINT32 Len
    );

/* извлечь один sealed-бокс (завершение poll/long-poll) */
NTSTATUS
AcCryptoDequeueSealed(
    _Inout_ PAC_CHANNEL_STATE Channel,
    _Out_ PVOID Buffer,
    _In_ UINT32 BufferSize,
    _Out_ UINT32* OutLen
    );

/* [0x14003d9ec] blake2_dispatch_init (evidence: golden v1 crypto.c) */
NTSTATUS
AcCryptoBlake2Init(VOID);

/* [0x140066ce8] pair_verifier (evidence: golden v1 crypto.c) */
NTSTATUS
AcCryptoPairVerify(VOID);

#endif /* FACEIT_AC_CRYPTO_H */
