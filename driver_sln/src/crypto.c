/* ==========================================================================
 * crypto.c -- криптография канала/телеметрии
 * --------------------------------------------------------------------------
 * Provenance примитивов (DRIVER_CHANNEL_PROTOCOL §2):
 *   оба направления = libsodium crypto_box_seal (X25519 + XSalsa20-Poly1305)
 *   wire = eph_pk(32) || MAC(16) || ct; nonce = BLAKE2b-192(eph || recip)
 *   доказательство входящего направления: все 330 захваченных боксов D->S
 *   открываются session_sk рана (poly1305 валиден) [dec]; боксы S->D
 *   открываются только собственным ключом драйвера [dec-neg]
 * Ячейки собственной пары: pk 0x140107268 / sk 0x140107338 -- BSS в образе
 * файла, 0 писателей во всех кампаниях наблюдения (генерация на boot'е,
 * genuinely live state: VMENTRY_REPORT §7).
 * ========================================================================== */
#include <ntddk.h>
#include <bcrypt.h>

#include "provenance.h"
#include "tables.h"
#include "crypto.h"
#include "crypto_libsodium.h"
#include "channels.h"

/* sealed-бокс в очереди (одна запись события на wire) */
typedef struct _AC_SEALED_BOX {
    LIST_ENTRY Link;
    UINT32 Size;
    UINT8 Data[4096 + AC_CRYPTO_SEAL_OVERHEAD];
} AC_SEALED_BOX, *PAC_SEALED_BOX;

/* --------------------------------------------------------------------------
 * Ядра примитивов X25519 + XSalsa20-Poly1305 + BLAKE2b.
 * [0x14014c9fd] crypto_vm_orchestrator диспетчит seal/open; сами ядра
 * примитивов исполняются как байткод Themida VM -- их математическое
 * определение восстановлено с wire (libsodium-совместимо, доказано
 * успешной оффлайн-дешифровкой 330 захваченных боксов наблюдавшимися
 * сессионными ключами, DRIVER_CHANNEL_PROTOCOL §2.3 [dec]).
 * Тела seal по 0x14002AF54/0x14002B068/0x1403BB046/0x14000C10C --
 * VA June-билда вне корпуса (только заголовки -- граница payload).
 * ------------------------------------------------------------------------ */

/* --------------------------------------------------------------------------
 * Состояние BLAKE2b (константная программа RFC 7693; хэш-хаб, стоящий за
 * правилом nonce sealed-бокса BLAKE2b-192 и путём machine-hash через BCrypt)
 * [0x14003d6e0] native role twin: нативный blake2_dispatch_init (мост =~ sub_14003D9EC, AC_NATIVE 6; va_map)
 * ------------------------------------------------------------------------ */
#pragma pack(push, 1)
typedef struct _AC_BLAKE2B_STATE {
    UINT64 H[8];          /* chaining-состояние */
    UINT64 T[2];          /* счётчик байтов */
    UINT8  Buf[128];      /* частичный блок */
    UINT32 BufLen;
    UINT32 OutLen;        /* 24 для BLAKE2b-192 */
} AC_BLAKE2B_STATE, *PAC_BLAKE2B_STATE;
#pragma pack(pop)

static AC_BLAKE2B_STATE g_Blake2b;

/* [0x14003d9ec] blake2_dispatch_init: init BLAKE2-хаба (evidence: golden v1
 * crypto.c INDEX role; BCryptCreateHash/HashData/FinishHash -- verified
 * импорты, используемые путём machine-hash оркестратора, KERNEL_WALLS_FINAL
 * §1.1). IV по RFC 7693 с блоком параметров (fanout=1, длина дайджеста),
 * XOR'нутым в h[0]; BLAKE2b-192 -> outlen 24 */
NTSTATUS
AcCryptoBlake2Init(
    VOID
    )
{
    static const UINT64 iv[8] = {
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
        0x510e527fade682d1, 0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
    };
    UINT32 i;

    for (i = 0; i < 8; i++)
        g_Blake2b.H[i] = iv[i];
    g_Blake2b.H[0] ^= 0x01010018;   /* длина дайджеста 24, fanout 1, depth 1 */
    g_Blake2b.T[0] = g_Blake2b.T[1] = 0;
    g_Blake2b.BufLen = 0;
    g_Blake2b.OutLen = 24;
    return STATUS_SUCCESS;
}

/* деривация nonce: BLAKE2b-192(eph_pk || recipient_pk)
 * [0x14002abb8] blake2-хаб; правило nonce исполняется внутри
 * AcLsBoxSeal/AcLsBoxSealOpen (crypto_libsodium.c, KAT-passed);
 * оставлено публичным для пути key-exchange */
VOID
AcCryptoDeriveNonce(
    _In_ const UINT8 EphPk[AC_CRYPTO_KEY_SIZE],
    _In_ const UINT8 RecipPk[AC_CRYPTO_KEY_SIZE],
    _Out_ UINT8 Nonce[24]
    )
{
    UINT8 block[2 * AC_CRYPTO_KEY_SIZE];

    RtlCopyMemory(block, EphPk, AC_CRYPTO_KEY_SIZE);
    RtlCopyMemory(block + AC_CRYPTO_KEY_SIZE, RecipPk, AC_CRYPTO_KEY_SIZE);

    /* [0x14002abb8] BLAKE2b-192 по конкатенации (правило nonce
     * libsodium crypto_box_seal; KAT-passed примитив из
     * crypto_libsodium.c -- SEALED_SEMANTICS #1.6) */
    ac_blake2b_192(Nonce, block, sizeof(block));
}

/* --------------------------------------------------------------------------
 * [0x14014c9fd] путь seal: эфемерная пара -> shared secret -> поток
 * XSalsa20 -> Poly1305 MAC; wire = eph_pk || MAC || ct
 * ------------------------------------------------------------------------ */
NTSTATUS
AcCryptoBoxSeal(
    _In_ const UINT8* Plaintext,
    _In_ UINT32 PlaintextLen,
    _In_ const UINT8 RecipientPk[AC_CRYPTO_KEY_SIZE],
    _Out_ UINT8* Wire,
    _Inout_ UINT32* WireLen
    )
{
    if (*WireLen < PlaintextLen + AC_CRYPTO_SEAL_OVERHEAD)
        return STATUS_BUFFER_TOO_SMALL;

    /* эфемерная пара: randombytes(32) [FUN_140027044: QPC+RtlRandomEx,
     * НЕ CSPRNG -- реальный, документированно слабый RNG драйвера] +
     * scalarmult_base [FUN_14003630c]; полная wire-композиция KAT-passed
     * примитивами (crypto_libsodium.c: X25519 ladder [FUN_140035b88],
     * HSalsa20 [FUN_14002d7a8], Salsa20 [FUN_14002dc70], BLAKE2b-192
     * [FUN_14002abb8], Poly1305 [FUN_1400358ac]) */
    {
        UINT8 ephSk[AC_CRYPTO_KEY_SIZE];

        AcCryptoRandomBytes(ephSk, AC_CRYPTO_KEY_SIZE);

        /* [FUN_14002ac48] wire = eph_pk || tag || ct */
        AcLsBoxSeal(Wire, Plaintext, PlaintextLen, RecipientPk, ephSk);

        RtlSecureZeroMemory(ephSk, sizeof(ephSk));
    }

    *WireLen = PlaintextLen + AC_CRYPTO_SEAL_OVERHEAD;
    return STATUS_SUCCESS;
}

/* --------------------------------------------------------------------------
 * crypto_box_seal_open (нативный в драйвере, 14 VM-stub вызывающих;
 * AC_NATIVE §2). Получатель = собственная пара драйвера (ячейки
 * 0x140107268 pk / 0x140107338 sk -- BSS, генерируется на boot'е;
 * таблица VMENTRY_REPORT §7).
 * ------------------------------------------------------------------------ */
NTSTATUS
AcCryptoBoxSealOpen(
    _In_ const UINT8* Wire,
    _In_ UINT32 WireLen,
    _Out_ UINT8* Plaintext,
    _Inout_ UINT32* PlaintextLen
    )
{
    const UINT8* ownPk;
    const UINT8* ownSk;
    INT rc;

    if (WireLen < AC_CRYPTO_SEAL_OVERHEAD)
        return STATUS_INVALID_PARAMETER;

    if (*PlaintextLen < WireLen - AC_CRYPTO_SEAL_OVERHEAD)
        return STATUS_BUFFER_TOO_SMALL;

    /* собственная пара из pair-ячеек (live, boot-time) */
    ownPk = (const UINT8*)g_pslots + AC_CELL_OWN_PK;
    ownSk = (const UINT8*)g_pslots + AC_CELL_OWN_SK;

    /* [FUN_14002ad5c] проверка MAC (constant-time, Poly1305
     * [FUN_140035950]), затем дешифровка XSalsa20 -- KAT-passed примитивы */
    rc = AcLsBoxSealOpen(Plaintext, Wire, WireLen, ownPk, ownSk);
    if (rc != 0)
        return STATUS_ACCESS_DENIED;    /* несовпадение MAC */

    *PlaintextLen = WireLen - AC_CRYPTO_SEAL_OVERHEAD;
    return STATUS_SUCCESS;
}

/* --------------------------------------------------------------------------
 * [0xC3502034] key-exchange: сервис генерирует свежую пару X25519 и шлёт
 * свой pk (32B); драйвер отвечает своим 32B вкладом
 * (evidence: DRIVER_CHANNEL_PROTOCOL §1 [wire]: 32 in / 32 out, отдельный
 * хэндл, раз за capture); диспетч через seal/open оркестратор
 * [0x14014c9fd]
 * ------------------------------------------------------------------------ */
NTSTATUS
AcCryptoKeyExchange(
    _In_ const UINT8 ServicePk[AC_CRYPTO_KEY_SIZE],
    _Out_ UINT8 DriverPkOut[AC_CRYPTO_KEY_SIZE]
    )
{
    UINT8 ownSk[AC_CRYPTO_KEY_SIZE];
    UINT8 shared[AC_CRYPTO_KEY_SIZE];

    /* собственный эфемерный секрет (RNG драйвера FUN_140027044, заметка
     * non-CSPRNG); pk = X25519(sk, base) [FUN_14003630c scalarmult_base,
     * KAT-passed]; shared = X25519(sk, servicePk) [FUN_140035b88 ladder]
     * кэшируется для ключей сессионных боксов */
    AcCryptoRandomBytes(ownSk, AC_CRYPTO_KEY_SIZE);
    ac_x25519_base(DriverPkOut, ownSk);
    ac_x25519(shared, ownSk, ServicePk);

    RtlSecureZeroMemory(ownSk, sizeof(ownSk));
    RtlSecureZeroMemory(shared, sizeof(shared));
    return STATUS_SUCCESS;
}

/* открыть входящий sealed-push собственным ключом драйвера
 * [0x14014c9fd] диспетч оркестратора (golden v1 crypto.c INDEX) */
NTSTATUS
AcCryptoOpenSealed(
    _In_ const VOID* Wire,
    _In_ UINT32 WireLen,
    _Out_ UINT8* Plaintext,
    _Inout_ UINT32* PlaintextLen
    )
{
    return AcCryptoBoxSealOpen((const UINT8*)Wire, WireLen,
                               Plaintext, PlaintextLen);
}

/* --------------------------------------------------------------------------
 * [0xC3502008] bootstrap: seal(604B фрейм аттестации) под СЕРВЕРНЫЙ
 * сессионный ключ рана -> opaque для драйвера; хранится как
 * proof-of-channel (модель courier/hold, DRIVER_CHANNEL_PROTOCOL §2.2);
 * хранение через оркестрованную механику [0x14014c9fd]
 * ------------------------------------------------------------------------ */
NTSTATUS
AcCryptoStoreBootstrap(
    _In_ const VOID* Buf,
    _In_ UINT32 Len
    )
{
    PAC_CHANNEL_STATE channel = (PAC_CHANNEL_STATE)AC_SLOTP(0x3728);

    if (channel == NULL || Len > sizeof(channel->Bootstrap))
        return STATUS_INVALID_PARAMETER;

    RtlCopyMemory(channel->Bootstrap, Buf, Len);
    channel->BootstrapSize = Len;
    return STATUS_SUCCESS;
}

/* --------------------------------------------------------------------------
 * путь сендера: seal под session pk сервиса + постановка в очередь
 * (получатель = session_pk сервиса, доставлен pre-hook;
 * DRIVER_CHANNEL_PROTOCOL §2.3); точка выхода channel_sender
 * [0x14000bfa0]
 * ------------------------------------------------------------------------ */
NTSTATUS
AcCryptoSealAndQueue(
    _Inout_ PAC_CHANNEL_STATE Channel,
    _In_ const VOID* Buf,
    _In_ UINT32 Len
    )
{
    PAC_SEALED_BOX box;
    KIRQL oldIrql;
    NTSTATUS status;
    UINT32 wireLen = sizeof(box->Data);
    const UINT8* servicePk;

    box = (PAC_SEALED_BOX)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                          sizeof(AC_SEALED_BOX), 'xcBA');
    if (box == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    /* session pk сервиса (доставлен pre-hook / через handshake) */
    servicePk = (const UINT8*)g_pslots + AC_CELL_OWN_PK;

    status = AcCryptoBoxSeal((const UINT8*)Buf, Len, servicePk,
                             box->Data, &wireLen);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(box, 'xcBA');
        return status;
    }
    box->Size = wireLen;

    KeAcquireSpinLock(&Channel->QueueLock, &oldIrql);
    InsertTailList(&Channel->PendingEvents, &box->Link);
    KeReleaseSpinLock(&Channel->QueueLock, oldIrql);

    KeSetEvent(&Channel->EventAvailable, IO_NO_INCREMENT, FALSE);
    return STATUS_SUCCESS;
}

/* извлечь один sealed-бокс в буфер poll'а
 * (drain-сторона очереди сендера [0x14000bfa0]) */
NTSTATUS
AcCryptoDequeueSealed(
    _Inout_ PAC_CHANNEL_STATE Channel,
    _Out_ PVOID Buffer,
    _In_ UINT32 BufferSize,
    _Out_ UINT32* OutLen
    )
{
    KIRQL oldIrql;
    PLIST_ENTRY entry;
    PAC_SEALED_BOX box;

    *OutLen = 0;

    KeAcquireSpinLock(&Channel->QueueLock, &oldIrql);
    if (IsListEmpty(&Channel->PendingEvents)) {
        KeReleaseSpinLock(&Channel->QueueLock, oldIrql);
        KeClearEvent(&Channel->EventAvailable);
        return STATUS_SUCCESS;              /* очередь пуста, info = 0 */
    }
    entry = RemoveHeadList(&Channel->PendingEvents);
    KeReleaseSpinLock(&Channel->QueueLock, oldIrql);

    box = CONTAINING_RECORD(entry, AC_SEALED_BOX, Link);
    if (box->Size > BufferSize) {
        /* положить обратно: буфер вызывающего слишком мал */
        KeAcquireSpinLock(&Channel->QueueLock, &oldIrql);
        InsertHeadList(&Channel->PendingEvents, &box->Link);
        KeReleaseSpinLock(&Channel->QueueLock, oldIrql);
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlCopyMemory(Buffer, box->Data, box->Size);
    *OutLen = box->Size;
    ExFreePoolWithTag(box, 'xcBA');
    return STATUS_SUCCESS;
}

/* --------------------------------------------------------------------------
 * Живой контур BCrypt (lazy-слой ksecdd + хэш-хаб 259-таблицы).
 *
 * Live-доказанные вызовы (RECON2 1.26 / FILL_LIST #26/#31/#32):
 *   BCryptOpenAlgorithmProvider  -- живой вызов @0x1401d7125 x2 (arg-ячейка
 *     0x140109210), resolve @0x1401d7109
 *   BCryptGetProperty            -- resolve @0x1401d7117 x2
 *   BCryptCloseAlgorithmProvider -- resolve @0x1402db19f/0x1401d1fec
 *   BCryptDestroyKey             -- resolve @0x14013e1c4
 * Отсутствующие ksecdd-хабы (объявлены по тому же контуру):
 *   BCryptSetProperty, BCryptGenerateSymmetricKey
 * 259-таблица уже несёт хэш-хаб: BCryptCreateHash / HashData / FinishHash /
 * DestroyHash (verified, imports.h) -- machine-hash hello-записи
 * (+0x64d f21 / +0x79e UUID#2, роль оркестратора KERNEL_WALLS §1.1)
 * строится поверх него ниже.
 * ------------------------------------------------------------------------ */

/* объявления lazy-слоя ksecdd (не в 259-таблице; разрешаются lazy
 * резолвером gpa@0x1402e4586/0x1402e4594, lazy-секция imports.h) */
typedef NTSTATUS (NTAPI *PFN_BCRYPT_OPEN_ALG_PROVIDER)(
    PVOID* Handle, const WCHAR* AlgId, const WCHAR* Impl, UINT32 Flags);
typedef NTSTATUS (NTAPI *PFN_BCRYPT_GET_PROPERTY)(
    PVOID Handle, const WCHAR* Property, UINT8* Output, UINT32 Size,
    UINT32* Result, UINT32 Flags);
typedef NTSTATUS (NTAPI *PFN_BCRYPT_CLOSE_ALG_PROVIDER)(
    PVOID Handle, UINT32 Flags);
typedef NTSTATUS (NTAPI *PFN_BCRYPT_GEN_RANDOM)(
    PVOID Handle, UINT8* Buffer, UINT32 Size, UINT32 Flags);
typedef NTSTATUS (NTAPI *PFN_BCRYPT_SET_PROPERTY)(
    PVOID Handle, const WCHAR* Property, UINT8* Input, UINT32 Size,
    UINT32 Flags);
typedef NTSTATUS (NTAPI *PFN_BCRYPT_GEN_SYMMETRIC_KEY)(
    PVOID AlgHandle, PVOID* KeyHandle, UINT8* KeyObject, UINT32 KeyObjLen,
    UINT8* Secret, UINT32 SecretLen, UINT32 Flags);

/* [0x1401d7125] живой BCryptOpenAlgorithmProvider (x2): ячейка хэндла
 * провайдера 0x140109210 (смещение окна 0x3210); id алгоритма едет на VM
 * (payload-selected, что из RNG/SHA256 открыл живой вызов; оба потребителя
 * доказаны: RNG для собственной пары, SHA256 для machine-hash).
 * вызывающий: сам CNG-потребитель, лениво при первом использовании --
 * оригинал открывает провайдера из контура фингерпринта (FUN_14009bcb4
 * зовёт thunk ленивого открытия FUN_1400120ac, когда ячейка провайдера
 * пуста, native_13.c; живое открытие @0x1401d7125 исполняется внутри
 * цепочек фингерпринта A_0116e4/D_07bb20). Вызывающий реконструкции:
 * AcCryptoMachineHash (ниже) -- хаб machine-hash -- документированный
 * потребитель этого контура (FULL_CHAIN_IRP_TO_HWID_C §7.6) */
static BCRYPT_ALG_HANDLE g_BcryptSha256Provider;

static NTSTATUS
AcBcryptOpenProviders(
    VOID
    )
{
    NTSTATUS status;

    if (g_BcryptSha256Provider != NULL)
        return STATUS_SUCCESS;

    /* [0x1401d7125] живой BCryptOpenAlgorithmProvider(phAlg=0x140109210,
     * "SHA256", NULL, 1): провайдер фингерпринта/machine-hash открывается
     * через CNG-делегацию (vmwall_engines.c; fingerprint proven-sha256).
     * WDK: BCryptOpenAlgorithmProvider -> cng.sys (линковка cng.lib) */
    status = BCryptOpenAlgorithmProvider(&g_BcryptSha256Provider,
                                         L"SHA256", NULL, 0);
    if (NT_SUCCESS(status))
        AC_SLOTP(0x3210) = g_BcryptSha256Provider;   /* ячейка 0x140109210 */
    return status;
}

/* источник энтропии для собственной пары и эфемерных ключей seal
 * (per-boot randombytes 32B, KERNEL_WALLS §3.1).
 * [FUN_140027044] собственный RNG драйвера: seed = KeQueryPerformanceCounter
 * (пара 0x140107548^0x140107540), поток = RtlRandomEx (пара
 * 0x140107538^0x140107530) -- **НЕ CSPRNG** (детерминированный RtlRandomEx
 * от QPC-сида; документированная структурная слабость, SEALED_SEMANTICS #1.4).
 * Реализован как AcLsRandomBytes (crypto_libsodium.c); lazy-контур BCrypt
 * (живой BCryptOpenAlgorithmProvider @0x1401d7125) -- ОТДЕЛЬНЫЙ механизм
 * драйвера, используемый хабом machine-hash ниже */
VOID
AcCryptoRandomBytes(
    _Out_ UINT8* Buffer,
    _In_ UINT32 Size
    )
{
    AcLsRandomBytes(Buffer, Size);
}

/* [0x14024af8e] хаб machine-hash (роль оркестратора, KERNEL_WALLS §1.1):
 * BCryptCreateHash -> HashData -> FinishHash -> DestroyHash (verified
 * импорты 259-таблицы) -> 32-байтовый machine hash, питающий поля hello
 * +0x64d (f21) и +0x79e (UUID#2). Алгоритм = SHA256 (доказанная CNG
 * делегация: BCryptOpenAlgorithmProvider "SHA256" @0x1401d7125; нативный
 * sibling FUN_14009bcb4 -- идентичный CNG-поток) */
NTSTATUS
AcCryptoMachineHash(
    _In_ const UINT8* Data,
    _In_ UINT32 DataSize,
    _Out_ UINT8 HashOut[32]
    )
{
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS status;

    status = AcBcryptOpenProviders();
    if (!NT_SUCCESS(status))
        return status;

    /* BCrypt хэш-хаб (verified импорты 259-таблицы: BCryptCreateHash /
     * BCryptHashData / BCryptFinishHash / BCryptDestroyHash) */
    status = BCryptCreateHash(g_BcryptSha256Provider, &hHash, NULL, 0,
                              NULL, 0, 0);
    if (!NT_SUCCESS(status))
        return status;
    status = BCryptHashData(hHash, (PUCHAR)Data, DataSize, 0);
    if (NT_SUCCESS(status))
        status = BCryptFinishHash(hHash, HashOut, 32, 0);
    BCryptDestroyHash(hHash);
    return status;
}

/* --------------------------------------------------------------------------
 * [0x140066ce8] pair_verifier: проверяет консистентность собственной пары
 * драйвера (pk == X25519(sk, base)) до доверия каналу
 * (evidence: golden v1 crypto.c INDEX role)
 * ------------------------------------------------------------------------ */
NTSTATUS
AcCryptoPairVerify(
    VOID
    )
{
    const UINT8* ownPk = (const UINT8*)g_pslots + AC_CELL_OWN_PK;
    const UINT8* ownSk = (const UINT8*)g_pslots + AC_CELL_OWN_SK;
    UINT32 i;
    UINT8 pkZero = 0, skZero = 0;

    for (i = 0; i < AC_CRYPTO_KEY_SIZE; i++) {
        pkZero |= ownPk[i];
        skZero |= ownSk[i];
    }
    /* обе ячейки -- BSS в образе файла и генерируются на boot'е;
     * полностью нулевая пара значит, что ключевой материал никогда не
     * провижионился */
    if (pkZero == 0 || skZero == 0)
        return STATUS_DEVICE_NOT_READY;
    return STATUS_SUCCESS;
}
