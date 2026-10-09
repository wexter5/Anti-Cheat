/* ==========================================================================
 * env_checks.h -- гейты окружения: детект HV, HVCI/code-integrity,
 *                 boot-окружение, семейство QSI-зондов, CPU-фичи
 * ========================================================================== */
#ifndef FACEIT_AC_ENV_CHECKS_H
#define FACEIT_AC_ENV_CHECKS_H

#include <ntddk.h>

/* [0x1403d0389]/[0x140006a90] цепочка boot-гейтов P0 (KERNEL_WALLS_FINAL §1.1) */
NTSTATUS EnvRunBootGates(VOID);

/* [0x1401c29f4] hv_gate_cpuid1_site: cpuid(1) bit31 -> cpuid 0x40000000 */
BOOLEAN EnvCheckHypervisor(VOID);

/* [0x140133ee1] ac_qsi_code_integrity_s01: QSI 0x67 HVCI/CI options */
NTSTATUS EnvCheckCodeIntegrity(_Out_ UINT32* Options);

/* [0x14018fa92] ac_qsi_c5a_s01: QSI 0x5A SystemBootEnvironmentInformation */
NTSTATUS EnvCheckBootEnvironment(_Out_writes_bytes_(64) UINT8* Info);

/* [replay 0x14030789b] QSI 0x5B SystemHypervisorInformation */
NTSTATUS EnvCheckHypervisorClass(_Out_writes_bytes_(16) UINT8* Info);

/* [0x14003d8c8] cpu_feature_detect: cpuid 0/1/7 + xgetbv флаги фич
 * (дословно восстановленное тело, golden v1 hwid.c) */
#pragma pack(push, 1)
typedef struct _AC_CPU_FEATURES {
    UINT32 Present;      /* 0x140108d00 = 1, когда детект завершён */
    UINT32 Sse3;         /* +0x04 */
    UINT32 Sse2;         /* +0x08 */
    UINT32 Ssse3;        /* +0x0C */
    UINT32 Sse41;        /* +0x10 */
    UINT32 Avx;          /* +0x14 */
    UINT32 Avx2;         /* +0x18 */
    UINT32 Pclmulqdq;    /* +0x1C */
    UINT32 AesNi;        /* +0x20 */
} AC_CPU_FEATURES, *PAC_CPU_FEATURES;
#pragma pack(pop)
UINT32 EnvDetectCpuFeatures(_Out_ PAC_CPU_FEATURES Features);

/* [семейство ac_qsi_*] обёртка сырого зонда */
NTSTATUS EnvQsiProbe(_In_ UINT32 InfoClass, _Out_ PVOID Buffer,
                     _In_ UINT32 BufferSize);

/* [семейство ac_qsi_*] прогнать replay-обоснованный набор зондов */
NTSTATUS EnvRunProbes(VOID);

/* [0x140006a90] шаг скана списка модулей P0 (QSI 0x0B + lowercase имена) */
NTSTATUS EnvScanModuleList(VOID);

/* [ac_env_irql_check_s01..s09] гейты expected-IRQL */
BOOLEAN EnvCheckIrql(_In_ KIRQL Expected);

/* [0x140053a90] build_gate_offsets (выбор семейства 19041) */
NTSTATUS EnvBuildGateOffsets(VOID);

/* [0x140018324]/[0x140018af0] тайминг-детектор VM-exit по CPUID/FPU */
VOID EnvVmExitTimingDetect(_In_ UINT32 Role, _In_ UINT32 LoadVariant);

/* [0x1402b99ca] скан блэклиста имён модулей lowercase/FNV */
UINT32 EnvScanModuleBlacklist(VOID);

/* [kd-кластер, IMPORTS_REPORT §4 + KEVLAR_RUN §3] многослойный детект kd */
BOOLEAN EnvCheckKdCluster(VOID);

/* [reader drv+0x129c7e7] KUSD+0x26C NtMajorVersion */
UINT32 EnvKusdNtMajorVersion(VOID);

/* [0x140108430] снапшот топологии KeQueryActiveProcessorCount ->
 * окно feature-ячеек, смещение 0xfc4 (распределение воркеров + тайминговые
 * нормы; сайт resolve импорта #257 @0x14024bde5 в init-оркестраторе,
 * AC_API_PAIRS) */
UINT32 EnvSnapshotTopology(VOID);

#endif /* FACEIT_AC_ENV_CHECKS_H */
