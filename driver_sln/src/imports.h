/* ==========================================================================
 * imports.h -- таблица разрешённых импортов FACEIT_AC.sys (PAIR/XOR-ячейки в .data)
 * --------------------------------------------------------------------------
 * [provenance] 260 verified API-пар, восстановлены под эмуляцией KEVLAR:
 *   источник: _research_tmp/imports/pair_resolutions.tsv + IMPORTS_REPORT.md
 *   метод: FNV-1a-64 по EAT-именам ntoskrnl.exe/hal.dll/cng.sys/fltmgr.sys,
 *          хук на fnv_eat_resolver (0x140026f68) + воч записей .data-окна.
 * Каждая ячейка держит XOR-пару: qword[cell] ^ qword[cell+8] == адрес API
 * (разрешается в рантайме api_resolve_orchestrator 0x14024af8e, 259 resolve'ов).
 * ========================================================================== */
#ifndef FACEIT_AC_IMPORTS_H
#define FACEIT_AC_IMPORTS_H

/* Механика резолвера (нативная):
 *   [0x140026f68] fnv_eat_resolver  -- in-image обходчик экспортов (матч FNV-1a-64)
 *   [0x1400024f4] fnv1a_tail_hasher -- хелпер-хэшер имён
 *   [0x14024af8e] api_resolve_orchestrator -- резолвит всю таблицу на init'е
 * Ячейки image-base модулей (live, boot-time): ntoskrnl, hal, cng, fltmgr, ci.
 */

typedef struct _AC_IMPORT_CELL {
    ULONG_PTR Pair[2];      /* q0 ^ q1 = разрешённый адрес API */
} AC_IMPORT_CELL, *PAC_IMPORT_CELL;


/* [0x1401080a0] cng.sys!BCryptCreateHash (fnv 0xd577120aeac34017) [verified] */
extern AC_IMPORT_CELL g_imp_BCryptCreateHash;
/* [0x140108210] cng.sys!BCryptDecrypt (fnv 0xe813f52a0c1eb360) [verified] */
extern AC_IMPORT_CELL g_imp_BCryptDecrypt;
/* [0x140107d60] cng.sys!BCryptDestroyHash (fnv 0x1256b5291ddc435f) [verified] */
extern AC_IMPORT_CELL g_imp_BCryptDestroyHash;
/* [0x140107520] cng.sys!BCryptEncrypt (fnv 0x7cfbe1a0e01ab5e4) [verified] */
extern AC_IMPORT_CELL g_imp_BCryptEncrypt;
/* [0x140108290] cng.sys!BCryptFinishHash (fnv 0xbd0e01391378b228) [verified] */
extern AC_IMPORT_CELL g_imp_BCryptFinishHash;
/* [0x1401080b0] cng.sys!BCryptHashData (fnv 0x96d6540c2cfbfbf7) [verified] */
extern AC_IMPORT_CELL g_imp_BCryptHashData;
/* [0x140108200] fltmgr.sys!FltAcquirePushLockExclusive (fnv 0xfd3a7de675977164) [verified] */
extern AC_IMPORT_CELL g_imp_FltAcquirePushLockExclusive;
/* [0x1401079e0] fltmgr.sys!FltAcquirePushLockShared (fnv 0x3029f114c2320309) [verified] */
extern AC_IMPORT_CELL g_imp_FltAcquirePushLockShared;
/* [0x1401083c0] fltmgr.sys!FltAllocatePoolAlignedWithTag (fnv 0xbf9557d7ebc22ca8) [verified] */
extern AC_IMPORT_CELL g_imp_FltAllocatePoolAlignedWithTag;
/* [0x140108100] fltmgr.sys!FltCancelFileOpen (fnv 0x03be7ab1a93882fd) [verified] */
extern AC_IMPORT_CELL g_imp_FltCancelFileOpen;
/* [0x140107e90] fltmgr.sys!FltFreePoolAlignedWithTag (fnv 0xe62457e974ff18cd) [verified] */
extern AC_IMPORT_CELL g_imp_FltFreePoolAlignedWithTag;
/* [0x140107de0] fltmgr.sys!FltGetDeviceObject (fnv 0xac6d3216751b25f6) [verified] */
extern AC_IMPORT_CELL g_imp_FltGetDeviceObject;
/* [0x140108170] fltmgr.sys!FltGetDiskDeviceObject (fnv 0x722923e00e82830b) [verified] */
extern AC_IMPORT_CELL g_imp_FltGetDiskDeviceObject;
/* [0x140107e70] fltmgr.sys!FltGetFileNameInformation (fnv 0x17599083d84a9450) [verified] */
extern AC_IMPORT_CELL g_imp_FltGetFileNameInformation;
/* [0x140108320] fltmgr.sys!FltGetFileNameInformationUnsafe (fnv 0xc844cbe7a78a26ee) [verified] */
extern AC_IMPORT_CELL g_imp_FltGetFileNameInformationUnsafe;
/* [0x1401082e0] fltmgr.sys!FltGetFileSystemType (fnv 0xbaa0b28423193d6c) [verified] */
extern AC_IMPORT_CELL g_imp_FltGetFileSystemType;
/* [0x1401084d0] fltmgr.sys!FltGetRequestorProcess (fnv 0xf4ef6492a300c2de) [verified] */
extern AC_IMPORT_CELL g_imp_FltGetRequestorProcess;
/* [0x140108260] fltmgr.sys!FltGetRequestorProcessIdEx (fnv 0x2796ae03a9b863fe) [verified] */
extern AC_IMPORT_CELL g_imp_FltGetRequestorProcessIdEx;
/* [0x140108570] fltmgr.sys!FltParseFileNameInformation (fnv 0x88b4c6380b126ced) [verified] */
extern AC_IMPORT_CELL g_imp_FltParseFileNameInformation;
/* [0x1401080c0] fltmgr.sys!FltQueryInformationFile (fnv 0x9c7f68cafb8ce4a5) [verified] */
extern AC_IMPORT_CELL g_imp_FltQueryInformationFile;
/* [0x140108410] fltmgr.sys!FltReadFile (fnv 0x6061886accbac087) [verified] */
extern AC_IMPORT_CELL g_imp_FltReadFile;
/* [0x140108350] fltmgr.sys!FltReleaseFileNameInformation (fnv 0x7c172def7e916113) [verified] */
extern AC_IMPORT_CELL g_imp_FltReleaseFileNameInformation;
/* [0x1401078b0] fltmgr.sys!FltReleasePushLock (fnv 0xaccfee3c0bd1332d) [verified] */
extern AC_IMPORT_CELL g_imp_FltReleasePushLock;
/* [0x140107dc0] fltmgr.sys!FltSendMessage (fnv 0xcd591267e08fb1da) [verified] */
extern AC_IMPORT_CELL g_imp_FltSendMessage;
/* [0x1401081d0] ntoskrnl.exe!CmRegisterCallbackEx (fnv 0x30d59e31bd19865e) [verified] */
extern AC_IMPORT_CELL g_imp_CmRegisterCallbackEx;
/* [0x140107d70] ntoskrnl.exe!CmUnRegisterCallback (fnv 0x7860a3cf7e37e954) [verified] */
extern AC_IMPORT_CELL g_imp_CmUnRegisterCallback;
/* [0x1401077f0] ntoskrnl.exe!ExAcquireFastMutex (fnv 0xfc5fdcf27d38f809) [verified] */
extern AC_IMPORT_CELL g_imp_ExAcquireFastMutex;
/* [0x1401083e0] ntoskrnl.exe!ExAcquirePushLockSharedEx (fnv 0x0f2a4b376c5c3353) [verified] */
extern AC_IMPORT_CELL g_imp_ExAcquirePushLockSharedEx;
/* [0x140107490] ntoskrnl.exe!ExAcquireResourceSharedLite (fnv 0x798d2183d1ae2cd1) [verified] */
extern AC_IMPORT_CELL g_imp_ExAcquireResourceSharedLite;
/* [0x140107cf0] ntoskrnl.exe!ExAcquireSpinLockExclusive (fnv 0xbb7ece449f848291) [verified] */
extern AC_IMPORT_CELL g_imp_ExAcquireSpinLockExclusive;
/* [0x140107d50] ntoskrnl.exe!ExAcquireSpinLockShared (fnv 0x81242e9e789b3eba) [verified] */
extern AC_IMPORT_CELL g_imp_ExAcquireSpinLockShared;
/* [0x140107500] ntoskrnl.exe!ExAllocatePool (fnv 0x48b8617d81fdd475) [verified] */
extern AC_IMPORT_CELL g_imp_ExAllocatePool;
/* [0x140107ec0] ntoskrnl.exe!ExAllocatePoolWithQuota (fnv 0xafd7001b25356fef) [verified] */
extern AC_IMPORT_CELL g_imp_ExAllocatePoolWithQuota;
/* [0x140107f10] ntoskrnl.exe!ExCreateCallback (fnv 0x98a7ce2c51ece267) [verified] */
extern AC_IMPORT_CELL g_imp_ExCreateCallback;
/* [0x140107910] ntoskrnl.exe!ExEnumHandleTable (fnv 0x264fa8f10cc6ab55) [verified] */
extern AC_IMPORT_CELL g_imp_ExEnumHandleTable;
/* [0x1401074a0] ntoskrnl.exe!ExFreePoolWithTag (fnv 0x7f6272c86a6eeadc) [verified] */
extern AC_IMPORT_CELL g_imp_ExFreePoolWithTag;
/* [0x140108270] ntoskrnl.exe!ExQueueWorkItem (fnv 0xbad0f9df33535629) [verified] */
extern AC_IMPORT_CELL g_imp_ExQueueWorkItem;
/* [0x140107f40] ntoskrnl.exe!ExRaiseHardError (fnv 0x9a66e66271e6f721) [verified] */
extern AC_IMPORT_CELL g_imp_ExRaiseHardError;
/* [0x140107780] ntoskrnl.exe!ExReleaseFastMutex (fnv 0x5330a71dbac02a1a) [verified] */
extern AC_IMPORT_CELL g_imp_ExReleaseFastMutex;
/* [0x140107e30] ntoskrnl.exe!ExReleasePushLockSharedEx (fnv 0xd06cd3a26219edc2) [verified] */
extern AC_IMPORT_CELL g_imp_ExReleasePushLockSharedEx;
/* [0x1401074b0] ntoskrnl.exe!ExReleaseResourceLite (fnv 0x9e78865a4516df59) [verified] */
extern AC_IMPORT_CELL g_imp_ExReleaseResourceLite;
/* [0x140107d40] ntoskrnl.exe!ExReleaseSpinLockExclusive (fnv 0x975dc95c8b875096) [verified] */
extern AC_IMPORT_CELL g_imp_ExReleaseSpinLockExclusive;
/* [0x140107d10] ntoskrnl.exe!ExReleaseSpinLockShared (fnv 0xebb2bd3517649d1b) [verified] */
extern AC_IMPORT_CELL g_imp_ExReleaseSpinLockShared;
/* [0x140107950] ntoskrnl.exe!ExfUnblockPushLock (fnv 0x618d01aa26b5b7b1) [verified] */
extern AC_IMPORT_CELL g_imp_ExfUnblockPushLock;
/* [0x1401080f0] ntoskrnl.exe!FsRtlCreateSectionForDataScan (fnv 0xd36c6d99120efe57) [verified] */
extern AC_IMPORT_CELL g_imp_FsRtlCreateSectionForDataScan;
/* [0x1401084e0] ntoskrnl.exe!FsRtlMupGetProviderInfoFromFileObject (fnv 0xc672c57813cca8de) [verified] */
extern AC_IMPORT_CELL g_imp_FsRtlMupGetProviderInfoFromFileObject;
/* [0x140108020] ntoskrnl.exe!FsRtlQueryInformationFile (fnv 0xb48b044a6fc8f738) [verified] */
extern AC_IMPORT_CELL g_imp_FsRtlQueryInformationFile;
/* [0x140108460] ntoskrnl.exe!IoAcquireRemoveLockEx (fnv 0x49fe64a336230841) [verified] */
extern AC_IMPORT_CELL g_imp_IoAcquireRemoveLockEx;
/* [0x140108080] ntoskrnl.exe!IoAllocateIrp (fnv 0xe938015833ffd9b7) [verified] */
extern AC_IMPORT_CELL g_imp_IoAllocateIrp;
/* [0x140107630] ntoskrnl.exe!IoAllocateMdl (fnv 0xc51c45581f224a39) [verified] */
extern AC_IMPORT_CELL g_imp_IoAllocateMdl;
/* [0x140107590] ntoskrnl.exe!IoAllocateWorkItem (fnv 0xe2e81be712f5dcac) [verified] */
extern AC_IMPORT_CELL g_imp_IoAllocateWorkItem;
/* [0x1401074c0] ntoskrnl.exe!IoBuildDeviceIoControlRequest (fnv 0x1d9b1572a04955d7) [verified] */
extern AC_IMPORT_CELL g_imp_IoBuildDeviceIoControlRequest;
/* [0x1401080e0] ntoskrnl.exe!IoBuildSynchronousFsdRequest (fnv 0x06962e349f375b36) [verified] */
extern AC_IMPORT_CELL g_imp_IoBuildSynchronousFsdRequest;
/* [0x140107810] ntoskrnl.exe!IoCreateDevice (fnv 0x1af62553deb3554f) [verified] */
extern AC_IMPORT_CELL g_imp_IoCreateDevice;
/* [0x1401075d0] ntoskrnl.exe!IoCreateFileEx (fnv 0x169d525ab4ac35da) [verified] */
extern AC_IMPORT_CELL g_imp_IoCreateFileEx;
/* [0x140108540] ntoskrnl.exe!IoCreateFileSpecifyDeviceObjectHint (fnv 0x09bf5d45659d609a) [verified] */
extern AC_IMPORT_CELL g_imp_IoCreateFileSpecifyDeviceObjectHint;
/* [0x140107760] ntoskrnl.exe!IoCreateSymbolicLink (fnv 0x205a8a33d7e0af99) [verified] */
extern AC_IMPORT_CELL g_imp_IoCreateSymbolicLink;
/* [0x140107860] ntoskrnl.exe!IoDeleteDevice (fnv 0x3b4b4822507dc0b8) [verified] */
extern AC_IMPORT_CELL g_imp_IoDeleteDevice;
/* [0x140107880] ntoskrnl.exe!IoDeleteSymbolicLink (fnv 0x1cdc4067f70bd79a) [verified] */
extern AC_IMPORT_CELL g_imp_IoDeleteSymbolicLink;
/* [0x1401078d0] ntoskrnl.exe!IoDeviceObjectType (fnv 0x37c80fdec17ef8f4) [verified] */
extern AC_IMPORT_CELL g_imp_IoDeviceObjectType;
/* [0x1401078a0] ntoskrnl.exe!IoDriverObjectType (fnv 0x7e429ba8d4712670) [verified] */
extern AC_IMPORT_CELL g_imp_IoDriverObjectType;
/* [0x1401081c0] ntoskrnl.exe!IoEnumerateDeviceObjectList (fnv 0x2e38ec048010bf14) [verified] */
extern AC_IMPORT_CELL g_imp_IoEnumerateDeviceObjectList;
/* [0x1401079f0] ntoskrnl.exe!IoFileObjectType (fnv 0x91e55ad26f4962bc) [verified] */
extern AC_IMPORT_CELL g_imp_IoFileObjectType;
/* [0x140107ef0] ntoskrnl.exe!IoFreeIrp (fnv 0xb2290d1b7f5907e0) [verified] */
extern AC_IMPORT_CELL g_imp_IoFreeIrp;
/* [0x140107610] ntoskrnl.exe!IoFreeMdl (fnv 0x8e6c891b6acc6c0e) [verified] */
extern AC_IMPORT_CELL g_imp_IoFreeMdl;
/* [0x140107510] ntoskrnl.exe!IoFreeWorkItem (fnv 0x59aa52b13ec91be1) [verified] */
extern AC_IMPORT_CELL g_imp_IoFreeWorkItem;
/* [0x140107660] ntoskrnl.exe!IoGetCurrentProcess (fnv 0xe921efa903d5d6a1) [verified] */
extern AC_IMPORT_CELL g_imp_IoGetCurrentProcess;
/* [0x140107920] ntoskrnl.exe!IoGetDeviceAttachmentBaseRef (fnv 0x019ce7ee7a0905ce) [verified] */
extern AC_IMPORT_CELL g_imp_IoGetDeviceAttachmentBaseRef;
/* [0x140107e20] ntoskrnl.exe!IoGetDeviceInterfaces (fnv 0x8c5fd7dd7ead5a15) [verified] */
extern AC_IMPORT_CELL g_imp_IoGetDeviceInterfaces;
/* [0x140107440] ntoskrnl.exe!IoGetDeviceObjectPointer (fnv 0x8d49244199afb66f) [verified] */
extern AC_IMPORT_CELL g_imp_IoGetDeviceObjectPointer;
/* [0x1401079c0] ntoskrnl.exe!IoGetDeviceProperty (fnv 0x427525a7e20cd804) [verified] */
extern AC_IMPORT_CELL g_imp_IoGetDeviceProperty;
/* [0x140108560] ntoskrnl.exe!IoGetDevicePropertyData (fnv 0x727d6f662630d06c) [verified] */
extern AC_IMPORT_CELL g_imp_IoGetDevicePropertyData;
/* [0x140107710] ntoskrnl.exe!IoGetRequestorProcess (fnv 0xec46abe6b6296d0e) [verified] */
extern AC_IMPORT_CELL g_imp_IoGetRequestorProcess;
/* [0x140107870] ntoskrnl.exe!IoGetRequestorProcessId (fnv 0xa2ebedccc316a4f3) [verified] */
extern AC_IMPORT_CELL g_imp_IoGetRequestorProcessId;
/* [0x140108010] ntoskrnl.exe!IoGetTopLevelIrp (fnv 0x54c2f633228f7089) [verified] */
extern AC_IMPORT_CELL g_imp_IoGetTopLevelIrp;
/* [0x1401084f0] ntoskrnl.exe!IoInitializeRemoveLockEx (fnv 0x3c1e342aab6a4401) [verified] */
extern AC_IMPORT_CELL g_imp_IoInitializeRemoveLockEx;
/* [0x140108090] ntoskrnl.exe!IoInvalidateDeviceState (fnv 0x5a3e0c9c61a0a1fb) [verified] */
extern AC_IMPORT_CELL g_imp_IoInvalidateDeviceState;
/* [0x140107820] ntoskrnl.exe!IoQueryFileDosDeviceName (fnv 0x82555ad1bdb4b59c) [verified] */
extern AC_IMPORT_CELL g_imp_IoQueryFileDosDeviceName;
/* [0x140107550] ntoskrnl.exe!IoQueueWorkItem (fnv 0x903c962008ca3562) [verified] */
extern AC_IMPORT_CELL g_imp_IoQueueWorkItem;
/* [0x140107800] ntoskrnl.exe!IoReleaseCancelSpinLock (fnv 0x5986bd7929cbaadf) [verified] */
extern AC_IMPORT_CELL g_imp_IoReleaseCancelSpinLock;
/* [0x1401081f0] ntoskrnl.exe!IoReleaseRemoveLockAndWaitEx (fnv 0x833164a350dfadd2) [verified] */
extern AC_IMPORT_CELL g_imp_IoReleaseRemoveLockAndWaitEx;
/* [0x1401081b0] ntoskrnl.exe!IoReleaseRemoveLockEx (fnv 0x7558512d6d4de7fc) [verified] */
extern AC_IMPORT_CELL g_imp_IoReleaseRemoveLockEx;
/* [0x1401084c0] ntoskrnl.exe!IoReplaceFileObjectName (fnv 0xdf8baf0885e5d45d) [verified] */
extern AC_IMPORT_CELL g_imp_IoReplaceFileObjectName;
/* [0x140108510] ntoskrnl.exe!IoThreadToProcess (fnv 0x82d7f5078d49df09) [verified] */
extern AC_IMPORT_CELL g_imp_IoThreadToProcess;
/* [0x140107410] ntoskrnl.exe!IofCallDriver (fnv 0xc26886d76545a61b) [verified] */
extern AC_IMPORT_CELL g_imp_IofCallDriver;
/* [0x140107720] ntoskrnl.exe!IofCompleteRequest (fnv 0x8b081062775ef4ff) [verified] */
extern AC_IMPORT_CELL g_imp_IofCompleteRequest;
/* [0x1401084b0] ntoskrnl.exe!KeAcquireInStackQueuedSpinLock (fnv 0x163d288ba175e54a) [verified] */
extern AC_IMPORT_CELL g_imp_KeAcquireInStackQueuedSpinLock;
/* [0x140107970] ntoskrnl.exe!KeAcquireQueuedSpinLock (fnv 0x36222c28b7d22f4d) [verified] */
extern AC_IMPORT_CELL g_imp_KeAcquireQueuedSpinLock;
/* [0x140108190] ntoskrnl.exe!KeAcquireSpinLockAtDpcLevel (fnv 0xd3069ae2074e43fc) [verified] */
extern AC_IMPORT_CELL g_imp_KeAcquireSpinLockAtDpcLevel;
/* [0x140107740] ntoskrnl.exe!KeAcquireSpinLockRaiseToDpc (fnv 0x117e94d87979d022) [verified] */
extern AC_IMPORT_CELL g_imp_KeAcquireSpinLockRaiseToDpc;
/* [0x140107bc0] ntoskrnl.exe!KeCancelTimer (fnv 0x5ce664ef96d5f488) [verified] */
extern AC_IMPORT_CELL g_imp_KeCancelTimer;
/* [0x1401077a0] ntoskrnl.exe!KeDelayExecutionThread (fnv 0x8654aa54092a0912) [verified] */
extern AC_IMPORT_CELL g_imp_KeDelayExecutionThread;
/* [0x1401074d0] ntoskrnl.exe!KeEnterCriticalRegion (fnv 0xb3356ee0dc91fd3c) [verified] */
extern AC_IMPORT_CELL g_imp_KeEnterCriticalRegion;
/* [0x140107ed0] ntoskrnl.exe!KeEnterGuardedRegion (fnv 0x5d8a0d15a2375187) [verified] */
extern AC_IMPORT_CELL g_imp_KeEnterGuardedRegion;
/* [0x140107c60] ntoskrnl.exe!KeGetCurrentProcessorNumberEx (fnv 0x00102d1be2546580) [verified] */
extern AC_IMPORT_CELL g_imp_KeGetCurrentProcessorNumberEx;
/* [0x140108500] ntoskrnl.exe!KeGetProcessorIndexFromNumber (fnv 0xba646ee43124767a) [verified] */
extern AC_IMPORT_CELL g_imp_KeGetProcessorIndexFromNumber;
/* [0x1401076b0] ntoskrnl.exe!KeInitializeApc (fnv 0x03e4cc01287b36c3) [verified] */
extern AC_IMPORT_CELL g_imp_KeInitializeApc;
/* [0x140107460] ntoskrnl.exe!KeInitializeEvent (fnv 0x0d9fe78ea5ee16a1) [verified] */
extern AC_IMPORT_CELL g_imp_KeInitializeEvent;
/* [0x140107ba0] ntoskrnl.exe!KeInitializeTimer (fnv 0xb5df23b5c20a8008) [verified] */
extern AC_IMPORT_CELL g_imp_KeInitializeTimer;
/* [0x140107680] ntoskrnl.exe!KeInsertQueueApc (fnv 0xe27b8a1201b675b7) [verified] */
extern AC_IMPORT_CELL g_imp_KeInsertQueueApc;
/* [0x140108390] ntoskrnl.exe!KeIpiGenericCall (fnv 0x443afb964e759208) [verified] */
extern AC_IMPORT_CELL g_imp_KeIpiGenericCall;
/* [0x1401073c0] ntoskrnl.exe!KeLeaveCriticalRegion (fnv 0x0e0936598737d071) [verified] */
extern AC_IMPORT_CELL g_imp_KeLeaveCriticalRegion;
/* [0x140107f90] ntoskrnl.exe!KeLeaveGuardedRegion (fnv 0xb06aab10a675d938) [verified] */
extern AC_IMPORT_CELL g_imp_KeLeaveGuardedRegion;
/* [0x140107a40] ntoskrnl.exe!KeLowerIrql (fnv 0xf55bee38f686359c) [verified] */
extern AC_IMPORT_CELL g_imp_KeLowerIrql;
/* [0x140108430] ntoskrnl.exe!KeQueryActiveProcessorCount (fnv 0xdb1f7971eb3f2f6e) [verified] */
extern AC_IMPORT_CELL g_imp_KeQueryActiveProcessorCount;
/* [0x140107540] ntoskrnl.exe!KeQueryPerformanceCounter (fnv 0x20ac1421621bacc9) [verified] */
extern AC_IMPORT_CELL g_imp_KeQueryPerformanceCounter;
/* [0x140108040] ntoskrnl.exe!KeQueryPrcbAddress (fnv 0x2a504755a5f17744) [verified] */
extern AC_IMPORT_CELL g_imp_KeQueryPrcbAddress;
/* [0x140107e40] ntoskrnl.exe!KeQueryTimeIncrement (fnv 0x567bb3a84e66e6cb) [verified] */
extern AC_IMPORT_CELL g_imp_KeQueryTimeIncrement;
/* [0x140108300] ntoskrnl.exe!KeQueryUnbiasedInterruptTimePrecise (fnv 0x545962443b907e5f) [verified] */
extern AC_IMPORT_CELL g_imp_KeQueryUnbiasedInterruptTimePrecise;
/* [0x140107e10] ntoskrnl.exe!KeReleaseInStackQueuedSpinLock (fnv 0x8175168e8c1161c5) [verified] */
extern AC_IMPORT_CELL g_imp_KeReleaseInStackQueuedSpinLock;
/* [0x140107980] ntoskrnl.exe!KeReleaseQueuedSpinLock (fnv 0x25be2474a8c7538c) [verified] */
extern AC_IMPORT_CELL g_imp_KeReleaseQueuedSpinLock;
/* [0x140107850] ntoskrnl.exe!KeReleaseSpinLock (fnv 0xa11785ea71211341) [verified] */
extern AC_IMPORT_CELL g_imp_KeReleaseSpinLock;
/* [0x140108470] ntoskrnl.exe!KeReleaseSpinLockFromDpcLevel (fnv 0x05c1b0b86ebd1550) [verified] */
extern AC_IMPORT_CELL g_imp_KeReleaseSpinLockFromDpcLevel;
/* [0x140107b20] ntoskrnl.exe!KeSetBasePriorityThread (fnv 0x60a49aca987c041e) [verified] */
extern AC_IMPORT_CELL g_imp_KeSetBasePriorityThread;
/* [0x140107b60] ntoskrnl.exe!KeSetEvent (fnv 0xe1d9c1f5194db7f9) [verified] */
extern AC_IMPORT_CELL g_imp_KeSetEvent;
/* [0x140107a50] ntoskrnl.exe!KeSetTimer (fnv 0x6f1d6ca44b017fd0) [verified] */
extern AC_IMPORT_CELL g_imp_KeSetTimer;
/* [0x140107430] ntoskrnl.exe!KeStackAttachProcess (fnv 0xb53a8a673a5397bf) [verified] */
extern AC_IMPORT_CELL g_imp_KeStackAttachProcess;
/* [0x140107670] ntoskrnl.exe!KeTestAlertThread (fnv 0x227d001f5e605755) [verified] */
extern AC_IMPORT_CELL g_imp_KeTestAlertThread;
/* [0x140107450] ntoskrnl.exe!KeUnstackDetachProcess (fnv 0x007ab4bee87ada0a) [verified] */
extern AC_IMPORT_CELL g_imp_KeUnstackDetachProcess;
/* [0x140107b00] ntoskrnl.exe!KeWaitForMultipleObjects (fnv 0x6492f84cb1d87e21) [verified] */
extern AC_IMPORT_CELL g_imp_KeWaitForMultipleObjects;
/* [0x140107470] ntoskrnl.exe!KeWaitForSingleObject (fnv 0x11bdfad31435cb3c) [verified] */
extern AC_IMPORT_CELL g_imp_KeWaitForSingleObject;
/* [0x140107ab0] ntoskrnl.exe!KfRaiseIrql (fnv 0x9251aedc7cb1fc62) [verified] */
extern AC_IMPORT_CELL g_imp_KfRaiseIrql;
/* [0x140108150] ntoskrnl.exe!MmAllocateMdlForIoSpace (fnv 0xbea17924f2045b28) [verified] */
extern AC_IMPORT_CELL g_imp_MmAllocateMdlForIoSpace;
/* [0x1401073f0] ntoskrnl.exe!MmCopyMemory (fnv 0x306328ee8e049a39) [verified] */
extern AC_IMPORT_CELL g_imp_MmCopyMemory;
/* [0x1401081e0] ntoskrnl.exe!MmCopyVirtualMemory (fnv 0xbdfca8c431baf4b6) [verified] */
extern AC_IMPORT_CELL g_imp_MmCopyVirtualMemory;
/* [0x1401082d0] ntoskrnl.exe!MmGetPhysicalAddress (fnv 0x0338042ab15f61cc) [verified] */
extern AC_IMPORT_CELL g_imp_MmGetPhysicalAddress;
/* [0x140108530] ntoskrnl.exe!MmGetSystemRoutineAddress (fnv 0x3e7c5650826a15d8) [verified] */
extern AC_IMPORT_CELL g_imp_MmGetSystemRoutineAddress;
/* [0x140108370] ntoskrnl.exe!MmGetVirtualForPhysical (fnv 0x7f2823d9ac4595a2) [verified] */
extern AC_IMPORT_CELL g_imp_MmGetVirtualForPhysical;
/* [0x1401079b0] ntoskrnl.exe!MmIsAddressValid (fnv 0x052478b3fd7abc6d) [verified] */
extern AC_IMPORT_CELL g_imp_MmIsAddressValid;
/* [0x140107e80] ntoskrnl.exe!MmIsDriverVerifyingByAddress (fnv 0x4e4d77f5af66e98b) [verified] */
extern AC_IMPORT_CELL g_imp_MmIsDriverVerifyingByAddress;
/* [0x140107ce0] ntoskrnl.exe!MmMapIoSpace (fnv 0x40ed8ea987b20683) [verified] */
extern AC_IMPORT_CELL g_imp_MmMapIoSpace;
/* [0x140107ca0] ntoskrnl.exe!MmMapIoSpaceEx (fnv 0x2be3b7dda50ff6fe) [verified] */
extern AC_IMPORT_CELL g_imp_MmMapIoSpaceEx;
/* [0x1401075f0] ntoskrnl.exe!MmMapLockedPagesSpecifyCache (fnv 0x96b081538803f1a4) [verified] */
extern AC_IMPORT_CELL g_imp_MmMapLockedPagesSpecifyCache;
/* [0x140107770] ntoskrnl.exe!MmMapViewInSystemSpace (fnv 0x94b55af62b25f602) [verified] */
extern AC_IMPORT_CELL g_imp_MmMapViewInSystemSpace;
/* [0x140107640] ntoskrnl.exe!MmProbeAndLockPages (fnv 0x1549df88d773bfa1) [verified] */
extern AC_IMPORT_CELL g_imp_MmProbeAndLockPages;
/* [0x1401075e0] ntoskrnl.exe!MmProtectMdlSystemAddress (fnv 0xb9b08032afeb3a00) [verified] */
extern AC_IMPORT_CELL g_imp_MmProtectMdlSystemAddress;
/* [0x140107d20] ntoskrnl.exe!MmSectionObjectType (fnv 0x7f7bbc8451d19ea9) [verified] */
extern AC_IMPORT_CELL g_imp_MmSectionObjectType;
/* [0x140107990] ntoskrnl.exe!MmSystemRangeStart (fnv 0x90f0c8b9a6ba9ef9) [verified] */
extern AC_IMPORT_CELL g_imp_MmSystemRangeStart;
/* [0x140107620] ntoskrnl.exe!MmUnlockPages (fnv 0x0d11f30a6b846b0d) [verified] */
extern AC_IMPORT_CELL g_imp_MmUnlockPages;
/* [0x1401083f0] ntoskrnl.exe!MmUnmapIoSpace (fnv 0x47e1ca0e288956c0) [verified] */
extern AC_IMPORT_CELL g_imp_MmUnmapIoSpace;
/* [0x140107600] ntoskrnl.exe!MmUnmapLockedPages (fnv 0x2a9366c7ea2547b0) [verified] */
extern AC_IMPORT_CELL g_imp_MmUnmapLockedPages;
/* [0x1401077d0] ntoskrnl.exe!MmUnmapViewInSystemSpace (fnv 0x4aa77b5ef1d9fea5) [verified] */
extern AC_IMPORT_CELL g_imp_MmUnmapViewInSystemSpace;
/* [0x140107c30] ntoskrnl.exe!MmUserProbeAddress (fnv 0x0a181c2368a387b6) [verified] */
extern AC_IMPORT_CELL g_imp_MmUserProbeAddress;
/* [0x140108230] ntoskrnl.exe!NtClose (fnv 0x6520f847354d9e65) [verified] */
extern AC_IMPORT_CELL g_imp_NtClose;
/* [0x140107ea0] ntoskrnl.exe!NtReadFile (fnv 0x6225d4823bc5fa5d) [verified] */
extern AC_IMPORT_CELL g_imp_NtReadFile;
/* [0x140107a20] ntoskrnl.exe!ObGetObjectType (fnv 0xca24fd8bde5a701f) [verified] */
extern AC_IMPORT_CELL g_imp_ObGetObjectType;
/* [0x140107890] ntoskrnl.exe!ObOpenObjectByPointer (fnv 0x82777f8de8963847) [verified] */
extern AC_IMPORT_CELL g_imp_ObOpenObjectByPointer;
/* [0x140107960] ntoskrnl.exe!ObQueryNameString (fnv 0x07f1057f564cedd6) [verified] */
extern AC_IMPORT_CELL g_imp_ObQueryNameString;
/* [0x140107840] ntoskrnl.exe!ObReferenceObjectByHandle (fnv 0x905061b4022a3e81) [verified] */
extern AC_IMPORT_CELL g_imp_ObReferenceObjectByHandle;
/* [0x1401078c0] ntoskrnl.exe!ObReferenceObjectByName (fnv 0x9f6a56d86bc44fec) [verified] */
extern AC_IMPORT_CELL g_imp_ObReferenceObjectByName;
/* [0x1401078f0] ntoskrnl.exe!ObReferenceObjectByPointer (fnv 0xe067973792d6b4bc) [verified] */
extern AC_IMPORT_CELL g_imp_ObReferenceObjectByPointer;
/* [0x140107400] ntoskrnl.exe!ObfDereferenceObject (fnv 0xb61941b7eb2f33e5) [verified] */
extern AC_IMPORT_CELL g_imp_ObfDereferenceObject;
/* [0x140107900] ntoskrnl.exe!ObfReferenceObject (fnv 0xe787e3c2b994c9d8) [verified] */
extern AC_IMPORT_CELL g_imp_ObfReferenceObject;
/* [0x1401082a0] ntoskrnl.exe!ProbeForRead (fnv 0xcfa5a285d6f4a508) [verified] */
extern AC_IMPORT_CELL g_imp_ProbeForRead;
/* [0x140107480] ntoskrnl.exe!PsAcquireProcessExitSynchronization (fnv 0xd92ad93cfdfe6033) [verified] */
extern AC_IMPORT_CELL g_imp_PsAcquireProcessExitSynchronization;
/* [0x1401077c0] ntoskrnl.exe!PsGetCurrentProcessId (fnv 0x9e67cc2a885fce27) [verified] */
extern AC_IMPORT_CELL g_imp_PsGetCurrentProcessId;
/* [0x140108240] ntoskrnl.exe!PsGetCurrentProcessWow64Process (fnv 0xa9e20a62c791402c) [verified] */
extern AC_IMPORT_CELL g_imp_PsGetCurrentProcessWow64Process;
/* [0x140107dd0] ntoskrnl.exe!PsGetCurrentThreadId (fnv 0xb2a3bea8ad2178f4) [verified] */
extern AC_IMPORT_CELL g_imp_PsGetCurrentThreadId;
/* [0x140107f30] ntoskrnl.exe!PsGetProcessExitProcessCalled (fnv 0x13ce4cc7ccde8187) [verified] */
extern AC_IMPORT_CELL g_imp_PsGetProcessExitProcessCalled;
/* [0x1401078e0] ntoskrnl.exe!PsGetProcessId (fnv 0xe3f7e2e94ad84598) [verified] */
extern AC_IMPORT_CELL g_imp_PsGetProcessId;
/* [0x140107fd0] ntoskrnl.exe!PsGetProcessImageFileName (fnv 0xf9cf74a391b379cf) [verified] */
extern AC_IMPORT_CELL g_imp_PsGetProcessImageFileName;
/* [0x140107fb0] ntoskrnl.exe!PsGetProcessInheritedFromUniqueProcessId (fnv 0x994e9ad86627d012) [verified] */
extern AC_IMPORT_CELL g_imp_PsGetProcessInheritedFromUniqueProcessId;
/* [0x140108480] ntoskrnl.exe!PsGetProcessPeb (fnv 0x0f05656aa822964c) [verified] */
extern AC_IMPORT_CELL g_imp_PsGetProcessPeb;
/* [0x140108140] ntoskrnl.exe!PsGetProcessSessionId (fnv 0x4b3fe7e600fa08f2) [verified] */
extern AC_IMPORT_CELL g_imp_PsGetProcessSessionId;
/* [0x1401076e0] ntoskrnl.exe!PsGetProcessWow64Process (fnv 0xca8dc58b141e3783) [verified] */
extern AC_IMPORT_CELL g_imp_PsGetProcessWow64Process;
/* [0x140107f00] ntoskrnl.exe!PsGetThreadId (fnv 0x4b2866269e48b93d) [verified] */
extern AC_IMPORT_CELL g_imp_PsGetThreadId;
/* [0x140107db0] ntoskrnl.exe!PsGetThreadProcess (fnv 0xdf811085516798fd) [verified] */
extern AC_IMPORT_CELL g_imp_PsGetThreadProcess;
/* [0x140108050] ntoskrnl.exe!PsGetThreadProcessId (fnv 0x6f5013581766d3a8) [verified] */
extern AC_IMPORT_CELL g_imp_PsGetThreadProcessId;
/* [0x140107690] ntoskrnl.exe!PsGetThreadTeb (fnv 0x5cb5ad9f2abd79db) [verified] */
extern AC_IMPORT_CELL g_imp_PsGetThreadTeb;
/* [0x140108520] ntoskrnl.exe!PsGetThreadWin32Thread (fnv 0xaae7f93692400cbf) [verified] */
extern AC_IMPORT_CELL g_imp_PsGetThreadWin32Thread;
/* [0x140107c70] ntoskrnl.exe!PsInitialSystemProcess (fnv 0x1660e4ca85654886) [verified] */
extern AC_IMPORT_CELL g_imp_PsInitialSystemProcess;
/* [0x140108310] ntoskrnl.exe!PsIsProtectedProcessLight (fnv 0x8101ebacce412759) [verified] */
extern AC_IMPORT_CELL g_imp_PsIsProtectedProcessLight;
/* [0x140108490] ntoskrnl.exe!PsIsSystemThread (fnv 0xc86cf9ff05c74381) [verified] */
extern AC_IMPORT_CELL g_imp_PsIsSystemThread;
/* [0x140108360] ntoskrnl.exe!PsIsThreadTerminating (fnv 0x1eb93372b3ca91fc) [verified] */
extern AC_IMPORT_CELL g_imp_PsIsThreadTerminating;
/* [0x1401073d0] ntoskrnl.exe!PsLookupProcessByProcessId (fnv 0x8a9495b5004b3e52) [verified] */
extern AC_IMPORT_CELL g_imp_PsLookupProcessByProcessId;
/* [0x140108030] ntoskrnl.exe!PsLookupThreadByThreadId (fnv 0x2cb28d18fd28ba7a) [verified] */
extern AC_IMPORT_CELL g_imp_PsLookupThreadByThreadId;
/* [0x140107cd0] ntoskrnl.exe!PsProcessType (fnv 0xafd89a203691dee1) [verified] */
extern AC_IMPORT_CELL g_imp_PsProcessType;
/* [0x140107790] ntoskrnl.exe!PsReferenceProcessFilePointer (fnv 0xfa0ab72f457045b1) [verified] */
extern AC_IMPORT_CELL g_imp_PsReferenceProcessFilePointer;
/* [0x1401073e0] ntoskrnl.exe!PsReleaseProcessExitSynchronization (fnv 0xfba735f9f055587a) [verified] */
extern AC_IMPORT_CELL g_imp_PsReleaseProcessExitSynchronization;
/* [0x140108440] ntoskrnl.exe!PsRemoveCreateThreadNotifyRoutine (fnv 0x03546c4519ba6957) [verified] */
extern AC_IMPORT_CELL g_imp_PsRemoveCreateThreadNotifyRoutine;
/* [0x140107cb0] ntoskrnl.exe!PsRemoveLoadImageNotifyRoutine (fnv 0x983d615838941bdc) [verified] */
extern AC_IMPORT_CELL g_imp_PsRemoveLoadImageNotifyRoutine;
/* [0x1401082b0] ntoskrnl.exe!PsResumeProcess (fnv 0x04a58a1647c79a34) [verified] */
extern AC_IMPORT_CELL g_imp_PsResumeProcess;
/* [0x140107df0] ntoskrnl.exe!PsSetCreateProcessNotifyRoutineEx (fnv 0x394102d5c46f1729) [verified] */
extern AC_IMPORT_CELL g_imp_PsSetCreateProcessNotifyRoutineEx;
/* [0x140108250] ntoskrnl.exe!PsSetCreateThreadNotifyRoutine (fnv 0x301ca5a691b968bf) [verified] */
extern AC_IMPORT_CELL g_imp_PsSetCreateThreadNotifyRoutine;
/* [0x140107d30] ntoskrnl.exe!PsSetLoadImageNotifyRoutine (fnv 0x1266348dbb3cd2c4) [verified] */
extern AC_IMPORT_CELL g_imp_PsSetLoadImageNotifyRoutine;
/* [0x140108330] ntoskrnl.exe!PsSuspendProcess (fnv 0x2b5dc13a56cd29b5) [verified] */
extern AC_IMPORT_CELL g_imp_PsSuspendProcess;
/* [0x140107ae0] ntoskrnl.exe!PsTerminateSystemThread (fnv 0x51cc0ffd2d35b286) [verified] */
extern AC_IMPORT_CELL g_imp_PsTerminateSystemThread;
/* [0x140107be0] ntoskrnl.exe!PsThreadType (fnv 0xe61eebba9eaa6ee4) [verified] */
extern AC_IMPORT_CELL g_imp_PsThreadType;
/* [0x140108220] ntoskrnl.exe!PsWrapApcWow64Thread (fnv 0x9ee612b4f5db20eb) [verified] */
extern AC_IMPORT_CELL g_imp_PsWrapApcWow64Thread;
/* [0x1401084a0] ntoskrnl.exe!RtlAnsiStringToUnicodeString (fnv 0x680c18a1a4f87984) [verified] */
extern AC_IMPORT_CELL g_imp_RtlAnsiStringToUnicodeString;
/* [0x140107f80] ntoskrnl.exe!RtlAppendUnicodeToString (fnv 0xa21fc1ee2d42b680) [verified] */
extern AC_IMPORT_CELL g_imp_RtlAppendUnicodeToString;
/* [0x140107d80] ntoskrnl.exe!RtlCaptureStackBackTrace (fnv 0xc8ad3966bd94e29d) [verified] */
extern AC_IMPORT_CELL g_imp_RtlCaptureStackBackTrace;
/* [0x140107f20] ntoskrnl.exe!RtlCompareMemory (fnv 0x713c67b5308446af) [verified] */
extern AC_IMPORT_CELL g_imp_RtlCompareMemory;
/* [0x140107f50] ntoskrnl.exe!RtlCompareUnicodeString (fnv 0x9a5b652f5744af6a) [verified] */
extern AC_IMPORT_CELL g_imp_RtlCompareUnicodeString;
/* [0x140107c50] ntoskrnl.exe!RtlCompareUnicodeStrings (fnv 0x8dfc087149b5877b) [verified] */
extern AC_IMPORT_CELL g_imp_RtlCompareUnicodeStrings;
/* [0x140108450] ntoskrnl.exe!RtlCreateUnicodeString (fnv 0x799238f9e50f33e9) [verified] */
extern AC_IMPORT_CELL g_imp_RtlCreateUnicodeString;
/* [0x1401073b0] ntoskrnl.exe!RtlDowncaseUnicodeString (fnv 0x54c1494e6041fff5) [verified] */
extern AC_IMPORT_CELL g_imp_RtlDowncaseUnicodeString;
/* [0x140107a00] ntoskrnl.exe!RtlEqualUnicodeString (fnv 0xc8adf83e6ff463f3) [verified] */
extern AC_IMPORT_CELL g_imp_RtlEqualUnicodeString;
/* [0x140107700] ntoskrnl.exe!RtlGetVersion (fnv 0x2f0fceed6fc55d71) [verified] */
extern AC_IMPORT_CELL g_imp_RtlGetVersion;
/* [0x1401076f0] ntoskrnl.exe!RtlImageDirectoryEntryToData (fnv 0x0b8083a25a2ce50a) [verified] */
extern AC_IMPORT_CELL g_imp_RtlImageDirectoryEntryToData;
/* [0x140108380] ntoskrnl.exe!RtlLookupFunctionEntry (fnv 0xfd2c04450ff7918d) [verified] */
extern AC_IMPORT_CELL g_imp_RtlLookupFunctionEntry;
/* [0x1401079d0] ntoskrnl.exe!RtlPrefixUnicodeString (fnv 0x1601a27858df0d9d) [verified] */
extern AC_IMPORT_CELL g_imp_RtlPrefixUnicodeString;
/* [0x140107530] ntoskrnl.exe!RtlRandomEx (fnv 0xa12ac26abe63b26f) [verified] */
extern AC_IMPORT_CELL g_imp_RtlRandomEx;
/* [0x140107580] ntoskrnl.exe!RtlTimeToTimeFields (fnv 0xa7841e19045174d1) [verified] */
extern AC_IMPORT_CELL g_imp_RtlTimeToTimeFields;
/* [0x1401083d0] ntoskrnl.exe!RtlUTF8ToUnicodeN (fnv 0x7dadfdf0c359a054) [verified] */
extern AC_IMPORT_CELL g_imp_RtlUTF8ToUnicodeN;
/* [0x140108160] ntoskrnl.exe!RtlUnicodeStringToInteger (fnv 0xbf3fe12ad9e3dcea) [verified] */
extern AC_IMPORT_CELL g_imp_RtlUnicodeStringToInteger;
/* [0x1401074f0] ntoskrnl.exe!RtlUnicodeToUTF8N (fnv 0x06980e701862ab78) [verified] */
extern AC_IMPORT_CELL g_imp_RtlUnicodeToUTF8N;
/* [0x140108400] ntoskrnl.exe!RtlVirtualUnwind (fnv 0x21103018bb52a5d1) [verified] */
extern AC_IMPORT_CELL g_imp_RtlVirtualUnwind;
/* [0x140107ee0] ntoskrnl.exe!RtlWalkFrameChain (fnv 0x88de0deca0e59476) [verified] */
extern AC_IMPORT_CELL g_imp_RtlWalkFrameChain;
/* [0x140107c20] ntoskrnl.exe!SeLocateProcessImageName (fnv 0x7a59e3f8b1eea6c2) [verified] */
extern AC_IMPORT_CELL g_imp_SeLocateProcessImageName;
/* [0x140107650] ntoskrnl.exe!ZwAllocateVirtualMemory (fnv 0xb643a0b849bfaa97) [verified] */
extern AC_IMPORT_CELL g_imp_ZwAllocateVirtualMemory;
/* [0x140107c80] ntoskrnl.exe!ZwAssignProcessToJobObject (fnv 0xc5ec6ed31b590083) [verified] */
extern AC_IMPORT_CELL g_imp_ZwAssignProcessToJobObject;
/* [0x140107560] ntoskrnl.exe!ZwClose (fnv 0x730beb78de086d3a) [verified] */
extern AC_IMPORT_CELL g_imp_ZwClose;
/* [0x140107fc0] ntoskrnl.exe!ZwCreateFile (fnv 0xb2652d28ddc25a6c) [verified] */
extern AC_IMPORT_CELL g_imp_ZwCreateFile;
/* [0x140107730] ntoskrnl.exe!ZwCreateSection (fnv 0x8ef4557eaa2d6cc5) [verified] */
extern AC_IMPORT_CELL g_imp_ZwCreateSection;
/* [0x140108280] ntoskrnl.exe!ZwDuplicateObject (fnv 0xadca2c6629d680dc) [verified] */
extern AC_IMPORT_CELL g_imp_ZwDuplicateObject;
/* [0x140108110] ntoskrnl.exe!ZwDuplicateToken (fnv 0x13851ced7342e454) [verified] */
extern AC_IMPORT_CELL g_imp_ZwDuplicateToken;
/* [0x140107570] ntoskrnl.exe!ZwFlushBuffersFile (fnv 0xf4c9711ea51ae225) [verified] */
extern AC_IMPORT_CELL g_imp_ZwFlushBuffersFile;
/* [0x140108420] ntoskrnl.exe!ZwFreeVirtualMemory (fnv 0x16a318092ae27058) [verified] */
extern AC_IMPORT_CELL g_imp_ZwFreeVirtualMemory;
/* [0x140107d00] ntoskrnl.exe!ZwLoadDriver (fnv 0x66c1051b24b2f710) [verified] */
extern AC_IMPORT_CELL g_imp_ZwLoadDriver;
/* [0x140107c90] ntoskrnl.exe!ZwMapViewOfSection (fnv 0xb47307868b40dffb) [verified] */
extern AC_IMPORT_CELL g_imp_ZwMapViewOfSection;
/* [0x1401079a0] ntoskrnl.exe!ZwOpenDirectoryObject (fnv 0x5adf7c4f8a14c22a) [verified] */
extern AC_IMPORT_CELL g_imp_ZwOpenDirectoryObject;
/* [0x140108060] ntoskrnl.exe!ZwOpenFile (fnv 0xef20fb16b5ef75c8) [verified] */
extern AC_IMPORT_CELL g_imp_ZwOpenFile;
/* [0x140107da0] ntoskrnl.exe!ZwOpenKey (fnv 0x68728064a1d2d535) [verified] */
extern AC_IMPORT_CELL g_imp_ZwOpenKey;
/* [0x140107eb0] ntoskrnl.exe!ZwOpenProcess (fnv 0x92b41f5411e03183) [verified] */
extern AC_IMPORT_CELL g_imp_ZwOpenProcess;
/* [0x1401083b0] ntoskrnl.exe!ZwOpenProcessTokenEx (fnv 0xccd88f108f1ecbc5) [verified] */
extern AC_IMPORT_CELL g_imp_ZwOpenProcessTokenEx;
/* [0x140107cc0] ntoskrnl.exe!ZwOpenSection (fnv 0xf01a3e91b3cd1a11) [verified] */
extern AC_IMPORT_CELL g_imp_ZwOpenSection;
/* [0x140107a10] ntoskrnl.exe!ZwOpenSymbolicLinkObject (fnv 0xe72b380c4636f2c9) [verified] */
extern AC_IMPORT_CELL g_imp_ZwOpenSymbolicLinkObject;
/* [0x140107ff0] ntoskrnl.exe!ZwProtectVirtualMemory (fnv 0x5731d7b491611d5f) [verified] */
extern AC_IMPORT_CELL g_imp_ZwProtectVirtualMemory;
/* [0x140108550] ntoskrnl.exe!ZwQueryDirectoryFile (fnv 0x79b29145d759b577) [verified] */
extern AC_IMPORT_CELL g_imp_ZwQueryDirectoryFile;
/* [0x1401083a0] ntoskrnl.exe!ZwQueryDirectoryObject (fnv 0x636f9e4c793304ae) [verified] */
extern AC_IMPORT_CELL g_imp_ZwQueryDirectoryObject;
/* [0x140108000] ntoskrnl.exe!ZwQueryInformationFile (fnv 0xdc83b36f65f257b2) [verified] */
extern AC_IMPORT_CELL g_imp_ZwQueryInformationFile;
/* [0x1401082c0] ntoskrnl.exe!ZwQueryInformationProcess (fnv 0xfab3c96c38396c59) [verified] */
extern AC_IMPORT_CELL g_imp_ZwQueryInformationProcess;
/* [0x140107c10] ntoskrnl.exe!ZwQueryInformationThread (fnv 0x241f343af4d0d4dc) [verified] */
extern AC_IMPORT_CELL g_imp_ZwQueryInformationThread;
/* [0x140107940] ntoskrnl.exe!ZwQueryObject (fnv 0xf4fc0bfdbfacbde9) [verified] */
extern AC_IMPORT_CELL g_imp_ZwQueryObject;
/* [0x140108340] ntoskrnl.exe!ZwQuerySection (fnv 0x80d264c03053748d) [verified] */
extern AC_IMPORT_CELL g_imp_ZwQuerySection;
/* [0x140107930] ntoskrnl.exe!ZwQuerySymbolicLinkObject (fnv 0x205229d2ba1a702d) [verified] */
extern AC_IMPORT_CELL g_imp_ZwQuerySymbolicLinkObject;
/* [0x140107830] ntoskrnl.exe!ZwQuerySystemInformation (fnv 0x9b3466f6ce10ac9f) [verified] */
extern AC_IMPORT_CELL g_imp_ZwQuerySystemInformation;
/* [0x140107e60] ntoskrnl.exe!ZwQuerySystemInformationEx (fnv 0xcc0b766123a46762) [verified] */
extern AC_IMPORT_CELL g_imp_ZwQuerySystemInformationEx;
/* [0x140107c00] ntoskrnl.exe!ZwQueryVirtualMemory (fnv 0x8661b2e02ff815c2) [verified] */
extern AC_IMPORT_CELL g_imp_ZwQueryVirtualMemory;
/* [0x140108180] ntoskrnl.exe!ZwReadFile (fnv 0x2ec75d1e8c947580) [verified] */
extern AC_IMPORT_CELL g_imp_ZwReadFile;
/* [0x1401080d0] ntoskrnl.exe!ZwSetInformationProcess (fnv 0xe50393744712e675) [verified] */
extern AC_IMPORT_CELL g_imp_ZwSetInformationProcess;
/* [0x1401082f0] ntoskrnl.exe!ZwTerminateProcess (fnv 0x77f97d35bed60da6) [verified] */
extern AC_IMPORT_CELL g_imp_ZwTerminateProcess;
/* [0x140107f60] ntoskrnl.exe!ZwUnmapViewOfSection (fnv 0xb2371a9592d9d34c) [verified] */
extern AC_IMPORT_CELL g_imp_ZwUnmapViewOfSection;
/* [0x140107a60] ntoskrnl.exe!ZwWaitForSingleObject (fnv 0xe7be11c1669bda6d) [verified] */
extern AC_IMPORT_CELL g_imp_ZwWaitForSingleObject;
/* [0x1401075b0] ntoskrnl.exe!ZwWriteFile (fnv 0x0ba1615476bbc9af) [verified] */
extern AC_IMPORT_CELL g_imp_ZwWriteFile;
/* [0x140107fa0] ntoskrnl.exe!_snprintf (fnv 0x404caedc462f1214) [verified] */
extern AC_IMPORT_CELL g_imp__snprintf;
/* [0x1401076c0] ntoskrnl.exe!_snwprintf (fnv 0xc0bc990031f590ff) [verified] */
extern AC_IMPORT_CELL g_imp__snwprintf;
/* [0x140107420] ntoskrnl.exe!_strnicmp (fnv 0x1918e33fd1ca46b0) [verified] */
extern AC_IMPORT_CELL g_imp__strnicmp;
/* [0x140107fe0] ntoskrnl.exe!_wcsnicmp (fnv 0x1a1bb22dbb2e58d0) [verified] */
extern AC_IMPORT_CELL g_imp__wcsnicmp;
/* [0x1401076d0] ntoskrnl.exe!strncmp (fnv 0xca73a7dbbf321b96) [verified] */
extern AC_IMPORT_CELL g_imp_strncmp;
/* [0x1401077b0] ntoskrnl.exe!strncpy (fnv 0xca4eacdbbf1307d8) [verified] */
extern AC_IMPORT_CELL g_imp_strncpy;
/* [0x140107750] ntoskrnl.exe!swprintf (fnv 0x677ca07180bab530) [verified] */
extern AC_IMPORT_CELL g_imp_swprintf;
/* [0x140107c40] ntoskrnl.exe!swprintf_s (fnv 0xdab4e3c897a7056a) [verified] */
extern AC_IMPORT_CELL g_imp_swprintf_s;
/* [0x140108070] ntoskrnl.exe!towlower (fnv 0xdf3baf285982e396) [verified] */
extern AC_IMPORT_CELL g_imp_towlower;
/* [0x140107f70] ntoskrnl.exe!towupper (fnv 0x9277b4dea7672923) [verified] */
extern AC_IMPORT_CELL g_imp_towupper;
/* [0x140107e50] ntoskrnl.exe!wcsncmp (fnv 0x966cf026b899765a) [verified] */
extern AC_IMPORT_CELL g_imp_wcsncmp;
/* [0x1401076a0] ntoskrnl.exe!wcsncpy (fnv 0x962ce526b8637fb4) [verified] */
extern AC_IMPORT_CELL g_imp_wcsncpy;
/* [0x140107d90] ntoskrnl.exe!wcsrchr (fnv 0x145c1f7ffa4b05d9) [verified] */
extern AC_IMPORT_CELL g_imp_wcsrchr;
/* [0x140107e00] ntoskrnl.exe!wcsstr (fnv 0xbeae6800e8791c23) [verified] */
extern AC_IMPORT_CELL g_imp_wcsstr;

#define AC_IMPORT_COUNT 260


/* ==========================================================================
 * imports.h -- LAZY LAYER (+46): second-tier resolver set
 * --------------------------------------------------------------------------
 * [provenance] RECON2_INVENTORY напр. 9 (редкие api_resolve вне 259-таблицы
 * оркестратора) + imp_census.json тел-потребителей. Резолвер второго
 * слоя: внутренний GetProcAddress-подобный gpa @0x1402e4586/0x1402e4594
 * (сайты вызова 0x1402e45be/0x1402e45e0/0x1402e45eb; api_store -- 133
 * записи в ~30 адресатов), т.е. эти API резолвятся ЛЕНИВО по месту
 * использования, а не разово в api_resolve_orchestrator 0x14024af8e.
 * ==========================================================================*/

/* [0x1402b1c16, 0x1403bd850] KeRegisterNmiCallback -- NMI-вачдог */
extern AC_IMPORT_CELL g_lazy_KeRegisterNmiCallback;
/* [0x1402b1c24] KeDeregisterNmiCallback -- NMI-вачдог */
extern AC_IMPORT_CELL g_lazy_KeDeregisterNmiCallback;
/* [0x1402b1bfa] HalSendNMI -- NMI-вачдог/cross-CPU свип */
extern AC_IMPORT_CELL g_lazy_HalSendNMI;
/* [0x1402a78bf] HalPerformEndOfInterrupt -- NMI/EOI */
extern AC_IMPORT_CELL g_lazy_HalPerformEndOfInterrupt;
/* [0x14012afb2] HalReturnToFirmware -- HAL/путь ребута */
extern AC_IMPORT_CELL g_lazy_HalReturnToFirmware;
/* [0x140215e57] HalSetEnvironmentVariableEx -- HAL/запись UEFI-переменной */
extern AC_IMPORT_CELL g_lazy_HalSetEnvironmentVariableEx;
/* [0x140370a84, 0x14037dd47] HalPrivateDispatchTable -- HAL dispatch (инфра syscall-хуков) */
extern AC_IMPORT_CELL g_lazy_HalPrivateDispatchTable;
/* [0x140297a4e] KeRegisterBoundCallback -- bound-callback */
extern AC_IMPORT_CELL g_lazy_KeRegisterBoundCallback;
/* [0x14016948e] PsRegisterAltSystemCallHandler -- alt-обработчик syscall */
extern AC_IMPORT_CELL g_lazy_PsRegisterAltSystemCallHandler;
/* [0x1402e8f7a] PsStartSiloMonitor -- монитор server-silo */
extern AC_IMPORT_CELL g_lazy_PsStartSiloMonitor;
/* [0x14023e019] EtwRegister -- ETW-провайдер */
extern AC_IMPORT_CELL g_lazy_EtwRegister;
/* [0x14020a959, 0x14017fbea] NtTraceControl -- ETW/trace-контроль */
extern AC_IMPORT_CELL g_lazy_NtTraceControl;
/* [0x14037056b] DbgSetDebugPrintCallback -- перехват debug-print */
extern AC_IMPORT_CELL g_lazy_DbgSetDebugPrintCallback;
/* [0x1403e2e44] RtlSelfRelativeToAbsoluteSD2 -- построение DACL/SD */
extern AC_IMPORT_CELL g_lazy_RtlSelfRelativeToAbsoluteSD2;
/* [0x1403e2ecd] ZwQuerySecurityObject -- чтение DACL/SD */
extern AC_IMPORT_CELL g_lazy_ZwQuerySecurityObject;
/* [0x1403e2e44..0x1403e2eb4 cluster] RtlGetDaclSecurityDescriptor -- чтение DACL/SD */
extern AC_IMPORT_CELL g_lazy_RtlGetDaclSecurityDescriptor;
/* [0x1403e2e44..0x1403e2eb4 cluster] RtlCopySid -- построение DACL/SD */
extern AC_IMPORT_CELL g_lazy_RtlCopySid;
/* [0x1403e2e44..0x1403e2eb4 cluster] RtlLengthSid -- построение DACL/SD */
extern AC_IMPORT_CELL g_lazy_RtlLengthSid;
/* [0x1403e2e44..0x1403e2eb4 cluster] RtlValidSid -- построение DACL/SD */
extern AC_IMPORT_CELL g_lazy_RtlValidSid;
/* [0x1403e2e44..0x1403e2eb4 cluster] RtlAddAce -- построение DACL/SD */
extern AC_IMPORT_CELL g_lazy_RtlAddAce;
/* [0x1403e2e44..0x1403e2eb4 cluster] RtlSetDaclSecurityDescriptor -- установка DACL/SD */
extern AC_IMPORT_CELL g_lazy_RtlSetDaclSecurityDescriptor;
/* [0x1403e2eb4] ZwSetSecurityObject -- применение DACL/SD */
extern AC_IMPORT_CELL g_lazy_ZwSetSecurityObject;
/* [0x1402b1c3d] KeInitializeAffinityEx -- affinity/пиннинг потоков */
extern AC_IMPORT_CELL g_lazy_KeInitializeAffinityEx;
/* [0x1402b1bec] KeAddProcessorAffinityEx -- affinity/пиннинг потоков */
extern AC_IMPORT_CELL g_lazy_KeAddProcessorAffinityEx;
/* [0x1401d2d32, 0x1402b1c32] KeQueryActiveProcessorCountEx -- affinity/топология */
extern AC_IMPORT_CELL g_lazy_KeQueryActiveProcessorCountEx;
/* [0x1402b1bd0] KeSetSystemAffinityThreadEx -- affinity/пиннинг потоков */
extern AC_IMPORT_CELL g_lazy_KeSetSystemAffinityThreadEx;
/* [0x1401d2d16, 0x14021308c] KeRevertToUserAffinityThreadEx -- affinity/пиннинг потоков */
extern AC_IMPORT_CELL g_lazy_KeRevertToUserAffinityThreadEx;
/* [0x1403b9bfd] KeSetTimerEx -- периодический DPC-таймер */
extern AC_IMPORT_CELL g_lazy_KeSetTimerEx;
/* [0x1403cc780] PsGetContextThread -- чтение контекста потока */
extern AC_IMPORT_CELL g_lazy_PsGetContextThread;
/* [0x1402b6c47] KseSetDeviceFlags -- флаги kernel shim engine */
extern AC_IMPORT_CELL g_lazy_KseSetDeviceFlags;
/* [0x1403ca075] ZwSetSystemInformation -- модификация системного состояния */
extern AC_IMPORT_CELL g_lazy_ZwSetSystemInformation;
/* [0x140395549] IoGetIommuInterface -- зонд IOMMU/DMA */
extern AC_IMPORT_CELL g_lazy_IoGetIommuInterface;
/* [0x140267e85] PsSetLoadImageNotifyRoutineEx -- Ex-вариант image notify */
extern AC_IMPORT_CELL g_lazy_PsSetLoadImageNotifyRoutineEx;
/* [0x140293153] FltUnregisterFilter -- жизненный цикл minifilter */
extern AC_IMPORT_CELL g_lazy_FltUnregisterFilter;
/* [0x140173d0f] FltCloseCommunicationPort -- comm-порт minifilter */
extern AC_IMPORT_CELL g_lazy_FltCloseCommunicationPort;
/* [0x140163f2f] FltCloseClientPort -- comm-порт minifilter */
extern AC_IMPORT_CELL g_lazy_FltCloseClientPort;
/* [0x14035fbe8] NtMapViewOfSection -- init воркера (user-mem) */
extern AC_IMPORT_CELL g_lazy_NtMapViewOfSection;
/* [0x1401f1e95] NtAllocateVirtualMemory -- init воркера (user-mem) */
extern AC_IMPORT_CELL g_lazy_NtAllocateVirtualMemory;
/* [0x14027cef3] NtWaitForSingleObject -- init воркера (sync) */
extern AC_IMPORT_CELL g_lazy_NtWaitForSingleObject;
/* [cell 0x140108330, body 0x1401824c2] PsSuspendProcess -- заморозка процесса */
extern AC_IMPORT_CELL g_lazy_PsSuspendProcess;
/* [cell 0x1401082f8, body 0x142acf237] ZwTerminateProcess -- убийство процесса */
extern AC_IMPORT_CELL g_lazy_ZwTerminateProcess;
/* [0x140289136] ZwOpenProcess -- доступ к процессу */
extern AC_IMPORT_CELL g_lazy_ZwOpenProcess;
/* [0x1401f376c] PsLookupProcessByProcessId -- поиск процесса */
extern AC_IMPORT_CELL g_lazy_PsLookupProcessByProcessId;
/* [0x1403a267e] PsAcquireProcessExitSynchronization -- синхронизация выхода процесса */
extern AC_IMPORT_CELL g_lazy_PsAcquireProcessExitSynchronization;
/* [0x141492278] ZwQueryInformationThread -- интроспекция потоков */
extern AC_IMPORT_CELL g_lazy_ZwQueryInformationThread;
/* [0x1401d7117] BCryptGetProperty -- контур BCrypt */
extern AC_IMPORT_CELL g_lazy_BCryptGetProperty;


/* --------------------------------------------------------------------------
 * контур ci.dll (kernel code integrity)
 * [0x1401074e0] g_mbase_ci -- ячейка image base ci.dll (класс modbase,
 * pair_resolutions.tsv; слот 0x1401074e8). Единственный используемый
 * экспорт: CiValidateFileObject -- неразрешим эмулятором KEVLAR без
 * реального модуля (IMPORTS_REPORT §617-618); резолвится в живую
 * KLDR-обходом + FNV-EAT сканом (game_integrity.c AcCiResolve).
 * ------------------------------------------------------------------------ */
extern UINT64 g_mbase_ci;           /* 0x1401074e0 (ячейка modbase) */

/* --------------------------------------------------------------------------
 * Контур инвентаря хэш-таблицы weak-enumeration
 * (COVERAGE_INVENTORY #2.10; AC_MONITORING #2.1/#3):
 * RtlCreateHashTable + weak-enumeration обход под
 * KeAcquireInStackQueuedSpinLockAtDpcLevel -> 80-байтовые записи инвентаря
 * -> канал; NumEntries/TableSize валидируются <= 0x100000.
 * ------------------------------------------------------------------------ */
/* [region_102/292] kernel_module_inventory_weak_enum */
extern AC_IMPORT_CELL g_imp_RtlCreateHashTable;
extern AC_IMPORT_CELL g_imp_RtlInitWeakEnumerationHashTable;
extern AC_IMPORT_CELL g_imp_RtlWeaklyEnumerateEntryHashTable;
extern AC_IMPORT_CELL g_imp_RtlEndWeakEnumerationHashTable;

/* --------------------------------------------------------------------------
 * VM-разрешённые (XOR-пара) импорты -- разрешаются через питание VM'а, НЕ
 * через парную таблицу на 260 входов (AC_NDIS #2; RECON2 #3):
 * ------------------------------------------------------------------------ */
/* [0x139DB613C0BCE905] ntoskrnl.exe!PsCreateSystemThread -- resolve+вызов
 * на init'е из мегачанка 0x140293018 (спавн AC system thread'а);
 * rdx=0x1FFFFF THREAD_ALL_ACCESS */
extern AC_IMPORT_CELL g_vmres_PsCreateSystemThread;
/* [0xC5184623A938587] ntoskrnl.exe!ObRegisterCallbacks -- resolve-и-вызов
 * 0x14036c16b (rcx=&reg-блок, rdx=0x18) */
extern AC_IMPORT_CELL g_vmres_ObRegisterCallbacks;

/* [AC_STRINGS.md taxonomy] ntoskrnl.exe!ExQueryDepthSList -- запрос
 * глубины SList (контур очередной механики; не в парной таблице на 260) */
extern AC_IMPORT_CELL g_lazy_ExQueryDepthSList;

#define AC_IMPORT_LAZY_COUNT 46

#endif /* FACEIT_AC_IMPORTS_H */