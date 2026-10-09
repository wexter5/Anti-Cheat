/* ==========================================================================
 * strings.h -- таблица декодированных строк FACEIT_AC.sys (145 входов)
 * --------------------------------------------------------------------------
 * [provenance] _research_tmp/strings/decoded.json: runtime-XOR декодеры
 * восстановлены статически (сайты декодеров -> plaintext), отчёт по строкам
 * sources/reports/corpus_reports/AC_STRINGS.md. Брутфорс не использовался:
 * каждая строка декодирована из своей формулы декодера, найденной в бинаре.
 * Формат: AC_STR_<cluster>_<n>  "text"  /* enc_rva | type | callsites */
 * ========================================================================== */
#ifndef FACEIT_AC_STRINGS_H
#define FACEIT_AC_STRINGS_H


#define AC_STR_164_0 "%02x " /* [0x14007b75c] format_log | calls: 0x14006b7a4,0x14006bf96,0x14006c028,0x14007b1a7 */
#define AC_STR_156_0 ".text" /* [0x140074bbc] ascii | calls: 0x140001885,0x1400022ae,0x14001bd88,0x140074ab2 */
#define AC_STR_037_0 "%08x" /* [0x140014858] format_log | calls: 0x140013bcb,0x14001465f */
#define AC_STR_201_0 "%4d-%02d-%02dT%02d:%02d:%02dZ" /* [0x140095a44] format_log | calls: 0x14009986a,0x140099b13 */
#define AC_STR_207_0 "%wZ+%x" /* [0x140099470] format_log | calls: 0x140092103,0x1400990c2 */
#define AC_STR_164_1 "%x %.8hs %wZ" /* [0x14007b81c] format_log | calls: 0x14007b345,0x14007b516 */
#define AC_STR_189_0 "\\Device" /* [0x14008e3a8] utf16 | calls: 0x14004b4a6,0x14008de69 */
#define AC_STR_189_1 "\\Device\\RaidPort" /* [0x14008e360] device_path | calls: 0x14004b435,0x14008de00 */
#define AC_STR_089_0 "%02x" /* [0x14004e14c] format_log | calls: 0x14004e0da */
#define AC_STR_037_1 "%08x %p" /* [0x1400147d8] format_log | calls: 0x1400145b0 */
#define AC_STR_034_0 "%d %p %p" /* [0x140013ce0] format_log | calls: 0x140013af5 */
#define AC_STR_196_0 "%llx" /* [0x140091bc4] format_log | calls: 0x140091a89 */
#define AC_STR_034_1 "%wZ %08x" /* [0x140013d20] format_log | calls: 0x140013b71 */
#define AC_STR_140_0 "%wZ %p %.8hs %wZ" /* [0x14006ba10] format_log | calls: 0x14006b8ca */
#define AC_STR_070_0 "%wZ %wZ" /* [0x140045b04] format_log | calls: 0x140045a0c */
#define AC_STR_196_1 "%wZ+%08x" /* [0x140091b7c] format_log | calls: 0x140091a20 */
#define AC_STR_208_0 "%wZ+%08x" /* [0x140099eb0] format_log | calls: 0x140099c83 */
#define AC_STR_130_0 "-tools" /* [0x140065e40] utf16 | calls: 0x140065d88 */
#define AC_STR_067_0 ".bsp" /* [0x140044684] game_path | calls: 0x1400444f6 */
#define AC_STR_048_0 ".data" /* [0x14001df40] ascii | calls: 0x14001bdb5 */
#define AC_STR_127_0 ".dll" /* [0x140063a00] module_dll | calls: 0x140063921 */
#define AC_STR_048_1 ".rdata" /* [0x14001df78] ascii | calls: 0x14001bdeb */
#define AC_STR_140_1 ".rsrc" /* [0x14006b928] ascii | calls: 0x14006b5b8 */
#define AC_STR_070_1 ".vpk" /* [0x140045ac4] game_path | calls: 0x1400457dd */
#define AC_STR_035_0 "AcGenral.DLL" /* [0x140014184] module_dll | calls: 0x140013f41 */
#define AC_STR_035_1 "AcLayers.DLL" /* [0x140014144] module_dll | calls: 0x140013ecf */
#define AC_STR_035_2 "AcXtrnal.DLL" /* [0x140014204] module_dll | calls: 0x140014024 */
#define AC_STR_048_2 "CorsairLLAccess64.pdb" /* [0x14001edb0] pdb_path | calls: 0x14001d9e8 */
#define AC_STR_037_2 "CreateInterface" /* [0x140014760] ascii | calls: 0x14001438a */
#define AC_STR_048_3 "DIRECTIOLPT" /* [0x14001ecf0] utf16 | calls: 0x14001d8a9 */
#define AC_STR_048_4 "DirectIo64.pdb" /* [0x14001ee60] pdb_path | calls: 0x14001daff */
#define AC_STR_022_0 "Directory" /* [0x14000e134] utf16 | calls: 0x14000dea6 */
#define AC_STR_048_5 "DriverEntry: Failed to allocate memory for DriverName" /* [0x14001eed8] ascii | calls: 0x14001dc0a */
#define AC_STR_048_6 "GIGABYTEPASSWORDD" /* [0x14001ef10] ascii | calls: 0x14001dc4b */
#define AC_STR_164_2 "INITKDBG" /* [0x14007b6e4] ascii | calls: 0x14007ad92 */
#define AC_STR_048_7 "LGHUBDevice\\LGHUBCompatibleVirtualDevice" /* [0x14001ec30] utf16 | calls: 0x14001d734 */
#define AC_STR_048_8 "LogiDevice\\LogiCompatibleVirtualDevice" /* [0x14001ec70] utf16 | calls: 0x14001d7ec */
#define AC_STR_048_9 "Mapped %d bytes at %X to %X" /* [0x14001efb8] format_log | calls: 0x14001dd26 */
#define AC_STR_048_10 "PAGE" /* [0x14001dfb0] pooltag? | calls: 0x14001be1e */
#define AC_STR_164_3 "PAGEwx3" /* [0x14007b6ac] ascii | calls: 0x14007ad4a */
#define AC_STR_048_11 "RTKVHD64.pdb" /* [0x14001f098] pdb_path | calls: 0x14001de39 */
#define AC_STR_048_12 "RzCommon.pdb" /* [0x14001ede8] pdb_path | calls: 0x14001da3e */
#define AC_STR_071_0 "ShimQueryInterface" /* [0x14004708c] ascii | calls: 0x140046a8f */
#define AC_STR_022_1 "SymbolicLink" /* [0x14000e0ec] utf16 | calls: 0x14000de41 */
#define AC_STR_036_0 "Valve" /* [0x1400142f4] ascii | calls: 0x1400142a5 */
#define AC_STR_065_0 "WSPStartup" /* [0x140043e1c] ascii | calls: 0x140043c49 */
#define AC_STR_135_0 "WorkingDirectory" /* [0x140067ec8] utf16 | calls: 0x1400679de */
#define AC_STR_048_13 "\\ATSZIO.pdb" /* [0x14001f0d0] pdb_path | calls: 0x14001de79 */
#define AC_STR_048_14 "\\ATSZIO_x64.pdb" /* [0x14001f108] pdb_path | calls: 0x14001deb1 */
#define AC_STR_048_15 "\\CmUpx.pdb" /* [0x14001f028] pdb_path | calls: 0x14001ddae */
#define AC_STR_048_16 "\\Device\\AMDRyzenMasterDriver" /* [0x14001eb30] device_path | calls: 0x14001d51f */
#define AC_STR_048_17 "\\Device\\AODDriver" /* [0x14001eb70] device_path | calls: 0x14001d597 */
#define AC_STR_069_0 "\\Device\\Dokan" /* [0x140045388] device_path | calls: 0x1400450c5 */
#define AC_STR_048_18 "\\Device\\GIOV2" /* [0x14001ebf0] device_path | calls: 0x14001d668 */
#define AC_STR_189_2 "\\Device\\Harddisk" /* [0x14008e2d0] device_path | calls: 0x14008dcd9 */
#define AC_STR_189_3 "\\Device\\HarddiskVolume" /* [0x14008e318] device_path | calls: 0x14008dd80 */
#define AC_STR_048_19 "\\Device\\PhysicalMemory" /* [0x14001e2ac] device_path | calls: 0x14001c3b5 */
#define AC_STR_048_20 "\\Device\\SysDrv3S" /* [0x14001ee20] device_path | calls: 0x14001dab5 */
#define AC_STR_069_1 "\\Device\\WinFsp" /* [0x1400453c8] device_path | calls: 0x140045141 */
#define AC_STR_048_21 "\\Device\\WinRing0" /* [0x14001ebb0] device_path | calls: 0x14001d603 */
#define AC_STR_048_22 "\\Device\\genericdrv" /* [0x14001eaf0] device_path | calls: 0x14001d46a */
#define AC_STR_069_2 "\\Device\\{066B0CB8-ADD8-4d50-ACE4-AFA10257284E}-" /* [0x140045408] device_path | calls: 0x140045229 */
#define AC_STR_048_23 "\\DosDevices\\" /* [0x14001dfe8] device_path | calls: 0x14001be84 */
#define AC_STR_048_24 "\\DosDevices\\AIDA64Driver" /* [0x14001e6ec] device_path | calls: 0x14001cc80 */
#define AC_STR_048_25 "\\DosDevices\\AIDA64Drivers" /* [0x14001e6ec] device_path | calls: 0x14001cc80 */
#define AC_STR_048_26 "\\DosDevices\\ALSysIO" /* [0x14001e128] device_path | calls: 0x14001c0ff */
#define AC_STR_048_27 "\\DosDevices\\ASUSBIOSIO" /* [0x14001e7ac] device_path | calls: 0x14001cdf5 */
#define AC_STR_048_28 "\\DosDevices\\AppShopDrv" /* [0x14001e72c] device_path | calls: 0x14001cd04 */
#define AC_STR_048_29 "\\DosDevices\\AppShopDrvT" /* [0x14001e72c] device_path | calls: 0x14001cd04 */
#define AC_STR_048_30 "\\DosDevices\\AsInsHelp" /* [0x14001eab0] device_path | calls: 0x14001d3f7 */
#define AC_STR_048_31 "\\DosDevices\\AsUpdateio" /* [0x14001e32c] device_path | calls: 0x14001c4ae */
#define AC_STR_048_32 "\\DosDevices\\AsUpdateiot" /* [0x14001e32c] device_path | calls: 0x14001c4ae */
#define AC_STR_048_33 "\\DosDevices\\AsrAutoChkUpdDrv" /* [0x14001e4ac] device_path | calls: 0x14001c805 */
#define AC_STR_048_34 "\\DosDevices\\AsrCDDrv" /* [0x14001e46c] device_path | calls: 0x14001c76f */
#define AC_STR_048_35 "\\DosDevices\\AsrDrv" /* [0x14001e3ec] device_path | calls: 0x14001c67e */
#define AC_STR_048_36 "\\DosDevices\\AsrIbDrv" /* [0x14001e4ec] device_path | calls: 0x14001c87f */
#define AC_STR_048_37 "\\DosDevices\\AsrOcDrv" /* [0x14001e42c] device_path | calls: 0x14001c6f8 */
#define AC_STR_048_38 "\\DosDevices\\AsrRapidStartDrv" /* [0x14001e56c] device_path | calls: 0x14001c9b5 */
#define AC_STR_048_39 "\\DosDevices\\AsrSmartConnectDrv" /* [0x14001e52c] device_path | calls: 0x14001c91f */
#define AC_STR_048_40 "\\DosDevices\\Asusgio" /* [0x14001e2ec] device_path | calls: 0x14001c42e */
#define AC_STR_048_41 "\\DosDevices\\AxtuDrv" /* [0x14001e6ac] device_path | calls: 0x14001cbf8 */
#define AC_STR_048_42 "\\DosDevices\\BS_HWMIO" /* [0x14001e068] device_path | calls: 0x14001bf90 */
#define AC_STR_048_43 "\\DosDevices\\BS_RCIO" /* [0x14001e0a8] device_path | calls: 0x14001c001 */
#define AC_STR_048_44 "\\DosDevices\\BiosToolCommonDriver" /* [0x14001e92c] device_path | calls: 0x14001d12b */
#define AC_STR_048_45 "\\DosDevices\\DELLWALDOS" /* [0x14001ea6c] device_path | calls: 0x14001d37f */
#define AC_STR_048_46 "\\DosDevices\\EneIo" /* [0x14001e62c] device_path | calls: 0x14001cb14 */
#define AC_STR_048_47 "\\DosDevices\\EneTechIo" /* [0x14001e5ec] device_path | calls: 0x14001caaa */
#define AC_STR_048_48 "\\DosDevices\\EnergyDriver" /* [0x14001e9ac] device_path | calls: 0x14001d21a */
#define AC_STR_048_49 "\\DosDevices\\EnergyDriver(" /* [0x14001e9ac] device_path | calls: 0x14001d21a */
#define AC_STR_048_50 "\\DosDevices\\GLCKIo" /* [0x14001e66c] device_path | calls: 0x14001cb87 */
#define AC_STR_048_51 "\\DosDevices\\GVCIDrv64" /* [0x14001e028] device_path | calls: 0x14001bf16 */
#define AC_STR_048_52 "\\DosDevices\\Global\\CPUZ" /* [0x14001e1ac] device_path | calls: 0x14001c1eb */
#define AC_STR_048_53 "\\DosDevices\\LenovoDiagnosticsDriver" /* [0x14001ee98] device_path | calls: 0x14001dbab */
#define AC_STR_048_54 "\\DosDevices\\MsIo" /* [0x14001e1ec] device_path | calls: 0x14001c257 */
#define AC_STR_048_55 "\\DosDevices\\NPR0_1_0_22" /* [0x14001e8ec] device_path | calls: 0x14001d084 */
#define AC_STR_048_56 "\\DosDevices\\NTIOLib" /* [0x14001e16c] device_path | calls: 0x14001c16c */
#define AC_STR_048_57 "\\DosDevices\\PMXDRV" /* [0x14001e76c] device_path | calls: 0x14001cd77 */
#define AC_STR_048_58 "\\DosDevices\\PhyMem" /* [0x14001e26c] device_path | calls: 0x14001c334 */
#define AC_STR_048_59 "\\DosDevices\\SONiXDDR_0_0_0_1" /* [0x14001e8ac] device_path | calls: 0x14001d005 */
#define AC_STR_048_60 "\\DosDevices\\SignalIo" /* [0x14001e5ac] device_path | calls: 0x14001ca2c */
#define AC_STR_048_61 "\\DosDevices\\SpeedFan" /* [0x14001ed30] device_path | calls: 0x14001d922 */
#define AC_STR_048_62 "\\DosDevices\\TdeIo" /* [0x14001e9ec] device_path | calls: 0x14001d284 */
#define AC_STR_048_63 "\\DosDevices\\WinHwDriver" /* [0x14001e86c] device_path | calls: 0x14001cf6f */
#define AC_STR_048_64 "\\DosDevices\\WinIo" /* [0x14001e22c] device_path | calls: 0x14001c2c1 */
#define AC_STR_048_65 "\\DosDevices\\WinMsrDev" /* [0x14001e7ec] device_path | calls: 0x14001ce76 */
#define AC_STR_048_66 "\\DosDevices\\WinRing0" /* [0x14001e0e8] device_path | calls: 0x14001c07b */
#define AC_STR_048_67 "\\DosDevices\\bsitf" /* [0x14001e96c] device_path | calls: 0x14001d192 */
#define AC_STR_048_68 "\\DosDevices\\cpqsysio" /* [0x14001e82c] device_path | calls: 0x14001cef0 */
#define AC_STR_048_69 "\\DosDevices\\hpvision" /* [0x14001ea2c] device_path | calls: 0x14001d2fe */
#define AC_STR_048_70 "\\DosDevices\\inpoutx64" /* [0x14001e3ac] device_path | calls: 0x14001c60b */
#define AC_STR_048_71 "\\DosDevices\\iocbios2" /* [0x14001ed70] device_path | calls: 0x14001d99e */
#define AC_STR_048_72 "\\DosDevices\\rtkio" /* [0x14001ecb0] device_path | calls: 0x14001d855 */
#define AC_STR_048_73 "\\DosDevices\\{E8F2FF20-6AF7-4914-9398-CE2132FE170F}" /* [0x14001e36c] device_path | calls: 0x14001c592 */
#define AC_STR_025_0 "\\GLOBAL??" /* [0x14000fd24] utf16 | calls: 0x14000fa5f */
#define AC_STR_134_0 "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options" /* [0x140067c5c] registry_path | calls: 0x14006734c */
#define AC_STR_066_0 "\\SystemRoot\\SysWOW64\\mswsock.dll" /* [0x140044428] device_path | calls: 0x140044255 */
#define AC_STR_066_1 "\\SystemRoot\\System32\\mswsock.dll" /* [0x140044468] device_path | calls: 0x140044318 */
#define AC_STR_135_1 "\\System\\GameConfigStore\\Children\\" /* [0x140067e88] utf16 | calls: 0x1400678f7 */
#define AC_STR_134_1 "\\System\\GameConfigStore\\Parents\\" /* [0x140067cdc] utf16 | calls: 0x1400676d8 */
#define AC_STR_135_2 "\\System\\GameConfigStore\\Parents\\cd548d5c66b8fe21110109576b111a5b6aa481d7" /* [0x140067e48] utf16 | calls: 0x14006774e */
#define AC_STR_048_74 "\\TcnPeripheral64.pdb" /* [0x14001f060] pdb_path | calls: 0x14001ddf2 */
#define AC_STR_068_0 "\\cfg\\gamestate_integration_" /* [0x140044ec8] game_path | calls: 0x140044b12 */
#define AC_STR_068_1 "\\csgo_lv\\" /* [0x140044e48] game_path | calls: 0x140044a04 */
#define AC_STR_048_75 "\\gdrv.pdb" /* [0x14001ef48] pdb_path | calls: 0x14001dc93 */
#define AC_STR_107_0 "\\matchmaking.dll" /* [0x14005887c] game_path | calls: 0x1400587f4 */
#define AC_STR_048_76 "\\mst.pdb" /* [0x14001eff0] pdb_path | calls: 0x14001dd67 */
#define AC_STR_068_2 "\\shaders\\" /* [0x140044e08] utf16 | calls: 0x1400449b9 */
#define AC_STR_048_77 "\\sysdiag-x64.pdb" /* [0x14001ef80] pdb_path | calls: 0x14001dcd3 */
#define AC_STR_068_3 "\\workshop\\" /* [0x140044e88] utf16 | calls: 0x140044a58 */
#define AC_STR_068_4 "_000.vpk" /* [0x140044cc8] game_path | calls: 0x1400447d3 */
#define AC_STR_068_5 "_003.vpk" /* [0x140044d48] game_path | calls: 0x140044897 */
#define AC_STR_068_6 "_dir.vpk" /* [0x140044c88] game_path | calls: 0x140044763 */
#define AC_STR_126_0 "api-" /* [0x140063590] utf16 | calls: 0x140063232 */
#define AC_STR_035_3 "apphelp.dll" /* [0x1400141c4] module_dll | calls: 0x140013fb0 */
#define AC_STR_002_0 "aswVmm\\vmm.cpp" /* [0x14000232c] ascii | calls: 0x1400022d3 */
#define AC_STR_130_1 "cs2.exe" /* [0x140065e00] process_name | calls: 0x140065d0f */
#define AC_STR_153_0 "csrss.exe" /* [0x140072194] process_name | calls: 0x1400720d5 */
#define AC_STR_126_1 "ext-" /* [0x140063590] utf16 | calls: 0x140063273 */
#define AC_STR_068_7 "gameinfo.gi" /* [0x140044dc8] game_path | calls: 0x14004495c */
#define AC_STR_035_4 "kernel32.dll" /* [0x140014104] module_dll | calls: 0x140013e30 */
#define AC_STR_066_2 "mswsock.dll" /* [0x1400443e8] module_dll | calls: 0x14004417d */
#define AC_STR_050_0 "netio.sys" /* [0x14001f708] driver_name | calls: 0x14001f61c */
#define AC_STR_064_0 "ntoskrnl.exe" /* [0x140042c54] process_name | calls: 0x140042700 */
#define AC_STR_097_0 "services.exe" /* [0x140052d14] process_name | calls: 0x140052c1b */
#define AC_STR_068_8 "zip0.zip" /* [0x140044d88] game_path | calls: 0x1400448f8 */

/* [0x14006b998] декодированные строки таксономии строк (AC_STRINGS.md
 * #264-265; декодер k(i)=(i%58)+0x51, сайт 0x14006b6b9) */
#define AC_STR_LGSV     "LGSV"
#define AC_STR_NCFBOLEV "NCFBOLEV"

#define AC_STRING_COUNT 145

#endif /* FACEIT_AC_STRINGS_H */