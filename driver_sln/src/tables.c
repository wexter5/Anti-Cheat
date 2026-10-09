/* ==========================================================================
 * tables.c -- .data pair/scratch-окно FACEIT_AC.sys (g_pslots)
 * --------------------------------------------------------------------------
 * [provenance] окно 0x140106000..0x140109d58 (1963 qword'а), материализованное
 * post-writer состояние DriverEntry; источник:
 *   _research_tmp/chainstate/trigger_snapshot.json (KEVLAR snapshot)
 *   _research_tmp/rebuild/corpus/de_tables.c (дословный инициализатор)
 *   _research_tmp/chainstate/writers_classified.jsonl (per-cell классы)
 * Классы ячеек: boot-random (per-boot энтропия, напр. куки pair-8 0x140106080),
 * runtime-vm (пишется VM-писателями), local-det/local-const (статические),
 * absent (никогда не писалась ни в одном наблюдении), [live] = заполняется
 * live-only путями (границы flavor, собственная пара, API-пары нулевые в
 * образе файла).
 * ========================================================================== */
#include "tables.h"

UINT64 g_pslots[AC_PSLOTS_COUNT] = {
    0xc34fffffac1d29dc,  /* 0x140106000: absent */
    0xffffac1d29dc400f,
    0x00000000400fc34f,
    0x0000000000000000,  /* 0x140106018: live */
    0x0000000000000000,  /* 0x140106020: live */
    0x0000000000000000,  /* 0x140106028: live */
    0x0000000000000000,  /* 0x140106030: live */
    0x0000000000000000,  /* 0x140106038: live */
    0x0000000000000000,  /* 0x140106040: live */
    0x0000000000000000,  /* 0x140106048: live */
    0x0000000000000000,  /* 0x140106050: live */
    0x0000000000000000,  /* 0x140106058: live */
    0x0000000000000000,  /* 0x140106060: live */
    0x0000000000000000,  /* 0x140106068: live */
    0x0000000000000000,  /* 0x140106070: live */
    0x0000000000000000,  /* 0x140106078: live */
    0x000015de19428389,  /* 0x140106080: boot-random */
    0xffffea21e6bd7c76,  /* 0x140106088: runtime-vm */
    0xfffff8010002f104,  /* 0x140106090: local-const */
    0xfffff801000358ac,  /* 0x140106098: absent */
    0xfffff80100035950,
    0xfffff80100035920,
    0xfffff80100035930,
    0xfffff80100035940,
    0xfffff80100035b88,  /* 0x1401060c0: absent */
    0xfffff8010003630c,
    0xfffff801000382e4,  /* 0x1401060d0: absent */
    0xfffff8010003836c,
    0xfffff801000383f4,
    0xfffff801000384ac,
    0xfffff801000392d8,  /* 0x1401060f0: absent */
    0xfffff80100039360,
    0xfffff801000393e8,
    0xfffff801000394a0,
    0xfffff80100039eec,  /* 0x140106110: absent */
    0xfffff80100039f74,
    0xfffff80100039ffc,
    0xfffff8010003a0b4,
    0xfffff8010003a15c,  /* 0x140106130: absent */
    0xfffff8010003a2a0,
    0xfffff8010003c1c4,  /* 0x140106140: absent */
    0xfffff8010003c24c,
    0xfffff8010003d404,  /* 0x140106150: absent */
    0xfffff8010003d48c,
    0xfffff8010003d6d8,  /* 0x140106160: absent */
    0xfffff8010003d6bc,
    0xfffff8010003d63c,
    0x0000000000000000,  /* 0x140106178: live */
    0xfffff8010003d66c,
    0xfffff8010003d650,
    0x0000100031415352,
    0x0000020000000003,
    0x0000000000000000,  /* 0x1401061a0: live */
    0xe968d706bd010001,
    0xbbad1684dd87c4db,
    0x0bd093ca6707fc2b,
    0x2444c9f9322013d1,
    0xdbacd7fdb7b03513,
    0x3694942d9153949c,
    0x5464163ca3c7871a,
    0xd8a0b4d3264ccd4f,
    0x9a8fbf2e07d35f78,
    0xd5729897ce92c936,
    0x719886250e92c26d,
    0xdfff6a2e47d41925,
    0x6d9f602e4d0e1616,
    0x2902fae1b80e91ed,
    0x3ab2c52b9232dc17,
    0x09aee626f6bba3c0,
    0x30257a15d96382b6,
    0x08ac754a6be352e0,
    0xe838a5582d8b2734,
    0x82fb1d8fe22fa47e,
    0xbcc7a3b16b59bc08,
    0x5b7b7a337f86be29,
    0xfab5000df865ea07,
    0xc6ffdc08f598d126,
    0x991f87566f9ffe90,
    0x3864721311c14000,
    0xf7aebef9eda5ea17,
    0x63a614fe9b324aaf,
    0xd53e848c2bb99742,
    0x5ce4225d76fa8d2a,
    0x2cef0d680e8cf045,
    0xb75ac2b8bd3cc583,
    0x8bc4c011b8e2b5ca,
    0x94070ed8f941e255,
    0x8c18ec1522858bd9,
    0xe77cd2234ca3054e,
    0x08d75e5c2027f12e,
    0xf8975287d667eb9d,
    0x4727536cb47769e3,
    0xbfd87fb72a156372,
    0x46e701f445168114,
    0x7925ff41a4e0d1cf,
    0x7e6f3cb54c0c38df,
    0x42709b50b53ad769,
    0xac85e6d498c21d9b,
    0xcf63cc95211ae659,
    0x6e52c3aef611da26,
    0x5ab2b60b747c33d3,
    0x84c0d56dafe64823,
    0x51ea3ba2ae643a49,
    0xce92369355e0c3fc,
    0xd099c18adc40e034,
    0x9b87a18c51003174,
    0xbdec54dadb8b7dd7,
    0xb35eeb1f22243c17,
    0x9f0358e313230b7b,
    0x56ea652349ba184c,
    0xd7f217152f2dcefc,
    0x6c01ee511e3bf07b,
    0x064a011118ff65b7,
    0xc7ba14c436bc14c8,
    0x971f23ad0ce2cbe9,
    0xce5703a88bb1dd1f,
    0x729d5f5ec5a0e70d,
    0x000000c200afa94c,
    0x66c8894838ec8348,  /* 0x1401063b0: absent */
    0x8944662024448944,
    0x40244c8d4c222444,  /* 0x1401063c0: absent */
    0x448d4c2824548948,  /* 0x1401063c8: absent */
    0xd0ffc931d2312024,  /* 0x1401063d0: absent */
    0xeb834828245c8b48,  /* 0x1401063d8: absent */
    0xc238c48348038904,  /* 0x1401063e0: absent */
    0x0000000000000000,  /* 0x1401063e8: live */
    0xe80d867c10be804e,
    0x4d5050ff3e4b3896,
    0x10f31d15c76ad7c2,
    0x4621037a6350442a,
    0x0000000000000000,  /* 0x140106410: live */
    0x0000000000000000,  /* 0x140106418: live */
    0xc2c92173cdc0ee34,
    0x2bd96411f3be0903,
    0xe27fe61d3492e888,
    0xe4c909da7f9e4d68,
    0xb4298eb38f49056b,
    0xcda4c7b8fe45e821,
    0xddabd93aa417f7f6,
    0x6254501cdefdcec8,
    0xf930e607137d5e53,
    0x6ef28bfe142d4a54,
    0x0000000000000000,  /* 0x140106470: live */
    0x0000000000000000,  /* 0x140106478: live */
    0x5cc510e3d0afc1ce,
    0x9172e1b81a60cc1d,
    0x82af5efb32aa0677,
    0x46dd02df7f541368,
    0x0000000000000000,  /* 0x1401064a0: live */
    0x0000000000000000,  /* 0x1401064a8: live */
    0x8e0874904d9ebed8,
    0x5549b66f6fbc18f8,
    0x12554175b27803e9,
    0xaef09c96bdbbee6f,
    0x0000000000000000,  /* 0x1401064d0: live */
    0x0000000000000000,  /* 0x1401064d8: live */
    0xb15c1f0076f44780,
    0x57c3d03f2a1d666a,
    0x00000000e2f56861,
    0x0000000000000000,  /* 0x1401064f8: live */
    0x0000000000000000,  /* 0x140106500: live */
    0x0000000000000000,  /* 0x140106508: live */
    0x0f1ccf0dd05bca6d,
    0xa69cb274d3597032,
    0x00000000a60ac5e3,
    0x0000000000000000,  /* 0x140106528: live */
    0x0000000000000000,  /* 0x140106530: live */
    0x0000000000000000,  /* 0x140106538: live */
    0x344af678947967e7,
    0xfe5790bbf33ff5b3,
    0xb0418017abf46817,
    0x65ba0c211effc0dc,
    0x0000000000000000,  /* 0x140106560: live */
    0x0000000000000000,  /* 0x140106568: live */
    0x7fcd11dc3181c5ee,
    0x07c6db5fb1012551,
    0x16f791ca683b604c,
    0xcfb0ed5420045a2d,
    0x0000000000000000,  /* 0x140106590: live */
    0x0000000000000000,  /* 0x140106598: live */
    0x0a0a4f888df05ee3,
    0x62ce0163e9752fde,
    0x00000000a813f230,
    0x0000000000000000,  /* 0x1401065b8: live */
    0x0000000000000000,  /* 0x1401065c0: live */
    0x0000000000000000,  /* 0x1401065c8: live */
    0xbe13fe8ff2bf20ee,
    0xd5ded6904c291c73,
    0x000000000eece0aa,
    0x0000000000000000,  /* 0x1401065e8: live */
    0x0000000000000000,  /* 0x1401065f0: live */
    0x0000000000000000,  /* 0x1401065f8: live */
    0x40cf32f7c0ad5172,
    0x5499bb35e362e49e,
    0x000000000fd42d4f,
    0x0000000000000000,  /* 0x140106618: live */
    0x0000000000000000,  /* 0x140106620: live */
    0x0000000000000000,  /* 0x140106628: live */
    0x04b3f9510e2e874a,
    0xe96e49dbded19c46,
    0x00000000a483b9b8,
    0x0000000000000000,  /* 0x140106648: live */
    0x0000000000000000,  /* 0x140106650: live */
    0x0000000000000000,  /* 0x140106658: live */
    0x7c3f8c04b425c9b3,
    0x8611102b8a244d44,
    0xdcb56e5939ba7cb5,
    0x192fb3e44e7ae1e0,
    0x0000000000000000,  /* 0x140106680: live */
    0x0000000000000000,  /* 0x140106688: live */
    0x873d0886c3798ea0,
    0x4e143dc109c41450,
    0xf10d98326138240a,
    0xb19e48c83797f51f,
    0x0000000000000000,  /* 0x1401066b0: live */
    0x0000000000000000,  /* 0x1401066b8: live */
    0xe0c0cd7dd3cb257f,
    0xc5c04b7c470d3ed9,
    0x2310af6c9e373142,
    0x6c7a46960d1f1e84,
    0x0000000000000000,  /* 0x1401066e0: live */
    0x0000000000000000,  /* 0x1401066e8: live */
    0x8a601d17af026145,
    0x7b6a377e5d7327e8,
    0x00000000608c7b50,
    0x0000000000000000,  /* 0x140106708: live */
    0x0000000000000000,  /* 0x140106710: live */
    0x0000000000000000,  /* 0x140106718: live */
    0xfb80b4a521072779,
    0x5e115f942089a7d2,
    0x00000000d691c903,
    0x0000000000000000,  /* 0x140106738: live */
    0x0000000000000000,  /* 0x140106740: live */
    0x0000000000000000,  /* 0x140106748: live */
    0xd4b7198d79fac739,
    0x213dd34774094416,
    0x000000000907aa1c,
    0x0000000000000000,  /* 0x140106768: live */
    0x0000000000000000,  /* 0x140106770: live */
    0x0000000000000000,  /* 0x140106778: live */
    0xf1f5118e317b4efc,
    0x5040cb98b2feba63,
    0x00000000d06032b9,
    0x0000000000000000,  /* 0x140106798: live */
    0x0000000000000000,  /* 0x1401067a0: live */
    0x0000000000000000,  /* 0x1401067a8: live */
    0xd9487cd76ca24ab9,
    0x25bd6c5044ac531a,
    0x000000002c361d5e,
    0x0000000000000000,  /* 0x1401067c8: live */
    0x0000000000000000,  /* 0x1401067d0: live */
    0x0000000000000000,  /* 0x1401067d8: live */
    0x21dc69a7e9f68cc3,
    0x0197014d09aaa987,
    0x69487c26ca557ab5,
    0x198b0383984d4e18,
    0x0000000000000000,  /* 0x140106800: live */
    0x0000000000000000,  /* 0x140106808: live */
    0x5009e35fd61440e1,
    0x7fafc6f2f80774a8,
    0x6ee4efc860d77ca4,
    0xe0b4fdc446f7d816,
    0x0000000000000000,  /* 0x140106830: live */
    0x0000000000000000,  /* 0x140106838: live */
    0x9a09ba9e826b14ac,
    0xfba7981716a62258,
    0x0000000069a6dd09,
    0x0000000000000000,  /* 0x140106858: live */
    0x0000000000000000,  /* 0x140106860: live */
    0x0000000000000000,  /* 0x140106868: live */
    0xd16b9de1910d9759,
    0xd80098a65a0f085e,
    0x00000000e1ed2c9f,
    0x0000000000000000,  /* 0x140106888: live */
    0x0000000000000000,  /* 0x140106890: live */
    0x0000000000000000,  /* 0x140106898: live */
    0xf6b8b3b057684eb4,
    0x4b5b79506cd81382,
    0x0000000085c6d7d1,
    0x0000000000000000,  /* 0x1401068b8: live */
    0x0000000000000000,  /* 0x1401068c0: live */
    0x0000000000000000,  /* 0x1401068c8: live */
    0x5176b44db2d2efa3,
    0x3a5554f63cba9650,
    0x0000000028744aa4,
    0x0000000000000000,  /* 0x1401068e8: live */
    0x0000000000000000,  /* 0x1401068f0: live */
    0x0000000000000000,  /* 0x1401068f8: live */
    0xe4176f919363dba1,
    0x02c7150440095518,
    0x000000006baeb040,
    0x0000000000000000,  /* 0x140106918: live */
    0x0000000000000000,  /* 0x140106920: live */
    0x0000000000000000,  /* 0x140106928: live */
    0xd6c7ef6b5ee301df,
    0x867b39179f312556,
    0x00000000568d611e,
    0x0000000000000000,  /* 0x140106948: live */
    0x0000000000000000,  /* 0x140106950: live */
    0x0000000000000000,  /* 0x140106958: live */
    0xea4f1a17356211fd,
    0x8591a5b786e5defe,
    0x00000000e6d75ffb,
    0x0000000000000000,  /* 0x140106978: live */
    0x0000000000000000,  /* 0x140106980: live */
    0x0000000000000000,  /* 0x140106988: live */
    0xe7ff0e8794656532,
    0xed06b9992a655152,
    0x00000000b06b2db9,
    0x0000000000000000,  /* 0x1401069a8: live */
    0x0000000000000000,  /* 0x1401069b0: live */
    0x0000000000000000,  /* 0x1401069b8: live */
    0xbf7392f9c9865e84,
    0xcbd0c8fd3fbc9ae1,
    0x000000002c93d771,
    0x0000000000000000,  /* 0x1401069d8: live */
    0x0000000000000000,  /* 0x1401069e0: live */
    0x0000000000000000,  /* 0x1401069e8: live */
    0x1dece0b89b3e464b,
    0x9efed599a1e8584a,
    0x000000008657095c,
    0x0000000000000000,  /* 0x140106a08: live */
    0x0000000000000000,  /* 0x140106a10: live */
    0x0000000000000000,  /* 0x140106a18: live */
    0xa265748c3a6d3b5b,
    0x7349695ed624e6b1,
    0x00000000eb610d74,
    0x0000000000000000,  /* 0x140106a38: live */
    0x0000000000000000,  /* 0x140106a40: live */
    0x0000000000000000,  /* 0x140106a48: live */
    0xdab039a6a942326b,
    0xbe02b4eec782584d,
    0x000000000cad1566,
    0x0000000000000000,  /* 0x140106a68: live */
    0x0000000000000000,  /* 0x140106a70: live */
    0x0000000000000000,  /* 0x140106a78: live */
    0x500786cdf4131676,
    0x7768febe0f523d8c,
    0xa9426f7473fc3537,
    0x04f0723bba5462fd,
    0xf67c6757afe59479,
    0xf15d96845996c1d2,
    0xd5a8f06816a11dde,
    0x5f75b23aed4633e1,
    0x0b1dfdfcbfbe255d,
    0x912c29bc879f5bde,
    0x0000000000000000,  /* 0x140106ad0: live */
    0x0000000000000000,  /* 0x140106ad8: live */
    0x17cd48e3fc601cc7,
    0xbeed59e7ea32b30c,
    0x000000004e227b16,
    0x0000000000000000,  /* 0x140106af8: live */
    0x0000000000000000,  /* 0x140106b00: live */
    0x0000000000000000,  /* 0x140106b08: live */
    0xbff2b1d32ea84348,
    0x0c94e1601967e9be,
    0x000000008d682f94,
    0x0000000000000000,  /* 0x140106b28: live */
    0x0000000000000000,  /* 0x140106b30: live */
    0x0000000000000000,  /* 0x140106b38: live */
    0x7a468f2b971e1ee9,
    0x388522a98f59e0b4,
    0x00000000c994ee7d,
    0x0000000000000000,  /* 0x140106b58: live */
    0x0000000000000000,  /* 0x140106b60: live */
    0x0000000000000000,  /* 0x140106b68: live */
    0xe232b59cb5c5ad20,
    0x58749c9aa01bf015,
    0x2f5113565506c298,
    0xed7cd1cf5c297cea,
    0x8aca7432bcc5e24f,
    0x3c34b89987c60f27,
    0x6f0c1bb315ba2952,
    0x97775198c289ca4c,
    0x35b9a389b6d12743,
    0xab22af325597bda0,
    0x0000000000000000,  /* 0x140106bc0: live */
    0x0000000000000000,  /* 0x140106bc8: live */
    0x46c45d6f16ff699f,
    0x378294d6d7458a57,
    0x0000000041e15537,
    0x0000000000000000,  /* 0x140106be8: live */
    0x0000000000000000,  /* 0x140106bf0: live */
    0x0000000000000000,  /* 0x140106bf8: live */
    0xb8145f1215ddd8fc,
    0x5e3506888355ec4f,
    0x83ac8b18077478c3,
    0xacf9ad41c8d6c0c2,
    0x63945cccec83ee76,
    0xee315a29c58ff8f1,
    0x5e0d2378fc7d862c,
    0xa32084d15d8cec14,
    0xe72ce3bde5268e0c,
    0x4f9473d413503280,
    0x0000000000000000,  /* 0x140106c50: live */
    0x0000000000000000,  /* 0x140106c58: live */
    0x27ae896a07d4b165,
    0xeab3ecedeee6573f,
    0x76fa768f16b429e1,
    0x22541d46df4c9171,
    0xae16b9859b9dc555,
    0x648e7acf0ffca60c,
    0xc298d4cc8a837e1d,
    0xc09e81af7393bae5,
    0x000000005c95bb97,
    0x0000000000000000,  /* 0x140106ca8: live */
    0x0000000000000000,  /* 0x140106cb0: live */
    0x0000000000000000,  /* 0x140106cb8: live */
    0xa982b9104bb3a14e,
    0x207850435891386a,
    0xe34383ad6a2c63ad,
    0x6f36d80c664db337,
    0xae6806e84a5454a1,
    0x96197ed53139df1f,
    0x68ce2c31c7ed5c40,
    0x7989c1fbb087aaee,
    0x00000000a93a03da,
    0x0000000000000000,  /* 0x140106d08: live */
    0x0000000000000000,  /* 0x140106d10: live */
    0x0000000000000000,  /* 0x140106d18: live */
    0x4742a722b9f41a12,
    0x9c6037de50df49ea,
    0xb72c6be01f1a45c1,
    0x9581bd92b479e0e1,
    0x0000000000000000,  /* 0x140106d40: live */
    0x0000000000000000,  /* 0x140106d48: live */
    0x9ff49d9872e3509d,
    0x763759d81206cd90,
    0x00000000fcfc86b7,
    0x0000000000000000,  /* 0x140106d68: live */
    0x0000000000000000,  /* 0x140106d70: live */
    0x0000000000000000,  /* 0x140106d78: live */
    0x4e6a326bfd3e5311,
    0x05fe00e36d935a06,
    0x249d563df979a486,
    0xb2f135adc762bd03,
    0xf410b5ade3ae9d19,
    0xe324b0b497fcc429,
    0x1d09c62b72d229a2,
    0xc98810b879d9b173,
    0x26bf7c6f8a02cb77,
    0xf899f0c85c1db84b,
    0xd709bf486e297c7d,
    0xa4618649f575e2eb,
    0xa96fe86d4ce45ec5,
    0x4a0def840fc93fac,
    0x4720116aac5aad6c,
    0xd1ae47757e998bc8,
    0x0000000000000000,  /* 0x140106e00: live */
    0x0000000000000000,  /* 0x140106e08: live */
    0x76990d1b07bf9550,
    0xd2e1f41284e00ae4,
    0x000000008cb5af41,
    0x0000000000000000,  /* 0x140106e28: live */
    0x0000000000000000,  /* 0x140106e30: live */
    0x0000000000000000,  /* 0x140106e38: live */
    0x22de12763f3a5427,
    0x022472218322c761,
    0x00000000de073af6,
    0x0000000000000000,  /* 0x140106e58: live */
    0x0000000000000000,  /* 0x140106e60: live */
    0x0000000000000000,  /* 0x140106e68: live */
    0x3fed8fb4f337226f,
    0xe4a0cacc3f5c2f6d,
    0x4b0d42e56e927546,
    0x4b81ef1e05f50f84,
    0x0000000000000000,  /* 0x140106e90: live */
    0x0000000000000000,  /* 0x140106e98: live */
    0x9956d143af27c7fe,
    0x6771b98e6ea2ce95,
    0x443085b1a5425816,
    0xc55412b7032ca925,
    0x3ef31575832212d5,
    0xba25c6e8d28ecb60,
    0x0d37e176093c6517,
    0xb1dea6f4eab584a5,
    0x59122f7cd9cab7d3,
    0xbd882b30c5967b2e,
    0x0aef6359fa300be2,
    0x9e8eb4833006f2c9,
    0x0e358b7ba3bb30c1,
    0x77784f6bd75efd89,
    0x29e7b9d320e2ee7f,
    0x4c8e6ef46aef2b04,
    0x680c08b3322e251b,
    0x3c0addafa1a8c91b,
    0x71f8985845e34cc6,
    0x58ac2a41da141cd1,
    0xc08a3d21d42220fa,
    0xfcb02f9b90d68d5f,
    0xbcf53d91a1196cc7,
    0xd115ad292266b10c,
    0xfffff80100106098,  /* 0x140106f60: local-const */
    0xfffff801001060c0,  /* 0x140106f68: local-const */
    0xfffff80100106110,  /* 0x140106f70: local-const */
    0xfffff80100106130,  /* 0x140106f78: local-const */
    0x00000000ffffffff,
    0x0000000100000000,
    0x0000000000000002,  /* 0x140106f90: absent */
    0x49a9d97af0e20f09,
    0x2ebbe6226ebb4680,
    0x0000000000000002,
    0x0000000000000000,  /* 0x140106fb0: live */
    0x0000000000000000,  /* 0x140106fb8: live */
    0x0000000000000002,  /* 0x140106fc0: unknown */
    0x0000000000000000,  /* 0x140106fc8: live */
    0x0000000000000000,  /* 0x140106fd0: live */
    0x0000000000000000,  /* 0x140106fd8: live */
    0x0000000000000000,  /* 0x140106fe0: live */
    0x0000000000000000,  /* 0x140106fe8: live */
    0x0000000000000000,  /* 0x140106ff0: live */
    0x0000000000000000,  /* 0x140106ff8: live */
    0x0000000000000000,  /* 0x140107000: unknown; live */
    0x0000000000000000,  /* 0x140107008: absent; live */
    0x0000000000000000,  /* 0x140107010: absent; live */
    0x0000000000000000,  /* 0x140107018: absent; live */
    0xffffb0000006f000,  /* 0x140107020: absent */
    0x0000000000000000,  /* 0x140107028: absent; live */
    0x0000000000000000,  /* 0x140107030: absent; live */
    0x0000000000000000,  /* 0x140107038: absent; live */
    0x0000000000000000,  /* 0x140107040: absent; live */
    0x0000000000000000,  /* 0x140107048: live */
    0x0000000000000000,  /* 0x140107050: live */
    0x0000000000000000,  /* 0x140107058: live */
    0x0000000000000000,  /* 0x140107060: live */
    0x0000000000000000,  /* 0x140107068: live */
    0x0000000000000000,  /* 0x140107070: live */
    0x0000000000000000,  /* 0x140107078: live */
    0x0000000000000000,  /* 0x140107080: live */
    0x0000000000000000,  /* 0x140107088: live */
    0x0000000000000000,  /* 0x140107090: live */
    0x0000000000000000,  /* 0x140107098: live */
    0x0000000000000000,  /* 0x1401070a0: live */
    0x0000000000000000,  /* 0x1401070a8: live */
    0x0000000000000000,  /* 0x1401070b0: live */
    0x0000000000000000,  /* 0x1401070b8: live */
    0x0000000000000000,  /* 0x1401070c0: live */
    0x0000000000000000,  /* 0x1401070c8: live */
    0x0000000000000000,  /* 0x1401070d0: live */
    0x0000000000000000,  /* 0x1401070d8: live */
    0x0000000000000000,  /* 0x1401070e0: live */
    0x0000000000000000,  /* 0x1401070e8: live */
    0x0000000000000000,  /* 0x1401070f0: live */
    0x0000000000000000,  /* 0x1401070f8: live */
    0x0000000000000000,  /* 0x140107100: live */
    0x0000000000000000,  /* 0x140107108: live */
    0x0000000000000000,  /* 0x140107110: live */
    0x0000000000000000,  /* 0x140107118: live */
    0x0000000000000000,  /* 0x140107120: live */
    0x0000000000000000,  /* 0x140107128: live */
    0x0000000000000000,  /* 0x140107130: live */
    0x0000000000000000,  /* 0x140107138: live */
    0x0000000000000000,  /* 0x140107140: live */
    0x0000000000000000,  /* 0x140107148: live */
    0x0000000000000000,  /* 0x140107150: live */
    0x0000000000000000,  /* 0x140107158: live */
    0x0000000000000000,  /* 0x140107160: live */
    0x0000000000000000,  /* 0x140107168: live */
    0x0000000000000000,  /* 0x140107170: live */
    0x0000000000000000,  /* 0x140107178: live */
    0x0000000000000000,  /* 0x140107180: live */
    0x0000000000000000,  /* 0x140107188: live */
    0x0000000000000000,  /* 0x140107190: live */
    0x0000000000000000,  /* 0x140107198: live */
    0x0000000000000000,  /* 0x1401071a0: live */
    0x0000000000000000,  /* 0x1401071a8: live */
    0x0000000000000000,  /* 0x1401071b0: live */
    0x0000000000000000,  /* 0x1401071b8: live */
    0x0000000000000000,  /* 0x1401071c0: live */
    0x0000000000000000,  /* 0x1401071c8: live */
    0x0000000000000000,  /* 0x1401071d0: live */
    0x0000000000000000,  /* 0x1401071d8: live */
    0x0000000000000000,  /* 0x1401071e0: live */
    0x0000000000000000,  /* 0x1401071e8: live */
    0x0000000000000000,  /* 0x1401071f0: live */
    0x0000000000000000,  /* 0x1401071f8: live */
    0x0000000000000000,  /* 0x140107200: live */
    0x0000000000000000,  /* 0x140107208: live */
    0x0000000000000000,  /* 0x140107210: live */
    0x0000000000000000,  /* 0x140107218: live */
    0x0000000000000000,  /* 0x140107220: live */
    0x0000000000000000,  /* 0x140107228: live */
    0x0000000000000000,  /* 0x140107230: live */
    0x0000000000000000,  /* 0x140107238: live */
    0x0000000000000000,  /* 0x140107240: live */
    0x0000000000000000,  /* 0x140107248: live */
    0x0000000000000000,  /* 0x140107250: live */
    0x0000000000000000,  /* 0x140107258: live */
    0x0000000000000000,  /* 0x140107260: absent; live */
    0x0000000000000000,  /* 0x140107268: absent; live */
    0x0000000000000000,  /* 0x140107270: absent; live */
    0x0000000000000000,  /* 0x140107278: live */
    0x0000000000000000,  /* 0x140107280: live */
    0x0000000000000000,  /* 0x140107288: live */
    0x0000000000000000,  /* 0x140107290: live */
    0x0000000000000000,  /* 0x140107298: live */
    0x0000000000000000,  /* 0x1401072a0: live */
    0x0000000000000000,  /* 0x1401072a8: unknown; live */
    0x0000000000000000,  /* 0x1401072b0: unknown; live */
    0x0000000000000000,  /* 0x1401072b8: unknown; live */
    0x0000000000000000,  /* 0x1401072c0: unknown; live */
    0x0000000000000000,  /* 0x1401072c8: live */
    0x0000000000000000,  /* 0x1401072d0: live */
    0x0000000000000000,  /* 0x1401072d8: live */
    0x0000000000000000,  /* 0x1401072e0: live */
    0x0000000000000000,  /* 0x1401072e8: live */
    0x0000000000000000,  /* 0x1401072f0: live */
    0x0000000000000000,  /* 0x1401072f8: live */
    0x0000000000000000,  /* 0x140107300: unknown; live */
    0x0000000000000000,  /* 0x140107308: unknown; live */
    0x0000000000000000,  /* 0x140107310: unknown; live */
    0x0000000000000000,  /* 0x140107318: unknown; live */
    0x0000000000000000,  /* 0x140107320: live */
    0x0000000000000000,  /* 0x140107328: live */
    0x0000000000000000,  /* 0x140107330: live */
    0x0000000000000000,  /* 0x140107338: live */
    0x0000000000000000,  /* 0x140107340: live */
    0x0000000000000000,  /* 0x140107348: live */
    0x0000000000000000,  /* 0x140107350: live */
    0x0000000000000000,  /* 0x140107358: absent; live */
    0x0000000000000000,  /* 0x140107360: absent; live */
    0x0000000000000000,  /* 0x140107368: absent; live */
    0x0000000000000000,  /* 0x140107370: absent; live */
    0x0000000000000000,  /* 0x140107378: unknown; live */
    0x0000000000000000,  /* 0x140107380: unknown; live */
    0x0000000000000000,  /* 0x140107388: unknown; live */
    0x0000000000000000,  /* 0x140107390: unknown; live */
    0x0000000000000000,  /* 0x140107398: absent; live */
    0x0000000000000000,  /* 0x1401073a0: absent; live */
    0x0000000000000000,  /* 0x1401073a8: absent; live */
    0x68c707284bb4110c,  /* 0x1401073b0: local-det; ntoskrnl.exe!RtlDowncaseUnicodeString */
    0x9738ff2b4bd3a40c,  /* 0x1401073b8: local-det */
    0x8622a34a40afdd9f,  /* 0x1401073c0: unknown; ntoskrnl.exe!KeLeaveCriticalRegion */
    0x79dd5b494083675f,  /* 0x1401073c8: unknown */
    0xbe97e3ef93e3d2da,  /* 0x1401073d0: unknown; ntoskrnl.exe!PsLookupProcessByProcessId */
    0x41681bec93818e7a,  /* 0x1401073d8: unknown */
    0xff2ceba3c1fd309b,  /* 0x1401073e0: local-det; ntoskrnl.exe!PsReleaseProcessExitSynchronization */
    0x00d313a0c195396b,  /* 0x1401073e8: local-det */
    0x82226f183468a66f,  /* 0x1401073f0: local-det; ntoskrnl.exe!MmCopyMemory */
    0x7ddd971b3458665f,  /* 0x1401073f8: local-det */
    0x4c6d0fcd3ac0a01f,  /* 0x140107400: unknown; ntoskrnl.exe!ObfDereferenceObject */
    0xb392f7ce3aec182f,  /* 0x140107408: unknown */
    0x772a0bee26e637fb,  /* 0x140107410: local-det; ntoskrnl.exe!IofCallDriver */
    0x88d5f3ed26cb168b,  /* 0x140107418: local-det */
    0x221acb50f922751c,  /* 0x140107420: local-det; ntoskrnl.exe!_strnicmp */
    0xdde53353f91f629c,  /* 0x140107428: local-det */
    0xb8618fb6d963fbf5,  /* 0x140107430: local-det; ntoskrnl.exe!KeStackAttachProcess */
    0x479e77b5d9464285,  /* 0x140107438: local-det */
    0xe8e12b5e8d36c6cd,  /* 0x140107440: local-det; ntoskrnl.exe!IoGetDeviceObjectPointer */
    0x171ed35d8d54d48d,  /* 0x140107448: local-det */
    0xd7f9cf351d57e36e,  /* 0x140107450: local-det; ntoskrnl.exe!KeUnstackDetachProcess */
    0x280637361d7796ee,  /* 0x140107458: local-det */
    0x090ecfc870e28da8,  /* 0x140107460: local-det; ntoskrnl.exe!KeInitializeEvent */
    0xf6f137cb70cfcd08,  /* 0x140107468: local-det */
    0xba90a34b8dbfceaa,  /* 0x140107470: local-det; ntoskrnl.exe!KeWaitForSingleObject */
    0x456f5b488d9390aa,  /* 0x140107478: local-det */
    0xa238abe3787024e3,  /* 0x140107480: unknown; ntoskrnl.exe!PsAcquireProcessExitSynchronization */
    0x5dc753e078113ef3,  /* 0x140107488: unknown */
    0x0f4d6fda5cbe41a4,  /* 0x140107490: unknown; ntoskrnl.exe!ExAcquireResourceSharedLite */
    0xf0b297d95c9287d4,  /* 0x140107498: unknown */
    0x16e64b58cd2a232e,  /* 0x1401074a0: unknown; ntoskrnl.exe!ExFreePoolWithTag */
    0xe919b35bcdb1626e,  /* 0x1401074a8: unknown */
    0x7429eb4a73a6684c,  /* 0x1401074b0: unknown; ntoskrnl.exe!ExReleaseResourceLite */
    0x8bd61349738ad34c,  /* 0x1401074b8: unknown */
    0xd50e234f6b925fac,  /* 0x1401074c0: local-det; ntoskrnl.exe!IoBuildDeviceIoControlRequest */
    0x2af1db4c6bb0e50c,  /* 0x1401074c8: local-det */
    0x2b75234a018b50db,  /* 0x1401074d0: unknown; ntoskrnl.exe!KeEnterCriticalRegion */
    0xd48adb4901a6497b,  /* 0x1401074d8: unknown */
    0xf86deb190790ea53,  /* 0x1401074e0: runtime-vm */
    0x0792131a06b6ea53,  /* 0x1401074e8: runtime-vm */
    0x74f003dba2e199b4,  /* 0x1401074f0: local-det; ntoskrnl.exe!RtlUnicodeToUTF8N */
    0x8b0ffbd8a2885ef4,  /* 0x1401074f8: local-det */
    0x6ec02bd8b02fe783,  /* 0x140107500: unknown; ntoskrnl.exe!ExAllocatePool */
    0x913fd3dbb01d5873,  /* 0x140107508: unknown */
    0x7848237c2174fe2a,  /* 0x140107510: local-det; ntoskrnl.exe!IoFreeWorkItem */
    0x87b7db7f214579da,  /* 0x140107518: local-det */
    0x33c26f65ad8deac8,  /* 0x140107520: local-det; cng.sys!BCryptEncrypt */
    0xcc3d9766aca40af8,  /* 0x140107528: local-det */
    0xaf2707bdc6c09365,  /* 0x140107530: local-det; ntoskrnl.exe!RtlRandomEx */
    0x50d8ffbec6f5e1b5,  /* 0x140107538: local-det */
    0xe1c3cf68d49c1203,  /* 0x140107540: local-det; ntoskrnl.exe!KeQueryPerformanceCounter */
    0x1e3c376bd4beaeb3,  /* 0x140107548: local-det */
    0xdd6b677c58a84af7,  /* 0x140107550: unknown; ntoskrnl.exe!IoQueueWorkItem */
    0x22949f7f589891e7,  /* 0x140107558: local-det */
    0xd7c3c3bb825fd41f,  /* 0x140107560: unknown; ntoskrnl.exe!ZwClose */
    0x283c3bb88260484f,  /* 0x140107568: local-det */
    0x57d9e39c40ec59c8,  /* 0x140107570: local-det; ntoskrnl.exe!ZwFlushBuffersFile */
    0xa8261b9f40d3fa18,  /* 0x140107578: local-det */
    0x2cdae35fb2344491,  /* 0x140107580: local-det; ntoskrnl.exe!RtlTimeToTimeFields */
    0xd3251b5cb2029af1,  /* 0x140107588: local-det */
    0x5613833dec2016c4,  /* 0x140107590: unknown; ntoskrnl.exe!IoAllocateWorkItem */
    0xa9ec7b3eec10daf4,  /* 0x140107598: local-det */
    0x4aa7eb19394d1051,  /* 0x1401075a0: runtime-vm */
    0xb558131a38651051,  /* 0x1401075a8: runtime-vm */
    0x1e01efddd2e14588,  /* 0x1401075b0: local-det; ntoskrnl.exe!ZwWriteFile */
    0xe1fe17ded2dedef8,  /* 0x1401075b8: local-det */
    0xffffeb1454112026,  /* 0x1401075c0: unknown */
    0x0000131754112026,  /* 0x1401075c8: unknown */
    0xbf048ff65fbe27ea,  /* 0x1401075d0: local-det; ntoskrnl.exe!IoCreateFileEx */
    0x40fb77f55fde913a,  /* 0x1401075d8: local-det */
    0x8e32437764d58e31,  /* 0x1401075e0: local-det; ntoskrnl.exe!MmProtectMdlSystemAddress */
    0x71cdbb746486aec1,  /* 0x1401075e8: local-det */
    0x37c5ef47275ad12b,  /* 0x1401075f0: local-det; ntoskrnl.exe!MmMapLockedPagesSpecifyCache */
    0xc83a17442778bdab,  /* 0x1401075f8: local-det */
    0xb940cbc7aeacf5de,  /* 0x140107600: local-det; ntoskrnl.exe!MmUnmapLockedPages */
    0x46bf33c4ae85251e,  /* 0x140107608: local-det */
    0x9899e3c62c506bdf,  /* 0x140107610: local-det; ntoskrnl.exe!IoFreeMdl */
    0x67661bc52c65c0bf,  /* 0x140107618: local-det */
    0x68750b67f931963a,  /* 0x140107620: local-det; ntoskrnl.exe!MmUnlockPages */
    0x978af364f915d5da,  /* 0x140107628: local-det */
    0x3511a7e098120ef2,  /* 0x140107630: local-det; ntoskrnl.exe!IoAllocateMdl */
    0xcaee5fe39827afe2,  /* 0x140107638: local-det */
    0x1a6b6b60df4ae526,  /* 0x140107640: local-det; ntoskrnl.exe!MmProbeAndLockPages */
    0xe5949363df6a73f6,  /* 0x140107648: local-det */
    0x77f067720e579a87,  /* 0x140107650: local-det; ntoskrnl.exe!ZwAllocateVirtualMemory */
    0x880f9f710e6807f7,  /* 0x140107658: local-det */
    0x8cb887d41a40683e,  /* 0x140107660: unknown; ntoskrnl.exe!IoGetCurrentProcess */
    0x73477fd71a6bd4ae,  /* 0x140107668: local-det */
    0x212dc36304d21f5f,  /* 0x140107670: local-det; ntoskrnl.exe!KeTestAlertThread */
    0xded23b6004e61a1f,  /* 0x140107678: local-det */
    0x217e8fa702a1f66b,  /* 0x140107680: local-det; ntoskrnl.exe!KeInsertQueueApc */
    0xde8177a40284074b,  /* 0x140107688: local-det */
    0xae75aba9f31186a7,  /* 0x140107690: local-det; ntoskrnl.exe!PsGetThreadTeb */
    0x518a53aaf32109e7,  /* 0x140107698: local-det */
    0x38426fd2cd727646,  /* 0x1401076a0: local-det; ntoskrnl.exe!wcsncpy */
    0xc7bd97d1cd4f4fc6,  /* 0x1401076a8: local-det */
    0x69648f20c5d8c3a8,  /* 0x1401076b0: local-det; ntoskrnl.exe!KeInitializeApc */
    0x969b7723c5ecddd8,  /* 0x1401076b8: local-det */
    0x4a7b6ff08e35f990,  /* 0x1401076c0: local-det; ntoskrnl.exe!_snwprintf */
    0xb58497f38e08ec00,  /* 0x1401076c8: local-det */
    0x58e347cdaf8be143,  /* 0x1401076d0: unknown; ntoskrnl.exe!strncmp */
    0xa71cbfceafb6ef03,  /* 0x1401076d8: local-det */
    0xc01aa76249bf095b,  /* 0x1401076e0: local-det; ntoskrnl.exe!PsGetProcessWow64Process */
    0x3fe55f614990741b,  /* 0x1401076e8: local-det */
    0x4bafeb30875e7129,  /* 0x1401076f0: local-det; ntoskrnl.exe!RtlImageDirectoryEntryToData */
    0xb4501333877b5a19,  /* 0x1401076f8: local-det */
    0x17104fd890cf8aab,  /* 0x140107700: local-det; ntoskrnl.exe!RtlGetVersion */
    0xe8efb7db90a77f7b,  /* 0x140107708: local-det */
    0x9c59c344822b8bc7,  /* 0x140107710: local-det; ntoskrnl.exe!IoGetRequestorProcess */
    0x63a63b4782061267,  /* 0x140107718: local-det */
    0x9c27af365169c422,  /* 0x140107720: local-det; ntoskrnl.exe!IofCompleteRequest */
    0x63d85735514dea22,  /* 0x140107728: local-det */
    0xa6f7eb5f577f7949,  /* 0x140107730: local-det; ntoskrnl.exe!ZwCreateSection */
    0x5908135c5740daf9,  /* 0x140107738: local-det */
    0x75862b3e32819834,  /* 0x140107740: local-det; ntoskrnl.exe!KeAcquireSpinLockRaiseToDpc */
    0x8a79d33d32ac11d4,  /* 0x140107748: local-det */
    0x139487ec9c5a171f,  /* 0x140107750: local-det; ntoskrnl.exe!swprintf */
    0xec6b7fef9c670f3f,  /* 0x140107758: local-det */
    0x57d42f65971fa4b8,  /* 0x140107760: local-det; ntoskrnl.exe!IoCreateSymbolicLink */
    0xa82bd766976976a8,  /* 0x140107768: local-det */
    0x15c08f58aba47904,  /* 0x140107770: local-det; ntoskrnl.exe!MmMapViewInSystemSpace */
    0xea3f775babce5d74,  /* 0x140107778: local-det */
    0xde9d4b6f52d7dc93,  /* 0x140107780: local-det; ntoskrnl.exe!ExReleaseFastMutex */
    0x2162b36c52fb4f83,  /* 0x140107788: local-det */
    0xd1cba3e02ae29cbe,  /* 0x140107790: local-det; ntoskrnl.exe!PsReferenceProcessFilePointer */
    0x2e345be32a82d75e,  /* 0x140107798: local-det */
    0x18ecafcaae0adcca,  /* 0x1401077a0: local-det; ntoskrnl.exe!KeDelayExecutionThread */
    0xe71357c9ae2fb03a,  /* 0x1401077a8: local-det */
    0xacfe4f6c26c3bfef,  /* 0x1401077b0: local-det; ntoskrnl.exe!strncpy */
    0x5301b76f26fe8c8f,  /* 0x1401077b8: local-det */
    0xcd156fee3caad4b0,  /* 0x1401077c0: unknown; ntoskrnl.exe!PsGetCurrentProcessId */
    0x32ea97ed3c87f4c0,  /* 0x1401077c8: unknown */
    0x4c0fe7f8e832530a,  /* 0x1401077d0: unknown; ntoskrnl.exe!MmUnmapViewInSystemSpace */
    0xb3f01ffbe85aa66a,  /* 0x1401077d8: local-det */
    0xfd85eb1bc7ce842d,  /* 0x1401077e0: runtime-vm */
    0x027a1318c6dc842d,  /* 0x1401077e8: runtime-vm */
    0x86c88fbf3cbd21c6,  /* 0x1401077f0: local-det; ntoskrnl.exe!ExAcquireFastMutex */
    0x793777bc3c9186b6,  /* 0x1401077f8: local-det */
    0xad5f23751ed76ab2,  /* 0x140107800: local-det; ntoskrnl.exe!IoReleaseCancelSpinLock */
    0x52a0db761efadc62,  /* 0x140107808: local-det */
    0x419b03f568623b8c,  /* 0x140107810: local-det; ntoskrnl.exe!IoCreateDevice */
    0xbe64fbf66813abdc,  /* 0x140107818: local-det */
    0x93de23ce54307365,  /* 0x140107820: local-det; ntoskrnl.exe!IoQueryFileDosDeviceName */
    0x6c21dbcd54527be5,  /* 0x140107828: local-det */
    0x1bc74b5f3ce458a2,  /* 0x140107830: unknown; ntoskrnl.exe!ZwQuerySystemInformation */
    0xe438b35c3cdbf992,  /* 0x140107838: local-det */
    0x07b547e8eb04fbca,  /* 0x140107840: unknown; ntoskrnl.exe!ObReferenceObjectByHandle */
    0xf84abfebeb67192a,  /* 0x140107848: unknown */
    0xdfb10bff44cb9ef8,  /* 0x140107850: local-det; ntoskrnl.exe!KeReleaseSpinLock */
    0x204ef3fc44e59288,  /* 0x140107858: local-det */
    0x35c40346b2b0b35f,  /* 0x140107860: local-det; ntoskrnl.exe!IoDeleteDevice */
    0xca3bfb45b286b15f,  /* 0x140107868: local-det */
    0x4890cb744f32a795,  /* 0x140107870: local-det; ntoskrnl.exe!IoGetRequestorProcessId */
    0xb76f33774f0e5545,  /* 0x140107878: local-det */
    0xb61f8356884299a2,  /* 0x140107880: local-det; ntoskrnl.exe!IoDeleteSymbolicLink */
    0x49e07b5588358732,  /* 0x140107888: local-det */
    0x5f41ebfd30acefbf,  /* 0x140107890: local-det; ntoskrnl.exe!ObOpenObjectByPointer */
    0xa0be13fe30c9d0af,  /* 0x140107898: local-det */
    0xdf08e3ba2fe2ed2f,  /* 0x1401078a0: local-det; ntoskrnl.exe!IoDriverObjectType */
    0x20f71bb92f2d2887,  /* 0x1401078a8: local-det */
    0xb672aba89a63624f,  /* 0x1401078b0: unknown; fltmgr.sys!FltReleasePushLock */
    0x498d53ab9b70efcf,  /* 0x1401078b8: local-det */
    0x9ed427260557784f,  /* 0x1401078c0: local-det; ntoskrnl.exe!ObReferenceObjectByName */
    0x612bdf25053ae5af,  /* 0x1401078c8: local-det */
    0x96c8eb7a60bd35f9,  /* 0x1401078d0: local-det; ntoskrnl.exe!IoDeviceObjectType */
    0x693713796072fde9,  /* 0x1401078d8: local-det */
    0x6f6943baaed980e0,  /* 0x1401078e0: unknown; ntoskrnl.exe!PsGetProcessId */
    0x9096bbb9aeedc650,  /* 0x1401078e8: unknown */
    0xee73474f3bb0fe87,  /* 0x1401078f0: unknown; ntoskrnl.exe!ObReferenceObjectByPointer */
    0x118cbf4c3b850a17,  /* 0x1401078f8: local-det */
    0x4141e34eed60d41a,  /* 0x140107900: unknown; ntoskrnl.exe!ObfReferenceObject */
    0xbebe1b4ded4c6d5a,  /* 0x140107908: local-det */
    0xf28f6b7c5ebbfa9c,  /* 0x140107910: local-det; ntoskrnl.exe!ExEnumHandleTable */
    0x0d70937f5eddadac,  /* 0x140107918: local-det */
    0xd9b8afe021ae9210,  /* 0x140107920: local-det; ntoskrnl.exe!IoGetDeviceAttachmentBaseRef */
    0x264757e3219a5730,  /* 0x140107928: local-det */
    0x6d128fddf0b063b4,  /* 0x140107930: local-det; ntoskrnl.exe!ZwQuerySymbolicLinkObject */
    0x92ed77def08fa5e4,  /* 0x140107938: local-det */
    0xb348efe12c664eaf,  /* 0x140107940: local-det; ntoskrnl.exe!ZwQueryObject */
    0x4cb717e22c59d2df,  /* 0x140107948: local-det */
    0xc3de272327c88aea,  /* 0x140107950: local-det; ntoskrnl.exe!ExfUnblockPushLock */
    0x3c21df2027f706da,  /* 0x140107958: local-det */
    0xff7403dea2c9c090,  /* 0x140107960: local-det; ntoskrnl.exe!ObQueryNameString */
    0x008bfbdda2b93960,  /* 0x140107968: local-det */
    0x5451affa2faa9487,  /* 0x140107970: local-det; ntoskrnl.exe!KeAcquireQueuedSpinLock */
    0xabae57f92f838677,  /* 0x140107978: local-det */
    0xeeae4f7a669d75e0,  /* 0x140107980: local-det; ntoskrnl.exe!KeReleaseQueuedSpinLock */
    0x1151b77966b467b0,  /* 0x140107988: local-det */
    0x62002b38440f0044,  /* 0x140107990: local-det; ntoskrnl.exe!MmSystemRangeStart */
    0x9dffd33b440d23ec,  /* 0x140107998: local-det */
    0xf844a3f33062a144,  /* 0x1401079a0: local-det; ntoskrnl.exe!ZwOpenDirectoryObject */
    0x07bb5bf0305d0434,  /* 0x1401079a8: local-det */
    0x7cb00344c7f04198,  /* 0x1401079b0: unknown; ntoskrnl.exe!MmIsAddressValid */
    0x834ffb47c7a32b28,  /* 0x1401079b8: local-det */
    0xd5d7cffec152f2f0,  /* 0x1401079c0: local-det; ntoskrnl.exe!IoGetDeviceProperty */
    0x2a2837fdc1397880,  /* 0x1401079c8: local-det */
    0xd1482b7820478052,  /* 0x1401079d0: unknown; ntoskrnl.exe!RtlPrefixUnicodeString */
    0x2eb7d37b20195bb2,  /* 0x1401079d8: local-det */
    0x238527287ae3ef80,  /* 0x1401079e0: unknown; fltmgr.sys!FltAcquirePushLockShared */
    0xdc7adf2b7bf062c0,  /* 0x1401079e8: local-det */
    0x19dc2fe958a20b8a,  /* 0x1401079f0: unknown; ntoskrnl.exe!IoFileObjectType */
    0xe623d7ea586dcfc2,  /* 0x1401079f8: local-det */
    0x6d8c07f47f610e95,  /* 0x140107a00: unknown; ntoskrnl.exe!RtlEqualUnicodeString */
    0x9273fff77f011a85,  /* 0x140107a08: local-det */
    0x8ad063fd7f1b5768,  /* 0x140107a10: local-det; ntoskrnl.exe!ZwOpenSymbolicLinkObject */
    0x752f9bfe7f249758,  /* 0x140107a18: local-det */
    0x3c792fa64e27c1d1,  /* 0x140107a20: unknown; ntoskrnl.exe!ObGetObjectType */
    0xc386d7a54e4ed411,  /* 0x140107a28: local-det */
    0x51cfeb14b0b82ca6,  /* 0x140107a30: runtime-vm */
    0xae301317b1be2ca6,  /* 0x140107a38: runtime-vm */
    0x4f0bcf5fe7e439c0,  /* 0x140107a40: local-det; ntoskrnl.exe!KeLowerIrql */
    0xb0f4375ce7cffa20,  /* 0x140107a48: local-det */
    0x72c7277b0cf027fd,  /* 0x140107a50: local-det; ntoskrnl.exe!KeSetTimer */
    0x8d38df780cd5d24d,  /* 0x140107a58: local-det */
    0x2e508731d3e04ac8,  /* 0x140107a60: local-det; ntoskrnl.exe!ZwWaitForSingleObject */
    0xd1af7f32d3dfd038,  /* 0x140107a68: local-det */
    0x0000000000000000,  /* 0x140107a70: absent; live */
    0x0000000000000000,  /* 0x140107a78: absent; live */
    0x0000000000000000,  /* 0x140107a80: absent; live */
    0x0000000000000000,  /* 0x140107a88: absent; live */
    0x0000000000000000,  /* 0x140107a90: absent; live */
    0x0000000000000000,  /* 0x140107a98: absent; live */
    0x0000000000000000,  /* 0x140107aa0: absent; live */
    0x0000000000000000,  /* 0x140107aa8: absent; live */
    0x317ce37e286c4104,  /* 0x140107ab0: local-det; ntoskrnl.exe!KfRaiseIrql */
    0xce831b7d284dbb64,  /* 0x140107ab8: local-det */
    0x0000000000000000,  /* 0x140107ac0: absent; live */
    0x0000000000000000,  /* 0x140107ac8: absent; live */
    0x0000000000000000,  /* 0x140107ad0: absent; live */
    0x0000000000000000,  /* 0x140107ad8: absent; live */
    0xf0ad43567911a885,  /* 0x140107ae0: local-det; ntoskrnl.exe!PsTerminateSystemThread */
    0x0f52bb55797b9bc5,  /* 0x140107ae8: local-det */
    0x0000000000000000,  /* 0x140107af0: absent; live */
    0x0000000000000000,  /* 0x140107af8: absent; live */
    0x68f40b4bc5c271b1,  /* 0x140107b00: local-det; ntoskrnl.exe!KeWaitForMultipleObjects */
    0x970bf348c5e6c4b1,  /* 0x140107b08: local-det */
    0x0000000000000000,  /* 0x140107b10: absent; live */
    0x0000000000000000,  /* 0x140107b18: absent; live */
    0xe124eb5ad43dfca0,  /* 0x140107b20: local-det; ntoskrnl.exe!KeSetBasePriorityThread */
    0x1edb1359d4187a60,  /* 0x140107b28: local-det */
    0x0000000000000000,  /* 0x140107b30: absent; live */
    0x0000000000000000,  /* 0x140107b38: absent; live */
    0x0000000000000000,  /* 0x140107b40: absent; live */
    0x0000000000000000,  /* 0x140107b48: absent; live */
    0x0000000000000000,  /* 0x140107b50: absent; live */
    0x0000000000000000,  /* 0x140107b58: absent; live */
    0xeece03c8346fadd3,  /* 0x140107b60: unknown; ntoskrnl.exe!KeSetEvent */
    0x1131fbcb344391e3,  /* 0x140107b68: local-det */
    0x0000000000000000,  /* 0x140107b70: absent; live */
    0x0000000000000000,  /* 0x140107b78: absent; live */
    0x0000000000000000,  /* 0x140107b80: absent; live */
    0x0000000000000000,  /* 0x140107b88: absent; live */
    0x0000000000000000,  /* 0x140107b90: absent; live */
    0x0000000000000000,  /* 0x140107b98: absent; live */
    0xa7360be8b21219b8,  /* 0x140107ba0: local-det; ntoskrnl.exe!KeInitializeTimer */
    0x58c9f3ebb22620c8,  /* 0x140107ba8: local-det */
    0x0000000000000000,  /* 0x140107bb0: absent; live */
    0x0000000000000000,  /* 0x140107bb8: absent; live */
    0x14f26f6b4b3ac6dd,  /* 0x140107bc0: local-det; ntoskrnl.exe!KeCancelTimer */
    0xeb0d97684b1f3c7d,  /* 0x140107bc8: local-det */
    0x0000000000000000,  /* 0x140107bd0: absent; live */
    0x0000000000000000,  /* 0x140107bd8: absent; live */
    0x38b72349facdb3e8,  /* 0x140107be0: unknown; ntoskrnl.exe!PsThreadType */
    0xc748db4afa0277a8,  /* 0x140107be8: local-det */
    0x0000000000000000,  /* 0x140107bf0: absent; live */
    0x0000000000000000,  /* 0x140107bf8: absent; live */
    0x39bba3b2e8a19a8c,  /* 0x140107c00: unknown; ntoskrnl.exe!ZwQueryVirtualMemory */
    0xc6445bb1e89e045c,  /* 0x140107c08: local-det */
    0x4f1fcb7e193f2be3,  /* 0x140107c10: local-det; ntoskrnl.exe!ZwQueryInformationThread */
    0xb0e0337d1900b4f3,  /* 0x140107c18: local-det */
    0x3522eb3ac714c1b8,  /* 0x140107c20: local-det; ntoskrnl.exe!SeLocateProcessImageName */
    0xcadd1339c7763078,  /* 0x140107c28: local-det */
    0xbec62bf88f9c9440,  /* 0x140107c30: local-det; ntoskrnl.exe!MmUserProbeAddress */
    0x4139d3fb8f9eb7e0,  /* 0x140107c38: local-det */
    0xc3a60bfcff528418,  /* 0x140107c40: local-det; ntoskrnl.exe!swprintf_s */
    0x3c59f3ffff6fe5e8,  /* 0x140107c48: local-det */
    0x4f7dafd42ef26b75,  /* 0x140107c50: local-det; ntoskrnl.exe!RtlCompareUnicodeStrings */
    0xb08257d72e979265,  /* 0x140107c58: local-det */
    0x00e7c7b73e64e156,  /* 0x140107c60: local-det; ntoskrnl.exe!KeGetCurrentProcessorNumberEx */
    0xff183fb43e42e486,  /* 0x140107c68: local-det */
    0x08dc875925871744,  /* 0x140107c70: local-det; ntoskrnl.exe!PsInitialSystemProcess */
    0xf7237f5a2548d364,  /* 0x140107c78: local-det */
    0xd95a6f75e6d388f2,  /* 0x140107c80: local-det; ntoskrnl.exe!ZwAssignProcessToJobObject */
    0x26a59776e6ec24a2,  /* 0x140107c88: local-det */
    0xd5866f77a5f62ead,  /* 0x140107c90: local-det; ntoskrnl.exe!ZwMapViewOfSection */
    0x2a799774a5c9b1dd,  /* 0x140107c98: local-det */
    0x3562cb30a769553b,  /* 0x140107ca0: local-det; ntoskrnl.exe!MmMapIoSpaceEx */
    0xca9d3333a7472a9b,  /* 0x140107ca8: local-det */
    0x24222761f7cd2324,  /* 0x140107cb0: local-det; ntoskrnl.exe!PsRemoveLoadImageNotifyRoutine */
    0xdbdddf62f75de734,  /* 0x140107cb8: local-det */
    0xf09523e2c38be9af,  /* 0x140107cc0: local-det; ntoskrnl.exe!ZwOpenSection */
    0x0f6adbe1c3b448ff,  /* 0x140107cc8: local-det */
    0xcc6f4349a4acdb41,  /* 0x140107cd0: local-det; ntoskrnl.exe!PsProcessType */
    0x3390bb4aa4631f51,  /* 0x140107cd8: local-det */
    0xa2fda770606e44d6,  /* 0x140107ce0: local-det; ntoskrnl.exe!MmMapIoSpace */
    0x5d025f7360403f96,  /* 0x140107ce8: local-det */
    0x93c74fd76eb42ef5,  /* 0x140107cf0: local-det; ntoskrnl.exe!ExAcquireSpinLockExclusive */
    0x6c38b7d46e95fed5,  /* 0x140107cf8: local-det */
    0x2658a3f582ba861a,  /* 0x140107d00: local-det; ntoskrnl.exe!ZwLoadDriver */
    0xd9a75bf682853d2a,  /* 0x140107d08: local-det */
    0x335763ed66d16018,  /* 0x140107d10: unknown; ntoskrnl.exe!ExReleaseSpinLockShared */
    0xcca89bee66ff9b58,  /* 0x140107d18: local-det */
    0xda51abfa082b4977,  /* 0x140107d20: local-det; ntoskrnl.exe!MmSectionObjectType */
    0x25ae53f908e48c57,  /* 0x140107d28: local-det */
    0x5af04741a1df5b92,  /* 0x140107d30: local-det; ntoskrnl.exe!PsSetLoadImageNotifyRoutine */
    0xa50fbf42a1a6ccd2,  /* 0x140107d38: local-det */
    0x7b2de35786910d1d,  /* 0x140107d40: local-det; ntoskrnl.exe!ExReleaseSpinLockExclusive */
    0x84d21b5486bace9d,  /* 0x140107d48: local-det */
    0xac38672d428b7261,  /* 0x140107d50: unknown; ntoskrnl.exe!ExAcquireSpinLockShared */
    0x53c79f2e42aabf21,  /* 0x140107d58: local-det */
    0xdac30b247d25c76d,  /* 0x140107d60: local-det; cng.sys!BCryptDestroyHash */
    0x253cf3277c0d100d,  /* 0x140107d68: local-det */
    0xa30043413df7b8c3,  /* 0x140107d70: local-det; ntoskrnl.exe!CmUnRegisterCallback */
    0x5cffbb423d712343,  /* 0x140107d78: local-det */
    0x2138233023aff295,  /* 0x140107d80: local-det; ntoskrnl.exe!RtlCaptureStackBackTrace */
    0xdec7db33238e3f75,  /* 0x140107d88: local-det */
    0xe50ba35138c05e38,  /* 0x140107d90: local-det; ntoskrnl.exe!wcsrchr */
    0x1af45b5238fd6438,  /* 0x140107d98: local-det */
    0x2f322733a22ab3a1,  /* 0x140107da0: local-det; ntoskrnl.exe!ZwOpenKey */
    0xd0cddf30a2152f11,  /* 0x140107da8: local-det */
    0xdc1f83f91d38b469,  /* 0x140107db0: local-det; ntoskrnl.exe!PsGetThreadProcess */
    0x23e07bfa1d18e2a9,  /* 0x140107db8: local-det */
    0x1c008f3f05ecbf30,  /* 0x140107dc0: local-det; fltmgr.sys!FltSendMessage */
    0xe3ff773c04fe11c0,  /* 0x140107dc8: local-det */
    0xaf0943fe8d696856,  /* 0x140107dd0: unknown; ntoskrnl.exe!PsGetCurrentThreadId */
    0x50f6bbfd8d5945a6,  /* 0x140107dd8: local-det */
    0x3d8bafa4c663aa91,  /* 0x140107de0: local-det; fltmgr.sys!FltGetDeviceObject */
    0xc27457a7c7717471,  /* 0x140107de8: local-det */
    0x8e710f3ec3a9011f,  /* 0x140107df0: local-det; ntoskrnl.exe!PsSetCreateProcessNotifyRoutineEx */
    0x718ef73dc3d0961f,  /* 0x140107df8: local-det */
    0xf2b8e351aee73e3f,  /* 0x140107e00: local-det; ntoskrnl.exe!wcsstr */
    0x0d471b52aeda04af,  /* 0x140107e08: local-det */
    0x1e88a3ffc7533acd,  /* 0x140107e10: unknown; ntoskrnl.exe!KeReleaseInStackQueuedSpinLock */
    0xe1775bfcc771f5bd,  /* 0x140107e18: unknown */
    0x4e31c35d230e3510,  /* 0x140107e20: local-det; ntoskrnl.exe!IoGetDeviceInterfaces */
    0xb1ce3b5e2367f370,  /* 0x140107e28: local-det */
    0x4a66eb37b90dfee1,  /* 0x140107e30: local-det; ntoskrnl.exe!ExReleasePushLockSharedEx */
    0xb5991334b9216c51,  /* 0x140107e38: local-det */
    0x8a99875a93ab1985,  /* 0x140107e40: local-det; ntoskrnl.exe!KeQueryTimeIncrement */
    0x75667f59938fa785,  /* 0x140107e48: local-det */
    0x0c4fcf5257f7ccda,  /* 0x140107e50: local-det; ntoskrnl.exe!wcsncmp */
    0xf3b0375157caf59a,  /* 0x140107e58: local-det */
    0xa1938bffad762041,  /* 0x140107e60: local-det; ntoskrnl.exe!ZwQuerySystemInformationEx */
    0x5e6c73fcad49e6f1,  /* 0x140107e68: local-det */
    0x0b3f2374e3cf30b5,  /* 0x140107e70: local-det; fltmgr.sys!FltGetFileNameInformation */
    0xf4c0db77e2dd71a5,  /* 0x140107e78: local-det */
    0x64e9e75866906e79,  /* 0x140107e80: local-det; ntoskrnl.exe!MmIsDriverVerifyingByAddress */
    0x9b161f5b66ed4469,  /* 0x140107e88: local-det */
    0x02a1cfaee2ba2a75,  /* 0x140107e90: local-det; fltmgr.sys!FltFreePoolAlignedWithTag */
    0xfd5e37ade3a9bd45,  /* 0x140107e98: local-det */
    0xb180cffb147aa485,  /* 0x140107ea0: local-det; ntoskrnl.exe!NtReadFile */
    0x4e7f37f814163f65,  /* 0x140107ea8: local-det */
    0xb7aa4b7ca94f17e9,  /* 0x140107eb0: local-det; ntoskrnl.exe!ZwOpenProcess */
    0x4855b37fa97088d9,  /* 0x140107eb8: local-det */
    0xeafba7f7a41ee252,  /* 0x140107ec0: local-det; ntoskrnl.exe!ExAllocatePoolWithQuota */
    0x15045ff4a445d772,  /* 0x140107ec8: local-det */
    0x20498777d7fc645d,  /* 0x140107ed0: local-det; ntoskrnl.exe!KeEnterGuardedRegion */
    0xdfb67f74d7d4ee2d,  /* 0x140107ed8: local-det */
    0x70bd8356e0634f30,  /* 0x140107ee0: local-det; ntoskrnl.exe!RtlWalkFrameChain */
    0x8f427b55e0428140,  /* 0x140107ee8: local-det */
    0x0ee2a7dff5d2f8d1,  /* 0x140107ef0: local-det; ntoskrnl.exe!IoFreeIrp */
    0xf11d5fdcf5ffc421,  /* 0x140107ef8: local-det */
    0xce72473af7f90ed4,  /* 0x140107f00: local-det; ntoskrnl.exe!PsGetThreadId */
    0x318dbf39f7c9d4e4,  /* 0x140107f08: local-det */
    0x6fb0675623a4ea6d,  /* 0x140107f10: local-det; ntoskrnl.exe!ExCreateCallback */
    0x904f9f5523ceea3d,  /* 0x140107f18: local-det */
    0x63b14fd52e6643ef,  /* 0x140107f20: unknown; ntoskrnl.exe!RtlCompareMemory */
    0x9c4eb7d62e263b6f,  /* 0x140107f28: local-det */
    0x0c100321d74d2b67,  /* 0x140107f30: local-det; ntoskrnl.exe!PsGetProcessExitProcessCalled */
    0xf3effb22d77f6c67,  /* 0x140107f38: local-det */
    0x7cb68fde3d28c259,  /* 0x140107f40: local-det; ntoskrnl.exe!ExRaiseHardError */
    0x834977dd3dbda2d9,  /* 0x140107f48: local-det */
    0x56c8cb55d633f329,  /* 0x140107f50: local-det; ntoskrnl.exe!RtlCompareUnicodeString */
    0xa9373356d66d1009,  /* 0x140107f58: local-det */
    0x533b43b15ff3cfe6,  /* 0x140107f60: local-det; ntoskrnl.exe!ZwUnmapViewOfSection */
    0xacc4bbb25fcc5056,  /* 0x140107f68: local-det */
    0xca19cbd3773d332a,  /* 0x140107f70: local-det; ntoskrnl.exe!towupper */
    0x35e633d0770005fa,  /* 0x140107f78: local-det */
    0x269ecbf4d63e74e0,  /* 0x140107f80: local-det; ntoskrnl.exe!RtlAppendUnicodeToString */
    0xd96133f7d60c9e50,  /* 0x140107f88: local-det */
    0x6a18c3560ebabda0,  /* 0x140107f90: local-det; ntoskrnl.exe!KeLeaveGuardedRegion */
    0x95e73b550e9f92f0,  /* 0x140107f98: local-det */
    0xa6e627702335cb6a,  /* 0x140107fa0: local-det; ntoskrnl.exe!_snprintf */
    0x5919df732308dfba,  /* 0x140107fa8: local-det */
    0x709d8b71335360c3,  /* 0x140107fb0: unknown; ntoskrnl.exe!PsGetProcessInheritedFromUniqueProcessId */
    0x8f627372337331f3,  /* 0x140107fb8: local-det */
    0x5a0fcff3e3873f13,  /* 0x140107fc0: local-det; ntoskrnl.exe!ZwCreateFile */
    0xa5f037f0e3b89a03,  /* 0x140107fc8: local-det */
    0x9f832b2533e2c9d4,  /* 0x140107fd0: local-det; ntoskrnl.exe!PsGetProcessImageFileName */
    0x607cd32633d3a704,  /* 0x140107fd8: local-det */
    0x0a28af77650d0350,  /* 0x140107fe0: local-det; ntoskrnl.exe!_wcsnicmp */
    0xf5d7577465301840,  /* 0x140107fe8: local-det */
    0x4eebabf43489cc32,  /* 0x140107ff0: local-det; ntoskrnl.exe!ZwProtectVirtualMemory */
    0xb11453f734b66842,  /* 0x140107ff8: local-det */
    0xaec28f7455b3a6eb,  /* 0x140108000: local-det; ntoskrnl.exe!ZwQueryInformationFile */
    0x513d7777558c3a7b,  /* 0x140108008: local-det */
    0x39348765e625e5d0,  /* 0x140108010: unknown; ntoskrnl.exe!IoGetTopLevelIrp */
    0xc6cb7f66e6089620,  /* 0x140108018: local-det */
    0xc7d6e32bf8e2d628,  /* 0x140108020: local-det; ntoskrnl.exe!FsRtlQueryInformationFile */
    0x38291b28f86a17d8,  /* 0x140108028: local-det */
    0xa9df47bfe88ea128,  /* 0x140108030: local-det; ntoskrnl.exe!PsLookupThreadByThreadId */
    0x5620bfbce8ecfb78,  /* 0x140108038: local-det */
    0x0ac86f26e3b0447e,  /* 0x140108040: local-det; ntoskrnl.exe!KeQueryPrcbAddress */
    0xf5379725e3e1007e,  /* 0x140108048: local-det */
    0x4ae36ba9aa0adf5c,  /* 0x140108050: local-det; ntoskrnl.exe!PsGetThreadProcessId */
    0xb51c93aaaa3b9d9c,  /* 0x140108058: local-det */
    0x421e2f62542e325b,  /* 0x140108060: local-det; ntoskrnl.exe!ZwOpenFile */
    0xbde1d7615411928b,  /* 0x140108068: local-det */
    0x73bdaff3ec4a1026,  /* 0x140108070: local-det; ntoskrnl.exe!towlower */
    0x8c4257f0ec772686,  /* 0x140108078: local-det */
    0x2addeb4fc3dd1792,  /* 0x140108080: local-det; ntoskrnl.exe!IoAllocateIrp */
    0xd522134cc3eb0152,  /* 0x140108088: local-det */
    0xbaaeefe306255d48,  /* 0x140108090: local-det; ntoskrnl.exe!IoInvalidateDeviceState */
    0x455117e0061f1708,  /* 0x140108098: local-det */
    0x2ca16f344a13d00d,  /* 0x1401080a0: local-det; cng.sys!BCryptCreateHash */
    0xd35e97374b3b0afd,  /* 0x1401080a8: local-det */
    0x6c014b246754d9b4,  /* 0x1401080b0: local-det; cng.sys!BCryptHashData */
    0x93feb327667c82b4,  /* 0x1401080b8: local-det */
    0x2dc08b2eafc286b6,  /* 0x1401080c0: local-det; fltmgr.sys!FltQueryInformationFile */
    0xd23f732daed715b6,  /* 0x1401080c8: local-det */
    0xbb80c73ef94deab0,  /* 0x1401080d0: local-det; ntoskrnl.exe!ZwSetInformationProcess */
    0x447f3f3df9727740,  /* 0x1401080d8: local-det */
    0x9599e75f9c0e39e5,  /* 0x1401080e0: local-det; ntoskrnl.exe!IoBuildSynchronousFsdRequest */
    0x6a661f5c9c61c955,  /* 0x1401080e8: local-det */
    0xb62f2b2bd9500e16,  /* 0x1401080f0: local-det; ntoskrnl.exe!FsRtlCreateSectionForDataScan */
    0x49d0d328d965ab66,  /* 0x1401080f8: local-det */
    0xa038a3e493ed3003,  /* 0x140108100: local-det; fltmgr.sys!FltCancelFileOpen */
    0x5fc75be792fa7673,  /* 0x140108108: local-det */
    0xb9df2f53765f5cd0,  /* 0x140108110: local-det; ntoskrnl.exe!ZwDuplicateToken */
    0x4620d7507660fe60,  /* 0x140108118: local-det */
    0x0000000000000000,  /* 0x140108120: live */
    0x0000000000000000,  /* 0x140108128: live */
    0x0000000000000000,  /* 0x140108130: absent; live */
    0x0000000000000000,  /* 0x140108138: absent; live */
    0x1803ef7184e50f73,  /* 0x140108140: local-det; ntoskrnl.exe!PsGetProcessSessionId */
    0xe7fc177284c02863,  /* 0x140108148: local-det */
    0x8c412f30ec9d3020,  /* 0x140108150: local-det; ntoskrnl.exe!MmAllocateMdlForIoSpace */
    0x73bed733ecce2e30,  /* 0x140108158: local-det */
    0x4c60037b3aa6f32f,  /* 0x140108160: local-det; ntoskrnl.exe!RtlUnicodeStringToInteger */
    0xb39ffb783ac0cbff,  /* 0x140108168: local-det */
    0x3ea12f24afa7036b,  /* 0x140108170: local-det; fltmgr.sys!FltGetDiskDeviceObject */
    0xc15ed727aeb5cceb,  /* 0x140108178: local-det */
    0xf60cab34c7d4148b,  /* 0x140108180: local-det; ntoskrnl.exe!ZwReadFile */
    0x09f35337c7eb8fbb,  /* 0x140108188: local-det */
    0xf4470bfff84d6fc5,  /* 0x140108190: unknown; ntoskrnl.exe!KeAcquireSpinLockAtDpcLevel */
    0x0bb8f3fcf86ffab5,  /* 0x140108198: local-det */
    0x0000000000000000,  /* 0x1401081a0: live */
    0x0000000000000000,  /* 0x1401081a8: live */
    0x8e4f4745ba30c86b,  /* 0x1401081b0: local-det; ntoskrnl.exe!IoReleaseRemoveLockEx */
    0x71b0bf46ba00f16b,  /* 0x1401081b8: local-det */
    0xc81147604ad61e38,  /* 0x1401081c0: local-det; ntoskrnl.exe!IoEnumerateDeviceObjectList */
    0x37eebf634aefbb18,  /* 0x1401081c8: local-det */
    0x55836f614c024a7b,  /* 0x1401081d0: local-det; ntoskrnl.exe!CmRegisterCallbackEx */
    0xaa7c97624c84d14b,  /* 0x1401081d8: local-det */
    0xc1858f22025dc37c,  /* 0x1401081e0: local-det; ntoskrnl.exe!MmCopyVirtualMemory */
    0x3e7a77210202aecc,  /* 0x1401081e8: local-det */
    0xaec5474585b87281,  /* 0x1401081f0: local-det; ntoskrnl.exe!IoReleaseRemoveLockAndWaitEx */
    0x513abf468581d5c1,  /* 0x1401081f8: local-det */
    0xd90d4b28622dcac4,  /* 0x140108200: unknown; fltmgr.sys!FltAcquirePushLockExclusive */
    0x26f2b32b633e47c4,  /* 0x140108208: local-det */
    0x937427a5c4b462fc,  /* 0x140108210: local-det; cng.sys!BCryptDecrypt */
    0x6c8bdfa6c59d837c,  /* 0x140108218: local-det */
    0x338c8fd971adf608,  /* 0x140108220: local-det; ntoskrnl.exe!PsWrapApcWow64Thread */
    0xcc7377da71f5dc28,  /* 0x140108228: local-det */
    0xd90daf3bc16490b5,  /* 0x140108230: local-det; ntoskrnl.exe!NtClose */
    0x26f25738c1077015,  /* 0x140108238: local-det */
    0x1169af229916000e,  /* 0x140108240: local-det; ntoskrnl.exe!PsGetCurrentProcessWow64Process */
    0xee965721993963ce,  /* 0x140108248: local-det */
    0x9aa0633d18a0b046,  /* 0x140108250: local-det; ntoskrnl.exe!PsSetCreateThreadNotifyRoutine */
    0x655f9b3e18d92766,  /* 0x140108258: local-det */
    0x47c7e72b8d3ec17a,  /* 0x140108260: local-det; fltmgr.sys!FltGetRequestorProcessIdEx */
    0xb8381f288c2d6a3a,  /* 0x140108268: local-det */
    0xb4046b5e5b3bea05,  /* 0x140108270: local-det; ntoskrnl.exe!ExQueueWorkItem */
    0x4bfb935d5b180ac5,  /* 0x140108278: local-det */
    0x769ae7acbe78e406,  /* 0x140108280: local-det; ntoskrnl.exe!ZwDuplicateObject */
    0x89651fafbe4745f6,  /* 0x140108288: local-det */
    0x65c1836477c8aa37,  /* 0x140108290: local-det; cng.sys!BCryptFinishHash */
    0x9a3e7b6776e07217,  /* 0x140108298: local-det */
    0x851faf38e1339e93,  /* 0x1401082a0: local-det; ntoskrnl.exe!ProbeForRead */
    0x7ae0573be15566c3,  /* 0x1401082a8: local-det */
    0x14684f79b3239da7,  /* 0x1401082b0: local-det; ntoskrnl.exe!PsResumeProcess */
    0xeb97b77ab349bdf7,  /* 0x1401082b8: local-det */
    0xbba84ffe8689cef7,  /* 0x1401082c0: local-det; ntoskrnl.exe!ZwQueryInformationProcess */
    0x4457b7fd86b65367,  /* 0x1401082c8: local-det */
    0x8ba363caeb317e37,  /* 0x1401082d0: local-det; ntoskrnl.exe!MmGetPhysicalAddress */
    0x745c9bc9eb016e17,  /* 0x1401082d8: local-det */
    0x86f76bbb13123c21,  /* 0x1401082e0: local-det; fltmgr.sys!FltGetFileSystemType */
    0x790893b81200ff11,  /* 0x1401082e8: local-det */
    0xecd58b3c37f127c4,  /* 0x1401082f0: local-det; ntoskrnl.exe!ZwTerminateProcess */
    0x132a733f37ceb834,  /* 0x1401082f8: local-det */
    0x7917a7ef1e2f38f7,  /* 0x140108300: local-det; ntoskrnl.exe!KeQueryUnbiasedInterruptTimePrecise */
    0x86e85fec1e013117,  /* 0x140108308: local-det */
    0xbebd2f79ef764d0d,  /* 0x140108310: local-det; ntoskrnl.exe!PsIsProtectedProcessLight */
    0x4142d77aef470eed,  /* 0x140108318: local-det */
    0xafc28b64fe575b53,  /* 0x140108320: unknown; fltmgr.sys!FltGetFileNameInformationUnsafe */
    0x503d7367ff42dac3,  /* 0x140108328: local-det */
    0x42cf47f9695f0aef,  /* 0x140108330: local-det; ntoskrnl.exe!PsSuspendProcess */
    0xbd30bffa69cfcd7f,  /* 0x140108338: local-det */
    0xb770ab7618bfd4bf,  /* 0x140108340: local-det; ntoskrnl.exe!ZwQuerySection */
    0x488f53751880702f,  /* 0x140108348: local-det */
    0x5cdfab3b33118516,  /* 0x140108350: unknown; fltmgr.sys!FltReleaseFileNameInformation */
    0xa320533832042b86,  /* 0x140108358: local-det */
    0x2c558b6dbbbd6a91,  /* 0x140108360: local-det; ntoskrnl.exe!PsIsThreadTerminating */
    0xd3aa736ebb8e8e21,  /* 0x140108368: local-det */
    0x7d76abe927736db1,  /* 0x140108370: local-det; ntoskrnl.exe!MmGetVirtualForPhysical */
    0x828953ea27204d11,  /* 0x140108378: local-det */
    0x17660376ac8d547f,  /* 0x140108380: local-det; ntoskrnl.exe!RtlLookupFunctionEntry */
    0xe899fb75acbea56f,  /* 0x140108388: local-det */
    0x9adb4ffc24fc8436,  /* 0x140108390: local-det; ntoskrnl.exe!KeIpiGenericCall */
    0x6524b7ff24c6c016,  /* 0x140108398: local-det */
    0xc6beefdd5ed7086c,  /* 0x1401083a0: local-det; ntoskrnl.exe!ZwQueryDirectoryObject */
    0x394117de5ee8ca9c,  /* 0x1401083a8: local-det */
    0x4f10afc3107c7147,  /* 0x1401083b0: local-det; ntoskrnl.exe!ZwOpenProcessTokenEx */
    0xb0ef57c01043d137,  /* 0x1401083b8: local-det */
    0x7f7a476ec6a3214f,  /* 0x1401083c0: local-det; fltmgr.sys!FltAllocatePoolAlignedWithTag */
    0x8085bf6dc7b0b7df,  /* 0x1401083c8: local-det */
    0x43b723dbfcd50000,  /* 0x1401083d0: local-det; ntoskrnl.exe!RtlUTF8ToUnicodeN */
    0xbc48dbd8fcbc9310,  /* 0x1401083d8: local-det */
    0x7d510b27993de030,  /* 0x1401083e0: local-det; ntoskrnl.exe!ExAcquirePushLockSharedEx */
    0x82aef32499115270,  /* 0x1401083e8: local-det */
    0x230447b735c33026,  /* 0x1401083f0: local-det; ntoskrnl.exe!MmUnmapIoSpace */
    0xdcfbbfb435ed96a6,  /* 0x1401083f8: local-det */
    0x5605a77cc3ec3610,  /* 0x140108400: local-det; ntoskrnl.exe!RtlVirtualUnwind */
    0xa9fa5f7fc3dfdfc0,  /* 0x140108408: local-det */
    0xe7966bb8f95361e3,  /* 0x140108410: local-det; fltmgr.sys!FltReadFile */
    0x186993bbf8417123,  /* 0x140108418: local-det */
    0xeb56a77274046aa7,  /* 0x140108420: local-det; ntoskrnl.exe!ZwFreeVirtualMemory */
    0x14a95f71743bf497,  /* 0x140108428: local-det */
    0xb77ea35c6425c50f,  /* 0x140108430: local-det; ntoskrnl.exe!KeQueryActiveProcessorCount */
    0x48815b5f6474910f,  /* 0x140108438: local-det */
    0x840507fd6d56b406,  /* 0x140108440: local-det; ntoskrnl.exe!PsRemoveCreateThreadNotifyRoutine */
    0x7bfafffe6dc67726,  /* 0x140108448: local-det */
    0x535a23d588c218ab,  /* 0x140108450: local-det; ntoskrnl.exe!RtlCreateUnicodeString */
    0xaca5dbd688accd7b,  /* 0x140108458: local-det */
    0x6efe23654eb0022e,  /* 0x140108460: local-det; ntoskrnl.exe!IoAcquireRemoveLockEx */
    0x9101db664e96020e,  /* 0x140108468: local-det */
    0x305be7ff86dd4e19,  /* 0x140108470: local-det; ntoskrnl.exe!KeReleaseSpinLockFromDpcLevel */
    0xcfa41ffc86ffdbf9,  /* 0x140108478: local-det */
    0xcba42fb2e068ae92,  /* 0x140108480: local-det; ntoskrnl.exe!PsGetProcessPeb */
    0x345bd7b1e0599702,  /* 0x140108488: local-det */
    0xddffe7b9fceabea7,  /* 0x140108490: local-det; ntoskrnl.exe!PsIsSystemThread */
    0x22001fbafcda2877,  /* 0x140108498: local-det */
    0x16ada759bd53418e,  /* 0x1401084a0: local-det; ntoskrnl.exe!RtlAnsiStringToUnicodeString */
    0xe9525f5abd3c29ce,  /* 0x1401084a8: local-det */
    0x43c34b3e6df23ab0,  /* 0x1401084b0: local-det; ntoskrnl.exe!KeAcquireInStackQueuedSpinLock */
    0xbc3cb33d6dd0dd30,  /* 0x1401084b8: local-det */
    0x96b8873a249f044f,  /* 0x1401084c0: local-det; ntoskrnl.exe!IoReplaceFileObjectName */
    0x69477f3924ec4adf,  /* 0x1401084c8: local-det */
    0x3561cbfb6f9f5504,  /* 0x1401084d0: local-det; fltmgr.sys!FltGetRequestorProcess */
    0xca9e33f86e8de8f4,  /* 0x1401084d8: local-det */
    0xa68d27fbb1575e39,  /* 0x1401084e0: local-det; ntoskrnl.exe!FsRtlMupGetProviderInfoFromFileObject */
    0x5972dff8b1dfe949,  /* 0x1401084e8: local-det */
    0x16b6c746e693904c,  /* 0x1401084f0: local-det; ntoskrnl.exe!IoInitializeRemoveLockEx */
    0xe9493f45e6a47b1c,  /* 0x1401084f8: local-det */
    0x2c870b277cff9b61,  /* 0x140108500: local-det; ntoskrnl.exe!KeGetProcessorIndexFromNumber */
    0xd378f3247ccbd5f1,  /* 0x140108508: local-det */
    0x4f4f2b6a5d5cb713,  /* 0x140108510: local-det; ntoskrnl.exe!IoThreadToProcess */
    0xb0b0d3695d7ce1d3,  /* 0x140108518: local-det */
    0xb34407b9542ce7a9,  /* 0x140108520: local-det; ntoskrnl.exe!PsGetThreadWin32Thread */
    0x4cbbffba5403cc79,  /* 0x140108528: local-det */
    0xd318073697422297,  /* 0x140108530: local-det; ntoskrnl.exe!MmGetSystemRoutineAddress */
    0x2ce7ff35972bbc17,  /* 0x140108538: local-det */
    0x2eeb63c07b38c66a,  /* 0x140108540: local-det; ntoskrnl.exe!IoCreateFileSpecifyDeviceObjectHint */
    0xd1149bc37b51332a,  /* 0x140108548: local-det */
    0x8f75af5cd2d86da2,  /* 0x140108550: local-det; ntoskrnl.exe!ZwQueryDirectoryFile */
    0x708a575fd2e7ccb2,  /* 0x140108558: local-det */
    0x4dc86ffef2411aa0,  /* 0x140108560: local-det; ntoskrnl.exe!IoGetDevicePropertyData */
    0xb23797fdf22a34c0,  /* 0x140108568: local-det */
    0x1ad667eb509e776e,  /* 0x140108570: local-det; fltmgr.sys!FltParseFileNameInformation */
    0xe5299fe8518b2f2e,  /* 0x140108578: local-det */
    0x0000000000000000,  /* 0x140108580: absent; live */
    0x0000000000000000,  /* 0x140108588: absent; live */
    0x0000000000000000,  /* 0x140108590: live */
    0x0000000000000000,  /* 0x140108598: absent; live */
    0x0000000000000000,  /* 0x1401085a0: absent; live */
    0x0000000000000000,  /* 0x1401085a8: unknown; live */
    0x0000000000000000,  /* 0x1401085b0: absent; live */
    0x0000000000000000,  /* 0x1401085b8: live */
    0x0000000000000000,  /* 0x1401085c0: unknown; live */
    0x0000000000000000,  /* 0x1401085c8: live */
    0x0000000000000000,  /* 0x1401085d0: live */
    0x0000000000000000,  /* 0x1401085d8: live */
    0x0000000000000000,  /* 0x1401085e0: live */
    0x0000000000000000,  /* 0x1401085e8: live */
    0x0000000000000000,  /* 0x1401085f0: live */
    0x0000000000000000,  /* 0x1401085f8: live */
    0x0000000000000000,  /* 0x140108600: live */
    0x0000000000000000,  /* 0x140108608: live */
    0x0000000000000000,  /* 0x140108610: live */
    0x0000000000000000,  /* 0x140108618: live */
    0x0000000000000000,  /* 0x140108620: live */
    0x0000000000000000,  /* 0x140108628: live */
    0x0000000000000000,  /* 0x140108630: live */
    0x0000000000000000,  /* 0x140108638: live */
    0x0000000000000000,  /* 0x140108640: live */
    0x0000000000000000,  /* 0x140108648: live */
    0x0000000000000000,  /* 0x140108650: live */
    0x0000000000000000,  /* 0x140108658: live */
    0x0000000000000000,  /* 0x140108660: live */
    0x0000000000000000,  /* 0x140108668: live */
    0x0000000000000000,  /* 0x140108670: live */
    0x0000000000000000,  /* 0x140108678: live */
    0x0000000000000000,  /* 0x140108680: live */
    0x0000000000000000,  /* 0x140108688: live */
    0x0000000000000000,  /* 0x140108690: live */
    0x0000000000000000,  /* 0x140108698: live */
    0x0000000000000000,  /* 0x1401086a0: live */
    0x0000000000000000,  /* 0x1401086a8: live */
    0x0000000000000000,  /* 0x1401086b0: live */
    0x0000000000000000,  /* 0x1401086b8: live */
    0x0000000000000000,  /* 0x1401086c0: live */
    0x0000000000000000,  /* 0x1401086c8: live */
    0x0000000000000000,  /* 0x1401086d0: live */
    0x0000000000000000,  /* 0x1401086d8: live */
    0x0000000000000000,  /* 0x1401086e0: live */
    0x0000000000000000,  /* 0x1401086e8: live */
    0x0000000000000000,  /* 0x1401086f0: live */
    0x0000000000000000,  /* 0x1401086f8: live */
    0x0000000000000000,  /* 0x140108700: live */
    0x0000000000000000,  /* 0x140108708: live */
    0x0000000000000000,  /* 0x140108710: live */
    0x0000000000000000,  /* 0x140108718: live */
    0x0000000000000000,  /* 0x140108720: live */
    0x0000000000000000,  /* 0x140108728: live */
    0x0000000000000000,  /* 0x140108730: live */
    0x0000000000000000,  /* 0x140108738: live */
    0x0000000000000000,  /* 0x140108740: live */
    0x0000000000000000,  /* 0x140108748: live */
    0x0000000000000000,  /* 0x140108750: unknown; live */
    0x0000000000000000,  /* 0x140108758: unknown; live */
    0x0000000000000000,  /* 0x140108760: unknown; live */
    0x0000000000000000,  /* 0x140108768: absent; live */
    0x0000000000000000,  /* 0x140108770: absent; live */
    0x0000000000000000,  /* 0x140108778: unknown; live */
    0x0000000000000000,  /* 0x140108780: absent; live */
    0x0000000000000000,  /* 0x140108788: absent; live */
    0x0000000000000000,  /* 0x140108790: absent; live */
    0x0000000000000000,  /* 0x140108798: live */
    0x0000000000000000,  /* 0x1401087a0: live */
    0x0000000000000000,  /* 0x1401087a8: live */
    0x0000000000000000,  /* 0x1401087b0: live */
    0x0000000000000000,  /* 0x1401087b8: live */
    0x0000000000000000,  /* 0x1401087c0: live */
    0x0000000000000000,  /* 0x1401087c8: live */
    0x0000000000000000,  /* 0x1401087d0: live */
    0x0000000000000000,  /* 0x1401087d8: live */
    0x0000000000000000,  /* 0x1401087e0: live */
    0x0000000000000000,  /* 0x1401087e8: live */
    0x0000000000000000,  /* 0x1401087f0: live */
    0x0000000000000000,  /* 0x1401087f8: live */
    0x0000000000000000,  /* 0x140108800: live */
    0x0000000000000000,  /* 0x140108808: live */
    0x0000000000000000,  /* 0x140108810: live */
    0x0000000000000000,  /* 0x140108818: live */
    0x0000000000000000,  /* 0x140108820: live */
    0x0000000000000000,  /* 0x140108828: live */
    0x0000000000000000,  /* 0x140108830: live */
    0x0000000000000000,  /* 0x140108838: live */
    0x0000000000000000,  /* 0x140108840: live */
    0x0000000000000000,  /* 0x140108848: live */
    0x0000000000000000,  /* 0x140108850: live */
    0x0000000000000000,  /* 0x140108858: live */
    0x0000000000000000,  /* 0x140108860: live */
    0x0000000000000000,  /* 0x140108868: live */
    0x0000000000000000,  /* 0x140108870: live */
    0x0000000000000000,  /* 0x140108878: live */
    0x0000000000000000,  /* 0x140108880: live */
    0x0000000000000000,  /* 0x140108888: live */
    0x0000000000000000,  /* 0x140108890: live */
    0x0000000000000000,  /* 0x140108898: live */
    0x0000000000000000,  /* 0x1401088a0: live */
    0x0000000000000000,  /* 0x1401088a8: live */
    0x0000000000000000,  /* 0x1401088b0: live */
    0x0000000000000000,  /* 0x1401088b8: live */
    0x0000000000000000,  /* 0x1401088c0: live */
    0x0000000000000000,  /* 0x1401088c8: live */
    0x0000000000000000,  /* 0x1401088d0: live */
    0x0000000000000000,  /* 0x1401088d8: live */
    0x0000000000000000,  /* 0x1401088e0: live */
    0x0000000000000000,  /* 0x1401088e8: live */
    0x0000000000000000,  /* 0x1401088f0: live */
    0x0000000000000000,  /* 0x1401088f8: live */
    0x0000000000000000,  /* 0x140108900: live */
    0x0000000000000000,  /* 0x140108908: live */
    0x0000000000000000,  /* 0x140108910: live */
    0x0000000000000000,  /* 0x140108918: live */
    0x0000000000000000,  /* 0x140108920: live */
    0x0000000000000000,  /* 0x140108928: live */
    0x0000000000000000,  /* 0x140108930: live */
    0x0000000000000000,  /* 0x140108938: live */
    0x0000000000000000,  /* 0x140108940: live */
    0x0000000000000000,  /* 0x140108948: live */
    0x0000000000000000,  /* 0x140108950: live */
    0x0000000000000000,  /* 0x140108958: live */
    0x0000000000000000,  /* 0x140108960: live */
    0x0000000000000000,  /* 0x140108968: live */
    0x0000000000000000,  /* 0x140108970: live */
    0x0000000000000000,  /* 0x140108978: live */
    0x0000000000000000,  /* 0x140108980: live */
    0x0000000000000000,  /* 0x140108988: live */
    0x0000000000000000,  /* 0x140108990: live */
    0x0000000000000000,  /* 0x140108998: absent; live */
    0x0000000000000000,  /* 0x1401089a0: live */
    0x0000000000000000,  /* 0x1401089a8: live */
    0x0000000000000000,  /* 0x1401089b0: live */
    0x0000000000000000,  /* 0x1401089b8: live */
    0x0000000000000000,  /* 0x1401089c0: live */
    0x0000000000000000,  /* 0x1401089c8: live */
    0x0000000000000000,  /* 0x1401089d0: live */
    0x0000000000000000,  /* 0x1401089d8: live */
    0x0000000000000000,  /* 0x1401089e0: live */
    0x0000000000000000,  /* 0x1401089e8: live */
    0x0000000000000000,  /* 0x1401089f0: live */
    0x0000000000000000,  /* 0x1401089f8: live */
    0x0000000000000000,  /* 0x140108a00: live */
    0x0000000000000000,  /* 0x140108a08: live */
    0x0000000000000000,  /* 0x140108a10: live */
    0x0000000000000000,  /* 0x140108a18: live */
    0x0000000000000000,  /* 0x140108a20: live */
    0x0000000000000000,  /* 0x140108a28: live */
    0x0000000000000000,  /* 0x140108a30: live */
    0x0000000000000000,  /* 0x140108a38: live */
    0x0000000000000000,  /* 0x140108a40: live */
    0x0000000000000000,  /* 0x140108a48: live */
    0x0000000000000000,  /* 0x140108a50: live */
    0x0000000000000000,  /* 0x140108a58: live */
    0x0000000000000000,  /* 0x140108a60: live */
    0x0000000000000000,  /* 0x140108a68: live */
    0x0000000000000000,  /* 0x140108a70: live */
    0x0000000000000000,  /* 0x140108a78: live */
    0x0000000000000000,  /* 0x140108a80: live */
    0x0000000000000000,  /* 0x140108a88: live */
    0x0000000000000000,  /* 0x140108a90: live */
    0x0000000000000000,  /* 0x140108a98: live */
    0x0000000000000000,  /* 0x140108aa0: live */
    0x0000000000000000,  /* 0x140108aa8: live */
    0x0000000000000000,  /* 0x140108ab0: live */
    0x0000000000000000,  /* 0x140108ab8: live */
    0x0000000000000000,  /* 0x140108ac0: live */
    0x0000000000000000,  /* 0x140108ac8: live */
    0x0000000000000000,  /* 0x140108ad0: live */
    0x0000000000000000,  /* 0x140108ad8: live */
    0x0000000000000000,  /* 0x140108ae0: live */
    0x0000000000000000,  /* 0x140108ae8: live */
    0x0000000000000000,  /* 0x140108af0: live */
    0x0000000000000000,  /* 0x140108af8: live */
    0x0000000000000000,  /* 0x140108b00: live */
    0x0000000000000000,  /* 0x140108b08: live */
    0x0000000000000000,  /* 0x140108b10: live */
    0x0000000000000000,  /* 0x140108b18: live */
    0x0000000000000000,  /* 0x140108b20: live */
    0x0000000000000000,  /* 0x140108b28: live */
    0x0000000000000000,  /* 0x140108b30: live */
    0x0000000000000000,  /* 0x140108b38: live */
    0x0000000000000000,  /* 0x140108b40: live */
    0x0000000000000000,  /* 0x140108b48: live */
    0x0000000000000000,  /* 0x140108b50: live */
    0x0000000000000000,  /* 0x140108b58: live */
    0x0000000000000000,  /* 0x140108b60: live */
    0x0000000000000000,  /* 0x140108b68: live */
    0x0000000000000000,  /* 0x140108b70: live */
    0x0000000000000000,  /* 0x140108b78: live */
    0x0000000000000000,  /* 0x140108b80: live */
    0x0000000000000000,  /* 0x140108b88: live */
    0x0000000000000000,  /* 0x140108b90: live */
    0x0000000000000000,  /* 0x140108b98: live */
    0x0000000000000000,  /* 0x140108ba0: unknown; live */
    0x0000000000000000,  /* 0x140108ba8: unknown; live */
    0x0000000000000000,  /* 0x140108bb0: absent; live */
    0x0000000000000000,  /* 0x140108bb8: absent; live */
    0x0000000000000000,  /* 0x140108bc0: absent; live */
    0x0000000000000000,  /* 0x140108bc8: absent; live */
    0x0000000000000000,  /* 0x140108bd0: live */
    0x0000000000000000,  /* 0x140108bd8: absent; live */
    0x0000000000000000,  /* 0x140108be0: live */
    0x0000000000000000,  /* 0x140108be8: absent; live */
    0x0000000000000000,  /* 0x140108bf0: absent; live */
    0x0000000000000000,  /* 0x140108bf8: unknown; live */
    0x0000000000000000,  /* 0x140108c00: unknown; live */
    0x0000000000000000,  /* 0x140108c08: unknown; live */
    0x0000000000000000,  /* 0x140108c10: absent; live */
    0x0000000000000000,  /* 0x140108c18: live */
    0x0000000000000000,  /* 0x140108c20: live */
    0x0000000000000000,  /* 0x140108c28: live */
    0x0000000000000000,  /* 0x140108c30: live */
    0x0000000000000000,  /* 0x140108c38: live */
    0x0000000000000000,  /* 0x140108c40: live */
    0x0000000000000000,  /* 0x140108c48: live */
    0x0000000000000000,  /* 0x140108c50: absent; live */
    0x0000000000000000,  /* 0x140108c58: absent; live */
    0x0000000000000000,  /* 0x140108c60: absent; live */
    0x0000000000000000,  /* 0x140108c68: absent; live */
    0x0000000000000000,  /* 0x140108c70: absent; live */
    0x0000000000000000,  /* 0x140108c78: absent; live */
    0x0000000000000000,  /* 0x140108c80: absent; live */
    0x0000000000000000,  /* 0x140108c88: absent; live */
    0x0000000000000000,  /* 0x140108c90: absent; live */
    0x0000000000000000,  /* 0x140108c98: live */
    0x0000000000000000,  /* 0x140108ca0: live */
    0x0000000000000000,  /* 0x140108ca8: absent; live */
    0x0000000000000000,  /* 0x140108cb0: absent; live */
    0x0000000000000000,  /* 0x140108cb8: absent; live */
    0x0000000000000000,  /* 0x140108cc0: live */
    0x0000000000000000,  /* 0x140108cc8: absent; live */
    0x0000000000000000,  /* 0x140108cd0: absent; live */
    0x0000000000000000,  /* 0x140108cd8: absent; live */
    0x0000000000000000,  /* 0x140108ce0: unknown; live */
    0x0000000000000000,  /* 0x140108ce8: local-const */
    0x0000000000000000,  /* 0x140108cf0: absent; live */
    0x0000000000000000,  /* 0x140108cf8: unknown; live */
    0x0000000000000000,  /* 0x140108d00: unknown; live */
    0x0000000000000000,  /* 0x140108d08: unknown; live */
    0x0000000000000000,  /* 0x140108d10: unknown; live */
    0x0000000000000000,  /* 0x140108d18: unknown; live */
    0x0000000000000000,  /* 0x140108d20: unknown; live */
    0x0000000000000000,  /* 0x140108d28: unknown; live */
    0x0000000000000000,  /* 0x140108d30: absent; live */
    0x0000000000000000,  /* 0x140108d38: live */
    0x0000000000000000,  /* 0x140108d40: absent; live */
    0x0000000000000000,  /* 0x140108d48: absent; live */
    0x0000000000000000,  /* 0x140108d50: absent; live */
    0x0000000000000000,  /* 0x140108d58: live */
    0x0000000000000000,  /* 0x140108d60: absent; live */
    0x0000000000000000,  /* 0x140108d68: unknown; live */
    0x0000000000000000,  /* 0x140108d70: absent; live */
    0x0000000000000000,  /* 0x140108d78: absent; live */
    0x0000000000000000,  /* 0x140108d80: absent; live */
    0x0000000000000000,  /* 0x140108d88: absent; live */
    0x0000000000000000,  /* 0x140108d90: live */
    0x0000000000000000,  /* 0x140108d98: absent; live */
    0x0000000000000000,  /* 0x140108da0: absent; live */
    0x0000000000000000,  /* 0x140108da8: absent; live */
    0x0000000000000000,  /* 0x140108db0: absent; live */
    0x0000000000000000,  /* 0x140108db8: unknown; live */
    0x0000000000000000,  /* 0x140108dc0: live */
    0x0000000000000000,  /* 0x140108dc8: absent; live */
    0x0000000000000000,  /* 0x140108dd0: absent; live */
    0x0000000000000000,  /* 0x140108dd8: absent; live */
    0x0000000000000000,  /* 0x140108de0: live */
    0x0000000000000000,  /* 0x140108de8: absent; live */
    0x0000000000000000,  /* 0x140108df0: absent; live */
    0x0000000000000000,  /* 0x140108df8: unknown; live */
    0x0000000000000000,  /* 0x140108e00: absent; live */
    0x0000000000000000,  /* 0x140108e08: absent; live */
    0x0000000000000000,  /* 0x140108e10: live */
    0x0000000000000000,  /* 0x140108e18: live */
    0x0000000000000000,  /* 0x140108e20: live */
    0x0000000000000000,  /* 0x140108e28: live */
    0x0000000000000000,  /* 0x140108e30: live */
    0x0000000000000000,  /* 0x140108e38: absent; live */
    0x0000000000000000,  /* 0x140108e40: absent; live */
    0x0000000000000000,  /* 0x140108e48: absent; live */
    0x0000000000000000,  /* 0x140108e50: absent; live */
    0x0000000000000000,  /* 0x140108e58: absent; live */
    0x0000000000000000,  /* 0x140108e60: live */
    0x0000000000000000,  /* 0x140108e68: live */
    0x0000000000000000,  /* 0x140108e70: live */
    0x0000000000000000,  /* 0x140108e78: live */
    0x0000000000000000,  /* 0x140108e80: live */
    0x0000000000000000,  /* 0x140108e88: absent; live */
    0x0000000000000000,  /* 0x140108e90: live */
    0x0000000000000000,  /* 0x140108e98: live */
    0x0000000000000000,  /* 0x140108ea0: live */
    0x0000000000000000,  /* 0x140108ea8: live */
    0x0000000000000000,  /* 0x140108eb0: live */
    0x0000000000000000,  /* 0x140108eb8: live */
    0x0000000000000000,  /* 0x140108ec0: live */
    0x0000000000000000,  /* 0x140108ec8: absent; live */
    0x0000000000000000,  /* 0x140108ed0: live */
    0x0000000000000000,  /* 0x140108ed8: live */
    0x0000000000000000,  /* 0x140108ee0: live */
    0x0000000000000000,  /* 0x140108ee8: live */
    0x0000000000000000,  /* 0x140108ef0: live */
    0x0000000000000000,  /* 0x140108ef8: live */
    0x0000000000000000,  /* 0x140108f00: live */
    0x0000000000000000,  /* 0x140108f08: live */
    0x0000000000000000,  /* 0x140108f10: live */
    0x0000000000000000,  /* 0x140108f18: live */
    0x0000000000000000,  /* 0x140108f20: live */
    0x0000000000000000,  /* 0x140108f28: live */
    0x0000000000000000,  /* 0x140108f30: live */
    0x0000000000000000,  /* 0x140108f38: live */
    0x0000000000000000,  /* 0x140108f40: live */
    0x0000000000000000,  /* 0x140108f48: live */
    0x0000000000000000,  /* 0x140108f50: live */
    0x0000000000000000,  /* 0x140108f58: live */
    0x0000000000000000,  /* 0x140108f60: live */
    0x0000000000000000,  /* 0x140108f68: live */
    0x0000000000000000,  /* 0x140108f70: live */
    0x0000000000000000,  /* 0x140108f78: live */
    0x0000000000000000,  /* 0x140108f80: live */
    0x0000000000000000,  /* 0x140108f88: live */
    0x0000000000000000,  /* 0x140108f90: live */
    0x0000000000000000,  /* 0x140108f98: live */
    0x0000000000000000,  /* 0x140108fa0: live */
    0x0000000000000000,  /* 0x140108fa8: live */
    0x0000000000000000,  /* 0x140108fb0: live */
    0x0000000000000000,  /* 0x140108fb8: live */
    0x0000000000000000,  /* 0x140108fc0: live */
    0x0000000000000000,  /* 0x140108fc8: live */
    0x0000000000000000,  /* 0x140108fd0: live */
    0x0000000000000000,  /* 0x140108fd8: live */
    0x0000000000000000,  /* 0x140108fe0: live */
    0x0000000000000000,  /* 0x140108fe8: live */
    0x0000000000000000,  /* 0x140108ff0: live */
    0x0000000000000000,  /* 0x140108ff8: live */
    0x0000000000000000,  /* 0x140109000: absent; live */
    0x0000000000000000,  /* 0x140109008: live */
    0x0000000000000000,  /* 0x140109010: live */
    0x0000000000000000,  /* 0x140109018: live */
    0x0000000000000000,  /* 0x140109020: live */
    0x0000000000000000,  /* 0x140109028: live */
    0x0000000000000000,  /* 0x140109030: live */
    0x0000000000000000,  /* 0x140109038: live */
    0x0000000000000000,  /* 0x140109040: live */
    0x0000000000000000,  /* 0x140109048: live */
    0x0000000000000000,  /* 0x140109050: live */
    0x0000000000000000,  /* 0x140109058: live */
    0x0000000000000000,  /* 0x140109060: live */
    0x0000000000000000,  /* 0x140109068: live */
    0x0000000000000000,  /* 0x140109070: live */
    0x0000000000000000,  /* 0x140109078: live */
    0x0000000000000000,  /* 0x140109080: live */
    0x0000000000000000,  /* 0x140109088: live */
    0x0000000000000000,  /* 0x140109090: live */
    0x0000000000000000,  /* 0x140109098: live */
    0x0000000000000000,  /* 0x1401090a0: live */
    0x0000000000000000,  /* 0x1401090a8: live */
    0x0000000000000000,  /* 0x1401090b0: live */
    0x0000000000000000,  /* 0x1401090b8: live */
    0x0000000000000000,  /* 0x1401090c0: live */
    0x0000000000000000,  /* 0x1401090c8: live */
    0x0000000000000000,  /* 0x1401090d0: live */
    0x0000000000000000,  /* 0x1401090d8: live */
    0x0000000000000000,  /* 0x1401090e0: live */
    0x0000000000000000,  /* 0x1401090e8: live */
    0x0000000000000000,  /* 0x1401090f0: live */
    0x0000000000000000,  /* 0x1401090f8: live */
    0x0000000000000000,  /* 0x140109100: live */
    0x0000000000000000,  /* 0x140109108: live */
    0x0000000000000000,  /* 0x140109110: live */
    0x0000000000000000,  /* 0x140109118: live */
    0x0000000000000000,  /* 0x140109120: live */
    0x0000000000000000,  /* 0x140109128: live */
    0x0000000000000000,  /* 0x140109130: live */
    0x0000000000000000,  /* 0x140109138: live */
    0x0000000000000000,  /* 0x140109140: live */
    0x0000000000000000,  /* 0x140109148: live */
    0x0000000000000000,  /* 0x140109150: live */
    0x0000000000000000,  /* 0x140109158: live */
    0x0000000000000000,  /* 0x140109160: live */
    0x0000000000000000,  /* 0x140109168: live */
    0x0000000000000000,  /* 0x140109170: live */
    0x0000000000000000,  /* 0x140109178: live */
    0x0000000000000000,  /* 0x140109180: live */
    0x0000000000000000,  /* 0x140109188: live */
    0x0000000000000000,  /* 0x140109190: live */
    0x0000000000000000,  /* 0x140109198: live */
    0x0000000000000000,  /* 0x1401091a0: live */
    0x0000000000000000,  /* 0x1401091a8: live */
    0x0000000000000000,  /* 0x1401091b0: absent; live */
    0x0000000000000000,  /* 0x1401091b8: live */
    0x0000000000000000,  /* 0x1401091c0: live */
    0x0000000000000000,  /* 0x1401091c8: live */
    0x0000000000000000,  /* 0x1401091d0: live */
    0x0000000000000000,  /* 0x1401091d8: live */
    0x0000000000000000,  /* 0x1401091e0: live */
    0x0000000000000000,  /* 0x1401091e8: live */
    0x0000000000000000,  /* 0x1401091f0: absent; live */
    0x0000000000000000,  /* 0x1401091f8: absent; live */
    0x0000000000000000,  /* 0x140109200: absent; live */
    0x0000000000000000,  /* 0x140109208: absent; live */
    0x0000000000000000,  /* 0x140109210: absent; live */
    0x0000000000000000,  /* 0x140109218: live */
    0x0000000000000000,  /* 0x140109220: live */
    0x0000000000000000,  /* 0x140109228: live */
    0x0000000000000000,  /* 0x140109230: live */
    0x0000000000000000,  /* 0x140109238: live */
    0x0000000000000000,  /* 0x140109240: live */
    0x0000000000000000,  /* 0x140109248: live */
    0x0000000000000000,  /* 0x140109250: live */
    0x0000000000000000,  /* 0x140109258: live */
    0x0000000000000000,  /* 0x140109260: live */
    0x0000000000000000,  /* 0x140109268: live */
    0x0000000000000000,  /* 0x140109270: live */
    0x0000000000000000,  /* 0x140109278: live */
    0x0000000000000000,  /* 0x140109280: live */
    0x0000000000000000,  /* 0x140109288: live */
    0x0000000000000000,  /* 0x140109290: live */
    0x0000000000000000,  /* 0x140109298: live */
    0x0000000000000000,  /* 0x1401092a0: live */
    0x0000000000000000,  /* 0x1401092a8: live */
    0x0000000000000000,  /* 0x1401092b0: live */
    0x0000000000000000,  /* 0x1401092b8: live */
    0x0000000000000000,  /* 0x1401092c0: live */
    0x0000000000000000,  /* 0x1401092c8: live */
    0x0000000000000000,  /* 0x1401092d0: live */
    0x0000000000000000,  /* 0x1401092d8: live */
    0x0000000000000000,  /* 0x1401092e0: live */
    0x0000000000000000,  /* 0x1401092e8: live */
    0x0000000000000000,  /* 0x1401092f0: live */
    0x0000000000000000,  /* 0x1401092f8: live */
    0x0000000000000000,  /* 0x140109300: live */
    0x0000000000000000,  /* 0x140109308: live */
    0x0000000000000000,  /* 0x140109310: live */
    0x0000000000000000,  /* 0x140109318: live */
    0x0000000000000000,  /* 0x140109320: live */
    0x0000000000000000,  /* 0x140109328: live */
    0x0000000000000000,  /* 0x140109330: live */
    0x0000000000000000,  /* 0x140109338: live */
    0x0000000000000000,  /* 0x140109340: live */
    0x0000000000000000,  /* 0x140109348: live */
    0x0000000000000000,  /* 0x140109350: live */
    0x0000000000000000,  /* 0x140109358: live */
    0x0000000000000000,  /* 0x140109360: live */
    0x0000000000000000,  /* 0x140109368: live */
    0x0000000000000000,  /* 0x140109370: live */
    0x0000000000000000,  /* 0x140109378: live */
    0x0000000000000000,  /* 0x140109380: live */
    0x0000000000000000,  /* 0x140109388: live */
    0x0000000000000000,  /* 0x140109390: live */
    0x0000000000000000,  /* 0x140109398: live */
    0x0000000000000000,  /* 0x1401093a0: live */
    0x0000000000000000,  /* 0x1401093a8: live */
    0x0000000000000000,  /* 0x1401093b0: absent; live */
    0x0000000000000000,  /* 0x1401093b8: unknown; live */
    0x0000000000000000,  /* 0x1401093c0: unknown; live */
    0x0000000000000000,  /* 0x1401093c8: absent; live */
    0x0000000000000000,  /* 0x1401093d0: unknown; live */
    0x0000000000000000,  /* 0x1401093d8: absent; live */
    0x0000000000000000,  /* 0x1401093e0: absent; live */
    0x0000000000000000,  /* 0x1401093e8: live */
    0x0000000000000000,  /* 0x1401093f0: live */
    0x0000000000000000,  /* 0x1401093f8: live */
    0x0000000000000000,  /* 0x140109400: live */
    0x0000000000000000,  /* 0x140109408: live */
    0x0000000000000000,  /* 0x140109410: live */
    0x0000000000000000,  /* 0x140109418: live */
    0x0000000000000000,  /* 0x140109420: live */
    0x0000000000000000,  /* 0x140109428: live */
    0x0000000000000000,  /* 0x140109430: live */
    0x0000000000000000,  /* 0x140109438: live */
    0x0000000000000000,  /* 0x140109440: absent; live */
    0x0000000000000000,  /* 0x140109448: live */
    0x0000000000000000,  /* 0x140109450: live */
    0x0000000000000000,  /* 0x140109458: live */
    0x0000000000000000,  /* 0x140109460: live */
    0x0000000000000000,  /* 0x140109468: live */
    0x0000000000000000,  /* 0x140109470: live */
    0x0000000000000000,  /* 0x140109478: live */
    0x0000000000000000,  /* 0x140109480: live */
    0x0000000000000000,  /* 0x140109488: live */
    0x0000000000000000,  /* 0x140109490: live */
    0x0000000000000000,  /* 0x140109498: live */
    0x0000000000000000,  /* 0x1401094a0: live */
    0x0000000000000000,  /* 0x1401094a8: live */
    0x0000000000000000,  /* 0x1401094b0: live */
    0x0000000000000000,  /* 0x1401094b8: live */
    0x0000000000000000,  /* 0x1401094c0: live */
    0x0000000000000000,  /* 0x1401094c8: live */
    0x0000000000000000,  /* 0x1401094d0: live */
    0x0000000000000000,  /* 0x1401094d8: live */
    0x0000000000000000,  /* 0x1401094e0: live */
    0x0000000000000000,  /* 0x1401094e8: live */
    0x0000000000000000,  /* 0x1401094f0: live */
    0x0000000000000000,  /* 0x1401094f8: live */
    0x0000000000000000,  /* 0x140109500: live */
    0x0000000000000000,  /* 0x140109508: live */
    0x0000000000000000,  /* 0x140109510: live */
    0x0000000000000000,  /* 0x140109518: live */
    0x0000000000000000,  /* 0x140109520: live */
    0x0000000000000000,  /* 0x140109528: live */
    0x0000000000000000,  /* 0x140109530: live */
    0x0000000000000000,  /* 0x140109538: live */
    0x0000000000000000,  /* 0x140109540: live */
    0x0000000000000000,  /* 0x140109548: live */
    0x0000000000000000,  /* 0x140109550: live */
    0x0000000000000000,  /* 0x140109558: live */
    0x0000000000000000,  /* 0x140109560: live */
    0x0000000000000000,  /* 0x140109568: live */
    0x0000000000000000,  /* 0x140109570: live */
    0x0000000000000000,  /* 0x140109578: live */
    0x0000000000000000,  /* 0x140109580: live */
    0x0000000000000000,  /* 0x140109588: live */
    0x0000000000000000,  /* 0x140109590: live */
    0x0000000000000000,  /* 0x140109598: live */
    0x0000000000000000,  /* 0x1401095a0: absent; live */
    0x0000000000000000,  /* 0x1401095a8: live */
    0x0000000000000000,  /* 0x1401095b0: live */
    0x0000000000000000,  /* 0x1401095b8: live */
    0x0000000000000000,  /* 0x1401095c0: live */
    0x0000000000000000,  /* 0x1401095c8: live */
    0x0000000000000000,  /* 0x1401095d0: live */
    0x0000000000000000,  /* 0x1401095d8: live */
    0x0000000000000000,  /* 0x1401095e0: live */
    0x0000000000000000,  /* 0x1401095e8: live */
    0x0000000000000000,  /* 0x1401095f0: live */
    0x0000000000000000,  /* 0x1401095f8: live */
    0x0000000000000000,  /* 0x140109600: live */
    0x0000000000000000,  /* 0x140109608: live */
    0x0000000000000000,  /* 0x140109610: live */
    0x0000000000000000,  /* 0x140109618: live */
    0x0000000000000000,  /* 0x140109620: live */
    0x0000000000000000,  /* 0x140109628: live */
    0x0000000000000000,  /* 0x140109630: live */
    0x0000000000000000,  /* 0x140109638: absent; live */
    0x0000000000000000,  /* 0x140109640: absent; live */
    0x0000000000000000,  /* 0x140109648: absent; live */
    0x0000000000000000,  /* 0x140109650: live */
    0x0000000000000000,  /* 0x140109658: live */
    0x0000000000000000,  /* 0x140109660: live */
    0x0000000000000000,  /* 0x140109668: live */
    0x0000000000000000,  /* 0x140109670: live */
    0x0000000000000000,  /* 0x140109678: live */
    0x0000000000000000,  /* 0x140109680: absent; live */
    0x0000000000000000,  /* 0x140109688: live */
    0x0000000000000000,  /* 0x140109690: absent; live */
    0x0000000000000000,  /* 0x140109698: unknown; live */
    0x0000000000000000,  /* 0x1401096a0: unknown; live */
    0x0000000000000000,  /* 0x1401096a8: absent; live */
    0x0000000000000000,  /* 0x1401096b0: absent; live */
    0x0000000000000000,  /* 0x1401096b8: absent; live */
    0x0000000000000000,  /* 0x1401096c0: absent; live */
    0x0000000000000000,  /* 0x1401096c8: absent; live */
    0x0000000000000000,  /* 0x1401096d0: absent; live */
    0x0000000000000000,  /* 0x1401096d8: absent; live */
    0x0000000000000000,  /* 0x1401096e0: absent; live */
    0x0000000000000000,  /* 0x1401096e8: absent; live */
    0x0000000000000000,  /* 0x1401096f0: live */
    0x0000000000000000,  /* 0x1401096f8: live */
    0x0000000000000000,  /* 0x140109700: absent; live */
    0x0000000000000000,  /* 0x140109708: unknown; live */
    0x0000000000000000,  /* 0x140109710: unknown; live */
    0x0000000000000000,  /* 0x140109718: live */
    0x0000000000000000,  /* 0x140109720: live */
    0x0000000000000000,  /* 0x140109728: absent; live */
    0x0000000000000000,  /* 0x140109730: unknown; live */
    0x0000000000000000,  /* 0x140109738: unknown; live */
    0x0000000000000000,  /* 0x140109740: absent; live */
    0x0000000000000000,  /* 0x140109748: live */
    0x0000000000000000,  /* 0x140109750: live */
    0x0000000000000000,  /* 0x140109758: live */
    0x0000000000000000,  /* 0x140109760: live */
    0x0000000000000000,  /* 0x140109768: live */
    0x0000000000000000,  /* 0x140109770: live */
    0x0000000000000000,  /* 0x140109778: live */
    0x0000000000000000,  /* 0x140109780: live */
    0x0000000000000000,  /* 0x140109788: live */
    0x0000000000000000,  /* 0x140109790: live */
    0x0000000000000000,  /* 0x140109798: live */
    0x0000000000000000,  /* 0x1401097a0: live */
    0x0000000000000000,  /* 0x1401097a8: live */
    0x0000000000000000,  /* 0x1401097b0: live */
    0x0000000000000000,  /* 0x1401097b8: live */
    0x0000000000000000,  /* 0x1401097c0: live */
    0x0000000000000000,  /* 0x1401097c8: live */
    0x0000000000000000,  /* 0x1401097d0: live */
    0x0000000000000000,  /* 0x1401097d8: live */
    0x0000000000000000,  /* 0x1401097e0: live */
    0x0000000000000000,  /* 0x1401097e8: live */
    0x0000000000000000,  /* 0x1401097f0: live */
    0x0000000000000000,  /* 0x1401097f8: live */
    0x0000000000000000,  /* 0x140109800: live */
    0x0000000000000000,  /* 0x140109808: live */
    0x0000000000000000,  /* 0x140109810: live */
    0x0000000000000000,  /* 0x140109818: live */
    0x0000000000000000,  /* 0x140109820: live */
    0x0000000000000000,  /* 0x140109828: live */
    0x0000000000000000,  /* 0x140109830: live */
    0x0000000000000000,  /* 0x140109838: live */
    0x0000000000000000,  /* 0x140109840: unknown; live */
    0x0000000000000000,  /* 0x140109848: unknown; live */
    0x0000000000000000,  /* 0x140109850: live */
    0x0000000000000000,  /* 0x140109858: unknown; live */
    0x0000000000000000,  /* 0x140109860: live */
    0x0000000000000000,  /* 0x140109868: live */
    0x0000000000000000,  /* 0x140109870: live */
    0x0000000000000000,  /* 0x140109878: live */
    0x0000000000000000,  /* 0x140109880: live */
    0x0000000000000000,  /* 0x140109888: live */
    0x0000000000000000,  /* 0x140109890: live */
    0x0000000000000000,  /* 0x140109898: live */
    0x0000000000000000,  /* 0x1401098a0: live */
    0x0000000000000000,  /* 0x1401098a8: live */
    0x0000000000000000,  /* 0x1401098b0: live */
    0x0000000000000000,  /* 0x1401098b8: live */
    0x0000000000000000,  /* 0x1401098c0: live */
    0x0000000000000000,  /* 0x1401098c8: live */
    0x0000000000000000,  /* 0x1401098d0: live */
    0x0000000000000000,  /* 0x1401098d8: live */
    0x0000000000000000,  /* 0x1401098e0: live */
    0x0000000000000000,  /* 0x1401098e8: live */
    0x0000000000000000,  /* 0x1401098f0: live */
    0x0000000000000000,  /* 0x1401098f8: live */
    0x0000000000000000,  /* 0x140109900: live */
    0x0000000000000000,  /* 0x140109908: live */
    0x0000000000000000,  /* 0x140109910: live */
    0x0000000000000000,  /* 0x140109918: live */
    0x0000000000000000,  /* 0x140109920: live */
    0x0000000000000000,  /* 0x140109928: live */
    0x0000000000000000,  /* 0x140109930: live */
    0x0000000000000000,  /* 0x140109938: live */
    0x0000000000000000,  /* 0x140109940: live */
    0x0000000000000000,  /* 0x140109948: live */
    0x0000000000000000,  /* 0x140109950: live */
    0x0000000000000000,  /* 0x140109958: live */
    0x0000000000000000,  /* 0x140109960: live */
    0x0000000000000000,  /* 0x140109968: live */
    0x0000000000000000,  /* 0x140109970: live */
    0x0000000000000000,  /* 0x140109978: live */
    0x0000000000000000,  /* 0x140109980: live */
    0x0000000000000000,  /* 0x140109988: live */
    0x0000000000000000,  /* 0x140109990: live */
    0x0000000000000000,  /* 0x140109998: live */
    0x0000000000000000,  /* 0x1401099a0: live */
    0x0000000000000000,  /* 0x1401099a8: live */
    0x0000000000000000,  /* 0x1401099b0: live */
    0x0000000000000000,  /* 0x1401099b8: live */
    0x0000000000000000,  /* 0x1401099c0: live */
    0x0000000000000000,  /* 0x1401099c8: live */
    0x0000000000000000,  /* 0x1401099d0: live */
    0x0000000000000000,  /* 0x1401099d8: live */
    0x0000000000000000,  /* 0x1401099e0: live */
    0x0000000000000000,  /* 0x1401099e8: live */
    0x0000000000000000,  /* 0x1401099f0: live */
    0x0000000000000000,  /* 0x1401099f8: live */
    0x0000000000000000,  /* 0x140109a00: live */
    0x0000000000000000,  /* 0x140109a08: live */
    0x0000000000000000,  /* 0x140109a10: live */
    0x0000000000000000,  /* 0x140109a18: live */
    0x0000000000000000,  /* 0x140109a20: live */
    0x0000000000000000,  /* 0x140109a28: live */
    0x0000000000000000,  /* 0x140109a30: live */
    0x0000000000000000,  /* 0x140109a38: live */
    0x0000000000000000,  /* 0x140109a40: live */
    0x0000000000000000,  /* 0x140109a48: live */
    0x0000000000000000,  /* 0x140109a50: live */
    0x0000000000000000,  /* 0x140109a58: live */
    0x0000000000000000,  /* 0x140109a60: live */
    0x0000000000000000,  /* 0x140109a68: live */
    0x0000000000000000,  /* 0x140109a70: live */
    0x0000000000000000,  /* 0x140109a78: live */
    0x0000000000000000,  /* 0x140109a80: live */
    0x0000000000000000,  /* 0x140109a88: live */
    0x0000000000000000,  /* 0x140109a90: live */
    0x0000000000000000,  /* 0x140109a98: live */
    0x0000000000000000,  /* 0x140109aa0: live */
    0x0000000000000000,  /* 0x140109aa8: live */
    0x0000000000000000,  /* 0x140109ab0: live */
    0x0000000000000000,  /* 0x140109ab8: live */
    0x0000000000000000,  /* 0x140109ac0: live */
    0x0000000000000000,  /* 0x140109ac8: live */
    0x0000000000000000,  /* 0x140109ad0: live */
    0x0000000000000000,  /* 0x140109ad8: live */
    0x0000000000000000,  /* 0x140109ae0: live */
    0x0000000000000000,  /* 0x140109ae8: live */
    0x0000000000000000,  /* 0x140109af0: live */
    0x0000000000000000,  /* 0x140109af8: live */
    0x0000000000000000,  /* 0x140109b00: live */
    0x0000000000000000,  /* 0x140109b08: live */
    0x0000000000000000,  /* 0x140109b10: live */
    0x0000000000000000,  /* 0x140109b18: live */
    0x0000000000000000,  /* 0x140109b20: live */
    0x0000000000000000,  /* 0x140109b28: live */
    0x0000000000000000,  /* 0x140109b30: live */
    0x0000000000000000,  /* 0x140109b38: live */
    0x0000000000000000,  /* 0x140109b40: live */
    0x0000000000000000,  /* 0x140109b48: live */
    0x0000000000000000,  /* 0x140109b50: live */
    0x0000000000000000,  /* 0x140109b58: live */
    0x0000000000000000,  /* 0x140109b60: live */
    0x0000000000000000,  /* 0x140109b68: live */
    0x0000000000000000,  /* 0x140109b70: live */
    0x0000000000000000,  /* 0x140109b78: live */
    0x0000000000000000,  /* 0x140109b80: live */
    0x0000000000000000,  /* 0x140109b88: live */
    0x0000000000000000,  /* 0x140109b90: live */
    0x0000000000000000,  /* 0x140109b98: live */
    0x0000000000000000,  /* 0x140109ba0: live */
    0x0000000000000000,  /* 0x140109ba8: live */
    0x0000000000000000,  /* 0x140109bb0: live */
    0x0000000000000000,  /* 0x140109bb8: live */
    0x0000000000000000,  /* 0x140109bc0: live */
    0x0000000000000000,  /* 0x140109bc8: live */
    0x0000000000000000,  /* 0x140109bd0: live */
    0x0000000000000000,  /* 0x140109bd8: live */
    0x0000000000000000,  /* 0x140109be0: live */
    0x0000000000000000,  /* 0x140109be8: live */
    0x0000000000000000,  /* 0x140109bf0: live */
    0x0000000000000000,  /* 0x140109bf8: live */
    0x0000000000000000,  /* 0x140109c00: live */
    0x0000000000000000,  /* 0x140109c08: live */
    0x0000000000000000,  /* 0x140109c10: live */
    0x0000000000000000,  /* 0x140109c18: live */
    0x0000000000000000,  /* 0x140109c20: live */
    0x0000000000000000,  /* 0x140109c28: live */
    0x0000000000000000,  /* 0x140109c30: live */
    0x0000000000000000,  /* 0x140109c38: live */
    0x0000000000000000,  /* 0x140109c40: live */
    0x0000000000000000,  /* 0x140109c48: live */
    0x0000000000000000,  /* 0x140109c50: live */
    0x0000000000000000,  /* 0x140109c58: live */
    0x0000000000000000,  /* 0x140109c60: live */
    0x0000000000000000,  /* 0x140109c68: live */
    0x0000000000000000,  /* 0x140109c70: live */
    0x0000000000000000,  /* 0x140109c78: live */
    0x0000000000000000,  /* 0x140109c80: live */
    0x0000000000000000,  /* 0x140109c88: live */
    0x0000000000000000,  /* 0x140109c90: live */
    0x0000000000000000,  /* 0x140109c98: live */
    0x0000000000000000,  /* 0x140109ca0: unknown; live */
    0x0000000000000000,  /* 0x140109ca8: live */
    0x0000000000000000,  /* 0x140109cb0: absent; live */
    0x0000000000000000,  /* 0x140109cb8: live */
    0x0000000000000000,  /* 0x140109cc0: live */
    0x0000000000000000,  /* 0x140109cc8: absent; live */
    0x0000000000000000,  /* 0x140109cd0: live */
    0x0000000000000000,  /* 0x140109cd8: live */
    0x0000000000000000,  /* 0x140109ce0: unknown; live */
    0x0000000000000000,  /* 0x140109ce8: absent; live */
    0x0000000000000000,  /* 0x140109cf0: absent; live */
    0x0000000000000000,  /* 0x140109cf8: live */
    0x0000000000000000,  /* 0x140109d00: live */
    0x0000000000000000,  /* 0x140109d08: live */
    0x0000000000000000,  /* 0x140109d10: live */
    0x0000000000000000,  /* 0x140109d18: absent; live */
    0x0000000000000000,  /* 0x140109d20: live */
    0x0000000000000000,  /* 0x140109d28: live */
    0x0000000000000000,  /* 0x140109d30: live */
    0x0000000000000000,  /* 0x140109d38: absent; live */
    0x0000000000000000,  /* 0x140109d40: live */
    0x0000000000000000,  /* 0x140109d48: absent; live */
    0x0000000000000000,  /* 0x140109d50: live */
};

/* ==========================================================================
 * Каталог callback-кандидатов: 83 no-caller VM-хаба <-> 83 нативных thunk'а
 * --------------------------------------------------------------------------
 * [AC_STATIC_VERDICTS P.2 + ac_vm_map.md (_ac_cbhubs_list.json,
 * _ac_cbhubs_classified.json): кандидаты OS callback-указателей выбираются
 * из этого 1:1 набора MBA-вычисленными записями регистрации; роли
 * поименованы для 83/83 (static_name + роль по классификатору).
 * Отображение "какой thunk в какую регистрацию" НЕ материализуется
 * статически (отложенный путь, AC_STATIC_VERDICTS P.2/P.3) -- класс:
 * genuinely-live (нужны были бы живые VM !callback/!drvobj).
 * Cross-ref: events.c AcRegisterNotifyCallbacks.
 * ==========================================================================*/

typedef struct _AC_CBHUB_ENTRY {
    UINT64 HubVa;           /* адрес no-caller VM-хаба */
    UINT32 Size;            /* размер хаба */
    const CHAR* StaticName; /* статическое имя из корпуса (v1/v4) */
    const CHAR* Role;       /* роль по классификатору */
} AC_CBHUB_ENTRY, *PAC_CBHUB_ENTRY;

#define AC_CBHUB_COUNT 83
const AC_CBHUB_ENTRY g_AcCbHubCatalog[AC_CBHUB_COUNT] = {
    { 0x140125ad4, 0x34, "ac_qsi_basic_s01", "environment probe body (QSI/IRQL/cpuid)" },
    { 0x14012f382, 0x4d, "ac_qsi_c18_s01", "environment probe body (QSI/IRQL/cpuid)" },
    { 0x14013257f, 0x159, "ac_apiuser_ExAllocatePool2_s020", "resolved-API wrapper body (internal)" },
    { 0x140133ee1, 0xca, "ac_qsi_code_integrity_s01", "environment probe body (QSI/IRQL/cpuid)" },
    { 0x140137978, 0x5d, "?", "unknown (weak replay footprint)" },
    { 0x140144a9e, 0x8f, "ac_env_irql_check_s01", "environment probe body (QSI/IRQL/cpuid)" },
    { 0x140151d9f, 0xc66, "vmexit_xor_api_ptr_call_s02", "API-obfuscation stub с собственным event_seq-бампом" },
    { 0x140154e07, 0x2e, "?", "unknown (weak replay footprint)" },
    { 0x1401565ed, 0xa5, "ac_apiuser_ExFreePoolWithTag_s01", "resolved-API wrapper body (internal)" },
    { 0x140162010, 0x89, "ac_sealed_compute_162010", "sealed-box crypto compute (internal)" },
    { 0x1401627e5, 0x7c, "ac_sealed_compute_1627e5", "sealed-box crypto compute (internal)" },
    { 0x1401666bc, 0x51, "?", "unknown (weak replay footprint)" },
    { 0x1401718d7, 0xec, "ac_env_irql_check_s03", "environment probe body (QSI/IRQL/cpuid)" },
    { 0x1401776c6, 0x77, "?", "unknown (weak replay footprint)" },
    { 0x14017ed57, 0x3e, "ac_sealed_compute_17ed57", "sealed-box crypto compute (internal)" },
    { 0x14018c296, 0x104, "ac_transport_client_s10", "channel/transport body" },
    { 0x1401a2afa, 0xe0, "ac_chan_list_reader_s01", "channel/transport body" },
    { 0x1401a36cc, 0x22, "ac_sealed_compute_1a36cc", "sealed-box crypto compute (internal)" },
    { 0x1401a51a5, 0x5e, "ac_apiuser_KeEnterCriticalRegion_s03", "resolved-API wrapper body (internal)" },
    { 0x1401a577e, 0x926, "ac_transport_client_s14", "channel/transport body" },
    { 0x1401aacbc, 0x41, "ac_sealed_compute_1aacbc", "sealed-box crypto compute (internal)" },
    { 0x1401abbf0, 0x57, "ac_sealed_compute_1abbf0", "sealed-box crypto compute (internal)" },
    { 0x1401ce711, 0x2db, "ac_sealed_compute_1ce711", "sealed-box crypto compute (internal)" },
    { 0x1401d3527, 0xb2, "ac_qsi_basic_s04", "environment probe body (QSI/IRQL/cpuid)" },
    { 0x1401d9300, 0x53, "ac_qsi_basic_s05", "environment probe body (QSI/IRQL/cpuid)" },
    { 0x1401d9ddf, 0x66, "ac_transport_client_s21", "channel/transport body" },
    { 0x1401da093, 0xa7, "ac_apiuser_ExAllocatePool2_s069", "resolved-API wrapper body (internal)" },
    { 0x1401e8a51, 0x5a, "ac_sealed_compute_1e8a51", "sealed-box crypto compute (internal)" },
    { 0x1401ee2bc, 0x55, "?", "unknown (weak replay footprint)" },
    { 0x1401f6dba, 0x1b6, "ac_qsi_c10_s01", "environment probe body (QSI/IRQL/cpuid)" },
    { 0x140201ba7, 0x21, "ac_init_spinlock_reg_s01", "environment probe body (QSI/IRQL/cpuid)" },
    { 0x14020496f, 0x711, "ac_event_producer_s02", "event enqueue (0x2b process/handle event)" },
    { 0x14020c262, 0x2c, "ac_qsi_basic_s07", "environment probe body (QSI/IRQL/cpuid)" },
    { 0x14020fe8a, 0xb5, "?", "module-inventory refresh body" },
    { 0x140211701, 0x3e, "?", "process-context self-check body" },
    { 0x140229cc0, 0xd3, "ac_sealed_compute_229cc0", "sealed-box crypto compute (internal)" },
    { 0x140232573, 0x126, "ac_sealed_compute_232573", "sealed-box crypto compute (internal)" },
    { 0x14023312a, 0x2b, "ac_chan_list_reader_s02", "channel/transport body" },
    { 0x140234578, 0x17c, "ac_verifmod_hub_s04", "verified-module pipeline hub" },
    { 0x14023a166, 0x32, "ac_sealed_compute_23a166", "sealed-box crypto compute (internal)" },
    { 0x140247e17, 0x1d6, "ac_env_irql_check_s05", "environment probe body (QSI/IRQL/cpuid)" },
    { 0x1402481a1, 0x21, "ac_chan_reader_s03", "channel/transport body" },
    { 0x14024a7a8, 0xb9, "ac_apiuser_ExAllocatePool2_s081", "resolved-API wrapper body (internal)" },
    { 0x14024c8c1, 0x2f, "?", "unknown (weak replay footprint)" },
    { 0x14024de7c, 0xb8, "ac_qsi_basic_s08", "environment probe body (QSI/IRQL/cpuid)" },
    { 0x140251257, 0x85, "ac_sealed_compute_251257", "sealed-box crypto compute (internal)" },
    { 0x140251872, 0xf5, "ac_apiresolve_user_s066", "resolved-API wrapper body (internal)" },
    { 0x14025f3f3, 0xf4, "ac_modinv_client_s16", "module-inventory/verify body" },
    { 0x1402602ac, 0xc7, "ac_sealed_compute_2602ac", "sealed-box crypto compute (internal)" },
    { 0x140263c95, 0xf0, "ac_qsi_basic_s09", "environment probe body (QSI/IRQL/cpuid)" },
    { 0x140267b2e, 0x161, "vmexit_xor_api_ptr_call_s07", "API-obfuscation stub (vmexit ptr call)" },
    { 0x140276580, 0x8f, "ac_sealed_compute_276580", "sealed-box crypto compute (internal)" },
    { 0x140279a19, 0xa1, "ac_apiuser_KeAcquireSpinLock_v1_s04", "resolved-API wrapper body (internal)" },
    { 0x14027a1c1, 0xd8, "ac_transport_client_s29", "channel/transport body" },
    { 0x14027f2b7, 0x27, "ac_apiuser_KeClearEvent_s01", "resolved-API wrapper body (internal)" },
    { 0x140280741, 0x70, "ac_apiuser_ExAllocatePool2_s084", "resolved-API wrapper body (internal)" },
    { 0x14029003d, 0x160, "vmexit_xor_api_ptr_call_s10", "API-obfuscation stub (vmexit ptr call)" },
    { 0x1402b05b0, 0x24, "ac_ctx_bookkeep_2b05b0", "sealed-box crypto compute (internal)" },
    { 0x1402b931b, 0xdd, "ac_transport_client_s40", "channel/transport body" },
    { 0x1402c3190, 0x40, "ac_apiuser_KeAcquireSpinLock_v2_s10", "resolved-API wrapper body (internal)" },
    { 0x1402c4aa8, 0x2c, "?", "large-object field patch (arg0 0x520+)" },
    { 0x140307d93, 0x181, "ac_apiresolve_user_s111", "resolved-API wrapper body (internal)" },
    { 0x140310f61, 0x1bb, "vmexit_xor_api_ptr_call_s11", "API-obfuscation stub (vmexit ptr call)" },
    { 0x14031f109, 0x96, "?", "locked list-insert helper (embedded spinlock)" },
    { 0x14032292b, 0x1a5, "ac_qsi_basic_s12", "environment probe body (QSI/IRQL/cpuid)" },
    { 0x14032365b, 0xac, "ac_apiuser_ExAllocatePool2_s090", "resolved-API wrapper body (internal)" },
    { 0x1403600db, 0xbd, "ac_sealed_compute_3600db", "sealed-box crypto compute (internal)" },
    { 0x140363a95, 0x24, "ac_chan_teardown_s02", "channel/transport body" },
    { 0x140369a56, 0x31, "?", "unknown (weak replay footprint)" },
    { 0x14037240b, 0x4b, "ac_apiuser_ExAllocatePool2_s092", "resolved-API wrapper body (internal)" },
    { 0x140374494, 0x59, "ac_sealed_compute_374494", "sealed-box crypto compute (internal)" },
    { 0x140382baa, 0xbf, "ac_qsi_c28_s07", "environment probe body (QSI/IRQL/cpuid)" },
    { 0x140385740, 0xd3, "vmexit_xor_api_ptr_call_s13", "API-obfuscation stub (vmexit ptr call)" },
    { 0x140397587, 0xf4, "?", "event enqueue (2xUNICODE_STRING, 0x658 record)" },
    { 0x1403998b7, 0xa0, "ac_sealed_compute_3998b7", "sealed-box crypto compute (internal)" },
    { 0x14039f251, 0xde, "ac_sealed_compute_39f251", "sealed-box crypto compute (internal)" },
    { 0x1403a252b, 0x8a, "ac_env_irql_check_s09", "environment probe body (QSI/IRQL/cpuid)" },
    { 0x1403ae948, 0xce, "ac_chan_list_reader_s03", "channel/transport body" },
    { 0x1403b9bcd, 0xdb, "ac_apiuser_ExAllocatePool2_s098", "resolved-API wrapper body (internal)" },
    { 0x1403ba8cd, 0x2b, "?", "unknown (weak replay footprint)" },
    { 0x1403bcbf9, 0x2cd, "vmexit_xor_api_ptr_call_s14", "API-obfuscation stub (vmexit ptr call)" },
    { 0x1403c578c, 0x20e, "vmexit_xor_api_ptr_call_s15", "API-obfuscation stub (vmexit ptr call)" },
    { 0x1403d0389, 0x46f, "ac_driverentry_hub", "DriverEntry VM hub (bootstrap, gated)" },
};

/* ==========================================================================
 * Реестр классов VA-владельцев (_research_tmp/va_map, таск va_map D4-b)
 * --------------------------------------------------------------------------
 * У каждого corpus VA (fullbody6 corpus INDEX: 4,393 VA-несущих записей,
 * 4,392 уникальных VA + 1 cross-listed дубликат 0x1401ac9aa, плюс 5
 * агрегатных записей без VA) есть владелец: либо функция sln, либо один из
 * документированных классов ниже. Построчно по VA с evidence:
 *   _research_tmp/va_map/va_to_owner.jsonl   (4,398 corpus записей)
 *   _research_tmp/va_map/coverage.json       (sln_fn + class = 100%, gap 0)
 * Конвенция обоснования: VM-механика/обфускационная фабрика и compiler
 * runtime -- НЕ семантика драйвера: они документируются как классы
 * (обфускационная материя, тела сохранены в корпусе), никогда не
 * пере-изобретаются как фальшивые функции.
 * ==========================================================================*/

typedef struct _AC_VA_OWNER_CLASS {
    const CHAR* ClassName;  /* id класса владельца (va_to_owner.jsonl) */
    UINT32 VaCount;         /* записи corpus VA, принадлежащие классу */
    const CHAR* Evidence;   /* evidence-артефакт(ы) */
    const CHAR* Role;       /* что это за материя */
} AC_VA_OWNER_CLASS;

#define AC_VA_CLASS_COUNT 13
const AC_VA_OWNER_CLASS g_AcVaOwnerClasses[AC_VA_CLASS_COUNT] = {
    { "ac_sealed_body", 2700,
      "corpus v4 sealed_chunks_*.c; README scope decision/NOT_IN_SLN 2",
      "Themida LION64 sealed VM bodies, source semantics not recovered "
      "(obfuscation fabric; bodies preserved in the corpus)" },
    { "ac_vmentry_tramp_A", 225,
      "route_map.json (327 chains) + enl_inventory (executed tramps)",
      "VM-entry trampoline family A (init_model resolver/finalizer A)" },
    { "ac_vmentry_tramp_B", 188,
      "route_map.json + enl_inventory",
      "VM-entry trampoline family B" },
    { "ac_vmentry_tramp_C", 162,
      "route_map.json + enl_inventory",
      "VM-entry trampoline family C" },
    { "ac_vmentry_tramp_D", 156,
      "route_map.json + enl_inventory",
      "VM-entry trampoline family D" },
    { "ac_native_crt", 220,
      "AC_NATIVE 0/6; body profile: no kernel-API/driver-string use",
      "compiler runtime / CRT leaf helpers in native .text (memset/"
      "memmove/security-cookie/snprintf family)" },
    { "ac_gap2_fragment", 138,
      "corpus gap2_*.c headers (algo-p4 lifted layers)",
      "gap2 lifted VM layers of generated-code regions" },
    { "ac_dead_stub", 74,
      "repoint_map.jsonl repoint-dead; dead_collapse classification; "
      "corpus final_wire_stubs.c",
      "e9-thunks proven dead-native" },
    { "ac_hole_dispatch", 44,
      "repoint_map.jsonl repoint-hole(-call); corpus final_wire_stubs.c",
      "e9-thunks to unmapped .grfn1 holes (content-in-corpus/"
      "hole-executed/payload-dead)" },
    { "ac_api_wrapper", 35,
      "AC_NATIVE 3.1 XOR-pair idiom; imports.h verified cells",
      "resolved-API XOR-pair call wrappers (VM clones of one idiom; "
      "semantic API set = imports.h 260 verified + kldr.c resolver)" },
    { "ac_ctx_bookkeep", 35,
      "cbhub catalog role 'sealed-box crypto compute (internal)'",
      "VM context bookkeeping fragments (per-site sealed compute)" },
    { "ac_native_slot_api", 9,
      "AC_NATIVE 1.5; facility-0x10 status constants 0x801000xx/"
      "0x802000xx in bodies",
      "slot-API internal status paths (slot-register/resolve contour)" },
    { "ac_crypto_primitive", 7,
      "AC_NATIVE 2 (native libsodium zone of .text) + 6 bridge",
      "native libsodium primitives (BLAKE2b/X25519/Salsa20/Poly1305/"
      "RNG; reconstructed logic in crypto_libsodium.c)" },
};

/* ==========================================================================
 * Карта окна crypto-vtable: 0x140106090..0x140106188 (31 указатель)
 * --------------------------------------------------------------------------
 * [RECON2_INVENTORY:164, AC_STATIC_VERDICTS:87]: 31 указатель из
 * data-окна на vtable'ы BLAKE2/X25519 криптослоя (второе окно после
 * stream/box vtable'ов 0x140106f68/0x140106f78, процитированных в
 * crypto_libsodium.c). Статический qword-скан: единственная таблица
 * код-указателей в .data (AC_STATIC_VERDICTS P.2 заметка 1).
 * Содержимое vtable (31 вход) строится в рантайме крипто-init'ом;
 * нативные VA примитивов за ними -- VA-карта crypto_libsodium.c
 * (HSalsa20 0x14002d7a8, Salsa20 0x14002dc70, X25519 0x140035b88,
 * scalarmult_base 0x14003630c, семейство BLAKE2 0x140034cd8/...).
 * ========================================================================== */

/* ==========================================================================
 * Якоря sealed-compute из Corpus INDEX (cross-ref, fullbody/corpus INDEX
 * = 11 дубликатов одного и того же манифеста на 147 маркеров):
 *   0x14010f73b  ac_apiuser_ExAllocatePool2_s002
 *   0x14010f125  ac_sealed_compute_10f125
 *   0x14010f697  ac_sealed_compute_10f697
 *   0x14010fad3  ac_sealed_compute_10fad3
 * (хосты sealed_chunks_01.c; якоря корпуса, не логика реконструкции)
 * ========================================================================== */
