/* ==========================================================================
 * records.c -- билдеры wire-записей из records.h
 * --------------------------------------------------------------------------
 * Кандидат на мерж для driver_sln/src/channels.c (отдельный мерж-таск).
 * Стиль следует реконструкции: provenance-тэг [0xVA] на каждом источнике
 * поля; шаги у VM-границы помечены payload-selected и никогда не
 * подделываются.
 *
 * Пополевой evidence:
 *   hello  : frames_pt/hello_2.pt (run-2) + in_0001.pt (shim72) [dec]
 *   disks  : frames_pt/in_0002.pt [dec]
 *   ram    : frames_pt/in_0003.pt [dec]
 *   events : frames_pt/in_0006.pt / in_0194.pt / in_0217.pt [dec]
 *   bus    : AC_EVENT_CHANNEL.md (static-proven продюсеры)
 * ========================================================================== */
#include "wire_records.h"

/* --------------------------------------------------------------------------
 * маленькие строковые хелперы (kernel-mode, без CRT)
 * ------------------------------------------------------------------------ */
/* helper: kernel-mode строковые утилиты для билдеров (авторитет layout'а
 * _research_tmp/wiremap/BYTE_MAP.md) */
static UINT32
AcRecStrLenA(
    _In_ const CHAR* S
    )
{
    UINT32 n = 0;
    while (S[n] != '\0')
        n++;
    return n;
}

/* helper: ограниченная ASCII-копия для билдеров */
static VOID
AcRecCopyStrA(
    _Out_writes_(Cap) CHAR* Dst,
    _In_ UINT32 Cap,
    _In_ const CHAR* Src
    )
{
    UINT32 n = AcRecStrLenA(Src);
    if (n >= Cap)
        n = Cap - 1;
    RtlCopyMemory(Dst, Src, n);
    Dst[n] = '\0';
}

/* helper: ограниченная UTF-16 копия для билдеров */
static VOID
AcRecCopyStrW(
    _Out_writes_(Chars) WCHAR* Dst,
    _In_ UINT32 Chars,
    _In_ const WCHAR* Src
    )
{
    UINT32 n = 0;
    while (Src[n] != L'\0')
        n++;
    if (n >= Chars)
        n = Chars - 1;
    RtlCopyMemory(Dst, Src, n * sizeof(WCHAR));
    Dst[n] = L'\0';
}

/* --------------------------------------------------------------------------
 * [0x140108db8] счётчик seq: qword seq @+8 каждого seq-события =
 * LOCK xadd глобального счётчика (AC_EVENT_CHANNEL #0; дословный LOCK inc
 * в module_notify_callback 0x140043258)
 * ------------------------------------------------------------------------ */
static LONG64 g_AcRecSeq;   /* замещает ячейку 0x140108db8 при мерже */

static UINT64
AcRecNextSeq(
    VOID
    )
{
    return (UINT64)InterlockedIncrement64(&g_AcRecSeq);
}

/* --------------------------------------------------------------------------
 * [0x14000c35c] тело heartbeat-продюсера (вызывается KTIMER-воркером
 * [0x14001278c], due ~-30s, два таймера ~4s друг от друга)
 * ------------------------------------------------------------------------ */
VOID
AcRecBuildHeartbeat(
    _Out_ PAC_REC_HEARTBEAT Rec,
    _In_ UINT32 Flag            /* 1 или 2: два класса keepalive [dec] */
    )
{
    Rec->Marker = AC_REC_MARK_HEARTBEAT;   /* (0x2481b1>>16) в оригинале */
    Rec->Flag   = Flag;
}

/* --------------------------------------------------------------------------
 * [0x140066c18] teardown первичного клиента: запись 0x02 {type, pid}
 * ------------------------------------------------------------------------ */
VOID
AcRecBuildTeardown(
    _Out_ PAC_REC_TEARDOWN Rec
    )
{
    Rec->Type = AC_EV_TEARDOWN;
    Rec->Pid  = (UINT64)PsGetCurrentProcessId();
}

/* --------------------------------------------------------------------------
 * [0x140066b3c] запись сброса канала 0x0A (форма шины); wire-вариант
 * attach (фрейм in_0194) несёт Flag=1 с pid подключающейся игры
 * ------------------------------------------------------------------------ */
VOID
AcRecBuildProcAttach(
    _Out_ PAC_REC_PROC_ATTACH Rec,
    _In_ UINT64 Pid,
    _In_ UINT32 Flag            /* 1 = attach (wire) / 0 = reset (static) */
    )
{
    Rec->Marker = AC_REC_MARK_PROC_ATTACH;
    Rec->Zero04 = 0;
    Rec->Pid    = Pid;
    Rec->State  = 0;            /* шина: значение ячейки 0x140108ba8 */
    Rec->Flag   = Flag;
    Rec->Zero1C = 0;
}

/* --------------------------------------------------------------------------
 * [part_0007.c:470] запись имени 0x1B (ветка verification-fail);
 * та же форма служит 0x1A (FUN_140041c74) и 0x29 (part_0008.c:617)
 * ------------------------------------------------------------------------ */
/* [0x140041c74] форма продюсера 0x1A (ветка 0x1B part_0007.c:470;
 * 0x29 part_0008.c:617) */
VOID
AcRecBuildName(
    _Out_ PAC_REC_NAME Rec,
    _In_ UINT32 Marker,         /* 0x1A / 0x1B / 0x29 */
    _In_ const WCHAR* Path
    )
{
    Rec->Marker = Marker;
    AcRecCopyStrW(Rec->Path, 0x104, Path);
}

/* --------------------------------------------------------------------------
 * [0x14003f0bc] событие состояния модуля 0x1E (гейт на канал 0x140108d50)
 * ------------------------------------------------------------------------ */
VOID
AcRecBuildModuleState(
    _Out_ PAC_REC_MODULE_STATE Rec,
    _In_ const WCHAR* Path,
    _In_ UINT8 State            /* 2 = открытие файла не удалось, 3 = классифицирован */
    )
{
    RtlZeroMemory(Rec, sizeof(*Rec));
    Rec->Marker = AC_EV_MODULE_STATE;
    AcRecCopyStrW(Rec->Path, 0x102, Path);
    Rec->State  = State;
}

/* --------------------------------------------------------------------------
 * [0x14003f78c] событие module-load 0x26 (0x4D8)
 * ------------------------------------------------------------------------ */
VOID
AcRecBuildModuleLoad(
    _Out_ PAC_REC_MODULE_LOAD Rec,
    _In_ UINT64 DllBase,
    _In_ UINT64 SizeOfImage,
    _In_ const WCHAR* Path,
    _In_ UINT32 VerifyFlags,    /* bit0 = file-open fail; 8 = clean */
    _In_ UINT32 VerdictStatus   /* NTSTATUS пути verify FUN_140042034 */
    )
{
    RtlZeroMemory(Rec, sizeof(*Rec));
    Rec->Marker       = AC_EV_MODULE_LOAD;
    Rec->Seq          = AcRecNextSeq();
    Rec->DllBase      = DllBase;
    Rec->SizeOfImage  = SizeOfImage;
    AcRecCopyStrW(Rec->Path, 0x104, Path);
    Rec->BranchFlag   = 1;      /* 0 для варианта FUN_140043414 */
    Rec->KuserRef     = 0xfffff78000000014ULL;   /* KUSER_SHARED_DATA+0x14 */
    Rec->VerifyFlags  = VerifyFlags;
    Rec->VerdictStatus= VerdictStatus;
}

/* --------------------------------------------------------------------------
 * [0x14003f78c ветка] дамп модуля/региона 0x22 (0x228 + size)
 * ------------------------------------------------------------------------ */
VOID
AcRecBuildModuleDump(
    _Out_writes_bytes_(AC_DUMP_HDR_SIZE + Size) PAC_REC_MODULE_DUMP Rec,
    _In_ UINT64 Base,
    _In_ const WCHAR* Name,
    _In_ UINT32 Size,
    _In_ UINT32 Reason,         /* 0 = неверифицированный модуль, 6 = регион паттерна */
    _In_reads_bytes_(Size) const UINT8* Raw
    )
{
    RtlZeroMemory(Rec, AC_DUMP_HDR_SIZE);
    Rec->Marker = AC_EV_MODULE_DUMP;
    Rec->Base   = Base;
    AcRecCopyStrW(Rec->Name, 0x108, Name);
    Rec->Size   = Size;
    Rec->Reason = Reason;
    RtlCopyMemory((UINT8*)Rec + AC_DUMP_HDR_SIZE, Raw, Size);
}

/* --------------------------------------------------------------------------
 * [0x1400713c8] событие файл+подпись 0x2B (wire = 0x498 + sigsize)
 * ------------------------------------------------------------------------ */
VOID
AcRecBuildFileSig(
    _Out_ PAC_REC_FILE_SIG Rec,
    _In_ const UINT64 ObjId[3],
    _In_ UINT64 ChannelId,
    _In_ const WCHAR* Path1,
    _In_ const WCHAR* Path2,
    _In_ UINT64 MappedSize,
    _In_ const CHAR* FileHashAscii,     /* 64 hex + NUL (FUN_14009be44 VM) */
    _In_opt_ const UINT8* SigBlob,
    _In_ UINT32 SigBlobSize,
    _In_ UINT32 SigStatus
    )
{
    RtlZeroMemory(Rec, AC_FILE_SIG_BASE_SIZE);
    Rec->Marker     = AC_EV_FILE_SIG;
    Rec->Seq        = AcRecNextSeq();
    Rec->ObjId[0]   = ObjId[0];
    Rec->ObjId[1]   = ObjId[1];
    Rec->ObjId[2]   = ObjId[2];
    Rec->ChannelId  = ChannelId;
    AcRecCopyStrW(Rec->Path1, 0x104, Path1);
    AcRecCopyStrW(Rec->Path2, 0x104, Path2);
    Rec->MappedSize = MappedSize;
    Rec->KuserRef   = 0xfffff78000000014ULL;
    AcRecCopyStrA(Rec->FileHashAscii, 0x41, FileHashAscii); /* ширина дедупа */
    if (SigBlob != NULL && SigBlobSize >= sizeof(AC_SIG_BLOB)) {
        Rec->Sig.Size   = SigBlobSize;
        Rec->Sig.Status = SigStatus;
        RtlCopyMemory((UINT8*)Rec + AC_FILE_SIG_BASE_SIZE +
                      sizeof(AC_SIG_BLOB),
                      SigBlob + sizeof(AC_SIG_BLOB),
                      SigBlobSize - sizeof(AC_SIG_BLOB));
    } else {
        Rec->Sig.Size   = 0;
        Rec->Sig.Status = SigStatus;
    }
}

/* --------------------------------------------------------------------------
 * писатель слотов disks (маркер 0x18)
 * [0x14017ae1c] storage_query_hub / [0x1403be16b] ata_srb_hub источник
 * полей; [0x14022d6ba] карта слов ata_identify_worker (serial w10-19,
 * fw w23-26, model w27-46, byte-swapped)
 *
 * ЗАМЕТКА о размещении serial'а: оригинал пишет serial по
 * slot_base + 0x148 -- на голову области Id СЛЕДУЮЩЕГО слота (пустой для
 * SATA), а для последнего слота -- за конец записи. Билдер ниже сохраняет
 * наблюдавшееся на wire размещение байтов [layout доказан; семантика
 * открыта].
 * ------------------------------------------------------------------------ */
VOID
AcRecBuildDisks(
    _Out_ PAC_REC_DISKS Rec,
    _In_ UINT32 Count,
    _In_reads_(Count) const AC_HWID_DISK_SRC* Src
    )
{
    UINT32 i;
    UINT32 recSize = 8 + Count * sizeof(AC_DISK_SLOT);

    Rec->Marker = AC_REC_MARK_DISKS;
    Rec->Count  = Count;

    for (i = 0; i < Count; i++) {
        AC_DISK_SLOT* slot = &Rec->Slots[i];

        RtlZeroMemory(slot, sizeof(*slot));
        AcRecCopyStrA(slot->Id,       sizeof(slot->Id),       Src[i].Id);
        AcRecCopyStrA(slot->Model,    sizeof(slot->Model),    Src[i].Model);
        AcRecCopyStrA(slot->Firmware, sizeof(slot->Firmware), Src[i].Firmware);
        slot->SerialLen = Src[i].SerialLen;   /* 0x11 на wire [dec] */
    }

    /* serial'ы после всех слотов: размещение на wire base+0x148 (см.
     * ЗАМЕТКУ) -- на голову Id следующего слота; serial последнего слота
     * ложится за конец записи и на wire отсутствует [dec] */
    for (i = 0; i < Count; i++) {
        UINT32 serOfs = 8 + i * sizeof(AC_DISK_SLOT) + AC_DISK_SERIAL_OFS;

        if (serOfs < recSize) {
            UINT32 room = recSize - serOfs;
            if (room > 0x20)
                room = 0x20;
            AcRecCopyStrA((CHAR*)Rec + serOfs, room, Src[i].Serial);
        }
    }
}

/* --------------------------------------------------------------------------
 * писатель слотов ram (маркер 0x19)
 * [0x14004b7a4] smbios_ram_collector -> [0x1401835f8] smbios_hub (строки t17)
 * ------------------------------------------------------------------------ */
VOID
AcRecBuildRam(
    _Out_ PAC_REC_RAM Rec,
    _In_ UINT32 Count,
    _In_reads_(Count) const AC_HWID_RAM_SRC* Src
    )
{
    UINT32 i;

    Rec->Marker = AC_REC_MARK_RAM;
    Rec->Count  = Count;

    for (i = 0; i < Count; i++) {
        AC_RAM_SLOT* slot = &Rec->Slots[i];

        RtlZeroMemory(slot, sizeof(*slot));
        AcRecCopyStrA(slot->Serial,     sizeof(slot->Serial),     Src[i].Serial);
        AcRecCopyStrA(slot->Vendor,     sizeof(slot->Vendor),     Src[i].Vendor);
        AcRecCopyStrA(slot->PartNumber, sizeof(slot->PartNumber),
                      Src[i].PartNumber);
    }
}

/* --------------------------------------------------------------------------
 * билдер hello (маркер 0x00)
 * --------------------------------------------------------------------------
 * В оригинале НЕТ единого нативного hello_build: буфер заполняется
 * фазовыми прямыми записями внутри VM handshake-continuation
 * (FULL_CHAIN_IRP_TO_HWID_C #7.6). Этот билдер воспроизводит наблюдавшийся
 * на wire layout; каждое поле несёт provenance своего продюсера. Входы
 * приходят от коллекторов (hwid.c / smbios.c в driver_sln); входы
 * hash/uuid, живущие за VM-стеной, берутся предвычисленными -- здесь
 * никогда не выдумываются.
 * ------------------------------------------------------------------------ */
/* [0x1402bac03] маршаллер фрагментов hello -> SMBIOS-хаб [0x1401835f8]
 * (фазовые записи FULL_CHAIN_IRP_TO_HWID_C #7.6) */
VOID
AcRecBuildHello(
    _Out_ PAC_REC_HELLO Rec,
    _In_ const AC_HELLO_SRC* Src
    )
{
    RtlZeroMemory(Rec, sizeof(*Rec));

    /* [VM-писатель] type + build (VM-собранный иммедиат; 0x67d на фреймах) */
    Rec->Marker = AC_REC_MARK_HELLO;
    Rec->Build  = Src->Build;

    /* [VM-писатель] per-run флаги; байт [1] всегда 1 на каждом фрейме */
    Rec->Flags[0] = Src->Flags[0];
    Rec->Flags[1] = Src->Flags[1];
    Rec->Flags[2] = Src->Flags[2];
    Rec->Flags[3] = Src->Flags[3];

    /* фаза SMBIOS: регион 10028 (0x1402bac03) -> хаб 2391 (0x1401835f8);
     * экстракторы t0 0x140216e50 / t1 0x1401ed25c / t2 0x1401ee2bc,
     * строки 0x1401edae4 / 0x1401db946 */
    AcRecCopyStrA(Rec->LabelSerial,  sizeof(Rec->LabelSerial),
                  "System Serial Number");
    AcRecCopyStrA(Rec->SystemSerial, sizeof(Rec->SystemSerial),
                  Src->SystemSerial);
    AcRecCopyStrA(Rec->LabelProduct, sizeof(Rec->LabelProduct),
                  "System Product Name");
    AcRecCopyStrA(Rec->SystemUuid,   sizeof(Rec->SystemUuid), Src->SystemUuid);
    AcRecCopyStrA(Rec->BoardSerial,  sizeof(Rec->BoardSerial),
                  Src->BoardSerial);
    AcRecCopyStrA(Rec->BoardVendor,  sizeof(Rec->BoardVendor),
                  Src->BoardVendor);
    AcRecCopyStrA(Rec->BoardModel,   sizeof(Rec->BoardModel), Src->BoardModel);

    /* +0x618 композитный GUID: цепочка region 487 GetIfEntry2; node = MAC
     * собственного NIC (MIB_IF_ROW2.PhysicalAddress) -- предвычислен выше
     * по потоку */
    AcRecCopyStrA(Rec->SynthGuid, sizeof(Rec->SynthGuid), Src->SynthGuid);

    /* +0x640 битмаска security-state f20 (== staging f20) */
    Rec->SecurityState = Src->SecurityState;

    /* фаза MAC: [base+0x648]=0x720 @0x14075fcfb, count @0x1437a659b,
     * слоты через sprintf-thunk 0x14022fc93 по строкам GetIpNetTable2 */
    Rec->MacCount   = Src->MacCount;
    Rec->MacListOfs = AC_HELLO_MACLIST_OFS;
    if (Src->MacCount > AC_HELLO_MAC_MAX) {
        /* недостижимо на wire (count <= 9 наблюдалось); у оригинала
         * фильтра тоже нет [static] */
    }
    {
        UINT32 i;
        for (i = 0; i < Src->MacCount && i < AC_HELLO_MAC_MAX; i++)
            AcRecCopyStrA(Rec->MacList[i], AC_HELLO_MAC_SLOT,
                          Src->MacList[i]);
    }

    /* +0x64D machine hash f21: BCrypt-хаб region 7341 (0x14024af8e);
     * вход за VM-стеной -- берётся предвычисленным */
    AcRecCopyStrA(Rec->MachineHash, sizeof(Rec->MachineHash),
                  Src->MachineHash);

    Rec->Flag690  = 1;                     /* = 1 на каждом фрейме [dec] */

    /* самоописательный указатель: доказанная формула 0x720 + count*0x12 */
    Rec->Uuid2Ofs   = AC_HELLO_UUID2_OFS(Src->MacCount);

    /* блок SMBIOS t0 */
    AcRecCopyStrA(Rec->BiosVersion, sizeof(Rec->BiosVersion),
                  Src->BiosVersion);
    AcRecCopyStrA(Rec->BiosVendor,  sizeof(Rec->BiosVendor), Src->BiosVendor);
    AcRecCopyStrA(Rec->BiosDate,    sizeof(Rec->BiosDate),   Src->BiosDate);

    Rec->Flag718  = 1;                     /* = 1 on every frame [dec] */

    /* f22 UUID#2 по самоописанному смещению (маршаллер 0x140282319 ->
     * @0x14028237c, thunk 0x1403891f9; производное, вход за VM-стеной) */
    AcRecCopyStrA((CHAR*)Rec + Rec->Uuid2Ofs, 0x25, Src->Uuid2);
}

/* --------------------------------------------------------------------------
 * заметка по wire: plaintext-запись проходит
 *   AcChannelSend -> AcCryptoSealAndQueue (seal под session pk сервиса,
 *   очередь 0x140107040) -> drain обработчиком poll 0xC3502004 ->
 *   IofCompleteRequest (пара 0x140107728^0x140107720).
 * Само запечатывание -- дело crypto.c (AcCryptoBoxSeal) и здесь НЕ
 * дублируется.
 * ------------------------------------------------------------------------ */
