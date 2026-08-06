/** @file
      Copyright (C) 2026. All rights reserved.

      Dynamic Binary Translation DXE Driver for ARM64 to x86_64
   **/

#include <Uefi.h>
#include <Guid/FileInfo.h>
#include <Guid/AppleApfsInfo.h>
#include <Guid/AppleApfsInfo.h>
#include <IndustryStandard/AppleBootArgs.h>
#include <IndustryStandard/AppleFatBinaryImage.h>
#include <IndustryStandard/AppleMachoImage.h>

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/DevicePathLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Library/OcDbtLib.h>
#include <Library/OcBootManagementLib.h>
#include <Library/OcAppleKernelLib.h>
#include <Library/OcMachoLib.h>
#include <Library/OcMemoryLib.h>
#include <Library/OcDeviceTreeLib.h>

#include <Library/OcCompressionLib/zlib/zlib.h>

#include <Protocol/OcBootEntry.h>
#include <Protocol/OcLog.h>
#include <Protocol/SimpleFileSystem.h>

//
// ARM64 thread state flavor for Mach-O LC_UNIXTHREAD
//
#define ARM64_THREAD_STATE_FLAVOR  6

//
// ZIP format constants
//
#define ZIP_LOCAL_FILE_SIGNATURE   0x04034B50U
#define ZIP_EOCD_SIGNATURE         0x06054B50U
#define ZIP_METHOD_STORED          0
#define ZIP_METHOD_DEFLATED        8

STATIC DBT_CONTEXT  *gDbtContext     = NULL;
STATIC EFI_HANDLE   gInstallerDevice = NULL;

//
// Force the OpenCore log protocol to maximum verbosity on both the console
// and in the log file.  Called from the entry point (covers the picker),
// from the boot entry enumeration (covers the boot picker scan) and from
// the boot entry action (covers the DirectKernel / macOS Translated boot).
//
STATIC
VOID
RaiseScreenVerbose (
  VOID
  )
{
  OC_LOG_PROTOCOL  *OcLog;
  EFI_STATUS       Status;

  Status = gBS->LocateProtocol (&gOcLogProtocolGuid, NULL, (VOID **)&OcLog);
  if (EFI_ERROR (Status) || OcLog == NULL) {
    DEBUG ((DEBUG_WARN, "DBT: OcLog protocol not found, screen trace unavailable\n"));
    return;
  }

  OcLog->DisplayLevel = (UINTN)0xFFFFFFFF;
  OcLog->Options     |= OC_LOG_CONSOLE | OC_LOG_FILE;
  OcLog->DisplayDelay = 0;
  DEBUG ((DEBUG_INFO, "DBT: on-screen log level raised to 0xFFFFFFFF\n"));
}

//
// True when an ARM64 instruction updates PC (so a translated block must end
// there for the dispatcher to continue from the new address).
//
STATIC
BOOLEAN
IsPcUpdatingBranch (
  IN UINT32  Inst
  )
{
  if ((Inst & 0x7C000000) == 0x14000000) return TRUE;   // B / BL
  if ((Inst & 0xFF000010) == 0x54000000) return TRUE;   // B.cond
  if ((Inst & 0x7E000000) == 0x34000000) return TRUE;   // CBZ / CBNZ
  if ((Inst & 0x7E000000) == 0x36000000) return TRUE;   // TBZ / TBNZ
  if ((Inst & 0xFE000000) == 0xD6000000) return TRUE;   // BR / BLR / RET
  return FALSE;
}

//
// Allocate the kernel image buffer below 1 GB if possible.  AllocatePool
// usually lands in the 2.3-2.6 GB region where reads are unreliable on
// this platform (observed: a UINT32 read of 0x01CEE165 and a UINT8 read
// of 0x00 at the very same address), which corrupts the translated
// loads/stores.  Fall back to any pages if the low range is exhausted.
//
STATIC
VOID *
AllocKernelImageBuffer (
  IN UINTN  Size
  )
{
  EFI_PHYSICAL_ADDRESS  Addr;
  EFI_STATUS            Status;
  UINTN                 Pages;

  if (Size == 0) {
    return NULL;
  }
  Pages = EFI_SIZE_TO_PAGES (Size);

  Addr   = 0x40000000;   // 1 GB
  Status = gBS->AllocatePages (AllocateMaxAddress, EfiBootServicesData, Pages, &Addr);
  if (EFI_ERROR (Status)) {
    Status = gBS->AllocatePages (AllocateAnyPages, EfiBootServicesData, Pages, &Addr);
  }
  if (EFI_ERROR (Status)) {
    return NULL;
  }
  return (VOID *)(UINTN)Addr;
}

//
// Read kernelcache from ZIP file.
// Returns allocated buffer with kernel data, or NULL.
//
STATIC
VOID *
ReadKernelFromZip (
  IN  EFI_FILE_PROTOCOL  *RootDir,
  IN  CONST CHAR16       *ZipPath,
  IN  CONST CHAR16       *EntryName,
  OUT UINT32             *OutSize
  )
{
  EFI_STATUS         Status;
  EFI_FILE_PROTOCOL  *ZipFile;
  UINT8              EocdBuf[128];
  UINTN              ReadSize;
  UINT64             FileSize;
  EFI_FILE_INFO      *Info;
  UINTN              InfoSize;
  UINT64             EocdOffset;
  UINT64             CentralDirOffset;
  UINT64             CentralDirSize;
  UINT64             TotalEntries;
  UINTN              I;
  UINT32             LocalOffset     = 0;
  UINT32             UncompSize      = 0;
  UINT32             CompressedSize  = 0;
  UINT16             Method       = 0;
  UINT16             NameLen;
  UINT16             ExtraLen;
  UINT8              *Result      = NULL;
  BOOLEAN            EntryFound   = FALSE;

  *OutSize = 0;

  Status = RootDir->Open (RootDir, &ZipFile, (CHAR16 *)ZipPath, EFI_FILE_MODE_READ, 0);
  if (EFI_ERROR (Status)) {
    return NULL;
  }

  //
  // Get file size
  //
  InfoSize = 0;
  ZipFile->GetInfo (ZipFile, &gEfiFileInfoGuid, &InfoSize, NULL);
  Info = AllocatePool (InfoSize);
  if (Info == NULL) {
    ZipFile->Close (ZipFile);
    return NULL;
  }
  Status = ZipFile->GetInfo (ZipFile, &gEfiFileInfoGuid, &InfoSize, Info);
  if (EFI_ERROR (Status)) {
    FreePool (Info);
    ZipFile->Close (ZipFile);
    return NULL;
  }
  FileSize = Info->FileSize;
  FreePool (Info);

  if (FileSize < sizeof (EocdBuf)) {
    ZipFile->Close (ZipFile);
    return NULL;
  }

  //
  // Read EOCD from end of file
  //
  ReadSize = sizeof (EocdBuf);
  Status = ZipFile->SetPosition (ZipFile, FileSize - sizeof (EocdBuf));
  if (EFI_ERROR (Status)) {
    ZipFile->Close (ZipFile);
    return NULL;
  }
  Status = ZipFile->Read (ZipFile, &ReadSize, EocdBuf);
  if (EFI_ERROR (Status)) {
    ZipFile->Close (ZipFile);
    return NULL;
  }

  //
  // Find EOCD signature
  //
  EocdOffset = 0;
  for (I = 0; I + 4 < ReadSize; I++) {
    if (*(UINT32 *)(EocdBuf + I) == ZIP_EOCD_SIGNATURE) {
      EocdOffset = FileSize - sizeof (EocdBuf) + I;
      //
      // EOCD fields at this offset:
      // +0: signature(4)
      // +4: disk_number(2)
      // +6: disk_cd(2)
      // +8: entries_on_disk(2)
      // +10: total_entries(2)
      // +12: cd_size(4)
      // +16: cd_offset(4)
      // +20: comment_len(2)
      //
      TotalEntries     = *(UINT16 *)(EocdBuf + I + 10);
      CentralDirSize   = *(UINT32 *)(EocdBuf + I + 12);
      CentralDirOffset = *(UINT32 *)(EocdBuf + I + 16);
      break;
    }
  }

  if (EocdOffset == 0 || CentralDirOffset == 0) {
    ZipFile->Close (ZipFile);
    return NULL;
  }

  //
  // If 32-bit CD offset is 0xFFFFFFFF, use ZIP64 EOCD
  //
  if (CentralDirOffset == 0xFFFFFFFFU) {
    UINT8   Zip64LocBuf[20];
    UINT64  Zip64EocdOff;

    Status = ZipFile->SetPosition (ZipFile, EocdOffset - 20);
    if (!EFI_ERROR (Status)) {
      ReadSize = 20;
      Status = ZipFile->Read (ZipFile, &ReadSize, Zip64LocBuf);
      if (!EFI_ERROR (Status) && (*(UINT32 *)Zip64LocBuf == 0x07064B50U)) {
        Zip64EocdOff = *(UINT64 *)(Zip64LocBuf + 8);
        UINT8   Zip64Buf[56];
        Status = ZipFile->SetPosition (ZipFile, Zip64EocdOff);
        if (!EFI_ERROR (Status)) {
          ReadSize = 56;
          Status = ZipFile->Read (ZipFile, &ReadSize, Zip64Buf);
          if (!EFI_ERROR (Status) && (*(UINT32 *)Zip64Buf == 0x06064B50U)) {
          CentralDirSize   = *(UINT64 *)(Zip64Buf + 40);
            CentralDirOffset = *(UINT64 *)(Zip64Buf + 48);
          }
        }
      }
    }
  }

  //
  // Read central directory
  //
  UINT8  *CdBuf = AllocatePool (CentralDirSize);
  if (CdBuf == NULL) {
    ZipFile->Close (ZipFile);
    return NULL;
  }
  Status = ZipFile->SetPosition (ZipFile, CentralDirOffset);
  if (EFI_ERROR (Status)) {
    FreePool (CdBuf);
    ZipFile->Close (ZipFile);
    return NULL;
  }
  ReadSize = CentralDirSize;
  Status = ZipFile->Read (ZipFile, &ReadSize, CdBuf);
  if (EFI_ERROR (Status)) {
    FreePool (CdBuf);
    ZipFile->Close (ZipFile);
    return NULL;
  }

  //
  // Scan central directory for kernelcache entry
  //
  UINT8  *Ptr = CdBuf;
  for (I = 0; I < TotalEntries; I++) {
    //
    // CFH: sig(4) ver_made(2) ver_need(2) flags(2) method(2) ...
    // +24: comp_size(4), +28: uncomp_size(4), +32: name_len(2), +34: extra_len(2), +36: comment_len(2)
    // +42: local_header_offset(4), +46: filename(N)
    //
    if (*(UINT32 *)Ptr != 0x02014B50U) {
      break;
    }
    Method       = *(UINT16 *)(Ptr + 10);
    UncompSize   = *(UINT32 *)(Ptr + 24);
    NameLen      = *(UINT16 *)(Ptr + 28);
    ExtraLen     = *(UINT16 *)(Ptr + 30);
    LocalOffset  = *(UINT32 *)(Ptr + 42);

    if (NameLen > 0) {
      CHAR8 *Name = (CHAR8 *)(Ptr + 46);
      //
      // Match kernelcache.* files
      //
      if ((NameLen >= 12) && (CompareMem (Name, "AssetData/boot/kernelcache.", 28) == 0)) {
        EntryFound = TRUE;
        DEBUG ((DEBUG_INFO, "DBT: Found kernelcache in ZIP: %a (method=%u, size=%u)\n", Name, Method, UncompSize));
        break;
      }
    }
    Ptr += 46 + NameLen + ExtraLen + *(UINT16 *)(Ptr + 32);
  }
  FreePool (CdBuf);

  if (!EntryFound) {
    ZipFile->Close (ZipFile);
    return NULL;
  }

  //
  // Read local file header to get exact data offset
  //
  UINT8  LocalBuf[128];
  Status = ZipFile->SetPosition (ZipFile, LocalOffset);
  if (EFI_ERROR (Status)) {
    ZipFile->Close (ZipFile);
    return NULL;
  }
  ReadSize = sizeof (LocalBuf);
  Status = ZipFile->Read (ZipFile, &ReadSize, LocalBuf);
  if (EFI_ERROR (Status)) {
    ZipFile->Close (ZipFile);
    return NULL;
  }

  if (*(UINT32 *)LocalBuf != ZIP_LOCAL_FILE_SIGNATURE) {
    ZipFile->Close (ZipFile);
    return NULL;
  }

  NameLen  = *(UINT16 *)(LocalBuf + 26);
  ExtraLen = *(UINT16 *)(LocalBuf + 28);
  UINT32  DataOffset = LocalOffset + 30 + NameLen + ExtraLen;

  if (Method == ZIP_METHOD_STORED) {
    CompressedSize = UncompSize;
  } else {
    CompressedSize = *(UINT32 *)(LocalBuf + 18);
    //
    // Check for ZIP64 extra field if compressed size is 0xFFFFFFFF
    //
    if ((CompressedSize == 0xFFFFFFFFU) && (ExtraLen >= 20)) {
      UINT8   *Extra = (UINT8 *)LocalBuf + 30 + NameLen;
      UINT16  Remaining = ExtraLen;
      while (Remaining >= 4) {
        UINT16  Tag  = *(UINT16 *)Extra;
        UINT16  Size = *(UINT16 *)(Extra + 2);
        if (Tag == 0x0001 && Size >= 16) {  // ZIP64 extra field
          CompressedSize = (UINT32)*(UINT64 *)(Extra + 4 + 8);  // compressed_size after uncompressed_size
          break;
        }
        Remaining = (UINT16)(Remaining - 4 - Size);
        Extra += 4 + Size;
      }
    }
  }

  if (Method == ZIP_METHOD_STORED) {
    //
    // Read uncompressed data directly
    //
    Result = AllocKernelImageBuffer (UncompSize + 1);
    if (Result != NULL) {
      Status = ZipFile->SetPosition (ZipFile, DataOffset);
      if (!EFI_ERROR (Status)) {
        ReadSize = UncompSize;
        Status = ZipFile->Read (ZipFile, &ReadSize, Result);
        if (!EFI_ERROR (Status) && ReadSize == UncompSize) {
          Result[UncompSize] = 0;
          *OutSize = UncompSize;
          DEBUG ((DEBUG_INFO, "DBT: Read kernelcache %u bytes (stored)\n", UncompSize));
        } else {
          FreePool (Result);
          Result = NULL;
        }
      } else {
        FreePool (Result);
        Result = NULL;
      }
    }
  } else {
    //
    // DEFLATE — decompress using zlib inflate
    //
    UINT8  *CompBuf = AllocatePool (CompressedSize);
    if (CompBuf != NULL) {
      Status = ZipFile->SetPosition (ZipFile, DataOffset);
      if (!EFI_ERROR (Status)) {
        ReadSize = CompressedSize;
        Status = ZipFile->Read (ZipFile, &ReadSize, CompBuf);
        if (!EFI_ERROR (Status)) {
          Result = AllocKernelImageBuffer (UncompSize + 1);
          if (Result != NULL) {
            z_stream  Strm;
            INT32     Ret;

            ZeroMem (&Strm, sizeof (Strm));
            Strm.next_in   = CompBuf;
            Strm.avail_in  = (UINT32)ReadSize;
            Strm.next_out  = Result;
            Strm.avail_out = UncompSize;

            Ret = inflateInit2 (&Strm, -MAX_WBITS);
            if (Ret == Z_OK) {
              Ret = inflate (&Strm, Z_FINISH);
              inflateEnd (&Strm);
              if ((Ret == Z_STREAM_END) && (Strm.total_out == UncompSize)) {
                Result[UncompSize] = 0;
                *OutSize = UncompSize;
                DEBUG ((DEBUG_INFO, "DBT: Decompressed kernelcache %u bytes (deflate)\n", UncompSize));
              } else {
                DEBUG ((DEBUG_INFO, "DBT: inflate failed ret=%d total_out=%lu expected=%u\n", Ret, (UINT64)Strm.total_out, UncompSize));
                FreePool (Result);
                Result = NULL;
              }
            } else {
              DEBUG ((DEBUG_INFO, "DBT: inflateInit2 failed ret=%d\n", Ret));
              FreePool (Result);
              Result = NULL;
            }
          }
        }
      }
      FreePool (CompBuf);
    }
  }

  ZipFile->Close (ZipFile);
  return Result;
}

STATIC
BOOLEAN
IsGoldenGateInstaller (
  IN  EFI_FILE_PROTOCOL  *RootDirectory
  )
{
  EFI_STATUS  Status;
  EFI_FILE_PROTOCOL  *File;
  CHAR16  *MarkerPath = L"\\.IAPhysicalMedia";

  Status = RootDirectory->Open (
                          RootDirectory,
                          &File,
                          MarkerPath,
                          EFI_FILE_MODE_READ,
                          0
                          );

  if (!EFI_ERROR (Status)) {
    File->Close (File);
    return TRUE;
  }

  return FALSE;
}

STATIC
BOOLEAN
IsSharedSupportVolume (
  IN  EFI_FILE_PROTOCOL  *RootDirectory
  )
{
  EFI_STATUS  Status;
  EFI_FILE_PROTOCOL  *Dir;
  CHAR16  *Path = L"\\com_apple_MobileAsset_MacSoftwareUpdate";

  Status = RootDirectory->Open (
                           RootDirectory,
                           &Dir,
                           Path,
                           EFI_FILE_MODE_READ,
                           0
                           );

  if (!EFI_ERROR (Status)) {
    Dir->Close (Dir);
    return TRUE;
  }

  return FALSE;
}

STATIC
BOOLEAN
#if defined (__GNUC__) || defined (__clang__)
__attribute__((unused))
#endif
IsPrebootVolume (
  IN  EFI_HANDLE  Device
  )
{
  EFI_STATUS                      Status;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *FileSystem;
  EFI_FILE_PROTOCOL               *RootDirectory;
  APPLE_APFS_VOLUME_INFO          *VolumeInfo;

  Status = gBS->HandleProtocol (
                   Device,
                   &gEfiSimpleFileSystemProtocolGuid,
                   (VOID **)&FileSystem
                   );
  if (EFI_ERROR (Status)) {
    return FALSE;
  }

  Status = FileSystem->OpenVolume (FileSystem, &RootDirectory);
  if (EFI_ERROR (Status)) {
    return FALSE;
  }

  VolumeInfo = OcGetFileInfo (
                   RootDirectory,
                   &gAppleApfsVolumeInfoGuid,
                   sizeof (*VolumeInfo),
                   NULL
                   );

  RootDirectory->Close (RootDirectory);

  if (VolumeInfo == NULL) {
    return FALSE;
  }

  if ((VolumeInfo->Role & APPLE_APFS_VOLUME_ROLE_PREBOOT) != 0) {
    DEBUG ((DEBUG_INFO, "DBT: Device is APFS Preboot volume\n"));
    FreePool (VolumeInfo);
    return TRUE;
  }

  FreePool (VolumeInfo);
  return FALSE;
}

STATIC
BOOLEAN
IsArm64Kernel (
  IN  UINT8    *KernelBuffer,
  IN  UINT32    KernelSize,
  IN  BOOLEAN   Prefer32Bit
  )
{
  UINT32  Magic;
  INT32   CpuType;
  UINT32  Offset;
  UINT32  Size;

  if (KernelSize < sizeof (UINT32)) {
    return FALSE;
  }

  Magic = *((UINT32 *)KernelBuffer);

  if (Magic == MACH_HEADER_64_SIGNATURE) {
    MACH_HEADER_64  *Header64 = (MACH_HEADER_64 *)KernelBuffer;
    CpuType = Header64->CpuType;
    return CpuType == MachCpuTypeArm64 || CpuType == MachCpuTypeArm6432;
  } else if (Magic == MACH_FAT_BINARY_SIGNATURE || Magic == MACH_FAT_BINARY_INVERT_SIGNATURE) {
    EFI_STATUS  Status;
    Status = FatGetArchitectureOffset (
               KernelBuffer,
               sizeof (MACH_HEADER_64),
               KernelSize,
               !Prefer32Bit ? MachCpuTypeArm64 : MachCpuTypeX8664,
               &Offset,
               &Size
               );
    if (!EFI_ERROR (Status)) {
      return !Prefer32Bit;
    }

    Status = FatGetArchitectureOffset (
               KernelBuffer,
               sizeof (MACH_HEADER_64),
               KernelSize,
               Prefer32Bit ? MachCpuTypeArm64 : MachCpuTypeX8664,
               &Offset,
               &Size
               );
    if (!EFI_ERROR (Status)) {
      return Prefer32Bit;
    }
  }

  return FALSE;
}

//
// Minimal device tree structure for XNU handoff
//
#pragma pack(push, 1)
typedef struct {
  UINT32  NumProperties;
  UINT32  NumChildren;
} DT_NODE;

typedef struct {
  CHAR8   Name[32];
  UINT32  Length;
} DT_PROP;
#pragma pack(pop)

STATIC
EFI_STATUS
CreateMinimalDeviceTree (
  OUT UINT8   **DeviceTree,
  OUT UINTN   *DeviceTreeSize
  )
{
  //
  // Simple flattened device tree with /chosen node containing boot-args
  // Will be allocated and populated at runtime
  //
  UINTN  Size = EFI_PAGE_SIZE;
  EFI_STATUS  Status;
  
  Status = gBS->AllocatePool (EfiBootServicesData, Size, (VOID **)DeviceTree);
  if (EFI_ERROR (Status)) {
    return Status;
  }
  
  ZeroMem (*DeviceTree, Size);
  *DeviceTreeSize = Size;
  
  //
  // Create minimal /chosen node
  // Format: DT_NODE { NumProperties, NumChildren } [0,0 ends]
  // followed by properties
  //
  DT_NODE  *Root = (DT_NODE *)*DeviceTree;
  Root->NumProperties = 1;
  Root->NumChildren = 0;
  
  DT_PROP  *Prop = (DT_PROP *)((UINTN)Root + sizeof (DT_NODE));
  AsciiStrCpyS (Prop->Name, 32, "boot-args");
  Prop->Length = 2;  // "1"
  *((CHAR8 *)((UINTN)Prop + sizeof (DT_PROP))) = '1';
  
  return EFI_SUCCESS;
}

//
// xnu's arm64 boot code (osfmk/arm64/start.s) scans a per-CPU data entries
// table that the bootloader is expected to have populated before jumping to
// the kernel:
//
//   mrs  x15, mpidr_el1
//   and  x0, x15, #0xff
//   adr  x1, <entries table>
//   add  x1, x1, #<pageoff>
//   ...
//   ldr  x21, [x1, #8]              // per-CPU data address of the entry
//   cbz  x21, .                     // spin forever if not set up
//   ldr  w2, [x21, #0x1c8]          // CPU_PHYS_ID
//   cmp  x0, x2
//   b.eq <found>
//
// On real hardware iBoot fills the table before starting the kernel; with a
// direct load the slots contain file data (observed: 0x201FD503201FD503),
// which makes the kernel dereference garbage and fault.  We locate the table
// by decoding the ADR/ADD pair right after the MRS/AND prologue and route the
// entry to a fake per-CPU data structure that lives inside the kernel image.
// xnu continues the handoff with strict VA checks (stack fields and a reset
// handler constant), so a separate host buffer can never pass them.
//
STATIC
UINT8 *
SetupCpuDataEntries (
  IN UINT8   *KernelBuffer,
  IN UINTN   SegCount,
  IN UINT64  *SegVmAddr,
  IN UINT64  *SegVmSize,
  IN UINT64  *SegFileOff,
  IN UINT64  EntryPoint,
  IN UINT8   *StackBase,
  IN UINTN   StackSize
  )
{
  UINTN   I;
  UINTN   J;
  UINTN   K;
  UINTN   L;
  UINTN   FirstSeg;
  UINT8   *CpuData = NULL;

  if (SegCount == 0) {
    return NULL;
  }

  FirstSeg = 0;
  for (I = 0; I < SegCount; I++) {
    if (EntryPoint >= SegVmAddr[I] && EntryPoint < SegVmAddr[I] + SegVmSize[I]) {
      FirstSeg = I;
      break;
    }
  }

  for (K = 0; K < 2 && CpuData == NULL; K++) {
    UINTN  SegStart = K == 0 ? FirstSeg : 0;
    UINTN  SegEnd   = K == 0 ? FirstSeg + 1 : SegCount;

    for (I = SegStart; I < SegEnd && CpuData == NULL; I++) {
      UINT8  *Seg = KernelBuffer + SegFileOff[I];
      UINTN  Len  = (UINTN)SegVmSize[I];

      for (J = 0; J + 16 <= Len && CpuData == NULL; J += 4) {
        UINT32  Inst;
        UINT64  Pc;
        UINT64  Addr;
        UINT64  TableVa;
        UINT64  Imm;
        UINT8   *HostTable;

        if (*(UINT32 *)(Seg + J) != 0xD53800AF) {          // mrs x15, mpidr_el1
          continue;
        }
        if (*(UINT32 *)(Seg + J + 4) != 0x92403DE0) {      // and x0, x15, #0xff
          continue;
        }
Inst = *(UINT32 *)(Seg + J + 8);
        if ((Inst & 0x1F000000) != 0x10000000 ||   // (adr|adrp) prologue
            (Inst & 0x1F) != 1) {
          continue;
        }
        Pc   = SegVmAddr[I] + J;
        Imm  = (((UINT64)((Inst >> 5) & 0x7FFFF)) << 2) | ((UINT64)((Inst >> 29) & 3));
        if (Imm & (1ULL << 20)) {
          Imm |= ~((UINT64)0x1FFFFF);
        }
        if ((Inst & 0x9F000000) == 0x90000000) {   // ADRP (not ADR)
          Addr = (Pc + (Imm << 12)) & ~((UINT64)0xFFF);
        } else {
          Addr = Pc + Imm;                         // ADR
        }
        Inst = *(UINT32 *)(Seg + J + 12);
        if ((Inst & 0xFF800000) != 0x91000000 ||           // add x1, x1, #imm
            (Inst & 0x3FF) != 0x21) {
          continue;
        }
        TableVa = Addr + ((Inst >> 10) & 0xFFF);

        HostTable = NULL;
        for (L = 0; L < SegCount; L++) {
          if (TableVa >= SegVmAddr[L] && TableVa < SegVmAddr[L] + SegVmSize[L]) {
            HostTable = KernelBuffer + SegFileOff[L] + (TableVa - SegVmAddr[L]);
            break;
          }
        }
        if (HostTable == NULL) {
          break;
        }

        // The kernel's per-CPU data handoff is fully VA-relative: after the
        // scan sets SP from cpu_data[+0x18] (machine stack) and [+0x28]
        // (exception stack) it reads cpu_data[+0xB8] and requires it to equal
        // one of two fixed kernel addresses (here EntryPoint+0x77B or
        // EntryPoint-0x420); anything else spins on DEADB001/DEADB002.  A
        // separate host heap buffer can never match those constants, so the
        // fake cpu_data lives inside the __TEXT_BOOT_EXEC NOP padding
        // (EntryPoint+0x77B is all NOPs).
        //
        {
          UINT64  CpuDataVa;
          UINT64  ResetHandler;
          UINTN   Pad;
          UINT8   *CpuDataHost;

          //
          // The kernel checks cpu_data[+0xB8] for equality against two fixed
          // kernel addresses that __TEXT_BOOT_EXEC builds with ADRP/ADD right
          // after the MRS/scan prologue (observed for macOS 27:
          // 0xFFFFFE000BD4FE04 and 0xFFFFFE000BD50258).  Decode both from the
          // two ADRP/ADD pairs that load x3 after the `ldr x2,[x21,#0xB8]`
          // check; the first candidate is the equality target of the first
          // branch.  On failure fall back to the legacy EntryPoint+0x77B.
          //
          {
            UINT64  ResetCandidates[2];
            UINTN   RC;

            ResetCandidates[0] = 0;
            ResetCandidates[1] = 0;
            for (RC = 0; RC < 2; RC++) {
              UINT32  RInst8;
              UINT64  RPc;
              UINT64  RImm;
              UINT64  RAddr;
              UINT32  RInst12;

              if (J + 0x94 > Len) {
                break;
              }

              //
              // Reset-handler check sequence (relative to master slot J);
              // disassembly of the macOS 27 prologue:
              //   J+0x70: ldr  x2, [x21, #0xb8]
              //   J+0x74: cbz  x2, dead
              //   J+0x78: adrp x3                    (candidate #0)
              //   J+0x7C: add  x3, x3, #imm
              //   J+0x80: cmp  x2, x3
              //   J+0x84: b.eq <handler0>
              //   J+0x88: adrp x3                    (candidate #1)
              //   J+0x8C: add  x3, x3, #imm
              //   J+0x90: cmp  x2, x3
              //   J+0x94: b.eq <handler1>
              //
              RInst8 = *(UINT32 *)(Seg + J + 0x78 + (RC * 0x10));
              if ((RInst8 & 0x1F000000) != 0x10000000 ||
                  (RInst8 & 0x1F) != 3) {
                continue;
              }
              RPc  = SegVmAddr[I] + J + 0x78 + (RC * 0x10);
              RImm = (((UINT64)((RInst8 >> 5) & 0x7FFFF)) << 2) |
                     ((UINT64)((RInst8 >> 29) & 3));
              if (RImm & (1ULL << 20)) {
                RImm |= ~((UINT64)0x1FFFFF);
              }
              if ((RInst8 & 0x9F000000) == 0x90000000) {
                RAddr = (RPc + (RImm << 12)) & ~((UINT64)0xFFF);
              } else {
                RAddr = RPc + RImm;
              }
              RInst12 = *(UINT32 *)(Seg + J + 0x7C + (RC * 0x10));
              if ((RInst12 & 0xFF800000) != 0x91000000 ||
                  (RInst12 & 0x3FF) != 0x63) {
                continue;
              }
              ResetCandidates[RC] = RAddr + ((RInst12 >> 10) & 0xFFF);
            }

            ResetHandler = 0;
            for (RC = 0; RC < 2; RC++) {
              if (ResetCandidates[RC] != 0) {
                ResetHandler = ResetCandidates[RC];
                break;
              }
            }
            if (ResetHandler == 0) {
              ResetHandler = EntryPoint + 0x77B;
            }
          }

          CpuDataVa     = EntryPoint + 0x77B;
          CpuDataHost   = KernelBuffer + SegFileOff[FirstSeg] + 0x77B;
          Pad = SegVmSize[FirstSeg] > 0x77B + 0x1000 ? 0x1000 : 0;

          if (Pad != 0) {
            ZeroMem (CpuDataHost, Pad);
          }

          //
          // CPU_PHYS_ID at +0x1C8 must match MPIDR_EL1 & 0xff (= 0 with the
          // virtual MPIDR reported by the DBT).
          //
          *(UINT32 *)(CpuDataHost + 0x1C8) = 0;

          //
          // Stacks: the kernel does 'mov sp, cpu_data[+0x18]' (intstack) and
          // again 'mov sp, cpu_data[+0x28]' (excepstack), so both must be
          // usable host addresses (identity-mapped by the DBT).
          //
          *(UINT64 *)(CpuDataHost + 0x18) = (UINT64)(UINTN)StackBase + StackSize;
          *(UINT64 *)(CpuDataHost + 0x28) = (UINT64)(UINTN)StackBase + StackSize;

          //
          // The +0xB8 reset handler is only checked for being nonzero (the
          // zero case falls into the DEADB001 spin), a value is enough.
          //
          *(UINT64 *)(CpuDataHost + 0xB8) = ResetHandler;
          CpuData = CpuDataHost;

          DEBUG ((DEBUG_INFO, "DirectKernel: cpu data entries table va=0x%llx host=%p\n",
                  TableVa, HostTable));
          DEBUG ((DEBUG_INFO, "DirectKernel: fake cpu_data va=0x%llx host=%p phys-id=%u\n",
                   CpuDataVa, CpuData, *(UINT32 *)(CpuData + 0x1C8)));
        }

        //
        // Write the handoff: entry[0] carries the per-CPU vaddr (kernel reads
        // the +8 slot) as a VA inside the kernel image, and the remaining 31
        // entries are cleared so the scan cannot dereference stale file data.
        //
        *(UINT64 *)(HostTable + 0) = (UINT64)EntryPoint + 0x77B;
        *(UINT64 *)(HostTable + 8) = (UINT64)EntryPoint + 0x77B;
        ZeroMem (HostTable + 16, 32 * 16 - 16);

        break;
      }
    }
  }

  return CpuData;
}

STATIC
EFI_STATUS
DirectLoadKernel (
  IN  OC_PICKER_CONTEXT  *PickerContext
  )
{
  EFI_STATUS                       Status;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL  *FileSystem;
  EFI_FILE_PROTOCOL                *RootDirectory;
  EFI_FILE_PROTOCOL                *KernelFile;
  UINT8                            *KernelBuffer   = NULL;
  UINT32                           KernelSize      = 0;
  UINT32                           AllocatedSize   = 0;
  BOOLEAN                          Is32Bit         = FALSE;
  OC_MACHO_CONTEXT                 MachoContext;
  UINT64                           EntryPoint;
  BootArgs2                       *BootArgs;
  UINTN                            BootArgsSize;
  BOOLEAN                          IsArm64;
  UINT8                            *StackBuffer;
  UINTN                            StackSize;
  UINT8                            *DeviceTreeBuffer;
  UINTN                            DeviceTreeSize;
  UINTN                            Index;
  MACH_LOAD_COMMAND                *Cmd;
  MACH_LOAD_COMMAND                *CmdEnd;
  MACH_HEADER_64                   *Header64;
  UINT64                           SegVmAddr[32];
  UINT64                           SegVmSize[32];
  UINT64                           SegFileOff[32];
  UINTN                            SegCount       = 0;
  EFI_HANDLE                       Device;
  CONST CHAR16                     *KernelPath;

  if (gDbtContext == NULL) {
    return EFI_NOT_STARTED;
  }

  Device     = DbtGetInstallerDevice (gDbtContext);
  KernelPath = DbtGetKernelPath (gDbtContext);

  DEBUG ((DEBUG_INFO, "DirectKernel: device=%p path=%s\n",
          Device, KernelPath != NULL ? KernelPath : L"<null>"));
  if (Device == NULL || KernelPath == NULL) {
    DEBUG ((DEBUG_ERROR, "DirectKernel: No boot info set\n"));
    return EFI_NOT_STARTED;
  }

  Status = gBS->HandleProtocol (
                   Device,
                   &gEfiSimpleFileSystemProtocolGuid,
                   (VOID **)&FileSystem
                   );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = FileSystem->OpenVolume (FileSystem, &RootDirectory);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // Try multiple kernel paths: the stored path first, then fallbacks
  //
  {
    STATIC CONST CHAR16  *FallbackPaths[] = {
      L"\\kernelcache.decomp",
      L"\\kernelcache.decomp",
      L"\\kernelcache.release",
      L"\\kernel",
      L"\\SharedSupport\\kernel",
      L"\\System\\Library\\Kernels\\kernel",
      L"\\com_apple_MobileAsset_MacSoftwareUpdate\\AssetData\\boot\\kernelcache.release.mac15j",
      L"\\com_apple_MobileAsset_MacSoftwareUpdate\\AssetData\\boot\\kernelcache.release.mac16j",
      L"\\AssetData\\boot\\kernelcache.release.mac15j",
      L"\\AssetData\\boot\\kernelcache.release.mac16j",
      NULL
    };
    UINTN  PathIndex;
    CONST CHAR16  *TryPath;

    KernelFile = NULL;

    TryPath = KernelPath;
    Status = RootDirectory->Open (
                             RootDirectory,
                             &KernelFile,
                             (CHAR16 *)TryPath,
                             EFI_FILE_MODE_READ,
                             0
                             );

    for (PathIndex = 0; EFI_ERROR (Status) && FallbackPaths[PathIndex] != NULL; PathIndex++) {
      if (StrCmp (FallbackPaths[PathIndex], KernelPath) == 0) {
        continue;
      }
      KernelFile = NULL;
      Status = RootDirectory->Open (
                               RootDirectory,
                               &KernelFile,
                               (CHAR16 *)FallbackPaths[PathIndex],
                               EFI_FILE_MODE_READ,
                               0
                               );
      if (!EFI_ERROR (Status)) {
        DEBUG ((DEBUG_INFO, "DirectKernel: Found kernel at fallback path %s\n", FallbackPaths[PathIndex]));
      }
    }

    if (EFI_ERROR (Status)) {
      //
      // All direct paths failed — try APFS firmlink subvolume paths
      //
      {
        EFI_FILE_PROTOCOL  *SubvolDir;
        STATIC CONST CHAR16  *SubvolPaths[] = {
          L"\\System\\Volumes\\Shared Support\\com_apple_MobileAsset_MacSoftwareUpdate",
          L"\\System\\Volumes\\SharedSupport\\com_apple_MobileAsset_MacSoftwareUpdate",
          L"\\System\\Volumes\\iMAS\\com_apple_MobileAsset_MacSoftwareUpdate",
          NULL
        };

        for (UINTN Si = 0; SubvolPaths[Si] != NULL; Si++) {
          Status = RootDirectory->Open (RootDirectory, &SubvolDir, (CHAR16 *)SubvolPaths[Si], EFI_FILE_MODE_READ, 0);
          if (!EFI_ERROR (Status)) {
            UINTN   DirBufSize = SIZE_256KB;
            VOID    *DirBuf = AllocatePool (DirBufSize);
            if (DirBuf != NULL) {
              while (TRUE) {
                UINTN  ReadSz = DirBufSize;
                Status = SubvolDir->Read (SubvolDir, &ReadSz, DirBuf);
                if (EFI_ERROR (Status) || ReadSz == 0) {
                  break;
                }
                EFI_FILE_INFO  *Entry = (EFI_FILE_INFO *)DirBuf;
                while ((UINTN)Entry < (UINTN)DirBuf + ReadSz) {
                  if ((Entry->Attribute & EFI_FILE_DIRECTORY) == 0) {
                    UINTN  NameLen = StrLen (Entry->FileName);
                    if ((NameLen > 4) && (StrCmp (Entry->FileName + NameLen - 4, L".zip") == 0)) {
                      CHAR16  FullPath[512];
                      UnicodeSPrint (FullPath, sizeof (FullPath), L"%s\\%s", SubvolPaths[Si], Entry->FileName);
                      KernelBuffer = ReadKernelFromZip (RootDirectory, FullPath, L"kernelcache", &KernelSize);
                      if (KernelBuffer != NULL) {
                        AllocatedSize = KernelSize;
                        Is32Bit       = FALSE;
                        Status        = EFI_SUCCESS;
                        DEBUG ((DEBUG_INFO, "DirectKernel: Extracted kernel from firmlink: %s - %u bytes\n", FullPath, KernelSize));
                        SubvolDir->Close (SubvolDir);
                        FreePool (DirBuf);
                        goto SKIP_READ_APPLE_KERNEL;
                      }
                    }
                  }
                  if (Entry->Size == 0) {
                    break;
                  }
                  Entry = (EFI_FILE_INFO *)((UINT8 *)Entry + Entry->Size);
                }
              }
              FreePool (DirBuf);
            }
            SubvolDir->Close (SubvolDir);
            Status = EFI_NOT_FOUND;
          }
        }
      }

      //
      // All direct paths failed — try ZIP extraction
      //
      DEBUG ((DEBUG_INFO, "DirectKernel: Direct kernel open failed — searching ZIP files\n"));

      {
        STATIC CONST CHAR16  *ZipDirs[] = {
          L"\\com_apple_MobileAsset_MacSoftwareUpdate",
          L"\\System\\Volumes\\Shared Support\\com_apple_MobileAsset_MacSoftwareUpdate",
          L"\\System\\Volumes\\SharedSupport\\com_apple_MobileAsset_MacSoftwareUpdate",
          L"",
          NULL
        };

        for (UINTN Zdi = 0; !EFI_ERROR (Status) && ZipDirs[Zdi] != NULL; Zdi++) {
          EFI_FILE_PROTOCOL  *ZipDir;
          Status = RootDirectory->Open (
                                  RootDirectory,
                                  &ZipDir,
                                  (CHAR16 *)ZipDirs[Zdi],
                                  EFI_FILE_MODE_READ,
                                  0
                                  );
          if (!EFI_ERROR (Status)) {
            //
            // Enumerate directory for .zip files
            //
            UINTN   DirBufSize = SIZE_256KB;
            VOID    *DirBuf = AllocatePool (DirBufSize);
            if (DirBuf != NULL) {
              while (TRUE) {
                UINTN  ReadSz = DirBufSize;
                Status = ZipDir->Read (ZipDir, &ReadSz, DirBuf);
                if (EFI_ERROR (Status) || ReadSz == 0) {
                  break;
                }
                EFI_FILE_INFO  *Entry = (EFI_FILE_INFO *)DirBuf;
                while ((UINTN)Entry < (UINTN)DirBuf + ReadSz) {
                  if ((Entry->Attribute & EFI_FILE_DIRECTORY) == 0) {
                    UINTN  NameLen = StrLen (Entry->FileName);
                    if ((NameLen > 4) && (StrCmp (Entry->FileName + NameLen - 4, L".zip") == 0)) {
                      CHAR16  FullPath[512];
                      if (ZipDirs[Zdi][0] != L'\0') {
                        UnicodeSPrint (FullPath, sizeof (FullPath), L"%s\\%s", ZipDirs[Zdi], Entry->FileName);
                      } else {
                        UnicodeSPrint (FullPath, sizeof (FullPath), L"%s", Entry->FileName);
                      }

                      KernelBuffer = ReadKernelFromZip (RootDirectory, FullPath, L"kernelcache", &KernelSize);
                      if (KernelBuffer != NULL) {
                        AllocatedSize = KernelSize;
                        Is32Bit       = FALSE;
                        Status        = EFI_SUCCESS;
                        DEBUG ((DEBUG_INFO, "DirectKernel: Extracted kernel from %s: %u bytes\n", FullPath, KernelSize));
                        ZipDir->Close (ZipDir);
                        FreePool (DirBuf);
                        goto SKIP_READ_APPLE_KERNEL;
                      }
                    }
                  }
                  if (Entry->Size == 0) {
                    break;
                  }
                  Entry = (EFI_FILE_INFO *)((UINT8 *)Entry + Entry->Size);
                }
              }
              FreePool (DirBuf);
            }
            ZipDir->Close (ZipDir);
            Status = EFI_NOT_FOUND;
          }
        }
      }

      if (EFI_ERROR (Status)) {
        DEBUG ((DEBUG_ERROR, "DirectKernel: Failed to open kernel - %r\n", Status));
        RootDirectory->Close (RootDirectory);
        return Status;
      }
    }
  }

SKIP_READ_APPLE_KERNEL:
  //
  // If kernel was extracted from ZIP, AllocatedSize > 0 and KernelBuffer is set.
  // Close KernelFile since we don't need it for ReadAppleKernel.
  // For the normal path (kernel from file), KernelFile stays open.
  //
  if (AllocatedSize > 0 && KernelBuffer != NULL && KernelFile != NULL) {
    KernelFile->Close (KernelFile);
    KernelFile = NULL;
  }

  if (EFI_ERROR (Status)) {
    RootDirectory->Close (RootDirectory);
    return Status;
  }

  //
  // If we got kernel from ZIP, skip ReadAppleKernel
  //
  if (AllocatedSize == 0 || KernelBuffer == NULL) {
    if (KernelFile == NULL) {
      DEBUG ((DEBUG_ERROR, "DirectKernel: No kernel file handle available\n"));
      RootDirectory->Close (RootDirectory);
      return EFI_NOT_FOUND;
    }
    Status = ReadAppleKernel (
              KernelFile,
              FALSE,
              &Is32Bit,
              &KernelBuffer,
              &KernelSize,
              &AllocatedSize,
              0,
              NULL
              );

    if (KernelFile != NULL) {
      KernelFile->Close (KernelFile);
    }
  }

  RootDirectory->Close (RootDirectory);

  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "DirectKernel: Failed to read kernel - %r\n", Status));
    return Status;
  }

  DEBUG ((DEBUG_INFO, "DirectKernel: Loaded kernel %u bytes (%a)\n",
          KernelSize, Is32Bit ? "32-bit" : "64-bit"));

  ZeroMem (&MachoContext, sizeof (MachoContext));
  IsArm64 = IsArm64Kernel (KernelBuffer, KernelSize, FALSE);

  if (IsArm64) {
    //
    // ARM64 kernel — skip MachoInitializeContext (filters for x86_64).
    // Set up basics manually since we only need the entry point.
    //
    MACH_HEADER_64  *Hdr = (MACH_HEADER_64 *)KernelBuffer;

    //
    // Force the kernel console "enabled" flag to 1.  In the stock image it
    // is 0, which sends pe_kputc down the emergency slot path
    // (console slots 0x7E287B8 hold linker-signed pointers that cannot be
    // authenticated without the hardware PAC key).  With the flag set the
    // fast ret path is taken instead and the kernel boot continues without
    // stalling in a bogus console function.
    //
    if (KernelSize > 0x59BE860) {
      *(volatile UINT32 *)((UINTN)KernelBuffer + 0x59BE860) = 1;
    }

    //
    // The timebase bit index global (0x7EB55C8) is written by the real
    // bootloader (boot.efi) before handing control to the kernel; in the
    // stock image it is 0xFFFFFFFF, which trips the 'invalid bit index'
    // panic in _enable_timebase_event_stream.  Zero is a valid index
    // (< 0x40), so patch it like the bootloader would.
    //
    if (KernelSize > 0xEB15C8) {
      *(volatile UINT32 *)((UINTN)KernelBuffer + 0xEB15C8) = 0;
    }

    //
    // The kernel's NEON strlen (0xBB796F0) loops on LDR-Q/UMINV/FMOV,
    // which the DBT does not emulate: W2 never becomes zero, so the
    // CBZ exit (0xBB7972C) never fires and the loop spins forever.
    // Patch the loop exit to a NOP and the final FMOV to MOV W2,#0, so
    // the scan runs once and returns length 0 (bogus %s prints are
    // skipped) instead of hanging.
    //
    if (KernelSize > 0x4B7572C + 4) {
      *(volatile UINT32 *)((UINTN)KernelBuffer + 0x4B7572C) = 0xD503201F;  // NOP (was cbnz w2, loop)
    }
    if (KernelSize > 0x4B75740 + 4) {
      *(volatile UINT32 *)((UINTN)KernelBuffer + 0x4B75740) = 0x52800002;  // MOV W2, #0 (was fmov w2, s1)
    }

    //
    // The static-memory-ready flag [0x7F47C90] is 0 in the stock image
    // (set by the early boot memory setup that never runs here).  With it
    // clear, ml_static_ptovirt (0xC518580) returns error 1 and the kernel
    // panics 'kvtophys_nofail: VA->PA translation failed'.  Set the flag
    // so the static walk (and the AT S1E1R fallback, emulated as PA=VA in
    // the DBT) runs instead.
    //
    if (KernelSize > 0xFDDC90) {
      //
      // Set bit 0 of the static-memory-ready flag.  The word already
      // holds a meaningful value (0x01CEE164) that other code reads, so
      // OR the bit in instead of clobbering the whole word.  Also patch
      // the same flag as seen through the simple (base-offset) mapping
      // (0xF47C90) in case the translated load path resolves image
      // addresses that way.
      //
      *(volatile UINT32 *)((UINTN)KernelBuffer + 0xFDDC90) |= 1;
      if (KernelSize > 0xF47C90) {
        *(volatile UINT32 *)((UINTN)KernelBuffer + 0xF47C90) |= 1;
      }
    }
    if (Hdr->Signature != MACH_HEADER_64_SIGNATURE) {
      DEBUG ((DEBUG_ERROR, "DirectKernel: Invalid Mach-O 64 magic %08X\n", Hdr->Signature));
      FreePool (KernelBuffer);
      return EFI_INVALID_PARAMETER;
    }
    //
    // Use a minimal fake context — the entry point code below handles LC_UNIXTHREAD directly.
    //
    MachoContext.MachHeader   = (MACH_HEADER_ANY *)Hdr;
    MachoContext.FileData     = KernelBuffer;
    MachoContext.FileSize     = KernelSize;
    MachoContext.InnerSize    = KernelSize;

    DEBUG ((DEBUG_INFO, "DirectKernel: ARM64 Mach-O parsed, NumCommands=%u\n", Hdr->NumCommands));
  } else {
    if (!MachoInitializeContext (
          &MachoContext,
          KernelBuffer,
          KernelSize,
          0,
          KernelSize,
          Is32Bit
          )) {
      DEBUG ((DEBUG_ERROR, "DirectKernel: Failed to initialize Mach-O context\n"));
      FreePool (KernelBuffer);
      return EFI_INVALID_PARAMETER;
    }
  }

  //
  // Get entry point from LC_UNIXTHREAD
  // Note: MachoRuntimeGetEntryAddress only handles x86 thread states.
  // For ARM64 kernels, we need platform-specific handling.
  //
  if (!IsArm64) {
    EntryPoint = MachoRuntimeGetEntryAddress (KernelBuffer);
    if (EntryPoint == 0) {
      DEBUG ((DEBUG_ERROR, "DirectKernel: Failed to get entry point from Mach-O\n"));
      FreePool (KernelBuffer);
      return EFI_INVALID_PARAMETER;
    }
  } else {
    //
    // For ARM64 kernels, extract entry point from thread state.
    // LC_UNIXTHREAD is cmd(4) + cmdsize(4) + flavor(4) + count(4) + state[],
    // where state is an arm_thread_state64_t: x0-x28, fp, lr, sp, pc, cpsr.
    // PC is UINT64 index 32 of the state.
    //
    Header64 = (MACH_HEADER_64 *)KernelBuffer;
    EntryPoint = 0;
    Cmd    = (MACH_LOAD_COMMAND *)((UINTN)Header64 + sizeof (MACH_HEADER_64));
    CmdEnd = (MACH_LOAD_COMMAND *)((UINTN)Cmd + Header64->CommandsSize);

    //
    // Walk all load commands: the LC_UNIXTHREAD entry point sits at the
    // start of the command list, but the LC_SEGMENT_64 layout needed for
    // VA->file-offset mapping only appears later in the list, so do not
    // stop at the thread state.
    //
    for (Index = 0; Index < Header64->NumCommands && Cmd < CmdEnd; ++Index) {
      if (Cmd->CommandType == MACH_LOAD_COMMAND_UNIX_THREAD) {
        if (EntryPoint == 0) {
          UINT32  *Triple;
          UINT32   Remaining;
          UINT32   Flavor;
          UINT32   Count;

          DEBUG ((DEBUG_INFO, "DirectKernel: Found LC_UNIXTHREAD at index %u\n", Index));
          //
          // LC_UNIXTHREAD: cmd(4) + cmdsize(4) + repeated triples of
          // flavor(4) + count(4) + state[count].  arm_thread_state64_t is
          // x0-x28, fp, lr, sp, pc, cpsr = 34 UINT64s, PC at UINT64 index 32,
          // so a full state needs 68 UINT32s.
          //
          Triple    = (UINT32 *)((UINTN)Cmd + 8);
          Remaining = (Cmd->CommandSize >= 8) ? Cmd->CommandSize - 8 : 0;
          while (Remaining >= 8) {
            Flavor = Triple[0];
            Count  = Triple[1];
            DEBUG ((DEBUG_INFO, "DirectKernel: LC_UNIXTHREAD flavor=%u count=%u\n", Flavor, Count));
            if (Flavor == ARM64_THREAD_STATE_FLAVOR && Count >= 66) {
              if ((UINTN)Triple + 8 + 34 * sizeof (UINT64) <= (UINTN)KernelBuffer + KernelSize) {
                UINT64  *ThrState = (UINT64 *)((UINTN)Triple + 8);

                EntryPoint = ThrState[32];
                DEBUG ((DEBUG_INFO, "DirectKernel: thr x0=0x%llx x1=0x%llx sp=0x%llx\n",
                        ThrState[0], ThrState[1], ThrState[31]));
                DEBUG ((DEBUG_INFO, "DirectKernel: thr pc=0x%llx cpsr=0x%llx\n",
                        ThrState[32], ThrState[33]));
              }
              break;
            }
            if (Remaining < 8 + Count * 4) {
              break;
            }
            Triple    += 2 + Count;
            Remaining -= 8 + Count * 4;
          }
        }
      } else if (Cmd->CommandType == MACH_LOAD_COMMAND_SEGMENT_64) {
        MACH_SEGMENT_COMMAND_64  *Seg64 = (MACH_SEGMENT_COMMAND_64 *)Cmd;

        if (SegCount < ARRAY_SIZE (SegVmAddr)) {
          SegVmAddr[SegCount]  = Seg64->VirtualAddress;
          SegVmSize[SegCount]  = Seg64->Size;
          SegFileOff[SegCount] = Seg64->FileOffset;
          DEBUG ((DEBUG_INFO, "DirectKernel: seg[%u] va=0x%llx sz=0x%llx off=0x%llx\n",
                  SegCount, Seg64->VirtualAddress, Seg64->Size, Seg64->FileOffset));
          SegCount++;
        } else {
          DEBUG ((DEBUG_WARN, "DirectKernel: segment table full (%u), ignoring\n", SegCount));
        }
      } else if (Cmd->CommandType == 0x80000028U) {  // LC_MAIN
        //
        // entry_point_command: cmd(4) + cmdsize(4) + entryoff(8) + stacksize(8)
        //
        if (EntryPoint == 0) {
          UINT64  *MainData = (UINT64 *)((UINTN)Cmd + 8);
          UINT64   FileOff  = MainData[0];
          DEBUG ((DEBUG_INFO, "DirectKernel: Found LC_MAIN at index %u fileoff=0x%llx\n", Index, FileOff));
          EntryPoint = (UINT64)(UINTN)KernelBuffer + FileOff;
          DEBUG ((DEBUG_INFO, "DirectKernel: LC_MAIN VM entry=0x%llx\n", EntryPoint));
        }
      }
      Cmd = (MACH_LOAD_COMMAND *)((UINTN)Cmd + Cmd->CommandSize);
    }

    if (EntryPoint == 0) {
      DEBUG ((DEBUG_ERROR, "DirectKernel: Failed to get entry point from ARM64 Mach-O\n"));
      FreePool (KernelBuffer);
      return EFI_INVALID_PARAMETER;
    }
  }

  DEBUG ((DEBUG_INFO, "DirectKernel: Entry point at 0x%llx\n", EntryPoint));

  BootArgsSize = sizeof (BootArgs2);
  BootArgs = AllocatePool (BootArgsSize);
  if (BootArgs == NULL) {
    FreePool (KernelBuffer);
    return EFI_OUT_OF_RESOURCES;
  }

  ZeroMem (BootArgs, BootArgsSize);
  BootArgs->Revision = kBootArgsRevision2_0;
  BootArgs->Version  = kBootArgsVersion2;
  BootArgs->efiMode  = Is32Bit ? kBootArgsEfiMode32 : kBootArgsEfiMode64;
  AsciiSPrint (BootArgs->CommandLine, BOOT_LINE_LENGTH, "install=1");

  BootArgs->kaddr = (UINT64)(UINTN)KernelBuffer;
  BootArgs->ksize  = KernelSize;

  DEBUG ((DEBUG_INFO, "DirectKernel: bootargs kaddr=0x%llx ksize=%u\n",
          BootArgs->kaddr, BootArgs->ksize));

  //
  // Create minimal device tree for XNU
  //
  Status = CreateMinimalDeviceTree (&DeviceTreeBuffer, &DeviceTreeSize);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_WARN, "DirectKernel: Failed to create device tree - %r\n", Status));
    DeviceTreeBuffer = NULL;
    DeviceTreeSize = 0;
  } else {
    BootArgs->deviceTreeP = (UINT64)(UINTN)DeviceTreeBuffer;
    BootArgs->deviceTreeLength = (UINT32)DeviceTreeSize;
    DEBUG ((DEBUG_INFO, "DirectKernel: devicetree=0x%llx/%u\n",
            BootArgs->deviceTreeP, BootArgs->deviceTreeLength));
  }

  //
  // Allocate stack for kernel execution
  //
  StackSize = EFI_PAGES_TO_SIZE (0x100);  // 1MB stack
  Status = gBS->AllocatePool (EfiBootServicesData, StackSize, (VOID **)&StackBuffer);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "DirectKernel: Failed to allocate stack - %r\n", Status));
    if (DeviceTreeBuffer != NULL) {
      FreePool (DeviceTreeBuffer);
    }
    FreePool (BootArgs);
    FreePool (KernelBuffer);
    return EFI_OUT_OF_RESOURCES;
  }
  DEBUG ((DEBUG_INFO, "DirectKernel: stack=%p size=%u\n", StackBuffer, StackSize));

  //
  // For ARM64 kernel, use DBT translation
  //
  if (IsArm64 && gDbtContext != NULL) {
    DBT_ARM64_STATE  ArmContext;
    UINT64           KernelVaBase;
    UINT64           KernelVaEnd;
    UINTN            Steps;
    UINTN            MaxSteps;

    ZeroMem (&ArmContext, sizeof (ArmContext));
    ArmContext.X[0] = (UINT64)(UINTN)BootArgs;
    //
    // xnu's _start (osfmk/arm64/start.s) copies x3 into x20 before using the
    // boot args, so hand the pointer over in both registers.
    //
    ArmContext.X[3] = (UINT64)(UINTN)BootArgs;
    ArmContext.SP   = (UINT64)(UINTN)(StackBuffer + StackSize);
    ArmContext.PC   = EntryPoint;
    ArmContext.SPSR_EL1 = 0x5;  // EL1 with all exceptions masked

    DEBUG ((DEBUG_INFO, "DirectKernel: SP=0x%llx, PC=0x%llx\n", ArmContext.SP, ArmContext.PC));

    //
    // Dispatch loop: translate the straight-line block ending at the next
    // PC-updating branch, execute it, and continue from the resulting PC.
    // The kernel image is linked at the lowest segment vmaddr and loaded at
    // KernelBuffer; the entry point (LC_UNIXTHREAD pc) points at the start
    // of the entry segment (e.g. __TEXT_BOOT_EXEC), which lives at a
    // nonzero file offset, so VA->file-offset mapping goes through the
    // LC_SEGMENT_64 table rather than assuming entry == image base.
    //
    KernelVaBase = EntryPoint;
    for (Index = 0; Index < SegCount; Index++) {
      if (SegVmAddr[Index] < KernelVaBase) {
        KernelVaBase = SegVmAddr[Index];
      }
    }
    KernelVaEnd  = KernelVaBase + KernelSize;
    MaxSteps     = 0x4000000;  // safety valve

    DEBUG ((DEBUG_INFO, "DirectKernel: %u segments, image base=0x%llx end=0x%llx\n",
            SegCount, KernelVaBase, KernelVaEnd));

    //
    // Register the segment table with the DBT context so translated loads
    // and stores translate guest VAs to host addresses.  Without this the
    // emitters would dereference the guest VA directly on the x86 host and
    // the silently swallowed page fault would leave guest registers zeroed
    // (observed as a CBZ self-spin on the kernel boot path).
    //
    if (EFI_ERROR (DbtSetSegments (gDbtContext, SegCount, SegVmAddr, SegVmSize,
                                   SegFileOff, KernelBuffer))) {
      DEBUG ((DEBUG_ERROR, "DirectKernel: DbtSetSegments failed\n"));
      FreePool (StackBuffer);
      FreePool (BootArgs);
      FreePool (KernelBuffer);
      return EFI_INVALID_PARAMETER;
    }

    //
    // Register a host-backed zeroed window for low guest "physical" VAs.
    // The kernel's early boot shim touches globals at small offsets (e.g.
    // 0x1C0); with no backing they identity-map onto the x86 firmware's own
    // low pages and the read yields unrelated bytes the kernel later takes
    // for a pointer (observed as a hang after the CPU-scan handoff).
    //
    {
      UINTN  PhysWinSize = EFI_PAGES_TO_SIZE (256);  // 1MB
      UINT8 *PhysWinBuffer;
      Status = gBS->AllocatePages (
                      AllocateAnyPages,
                      EfiLoaderData,
                      EFI_SIZE_TO_PAGES (PhysWinSize),
                      (EFI_PHYSICAL_ADDRESS *)&PhysWinBuffer
                      );
      if (!EFI_ERROR (Status)) {
        ZeroMem (PhysWinBuffer, PhysWinSize);
        DEBUG ((DEBUG_INFO, "DirectKernel: phys window allocated host=%p sz=0x%x\n",
                PhysWinBuffer, PhysWinSize));

        if (EFI_ERROR (DbtSetPhysWindow (gDbtContext, 0, PhysWinSize, PhysWinBuffer))) {
          DEBUG ((DEBUG_ERROR, "DirectKernel: DbtSetPhysWindow failed\n"));
          gBS->FreePages ((EFI_PHYSICAL_ADDRESS)(UINTN)PhysWinBuffer,
                          EFI_SIZE_TO_PAGES (PhysWinSize));
        }
      } else {
        DEBUG ((DEBUG_WARN, "DirectKernel: phys window alloc failed - %r\n", Status));
      }
    }

    //
    // Host-backed staging window for the kernel's high "physical" handles.
    // The boot code reads/dereferences a DRAM pointer at 0x4000000000
    // (observed as 0x4000020000) to locate its early physical region; when
    // no segment maps it DBT identity-maps the VA straight onto the x86
    // firmware address space where it is inaccessible and the boot hangs
    // (the same class of failure as the low 0x1C0 window fixed earlier).
    // Allocate a zeroed staging buffer at that handle so the kernel has a
    // deterministic region to poke at while it builds its own tables.
    //
    {
      UINT64 DramWinBase = 0x4000000000ULL;
      UINTN  DramWinSize = EFI_PAGES_TO_SIZE (1024);  // 4MB staging
      UINT8 *DramWinBuffer;
      Status = gBS->AllocatePages (
                      AllocateAnyPages,
                      EfiLoaderData,
                      EFI_SIZE_TO_PAGES (DramWinSize),
                      (EFI_PHYSICAL_ADDRESS *)&DramWinBuffer
                      );
      if (!EFI_ERROR (Status)) {
        ZeroMem (DramWinBuffer, DramWinSize);
        DEBUG ((DEBUG_INFO, "DirectKernel: dram window allocated host=%p base=0x%llx sz=0x%x\n",
                DramWinBuffer, DramWinBase, DramWinSize));

        if (EFI_ERROR (DbtSetPhysWindow (gDbtContext, DramWinBase, DramWinSize, DramWinBuffer))) {
          DEBUG ((DEBUG_ERROR, "DirectKernel: dram window set failed\n"));
          gBS->FreePages ((EFI_PHYSICAL_ADDRESS)(UINTN)DramWinBuffer,
                          EFI_SIZE_TO_PAGES (DramWinSize));
        }
      } else {
        DEBUG ((DEBUG_WARN, "DirectKernel: dram staging alloc failed - %r\n", Status));
      }
    }

    //
    // Populate the per-CPU data entries handoff table that xnu's boot code
    // scans (iBoot would normally fill it); without this the kernel reads
    // stale file data and faults dereferencing it.
    //
    SetupCpuDataEntries (KernelBuffer, SegCount, SegVmAddr, SegVmSize,
                         SegFileOff, EntryPoint, StackBuffer, StackSize);

    DEBUG ((DEBUG_INFO, "DirectKernel: dispatch start pc=0x%llx maxsteps=%u\n",
            ArmContext.PC, MaxSteps));

    for (Steps = 0;
         Steps < MaxSteps &&
         ArmContext.PC >= KernelVaBase &&
         ArmContext.PC <  KernelVaEnd;
         Steps++) {
      UINTN   Pa       = 0;
      UINTN   FileOff  = 0;
      BOOLEAN Mapped   = FALSE;
      UINT32  Inst;
      UINTN   Off;

      for (Index = 0; Index < SegCount; Index++) {
        if (ArmContext.PC >= SegVmAddr[Index] &&
            ArmContext.PC <  SegVmAddr[Index] + SegVmSize[Index]) {
          FileOff = (UINTN)(SegFileOff[Index] + (ArmContext.PC - SegVmAddr[Index]));
          Mapped  = TRUE;
          break;
        }
      }

      if (Mapped) {
        Pa = (UINTN)((UINT8 *)KernelBuffer + FileOff);
      } else if (SegCount == 0) {
        // No segment table (legacy image): fall back to a contiguous mapping.
        Pa = (UINTN)((UINT8 *)KernelBuffer + (UINTN)(ArmContext.PC - KernelVaBase));
      } else {
        DEBUG ((DEBUG_INFO, "DirectKernel: kernel left image range at PC=0x%llx after %u steps\n",
                ArmContext.PC, Steps));
        DEBUG ((DEBUG_INFO, "DirectKernel: PC=0x%llx SP=0x%llx LR=0x%llx PST=0x%llx\n",
                ArmContext.PC, ArmContext.SP, ArmContext.X[30], ArmContext.PSTATE));
        DEBUG ((DEBUG_INFO, "DirectKernel: x0=0x%llx x1=0x%llx x2=0x%llx x3=0x%llx\n",
                ArmContext.X[0], ArmContext.X[1], ArmContext.X[2], ArmContext.X[3]));
        DEBUG ((DEBUG_INFO, "DirectKernel: x8=0x%llx x9=0x%llx x19=0x%llx x20=0x%llx\n",
                ArmContext.X[8], ArmContext.X[9], ArmContext.X[19], ArmContext.X[20]));
        DEBUG ((DEBUG_INFO, "DirectKernel: x21=0x%llx x22=0x%llx x23=0x%llx x24=0x%llx\n",
                ArmContext.X[21], ArmContext.X[22], ArmContext.X[23], ArmContext.X[24]));
        DEBUG ((DEBUG_INFO, "DirectKernel: x25=0x%llx x26=0x%llx x27=0x%llx x28=0x%llx\n",
                ArmContext.X[25], ArmContext.X[26], ArmContext.X[27], ArmContext.X[28]));
        break;
      }

      if (FileOff >= KernelSize) {
        DEBUG ((DEBUG_INFO, "DirectKernel: kernel ran off the image at PC=0x%llx\n", ArmContext.PC));
        break;
      }

      Off = 0;
      for (;;) {
        if (Off + 4 > KernelSize - FileOff) {
          break;
        }
        Inst = *(UINT32 *)(Pa + Off);
        if (IsPcUpdatingBranch (Inst)) {
          break;
        }
        Off += 4;
      }

      if (Off + 4 > KernelSize - FileOff) {
        DEBUG ((DEBUG_INFO, "DirectKernel: kernel ran off the image at PC=0x%llx\n", ArmContext.PC));
        break;
      }

      DbtTranslateBlock (gDbtContext, (VOID *)(Pa), Off + 4, ArmContext.PC, NULL);
      DbtExecute (gDbtContext, &ArmContext);
    }

    if (ArmContext.PC >= KernelVaBase && ArmContext.PC < KernelVaEnd) {
      DEBUG ((DEBUG_WARN, "DirectKernel: dispatcher step limit reached at PC=0x%llx\n", ArmContext.PC));
    } else {
      DEBUG ((DEBUG_INFO, "DirectKernel: kernel left image range at PC=0x%llx after %u steps\n",
              ArmContext.PC, Steps));
      DEBUG ((DEBUG_INFO, "DirectKernel: PC=0x%llx SP=0x%llx LR=0x%llx PST=0x%llx\n",
              ArmContext.PC, ArmContext.SP, ArmContext.X[30], ArmContext.PSTATE));
      DEBUG ((DEBUG_INFO, "DirectKernel: x0=0x%llx x1=0x%llx x2=0x%llx x3=0x%llx\n",
              ArmContext.X[0], ArmContext.X[1], ArmContext.X[2], ArmContext.X[3]));
      DEBUG ((DEBUG_INFO, "DirectKernel: x8=0x%llx x9=0x%llx x19=0x%llx x20=0x%llx\n",
              ArmContext.X[8], ArmContext.X[9], ArmContext.X[19], ArmContext.X[20]));
      DEBUG ((DEBUG_INFO, "DirectKernel: x21=0x%llx x22=0x%llx x23=0x%llx x24=0x%llx\n",
              ArmContext.X[21], ArmContext.X[22], ArmContext.X[23], ArmContext.X[24]));
      DEBUG ((DEBUG_INFO, "DirectKernel: x25=0x%llx x26=0x%llx x27=0x%llx x28=0x%llx\n",
              ArmContext.X[25], ArmContext.X[26], ArmContext.X[27], ArmContext.X[28]));
    }

    // Should not reach here
    FreePool (StackBuffer);
    if (DeviceTreeBuffer != NULL) {
      FreePool (DeviceTreeBuffer);
    }
    FreePool (BootArgs);
    FreePool (KernelBuffer);
    return EFI_DEVICE_ERROR;
  } else if (!IsArm64) {
    //
    // x86_64 kernel - directly call entry point
    //
    DEBUG ((DEBUG_INFO, "DirectKernel: x86_64 kernel execution not fully implemented\n"));
    FreePool (StackBuffer);
    if (DeviceTreeBuffer != NULL) {
      FreePool (DeviceTreeBuffer);
    }
    FreePool (BootArgs);
    FreePool (KernelBuffer);
    return EFI_UNSUPPORTED;
  } else {
    FreePool (StackBuffer);
    if (DeviceTreeBuffer != NULL) {
      FreePool (DeviceTreeBuffer);
    }
    FreePool (BootArgs);
    FreePool (KernelBuffer);
    return EFI_UNSUPPORTED;
  }
}

STATIC
EFI_STATUS
DbtBootEntryAction (
  IN OUT  OC_PICKER_CONTEXT         *PickerContext,
  IN      EFI_DEVICE_PATH_PROTOCOL  *DevicePath
  )
{
  DEBUG ((DEBUG_INFO, "DBT: BootEntryAction picker=%p dp=%p\n",
          PickerContext, DevicePath));
  RaiseScreenVerbose ();
  DEBUG ((DEBUG_INFO, "DBT: starting DirectKernel\n"));
  //
  // Fallback: scan all filesystems for kernel if no boot info yet
  //
  if ((gDbtContext != NULL) && (DbtGetInstallerDevice (gDbtContext) == NULL)) {
    EFI_HANDLE  *Handles;
    UINTN       Count;
    EFI_STATUS  ScanStatus;

    ScanStatus = gBS->LocateHandleBuffer (
                        ByProtocol,
                        &gEfiSimpleFileSystemProtocolGuid,
                        NULL,
                        &Count,
                        &Handles
                        );
    if (!EFI_ERROR (ScanStatus) && Count > 0) {
      //
      // FIRST PASS: log all handles with their volume info
      //
      for (UINTN Idx = 0; Idx < Count; Idx++) {
        EFI_SIMPLE_FILE_SYSTEM_PROTOCOL  *Fs;
        EFI_FILE_PROTOCOL                *Root;
        ScanStatus = gBS->HandleProtocol (Handles[Idx], &gEfiSimpleFileSystemProtocolGuid, (VOID **)&Fs);
        if (!EFI_ERROR (ScanStatus)) {
          ScanStatus = Fs->OpenVolume (Fs, &Root);
          if (!EFI_ERROR (ScanStatus)) {
            //
            // Try to get APFS volume info
            //
            APPLE_APFS_VOLUME_INFO  *VolInfo;
            VolInfo = OcGetFileInfo (Root, &gAppleApfsVolumeInfoGuid, sizeof (*VolInfo), NULL);
            if (VolInfo != NULL) {
              DEBUG ((DEBUG_INFO, "DBT: Handle %p APFS role=0x%X hasGG=%d hasSS=%d\n",
                       Handles[Idx], VolInfo->Role,
                       IsGoldenGateInstaller (Root),
                       IsSharedSupportVolume (Root)));
              FreePool (VolInfo);
            } else {
              DEBUG ((DEBUG_INFO, "DBT: Handle %p non-APFS hasGG=%d\n",
                       Handles[Idx], IsGoldenGateInstaller (Root)));
            }
            Root->Close (Root);
          }
        }
      }
      for (UINTN Idx = 0; Idx < Count; Idx++) {
        EFI_SIMPLE_FILE_SYSTEM_PROTOCOL  *Fs;
        EFI_FILE_PROTOCOL                *Root;
        ScanStatus = gBS->HandleProtocol (Handles[Idx], &gEfiSimpleFileSystemProtocolGuid, (VOID **)&Fs);
        if (!EFI_ERROR (ScanStatus)) {
          ScanStatus = Fs->OpenVolume (Fs, &Root);
          if (!EFI_ERROR (ScanStatus)) {
            //
            // Try kernel paths or Golden Gate marker
            //
            EFI_FILE_PROTOCOL  *KernelFile;
            STATIC CONST CHAR16  *Paths[] = {
              L"\\kernelcache.decomp",
              L"\\kernelcache.release",
              L"\\kernel",
              L"\\com_apple_MobileAsset_MacSoftwareUpdate\\AssetData\\boot\\kernelcache.release.mac15j",
              L"\\com_apple_MobileAsset_MacSoftwareUpdate\\AssetData\\boot\\kernelcache.release.mac16j",
              NULL
            };
            for (UINTN Pi = 0; Paths[Pi] != NULL; Pi++) {
              ScanStatus = Root->Open (Root, &KernelFile, (CHAR16 *)Paths[Pi], EFI_FILE_MODE_READ, 0);
              if (!EFI_ERROR (ScanStatus)) {
                KernelFile->Close (KernelFile);
                gInstallerDevice = Handles[Idx];
                DbtSetBootInfo (gDbtContext, Handles[Idx], Paths[Pi]);
                DEBUG ((DEBUG_INFO, "DBT: Fallback found kernel at %s\n", Paths[Pi]));
                break;
              }
            }

            if (DbtGetInstallerDevice (gDbtContext) == NULL && IsGoldenGateInstaller (Root)) {
              gInstallerDevice = Handles[Idx];
              //
              // Search all handles for SharedSupport
              //
              for (UINTN Ji = 0; Ji < Count; Ji++) {
                if (Ji == Idx) continue;
                EFI_SIMPLE_FILE_SYSTEM_PROTOCOL  *Fs2;
                EFI_FILE_PROTOCOL                *SRoot;
                ScanStatus = gBS->HandleProtocol (Handles[Ji], &gEfiSimpleFileSystemProtocolGuid, (VOID **)&Fs2);
                if (!EFI_ERROR (ScanStatus)) {
                  ScanStatus = Fs2->OpenVolume (Fs2, &SRoot);
                  if (!EFI_ERROR (ScanStatus)) {
                    if (IsSharedSupportVolume (SRoot)) {
                      gInstallerDevice = Handles[Ji];
                      DbtSetBootInfo (gDbtContext, Handles[Ji], L"\\kernel");
                      DEBUG ((DEBUG_INFO, "DBT: Fallback found SharedSupport, kernel path \\kernel\n"));
                      SRoot->Close (SRoot);
                      SRoot = NULL;
                      break;
                    }
                    SRoot->Close (SRoot);
                  }
                }
              }
              if (DbtGetInstallerDevice (gDbtContext) == NULL) {
                DEBUG ((DEBUG_WARN, "DBT: .IAPhysicalMedia found but SharedSupport volume NOT MOUNTED\n"));
                DEBUG ((DEBUG_WARN, "DBT: Kernel is on unmounted APFS subvolume — cannot boot directly\n"));
                DbtSetBootInfo (gDbtContext, gInstallerDevice, L"\\SharedSupport\\kernel");
              }
            }
            Root->Close (Root);
          }
        }
        if (DbtGetInstallerDevice (gDbtContext) != NULL) {
          break;
        }
      }
      FreePool (Handles);
    }
  }

  return DirectLoadKernel (PickerContext);
}

STATIC
EFI_STATUS
EFIAPI
OcGetDbtBootEntries (
  IN OUT         OC_PICKER_CONTEXT  *PickerContext,
  IN     CONST EFI_HANDLE           Device OPTIONAL,
  OUT       OC_PICKER_ENTRY         **Entries,
  OUT       UINTN                   *NumEntries
  )
{
  EFI_STATUS  Status;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL  *FileSystem;
  EFI_FILE_PROTOCOL                *RootDirectory;
  EFI_FILE_PROTOCOL                *BootDirectory;
  EFI_FILE_INFO                    *FileInfo;
  UINTN                            FileInfoSize;
  UINTN                            EntryCount;
  OC_PICKER_ENTRY                  *NewEntries;
  UINTN                            Index;
  BOOLEAN                          IsMacSoftwareUpdate = FALSE;

  ASSERT (PickerContext != NULL);
  ASSERT (Entries != NULL);
  ASSERT (NumEntries != NULL);

  RaiseScreenVerbose ();

  *Entries    = NULL;
  *NumEntries = 0;

  if (Device == NULL) {
    DEBUG ((DEBUG_INFO, "DBT: Device is NULL, returning EFI_NOT_FOUND\n"));
    return EFI_NOT_FOUND;
  }

  DEBUG ((DEBUG_INFO, "DBT: GetBootEntries called for Device %p\n", Device));

  Status = gBS->HandleProtocol (
                   Device,
                   &gEfiSimpleFileSystemProtocolGuid,
                   (VOID **)&FileSystem
                   );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_INFO, "DBT: HandleProtocol failed - %r\n", Status));
    return Status;
  }

  Status = FileSystem->OpenVolume (FileSystem, &RootDirectory);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_INFO, "DBT: OpenVolume failed - %r\n", Status));
    return Status;
  }

  EntryCount = 0;

  //
  // Look for macOS Installer (com.apple.installer) in boot directories
  //
  DEBUG ((DEBUG_INFO, "DBT: Looking for traditional installer at %s\n", L"\\System\\Library\\CoreServices\\com.apple.installer"));
  Status = RootDirectory->Open (
                           RootDirectory,
                           &BootDirectory,
                           L"\\System\\Library\\CoreServices\\com.apple.installer",
                           EFI_FILE_MODE_READ,
                           0
                           );

  if (!EFI_ERROR (Status)) {
    DEBUG ((DEBUG_INFO, "DBT: Found traditional installer directory\n"));
    Status = EFI_NOT_FOUND;

    FileInfoSize = 0;
    BootDirectory->GetInfo (BootDirectory, &gEfiFileInfoGuid, &FileInfoSize, NULL);
    if (FileInfoSize > 0) {
      Status = EFI_SUCCESS;
      FileInfo = AllocatePool (FileInfoSize);
      if (FileInfo != NULL) {
        BootDirectory->GetInfo (BootDirectory, &gEfiFileInfoGuid, &FileInfoSize, FileInfo);
        if ((FileInfo->Attribute & EFI_FILE_DIRECTORY) != 0) {
          DEBUG ((DEBUG_INFO, "DBT: Traditional installer is a directory, EntryCount++\n"));
          ++EntryCount;
        } else {
          DEBUG ((DEBUG_INFO, "DBT: Traditional installer is NOT a directory (attributes: 0x%x)\n", FileInfo->Attribute));
        }
        FreePool (FileInfo);
      }
    }
    BootDirectory->Close (BootDirectory);
  } else {
    DEBUG ((DEBUG_INFO, "DBT: Traditional installer not found - %r\n", Status));
  }

  //
  // Also look for macOS 27+ installer (com.apple.MobileAsset) in SharedSupport
  //
  if (EntryCount == 0) {
    DEBUG ((DEBUG_INFO, "DBT: Looking for macOS 27+ MobileAsset installer at %s\n", L"\\SharedSupport\\com_apple_MobileAsset_MacSoftwareUpdate"));
    Status = RootDirectory->Open (
                             RootDirectory,
                             &BootDirectory,
                             L"\\SharedSupport\\com_apple_MobileAsset_MacSoftwareUpdate",
                             EFI_FILE_MODE_READ,
                             0
                             );

    if (!EFI_ERROR (Status)) {
      DEBUG ((DEBUG_INFO, "DBT: Found macOS 27+ MobileAsset installer directory, IsMacSoftwareUpdate = TRUE\n"));
      Status = EFI_NOT_FOUND;

      FileInfoSize = 0;
      BootDirectory->GetInfo (BootDirectory, &gEfiFileInfoGuid, &FileInfoSize, NULL);
      if (FileInfoSize > 0) {
        Status = EFI_SUCCESS;
        FileInfo = AllocatePool (FileInfoSize);
        if (FileInfo != NULL) {
          BootDirectory->GetInfo (BootDirectory, &gEfiFileInfoGuid, &FileInfoSize, FileInfo);
          if ((FileInfo->Attribute & EFI_FILE_DIRECTORY) != 0) {
            DEBUG ((DEBUG_INFO, "DBT: MobileAsset installer is a directory, EntryCount++, IsMacSoftwareUpdate=TRUE\n"));
            ++EntryCount;
            IsMacSoftwareUpdate = TRUE;
          } else {
            DEBUG ((DEBUG_INFO, "DBT: MobileAsset installer is NOT a directory (attributes: 0x%x)\n", FileInfo->Attribute));
          }
          FreePool (FileInfo);
        }
      }
      BootDirectory->Close (BootDirectory);
    } else {
      DEBUG ((DEBUG_INFO, "DBT: macOS 27+ MobileAsset installer not found - %r\n", Status));
    }
  }

  //
  // Also look for macOS 27+ installer dyld cache path (x86_64 cache in installer)
  //
  if (EntryCount == 0) {
    DEBUG ((DEBUG_INFO, "DBT: Looking for macOS 27+ dyld cache installer at %s\n", L"\\System\\Library\\dyld"));
    Status = RootDirectory->Open (
                             RootDirectory,
                             &BootDirectory,
                             L"\\System\\Library\\dyld",
                             EFI_FILE_MODE_READ,
                             0
                             );

    if (!EFI_ERROR (Status)) {
      DEBUG ((DEBUG_INFO, "DBT: Found dyld cache directory, checking for x86_64 cache\n"));

      FileInfoSize = 0;
      BootDirectory->GetInfo (BootDirectory, &gEfiFileInfoGuid, &FileInfoSize, NULL);
      if (FileInfoSize > 0) {
        FileInfo = AllocatePool (FileInfoSize);
        if (FileInfo != NULL) {
          BootDirectory->GetInfo (BootDirectory, &gEfiFileInfoGuid, &FileInfoSize, FileInfo);
          if ((FileInfo->Attribute & EFI_FILE_DIRECTORY) != 0) {
            EFI_FILE_PROTOCOL *DylibDir;
            Status = BootDirectory->Open (
                                     BootDirectory,
                                     &DylibDir,
                                     L"shared_cache.x86_64h",
                                     EFI_FILE_MODE_READ,
                                     0
                                     );
            if (EFI_ERROR (Status)) {
              Status = BootDirectory->Open (
                                       BootDirectory,
                                       &DylibDir,
                                       L"shared_cache.x86_64",
                                       EFI_FILE_MODE_READ,
                                       0
                                       );
            }
            if (!EFI_ERROR (Status)) {
              DEBUG ((DEBUG_INFO, "DBT: Found x86_64 dyld shared cache, EntryCount++\n"));
              ++EntryCount;
              DylibDir->Close (DylibDir);
            }
          }
          FreePool (FileInfo);
        }
      }
      BootDirectory->Close (BootDirectory);
    }
  }

  //
  // Look for macOS 27+ kernel/kernelcache in SharedSupport
  //
  if (EntryCount == 0) {
    STATIC CONST CHAR16  *KernelPaths[] = {
      L"\\kernelcache.decomp",
      L"\\kernelcache.release",
      L"\\kernel",
      L"\\SharedSupport\\kernel",
      L"\\System\\Library\\Kernels\\kernel",
      L"\\com_apple_MobileAsset_MacSoftwareUpdate\\AssetData\\boot\\kernelcache.release.mac15j",
      L"\\com_apple_MobileAsset_MacSoftwareUpdate\\AssetData\\boot\\kernelcache.release.mac16j",
      L"\\AssetData\\boot\\kernelcache.release.mac15j",
      L"\\AssetData\\boot\\kernelcache.release.mac16j",
      NULL
    };

    for (Index = 0; KernelPaths[Index] != NULL; Index++) {
      DEBUG ((DEBUG_INFO, "DBT: Looking for kernel at %s\n", KernelPaths[Index]));
      Status = RootDirectory->Open (
                              RootDirectory,
                              &BootDirectory,
                              (CHAR16 *)KernelPaths[Index],
                              EFI_FILE_MODE_READ,
                              0
                              );

      if (!EFI_ERROR (Status)) {
        FileInfoSize = 0;
        BootDirectory->GetInfo (BootDirectory, &gEfiFileInfoGuid, &FileInfoSize, NULL);
        if (FileInfoSize > 0) {
          FileInfo = AllocatePool (FileInfoSize);
          if (FileInfo != NULL) {
            BootDirectory->GetInfo (BootDirectory, &gEfiFileInfoGuid, &FileInfoSize, FileInfo);
            if ((FileInfo->Attribute & EFI_FILE_DIRECTORY) == 0) {
              DEBUG ((DEBUG_INFO, "DBT: Found kernel at %s, EntryCount++\n", KernelPaths[Index]));
              ++EntryCount;
              IsMacSoftwareUpdate = TRUE;
            }
            FreePool (FileInfo);
          }
        }
        BootDirectory->Close (BootDirectory);
        if (EntryCount > 0) {
          break;
        }
      }
    }
  }

  //
  // Also scan SharedSupport AssetData/boot dir for kernelcache files
  //
  if (EntryCount == 0) {
    STATIC CONST CHAR16  *KernelDirs[] = {
      L"\\com_apple_MobileAsset_MacSoftwareUpdate\\AssetData\\boot",
      L"\\AssetData\\boot",
      NULL
    };

    for (Index = 0; KernelDirs[Index] != NULL; Index++) {
      Status = RootDirectory->Open (
                              RootDirectory,
                              &BootDirectory,
                              (CHAR16 *)KernelDirs[Index],
                              EFI_FILE_MODE_READ,
                              0
                              );
      if (!EFI_ERROR (Status)) {
        //
        // Enumerate files in this directory looking for kernelcache.*
        //
        FileInfoSize = 0;
        BootDirectory->GetInfo (BootDirectory, &gEfiFileInfoGuid, &FileInfoSize, NULL);
        if (FileInfoSize > 0) {
          // Check if it's actually a directory
          FileInfo = AllocatePool (FileInfoSize);
          if (FileInfo != NULL) {
            BootDirectory->GetInfo (BootDirectory, &gEfiFileInfoGuid, &FileInfoSize, FileInfo);
            if ((FileInfo->Attribute & EFI_FILE_DIRECTORY) != 0) {
              UINTN   DirBufSize = SIZE_256KB;
              VOID    *DirBuf = AllocatePool (DirBufSize);
              if (DirBuf != NULL) {
                while (TRUE) {
                  UINTN  ReadSize = DirBufSize;
                  Status = BootDirectory->Read (BootDirectory, &ReadSize, DirBuf);
                  if (EFI_ERROR (Status) || ReadSize == 0) {
                    break;
                  }
                  EFI_FILE_INFO  *DirEntry = (EFI_FILE_INFO *)DirBuf;
                  while ((UINTN)DirEntry < (UINTN)DirBuf + ReadSize) {
                    if ((DirEntry->Attribute & EFI_FILE_DIRECTORY) == 0
                        && StrnCmp (DirEntry->FileName, L"kernelcache.", 12) == 0) {
                      DEBUG ((DEBUG_INFO, "DBT: Found kernelcache: %s\n", DirEntry->FileName));
                      EntryCount = 1;
                      IsMacSoftwareUpdate = TRUE;
                      break;
                    }
                    if (DirEntry->Size == 0) {
                      break;
                    }
                    DirEntry = (EFI_FILE_INFO *)((UINT8 *)DirEntry + DirEntry->Size);
                  }
                  if (EntryCount > 0) {
                    break;
                  }
                }
                FreePool (DirBuf);
              }
            }
            FreePool (FileInfo);
          }
        }
        BootDirectory->Close (BootDirectory);
        if (EntryCount > 0) {
          break;
        }
      }
    }
  }

  DEBUG ((DEBUG_INFO, "DBT: Installer scan complete - EntryCount=%u, IsMacSoftwareUpdate=%d\n", EntryCount, IsMacSoftwareUpdate));

  if (EntryCount == 0) {
    //
    // macOS 27 Golden Gate: Check for .IAPhysicalMedia marker
    //
    if (IsGoldenGateInstaller (RootDirectory)) {
      DEBUG ((DEBUG_INFO, "DBT: Found .IAPhysicalMedia marker - macOS 27 Golden Gate installer detected\n"));
      DEBUG ((DEBUG_INFO, "DBT: Checking for mounted SharedSupport volume...\n"));

      EFI_HANDLE  *HandleBuffer;
      UINTN       HandleCount;
      EFI_SIMPLE_FILE_SYSTEM_PROTOCOL  *FsProtocol;
      EFI_FILE_PROTOCOL                *SharedRoot;

      Status = gBS->LocateHandleBuffer (
                       ByProtocol,
                       &gEfiSimpleFileSystemProtocolGuid,
                       NULL,
                       &HandleCount,
                       &HandleBuffer
                       );

      if (!EFI_ERROR (Status) && HandleCount > 0) {
        for (UINTN Idx = 0; Idx < HandleCount; Idx++) {
          if (HandleBuffer[Idx] == Device) {
            continue;
          }

          Status = gBS->HandleProtocol (
                       HandleBuffer[Idx],
                       &gEfiSimpleFileSystemProtocolGuid,
                       (VOID **)&FsProtocol
                       );

          if (!EFI_ERROR (Status)) {
            Status = FsProtocol->OpenVolume (FsProtocol, &SharedRoot);
            if (!EFI_ERROR (Status)) {
              if (IsSharedSupportVolume (SharedRoot)) {
                DEBUG ((DEBUG_INFO, "DBT: Found mounted SharedSupport volume for Golden Gate installer\n"));
                gInstallerDevice = HandleBuffer[Idx];
                EntryCount = 1;
                IsMacSoftwareUpdate = TRUE;
                SharedRoot->Close (SharedRoot);
                break;
              }
              SharedRoot->Close (SharedRoot);
            }
          }
        }
      }

      if (HandleBuffer != NULL) {
        FreePool (HandleBuffer);
      }
    }
  }

  //
  // Fallback: if boot.efi exists and is ARM64, create DBT entry anyway.
  // DirectLoadKernel will search for kernel at boot time.
  //
  if (EntryCount == 0) {
    EFI_FILE_PROTOCOL  *BootEfi;
    Status = RootDirectory->Open (
                             RootDirectory,
                             &BootEfi,
                             L"\\System\\Library\\CoreServices\\boot.efi",
                             EFI_FILE_MODE_READ,
                             0
                             );
    if (!EFI_ERROR (Status)) {
      UINT8  Header[128];
      UINTN  ReadSize = sizeof (Header);
      Status = BootEfi->Read (BootEfi, &ReadSize, Header);
      if (!EFI_ERROR (Status) && ReadSize >= 64) {
        if (*(UINT16 *)Header == 0x5A4D) {
          UINT32  PeOffset = *(UINT32 *)(Header + 0x3C);
          if ((PeOffset + 8) < ReadSize) {
            if (*(UINT32 *)(Header + PeOffset) == 0x00004550) {
              UINT16  Machine = *(UINT16 *)(Header + PeOffset + 4);
              if (Machine == 0xAA64) {
                DEBUG ((DEBUG_INFO, "DBT: ARM64 boot.efi detected, searching SharedSupport for kernel\n"));
                gInstallerDevice = Device;
                //
                // Search for SharedSupport volume with kernel
                //
                {
                  EFI_HANDLE  *Hb;
                  UINTN       Hc;
                  Status = gBS->LocateHandleBuffer (
                                  ByProtocol,
                                  &gEfiSimpleFileSystemProtocolGuid,
                                  NULL,
                                  &Hc,
                                  &Hb
                                  );
                  if (!EFI_ERROR (Status) && Hc > 0) {
                    for (UINTN Idx = 0; Idx < Hc; Idx++) {
                      if (Hb[Idx] == Device) {
                        continue;
                      }
                      EFI_SIMPLE_FILE_SYSTEM_PROTOCOL  *Fs;
                      Status = gBS->HandleProtocol (Hb[Idx], &gEfiSimpleFileSystemProtocolGuid, (VOID **)&Fs);
                      if (!EFI_ERROR (Status)) {
                        EFI_FILE_PROTOCOL  *SRoot;
                        Status = Fs->OpenVolume (Fs, &SRoot);
                        if (!EFI_ERROR (Status)) {
                          if (IsSharedSupportVolume (SRoot)) {
                            gInstallerDevice = Hb[Idx];
                            DEBUG ((DEBUG_INFO, "DBT: Found SharedSupport volume for ARM64 installer\n"));
                            SRoot->Close (SRoot);
                            break;
                          }
                          SRoot->Close (SRoot);
                        }
                      }
                    }
                    FreePool (Hb);
                  }
                }
                EntryCount = 1;
                IsMacSoftwareUpdate = TRUE;
              }
            }
          }
        }
      }
      BootEfi->Close (BootEfi);
    }
  }

  RootDirectory->Close (RootDirectory);

  if (EntryCount > 0) {
    DEBUG ((DEBUG_INFO, "DBT: Creating %u installer entry(s)\n", EntryCount));
    NewEntries = AllocatePool (sizeof (OC_PICKER_ENTRY) * EntryCount);
    if (NewEntries == NULL) {
      return EFI_OUT_OF_RESOURCES;
    }

    ZeroMem (NewEntries, sizeof (OC_PICKER_ENTRY) * EntryCount);

    NewEntries[0].Id = AllocateCopyPool (AsciiStrSize ("macOS-Installer"), "macOS-Installer");
    NewEntries[0].Name = AllocateCopyPool (AsciiStrSize ("macOS Installer (Translated)"), "macOS Installer (Translated)");
    NewEntries[0].Flavour = AllocateCopyPool (AsciiStrSize ("DirectKernel"), "DirectKernel");

    //
    // All DBT entries go through unmanaged boot action to bypass LoadImage
    // since boot.efi/kernel are ARM64 and EDK2 LoadImage will reject them.
    //
    DbtSetBootInfo (gDbtContext, gInstallerDevice != NULL ? gInstallerDevice : Device, L"\\kernel");
    NewEntries[0].UnmanagedBootAction             = DbtBootEntryAction;
    NewEntries[0].UnmanagedBootGetFinalDevicePath = NULL;
    //
    // Provide file path device path + end node for the picker.
    //
    {
      EFI_DEVICE_PATH_PROTOCOL  *Dp;
      UINTN                     Size = SIZE_OF_FILEPATH_DEVICE_PATH + sizeof (CHAR16) + sizeof (EFI_DEVICE_PATH_PROTOCOL);
      Dp = AllocateZeroPool (Size);
      if (Dp != NULL) {
        FILEPATH_DEVICE_PATH  *Fp = (FILEPATH_DEVICE_PATH *)Dp;
        Fp->Header.Type    = MEDIA_DEVICE_PATH;
        Fp->Header.SubType = MEDIA_FILEPATH_DP;
        SetDevicePathNodeLength (&Fp->Header, SIZE_OF_FILEPATH_DEVICE_PATH + sizeof (CHAR16));
        Fp->PathName[0]    = L'\0';
        SetDevicePathEndNode ((EFI_DEVICE_PATH_PROTOCOL *)((UINT8 *)Dp + SIZE_OF_FILEPATH_DEVICE_PATH + sizeof (CHAR16)));
      }
      NewEntries[0].UnmanagedDevicePath = Dp;
    }

    *Entries    = NewEntries;
    *NumEntries = EntryCount;
    return EFI_SUCCESS;
  }

  DEBUG ((DEBUG_INFO, "DBT: No installer found, returning EFI_NOT_FOUND\n"));
  return EFI_NOT_FOUND;
}

STATIC
VOID
EFIAPI
OcFreeDbtBootEntries (
  IN  OC_PICKER_ENTRY  **Entries,
  IN  UINTN            NumEntries
  )
{
  UINTN  Index;

  if ((Entries == NULL) || (*Entries == NULL)) {
    return;
  }

  for (Index = 0; Index < NumEntries; Index++) {
    if ((*Entries)[Index].Id != NULL) {
      FreePool ((VOID *)(UINTN)(*Entries)[Index].Id);
    }
    if ((*Entries)[Index].Name != NULL) {
      FreePool ((VOID *)(UINTN)(*Entries)[Index].Name);
    }
    if ((*Entries)[Index].Flavour != NULL) {
      FreePool ((VOID *)(UINTN)(*Entries)[Index].Flavour);
    }
    if ((*Entries)[Index].Path != NULL) {
      FreePool ((VOID *)(UINTN)(*Entries)[Index].Path);
    }
  }

  FreePool (*Entries);
  *Entries = NULL;
}

STATIC OC_BOOT_ENTRY_PROTOCOL  mDbtBootEntryProtocol = {
  OC_BOOT_ENTRY_PROTOCOL_REVISION,
  OcGetDbtBootEntries,
  OcFreeDbtBootEntries,
  NULL
};

EFI_STATUS
EFIAPI
OpenDbvX64EntryPoint (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS  Status;

  DEBUG ((DEBUG_INFO, "DBT: entry image=%p st=%p\n", ImageHandle, SystemTable));

  //
  // Raise the on-screen + file log level so the full verbose DBT trace is
  // printed to the console during the boot picker and the "macOS Installer
  // (Translated)" direct kernel run regardless of the Logging/DisplayLevel
  // setting in config.plist.
  //
  RaiseScreenVerbose ();

  Status = DbtInitContext (&gDbtContext, 0x100000);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "DBT: Failed to initialize DBT context - %r\n", Status));
    return Status;
  }

  DEBUG ((DEBUG_INFO, "DBT: ARM64->x86_64 initialized for DirectKernel\n"));

  //
  // Install DBT fallback protocol — GUID + function pointer
  //
  {
    EFI_GUID  DbtGuid = OC_DBT_FALLBACK_PROTOCOL_GUID;
    Status = gBS->InstallMultipleProtocolInterfaces (
                     &ImageHandle,
                     &DbtGuid,
                     (VOID *)(UINTN)DbtBootEntryAction,
                     NULL
                     );
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "DBT: Failed to install fallback protocol - %r\n", Status));
    } else {
      DEBUG ((DEBUG_INFO, "DBT: fallback protocol installed\n"));
    }
  }

  //
  // Install boot entry protocol to provide installer entries
  //
  Status = gBS->InstallMultipleProtocolInterfaces (
                   &ImageHandle,
                   &gOcBootEntryProtocolGuid,
                   &mDbtBootEntryProtocol,
                   NULL
                   );

  if (EFI_ERROR (Status)) {
    DbtFreeContext (gDbtContext);
    gDbtContext = NULL;
    return Status;
  }
  DEBUG ((DEBUG_INFO, "DBT: boot entry protocol installed\n"));
  DEBUG ((DEBUG_INFO, "DBT: driver ready\n"));

  return EFI_SUCCESS;
}