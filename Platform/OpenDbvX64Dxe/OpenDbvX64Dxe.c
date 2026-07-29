/** @file
      Copyright (C) 2026. All rights reserved.

      Dynamic Binary Translation DXE Driver for ARM64 to x86_64
   **/

#include <Uefi.h>
#include <Guid/FileInfo.h>
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

#include <Protocol/OcBootEntry.h>
#include <Protocol/SimpleFileSystem.h>

//
// ARM64 thread state flavor for Mach-O LC_UNIXTHREAD
//
#define ARM64_THREAD_STATE_FLAVOR  6

STATIC DBT_CONTEXT  *gDbtContext     = NULL;
STATIC EFI_HANDLE   gInstallerDevice = NULL;

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
__attribute__((unused))
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
  UINT8                            *KernelBuffer;
  UINT32                           KernelSize;
  UINT32                           AllocatedSize;
  BOOLEAN                          Is32Bit;
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
  MACH_HEADER_64                   *Header64;
  EFI_HANDLE                       Device;
  CONST CHAR16                     *KernelPath;

  if (gDbtContext == NULL) {
    return EFI_NOT_STARTED;
  }

  Device     = DbtGetInstallerDevice (gDbtContext);
  KernelPath = DbtGetKernelPath (gDbtContext);

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
      DEBUG ((DEBUG_ERROR, "DirectKernel: Failed to open kernel - %r\n", Status));
      RootDirectory->Close (RootDirectory);
      return Status;
    }
  }

  KernelBuffer = NULL;
  KernelSize = 0;
  AllocatedSize = 0;

  Status = ReadAppleKernel (
            KernelFile,
            FALSE,  // Prefer 64-bit
            &Is32Bit,
            &KernelBuffer,
            &KernelSize,
            &AllocatedSize,
            0,    // Reserved size
            NULL  // No digest
            );

  KernelFile->Close (KernelFile);
  RootDirectory->Close (RootDirectory);

  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "DirectKernel: Failed to read kernel - %r\n", Status));
    return Status;
  }

  DEBUG ((DEBUG_INFO, "DirectKernel: Loaded kernel %u bytes (%a)\n",
          KernelSize, Is32Bit ? "32-bit" : "64-bit"));

  ZeroMem (&MachoContext, sizeof (MachoContext));
  IsArm64 = IsArm64Kernel (KernelBuffer, KernelSize, FALSE);

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
    // For ARM64 kernels, extract entry point from thread state
    // arm_thread_state64_t: x0-x28 (29) + fp + sp + pc + cpsr = 32 UINT64 values
    // Flavor(4) + Count(4) + 32*8 = PC at offset 0x108 (index 31 in UINT64 array after flavor/count)
    //
    Header64 = (MACH_HEADER_64 *)KernelBuffer;
    EntryPoint = 0;

    for (Index = 0; Index < Header64->NumCommands; ++Index) {
      Cmd = &Header64->Commands[Index];
      if (Cmd->CommandType == MACH_LOAD_COMMAND_UNIX_THREAD) {
        UINT32   Flavor;
        UINT32   Count;
        UINT64   *ThreadState;

        ThreadState = (UINT64 *)((UINTN)Cmd + sizeof (MACH_THREAD_COMMAND));

        // Verify we have flavor and count
        if ((UINTN)&ThreadState[2] > (UINTN)KernelBuffer + KernelSize) {
          break;
        }
        Flavor = *((UINT32 *)ThreadState);
        Count = *((UINT32 *)((UINTN)ThreadState + 4));

        // Skip flavor and count to get to actual thread state values
        ThreadState = (UINT64 *)((UINTN)ThreadState + 8);

        // ARM64_THREAD_STATE: flavor=6, PC at index 31 (after x0-x28, fp, sp)
        if (Flavor == ARM64_THREAD_STATE_FLAVOR && Count >= 32) {
          if ((UINTN)&ThreadState[31] <= (UINTN)KernelBuffer + KernelSize) {
            EntryPoint = ThreadState[31];
          }
        }
        break;
      }
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

  //
  // For ARM64 kernel, use DBT translation
  //
  if (IsArm64 && gDbtContext != NULL) {
    DBT_ARM64_CONTEXT  ArmContext;

    ZeroMem (&ArmContext, sizeof (ArmContext));
    ArmContext.X0 = (UINT64)(UINTN)BootArgs;  // First argument: boot_args
    ArmContext.SP = (UINT64)(UINTN)(StackBuffer + StackSize);  // Stack grows down
    ArmContext.PC = EntryPoint;              // Entry point (already virtual address)

    DEBUG ((DEBUG_INFO, "DirectKernel: Executing ARM64 kernel via DBT\n"));
    DEBUG ((DEBUG_INFO, "DirectKernel: SP=0x%llx, PC=0x%llx\n", ArmContext.SP, ArmContext.PC));

    Status = DbtTranslateBlock (gDbtContext, KernelBuffer, KernelSize, NULL);
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "DirectKernel: DBT translation failed - %r\n", Status));
      FreePool (StackBuffer);
      if (DeviceTreeBuffer != NULL) {
        FreePool (DeviceTreeBuffer);
      }
      FreePool (BootArgs);
      FreePool (KernelBuffer);
      return Status;
    }

    DbtExecute (gDbtContext, &ArmContext);

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
              DbtSetBootInfo (gDbtContext, gInstallerDevice, L"\\SharedSupport\\kernel");
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
    DbtSetBootInfo (gDbtContext, gInstallerDevice != NULL ? gInstallerDevice : Device, L"\\SharedSupport\\kernel");
    NewEntries[0].UnmanagedBootAction             = DbtBootEntryAction;
    NewEntries[0].UnmanagedBootGetFinalDevicePath = NULL;
    //
    // Provide a minimal valid device path (vendor node + end).
    // DuplicateDevicePath requires valid device path with end node.
    //
    {
      UINT8  *Buf;
      Buf = AllocateZeroPool (sizeof (EFI_DEVICE_PATH_PROTOCOL) * 2);
      if (Buf != NULL) {
        EFI_DEVICE_PATH_PROTOCOL  *Node = (EFI_DEVICE_PATH_PROTOCOL *)Buf;
        Node->Type    = HARDWARE_DEVICE_PATH;
        Node->SubType = HW_VENDOR_DP;
        SetDevicePathNodeLength (Node, sizeof (EFI_DEVICE_PATH_PROTOCOL));
        SetDevicePathEndNode ((EFI_DEVICE_PATH_PROTOCOL *)(Buf + sizeof (EFI_DEVICE_PATH_PROTOCOL)));
        NewEntries[0].UnmanagedDevicePath = (EFI_DEVICE_PATH_PROTOCOL *)Buf;
      }
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

  Status = DbtInitContext (&gDbtContext, 0x400000);
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
      DEBUG ((DEBUG_INFO, "DBT: Fallback protocol installed\n"));
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

  return EFI_SUCCESS;
}