#include <Library/OcDbtLib.h>
#include <Library/OcMemoryLib.h>

typedef struct DBT_CONTEXT {
  OC_VMEM_CONTEXT  VmContext;
  EFI_HANDLE       InstallerDevice;
  CHAR16          *KernelPath;
  DBT_ARM64_STATE  ArmState;
  UINT64           SysRegs[256];
  VOID            *TranslatedCode;
  UINTN            TranslatedSize;
  UINTN            CodeCapacity;
  UINT8            CodeBuffer[0];
} DBT_CONTEXT;