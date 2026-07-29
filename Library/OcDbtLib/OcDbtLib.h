#include <Library/OcDbtLib.h>
#include <Library/OcMemoryLib.h>

typedef struct DBT_CONTEXT {
  OC_VMEM_CONTEXT  VmContext;
  EFI_HANDLE       InstallerDevice;
  CHAR16          *KernelPath;
  VOID            *TranslatedCode;
  UINTN            TranslatedSize;
  UINTN            CodeCapacity;
  UINT8            CodeBuffer[0];
} DBT_CONTEXT;