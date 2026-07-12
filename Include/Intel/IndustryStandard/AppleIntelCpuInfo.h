/** @file
  Include compatibility wrapper for AppleIntelCpuInfo.h.

  This header provides a compatibility alias for standalone builds.
  Redirect from Intel/IndustryStandard to Apple/IndustryStandard path.
**/

#ifndef EFI_AP_PROCEDURE
typedef VOID (EFIAPI *EFI_AP_PROCEDURE)(IN OUT VOID *Buffer);
#endif
typedef EFI_AP_PROCEDURE EFI_MP_SERVICES_STARTUP_ALL_APS;
typedef EFI_AP_PROCEDURE EFI_MP_SERVICES_STARTUP_THIS_AP;

#include <Apple/IndustryStandard/AppleIntelCpuInfo.h>