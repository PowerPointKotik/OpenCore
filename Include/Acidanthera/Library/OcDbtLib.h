/** @file
   Copyright (C) 2026. All rights reserved.

   Dynamic Binary Translation Library for ARM64 to x86_64
**/

#ifndef OC_DBT_LIB_H
#define OC_DBT_LIB_H

#include <Uefi.h>

/**
  ARM64 CPU state for translation
**/
typedef struct {
  UINT64 X0;
  UINT64 X1;
  UINT64 X2;
  UINT64 X3;
  UINT64 X4;
  UINT64 X5;
  UINT64 X6;
  UINT64 X7;
  UINT64 X8;
  UINT64 X9;
  UINT64 X10;
  UINT64 X11;
  UINT64 X12;
  UINT64 X13;
  UINT64 X14;
  UINT64 X15;
  UINT64 X16;
  UINT64 X17;
  UINT64 X18;
  UINT64 X19;
  UINT64 X20;
  UINT64 X21;
  UINT64 X22;
  UINT64 X23;
  UINT64 X24;
  UINT64 X25;
  UINT64 X26;
  UINT64 X27;
  UINT64 X28;
  UINT64 FP;
  UINT64 SP;
  UINT64 PC;
  UINT64 SP_SR;
} DBT_ARM64_CONTEXT;

/**
  DBT translation context (opaque)
**/
typedef struct DBT_CONTEXT DBT_CONTEXT;

EFI_STATUS
DbtInitContext (
  OUT DBT_CONTEXT  **Context,
  IN  UINTN         CodeSize
  );

EFI_STATUS
DbtSetBootInfo (
  IN DBT_CONTEXT  *Context,
  IN EFI_HANDLE   InstallerDevice,
  IN CONST CHAR16 *KernelPath
  );

EFI_HANDLE
DbtGetInstallerDevice (
  IN DBT_CONTEXT  *Context
  );

CONST CHAR16 *
DbtGetKernelPath (
  IN DBT_CONTEXT  *Context
  );

VOID
DbtExecute (
  IN DBT_CONTEXT       *Context,
  IN DBT_ARM64_CONTEXT *ArmContext
  );

EFI_STATUS
DbtTranslateBlock (
  IN OUT DBT_CONTEXT  *Context,
  IN     VOID         *ArmCode,
  IN     UINTN         CodeSize,
  OUT    VOID         *X86Code  OPTIONAL
  );

VOID
DbtFreeContext (
  IN DBT_CONTEXT  *Context
  );

#endif // OC_DBT_LIB_H