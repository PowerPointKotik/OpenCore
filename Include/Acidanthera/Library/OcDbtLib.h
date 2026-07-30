/** @file
   Copyright (C) 2026. All rights reserved.

   Dynamic Binary Translation Library for ARM64 to x86_64
**/

#ifndef OC_DBT_LIB_H
#define OC_DBT_LIB_H

#include <Uefi.h>

/**
  ARM64 CPU state for translation. Registers stored in memory for save/restore.
  XZR (register 31) always reads as 0 and ignores writes.
**/
typedef struct {
  UINT64 X[31];     // X0-X30
  UINT64 SP;        // Stack pointer
  UINT64 PC;        // Program counter
  UINT64 PSTATE;    // NZCV flags at bits 31-28, mode/DAIF at lower bits
  UINT64 SP_EL0;    // EL0 stack pointer
  UINT64 SP_EL1;    // EL1 stack pointer
  UINT64 ELR_EL1;   // Exception link register
  UINT64 SPSR_EL1;  // Saved PSTATE
  //
  // System register stubs
  //
  UINT64 SCTLR_EL1;
  UINT64 TTBR0_EL1;
  UINT64 TTBR1_EL1;
  UINT64 TCR_EL1;
  UINT64 MAIR_EL1;
  UINT64 VBAR_EL1;
  UINT64 ESR_EL1;
  UINT64 FAR_EL1;
  UINT64 MIDR_EL1;
  UINT64 MPIDR_EL1;
  UINT64 CNTFRQ_EL0;
  UINT64 CNTVCT_EL0;
  UINT64 CNTV_CTL_EL0;
  UINT64 CNTV_CVAL_EL0;
  UINT64 ACTLR_EL1;
  UINT64 CPACR_EL1;
  //
  // NEON/SIMD register file (Q0-Q31, 128 bits each)
  //
  UINT64 Qlo[32];   // Vn.2D[0]
  UINT64 Qhi[32];   // Vn.2D[1]
} DBT_ARM64_STATE;

/**
  Compatibility alias
**/
typedef DBT_ARM64_STATE DBT_ARM64_CONTEXT;

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

UINT64
DbtTranslateVaToPa (
  IN DBT_CONTEXT  *Context,
  IN UINT64       Va
  );

UINT64
DbtHandleException (
  IN DBT_CONTEXT  *Context,
  IN UINT64       ExceptionType,
  IN UINT64       FaultAddr,
  IN UINT64       CurrentPc
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