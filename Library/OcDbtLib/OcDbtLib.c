/** @file
   Copyright (C) 2026. All rights reserved.

   Dynamic Binary Translation Library for ARM64 to x86_64
**/

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/OcMemoryLib.h>

#include "OcDbtLib.h"

//
// ARM64 instruction decode helpers
//
STATIC
UINT32
Arm64GetOpcode (
  IN  UINT32  Encoding
  )
{
  return Encoding >> 24;
}

STATIC
UINT8
Arm64GetRd (
  IN  UINT32  Encoding
  )
{
  return (Encoding >> 0) & 0x1F;
}

STATIC
UINT8
Arm64GetRn (
  IN  UINT32  Encoding
  )
{
  return (Encoding >> 5) & 0x1F;
}

STATIC
UINT8
Arm64ToX86Reg (
  IN  UINT8  ArmReg
  )
{
  if (ArmReg <= 15) return ArmReg;
  if (ArmReg == 28) return 6;  // FP -> RBP
  if (ArmReg == 29) return 4;  // SP -> RSP
  if (ArmReg == 30) return 4;  // FP -> RBP alternate
  if (ArmReg == 31) return 0;  // XZR/WZR -> RAX (zero)
  return 0;
}

//
// Emit x86_64 code
//
STATIC
VOID
EmitMovRegToReg (
  IN  UINT8    **Buffer,
  IN  UINT8     DstReg,
  IN  UINT8     SrcReg
  )
{
  *((*Buffer)++) = 0x48;
  *((*Buffer)++) = 0x89;
  *((*Buffer)++) = 0xC0 | (SrcReg << 3) | DstReg;
}

/**
  Translate single ARM64 instruction to x86_64
**/
STATIC
UINTN
DbtDecodeAndTranslateInst (
  IN     UINT32  *ArmInstruction,
  OUT    UINT8   *X86Buffer
  )
{
  UINT32  Inst      = *ArmInstruction;
  UINT8   Buffer[16];
  UINT8   *Ptr      = Buffer;
  UINT32  Opcode    = Arm64GetOpcode (Inst);

  //
  // ARM64 data processing (op0=1xx) - categories 0, 1, 2, 3
  //
  if ((Opcode & 0xE0) == 0x20) {
    //
    // Data processing register (0xx)
    //
    UINT32  Opc    = (Inst >> 21) & 0x7FF;
    UINT8   Rd     = Arm64GetRd (Inst);
    UINT8   Rn     = Arm64GetRn (Inst);

    switch (Opc) {
      case 0x0B:  // ADD (extended register)
        EmitMovRegToReg (&Ptr, Arm64ToX86Reg (Rd), Arm64ToX86Reg (Rn));
        break;

      case 0x0D:  // SUB (extended register)
        EmitMovRegToReg (&Ptr, Arm64ToX86Reg (Rd), Arm64ToX86Reg (Rn));
        break;

      default:
        *Ptr++ = 0x90;
        break;
    }
  } else if ((Opcode & 0xE0) == 0x80) {
    //
    // Branch instructions
    //
    *Ptr++ = 0x90;  // NOP for now
  } else if ((Opcode & 0xC0) == 0x40) {
    //
    // Load/store (0x40-0xBF range)
    //
    UINT32  LsOpc  = (Inst >> 21) & 0x7FF;

    if (LsOpc == 0x0C8) {
      // LDP - load pair
      *Ptr++ = 0x90;  // NOP
    } else if (LsOpc == 0x088) {
      // STP - store pair
      *Ptr++ = 0x90;  // NOP
    } else if (LsOpc == 0x0D8) {
      // LDP (post-index)
      *Ptr++ = 0x90;
    } else {
      *Ptr++ = 0x90;
    }
  } else {
    //
    // Unknown - emit NOP
    //
    *Ptr++ = 0x90;
  }

  CopyMem (X86Buffer, Buffer, Ptr - Buffer);
  return (UINTN)(Ptr - Buffer);
}

EFI_STATUS
DbtInitContext (
  OUT DBT_CONTEXT  **Context,
  IN  UINTN         CodeSize
  )
{
  EFI_STATUS       Status;
  DBT_CONTEXT     *Ctx;
  UINTN            TotalSize;
  EFI_PHYSICAL_ADDRESS  Addr;

  if (Context == NULL || CodeSize == 0) {
    return EFI_INVALID_PARAMETER;
  }

  TotalSize = sizeof (DBT_CONTEXT) + CodeSize;
  Addr      = BASE_4GB;

  Status = gBS->AllocatePages (
                  AllocateMaxAddress,
                  EfiBootServicesData,
                  EFI_SIZE_TO_PAGES (TotalSize),
                  &Addr
                  );

  if (EFI_ERROR (Status)) {
    return Status;
  }

  Ctx = (DBT_CONTEXT *)(UINTN)Addr;
  ZeroMem (Ctx, TotalSize);

  Status = VmAllocateMemoryPool (&Ctx->VmContext, OC_DEFAULT_VMEM_PAGE_COUNT, NULL);
  if (EFI_ERROR (Status)) {
    gBS->FreePages (Addr, EFI_SIZE_TO_PAGES (TotalSize));
    return Status;
  }

  Ctx->CodeCapacity  = CodeSize;
  Ctx->TranslatedCode = (VOID *)((UINTN)Ctx + sizeof (DBT_CONTEXT));
  *Context = Ctx;

  return EFI_SUCCESS;
}

EFI_STATUS
DbtSetBootInfo (
  IN DBT_CONTEXT  *Context,
  IN EFI_HANDLE   InstallerDevice,
  IN CONST CHAR16 *KernelPath
  )
{
  UINTN  Len;

  if (Context == NULL || KernelPath == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (Context->KernelPath != NULL) {
    FreePool (Context->KernelPath);
  }

  Len = StrSize (KernelPath);
  Context->KernelPath = AllocateCopyPool (Len, (VOID *)KernelPath);
  if (Context->KernelPath == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  Context->InstallerDevice = InstallerDevice;
  return EFI_SUCCESS;
}

EFI_HANDLE
DbtGetInstallerDevice (
  IN DBT_CONTEXT  *Context
  )
{
  if (Context == NULL) {
    return NULL;
  }
  return Context->InstallerDevice;
}

CONST CHAR16 *
DbtGetKernelPath (
  IN DBT_CONTEXT  *Context
  )
{
  if (Context == NULL) {
    return NULL;
  }
  return Context->KernelPath;
}

EFI_STATUS
DbtTranslateBlock (
  IN OUT DBT_CONTEXT  *Context,
  IN     VOID         *ArmCode,
  IN     UINTN         CodeSize,
  OUT    VOID         *X86Code  OPTIONAL
  )
{
  UINT32  *ArmInst = (UINT32 *)ArmCode;
  UINT8   *X86Buf;
  UINTN   X86Size;
  UINTN   ArmOffset;
  UINTN   X86Offset;
  UINTN   MaxX86Size;

  if (Context == NULL || ArmCode == NULL || CodeSize == 0) {
    return EFI_INVALID_PARAMETER;
  }

  if (CodeSize % 4 != 0) {
    return EFI_INVALID_PARAMETER;
  }

  if (X86Code != NULL) {
    X86Buf = (UINT8 *)X86Code;
    X86Offset = 0;
  } else {
    X86Buf = (UINT8 *)Context->TranslatedCode + Context->TranslatedSize;
    X86Offset = 0;
  }

  MaxX86Size = Context->CodeCapacity - Context->TranslatedSize;

  //
  // Add prologue on first translation
  //
  if (Context->TranslatedSize == 0 && X86Code == NULL) {
    //
    // push rbp; mov rbp, rsp; sub rsp, 0x1000 (shadow space)
    //
    X86Buf[X86Offset++] = 0x55;        // push rbp
    X86Buf[X86Offset++] = 0x48;        // REX.W
    X86Buf[X86Offset++] = 0x89;        // MOV r/m64, r64
    X86Buf[X86Offset++] = 0xE5;        // MOV RBP, RSP
    X86Buf[X86Offset++] = 0x48;        // REX.W
    X86Buf[X86Offset++] = 0x81;        // SUB r/m64, imm32
    X86Buf[X86Offset++] = 0xEC;        // SUB RSP, ...
    X86Buf[X86Offset++] = 0x00;        // imm32[0]
    X86Buf[X86Offset++] = 0x10;        // imm32[1]
    X86Buf[X86Offset++] = 0x00;        // imm32[2]
    X86Buf[X86Offset++] = 0x00;        // imm32[3]

    //
    // Save ARM64 context pointer (in RDI) -> [RBP-8]
    //
    X86Buf[X86Offset++] = 0x48;        // REX.W
    X86Buf[X86Offset++] = 0x89;        // MOV r/m64, r64
    X86Buf[X86Offset++] = 0x7D;        // MOV [RBP-8], RDI
    X86Buf[X86Offset++] = 0xF8;        // offset = -8
  }

  ArmOffset = 0;
  while (ArmOffset < CodeSize) {
    if (X86Offset >= MaxX86Size) {
      return EFI_OUT_OF_RESOURCES;
    }
    X86Size = DbtDecodeAndTranslateInst (&ArmInst[ArmOffset / 4], &X86Buf[X86Offset]);
    ArmOffset += 4;
    X86Offset += X86Size;
  }

  //
  // Add epilogue: leave; ret
  //
  if (X86Code == NULL) {
    X86Buf[X86Offset++] = 0xC9;        // LEAVE
    X86Buf[X86Offset++] = 0xC3;        // RET
  }

  if (X86Code == NULL) {
    Context->TranslatedSize += X86Offset;
  }

  return EFI_SUCCESS;
}

VOID
DbtExecute (
  IN DBT_CONTEXT      *Context,
  IN DBT_ARM64_CONTEXT *ArmContext
  )
{
  VOID  (*TranslatedEntry)(DBT_ARM64_CONTEXT *);

  if (Context == NULL || ArmContext == NULL || Context->TranslatedCode == NULL) {
    return;
  }

  DEBUG ((
    DEBUG_INFO,
    "DBT: Jumping to translated code at %p SP=0x%llx PC=0x%llx\n",
    Context->TranslatedCode,
    ArmContext->SP,
    ArmContext->PC
    ));

  //
  // Jump to translated code
  //
  TranslatedEntry = (VOID (*)(DBT_ARM64_CONTEXT *))Context->TranslatedCode;

  TranslatedEntry (ArmContext);
}

VOID
DbtFreeContext (
  IN DBT_CONTEXT  *Context
  )
{
  if (Context != NULL) {
    if (Context->VmContext.MemoryPool != NULL) {
      gBS->FreePages ((UINTN)Context->VmContext.MemoryPool, Context->VmContext.FreePages);
    }
    if (Context->KernelPath != NULL) {
      FreePool (Context->KernelPath);
    }
    gBS->FreePages ((UINTN)Context, EFI_SIZE_TO_PAGES (sizeof (DBT_CONTEXT) + Context->CodeCapacity));
  }
}
