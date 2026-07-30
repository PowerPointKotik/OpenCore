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
// x86_64 instruction emitters
//
STATIC
VOID
EmitNop (
  OUT UINT8  **Buf
  )
{
  *((*Buf)++) = 0x90;
}

STATIC
VOID
EmitMovRegReg (
  OUT UINT8  **Buf,
  IN  UINT8   Dst,
  IN  UINT8   Src
  )
{
  // REX.W + MOV r64, r/m64
  *((*Buf)++) = 0x48;
  *((*Buf)++) = 0x89;
  *((*Buf)++) = 0xC0 | (Src << 3) | Dst;
}

STATIC
VOID
EmitAddRegReg (
  OUT UINT8  **Buf,
  IN  UINT8   Dst,
  IN  UINT8   Src
  )
{
  // REX.W + ADD r/m64, r64
  *((*Buf)++) = 0x48;
  *((*Buf)++) = 0x01;
  *((*Buf)++) = 0xC0 | (Src << 3) | Dst;
}

STATIC
VOID
EmitSubRegReg (
  OUT UINT8  **Buf,
  IN  UINT8   Dst,
  IN  UINT8   Src
  )
{
  // REX.W + SUB r/m64, r64
  *((*Buf)++) = 0x48;
  *((*Buf)++) = 0x29;
  *((*Buf)++) = 0xC0 | (Src << 3) | Dst;
}

STATIC
VOID
EmitAndRegReg (
  OUT UINT8  **Buf,
  IN  UINT8   Dst,
  IN  UINT8   Src
  )
{
  // REX.W + AND r/m64, r64
  *((*Buf)++) = 0x48;
  *((*Buf)++) = 0x21;
  *((*Buf)++) = 0xC0 | (Src << 3) | Dst;
}

STATIC
VOID
EmitOrRegReg (
  OUT UINT8  **Buf,
  IN  UINT8   Dst,
  IN  UINT8   Src
  )
{
  // REX.W + OR r/m64, r64
  *((*Buf)++) = 0x48;
  *((*Buf)++) = 0x09;
  *((*Buf)++) = 0xC0 | (Src << 3) | Dst;
}

STATIC
VOID
EmitXorRegReg (
  OUT UINT8  **Buf,
  IN  UINT8   Dst,
  IN  UINT8   Src
  )
{
  // REX.W + XOR r/m64, r64
  *((*Buf)++) = 0x48;
  *((*Buf)++) = 0x31;
  *((*Buf)++) = 0xC0 | (Src << 3) | Dst;
}

STATIC
VOID
EmitCmpRegReg (
  OUT UINT8  **Buf,
  IN  UINT8   R1,
  IN  UINT8   R2
  )
{
  // REX.W + CMP r/m64, r64
  *((*Buf)++) = 0x48;
  *((*Buf)++) = 0x39;
  *((*Buf)++) = 0xC0 | (R2 << 3) | R1;
}

STATIC
VOID
EmitMovImm64 (
  OUT UINT8  **Buf,
  IN  UINT8   Reg,
  IN  UINT64  Imm
  )
{
  // REX.W + B8+reg, 8-byte immediate (MOV reg, imm64)
  *((*Buf)++) = 0x48;
  *((*Buf)++) = 0xB8 | Reg;
  *(UINT64 *)(*Buf) = Imm;
  *Buf += 8;
}

STATIC
VOID
EmitMovImm32 (
  OUT UINT8  **Buf,
  IN  UINT8   Reg,
  IN  UINT32  Imm
  )
{
  // MOV r32, imm32
  *((*Buf)++) = 0xB8 | Reg;
  *(UINT32 *)(*Buf) = Imm;
  *Buf += 4;
}

STATIC
VOID
EmitAddImm32 (
  OUT UINT8  **Buf,
  IN  UINT8   Reg,
  IN  UINT32  Imm
  )
{
  // REX.W + 81 /0 + imm32 (ADD r/m64, imm32)
  *((*Buf)++) = 0x48;
  *((*Buf)++) = 0x81;
  *((*Buf)++) = 0xC0 | Reg;
  *(UINT32 *)(*Buf) = Imm;
  *Buf += 4;
}

STATIC
VOID
EmitSubImm32 (
  OUT UINT8  **Buf,
  IN  UINT8   Reg,
  IN  UINT32  Imm
  )
{
  // REX.W + 81 /5 + imm32 (SUB r/m64, imm32)
  *((*Buf)++) = 0x48;
  *((*Buf)++) = 0x81;
  *((*Buf)++) = 0xE8 | Reg;
  *(UINT32 *)(*Buf) = Imm;
  *Buf += 4;
}

STATIC
VOID
EmitMovRegMem (
  OUT UINT8  **Buf,
  IN  UINT8   Reg,
  IN  UINT8   Base,
  IN  INT32   Disp
  )
{
  // MOV r64, [base + disp]
  if (Disp == 0 && Base != 5) {
    *((*Buf)++) = 0x48;
    *((*Buf)++) = 0x8B;
    if (Base == 4) {
      *((*Buf)++) = 0x04 | (Reg << 3);
      *((*Buf)++) = 0x24;  // SIB: [RSP]
    } else {
      *((*Buf)++) = (Reg << 3) | Base;
    }
  } else if (Disp >= -128 && Disp <= 127) {
    *((*Buf)++) = 0x48;
    *((*Buf)++) = 0x8B;
    if (Base == 4) {
      *((*Buf)++) = 0x44 | (Reg << 3);
      *((*Buf)++) = 0x24;
    } else {
      *((*Buf)++) = 0x40 | (Reg << 3) | Base;
    }
    *((*Buf)++) = (UINT8)Disp;
  } else {
    *((*Buf)++) = 0x48;
    *((*Buf)++) = 0x8B;
    if (Base == 4) {
      *((*Buf)++) = 0x84 | (Reg << 3);
      *((*Buf)++) = 0x24;
    } else {
      *((*Buf)++) = 0x80 | (Reg << 3) | Base;
    }
    *(INT32 *)(*Buf) = Disp;
    *Buf += 4;
  }
}

STATIC
VOID
EmitMovMemReg (
  OUT UINT8  **Buf,
  IN  UINT8   Base,
  IN  INT32   Disp,
  IN  UINT8   Reg
  )
{
  // MOV [base + disp], r64
  if (Disp == 0 && Base != 5) {
    *((*Buf)++) = 0x48;
    *((*Buf)++) = 0x89;
    if (Base == 4) {
      *((*Buf)++) = 0x04 | (Reg << 3);
      *((*Buf)++) = 0x24;
    } else {
      *((*Buf)++) = (Reg << 3) | Base;
    }
  } else if (Disp >= -128 && Disp <= 127) {
    *((*Buf)++) = 0x48;
    *((*Buf)++) = 0x89;
    if (Base == 4) {
      *((*Buf)++) = 0x44 | (Reg << 3);
      *((*Buf)++) = 0x24;
    } else {
      *((*Buf)++) = 0x40 | (Reg << 3) | Base;
    }
    *((*Buf)++) = (UINT8)Disp;
  } else {
    *((*Buf)++) = 0x48;
    *((*Buf)++) = 0x89;
    if (Base == 4) {
      *((*Buf)++) = 0x84 | (Reg << 3);
      *((*Buf)++) = 0x24;
    } else {
      *((*Buf)++) = 0x80 | (Reg << 3) | Base;
    }
    *(INT32 *)(*Buf) = Disp;
    *Buf += 4;
  }
}

STATIC
VOID
EmitRet (
  OUT UINT8  **Buf
  )
{
  *((*Buf)++) = 0xC3;
}

STATIC
VOID
EmitCall (
  OUT UINT8  **Buf
  )
{
  *((*Buf)++) = 0xE8;
  *(UINT32 *)(*Buf) = 0;  // relative offset = 0 (self-call, will be patched)
  *Buf += 4;
}

STATIC
VOID
EmitJmpRel32 (
  OUT UINT8  **Buf,
  IN  INT32   Rel
  )
{
  *((*Buf)++) = 0xE9;
  *(INT32 *)(*Buf) = Rel - 5;  // 5 bytes for JMP rel32 instruction
  *Buf += 4;
}

STATIC
VOID
EmitTestRegReg (
  OUT UINT8  **Buf,
  IN  UINT8   R1,
  IN  UINT8   R2
  )
{
  // REX.W + TEST r/m64, r64
  *((*Buf)++) = 0x48;
  *((*Buf)++) = 0x85;
  *((*Buf)++) = 0xC0 | (R2 << 3) | R1;
}

STATIC
VOID
EmitJccRel8 (
  OUT UINT8  **Buf,
  IN  UINT8   Cc,
  IN  INT8    Rel
  )
{
  *((*Buf)++) = 0x70 | Cc;
  *((*Buf)++) = Rel;
}

STATIC
VOID
EmitShlImm8 (
  OUT UINT8  **Buf,
  IN  UINT8   Reg,
  IN  UINT8   Imm
  )
{
  // REX.W + C1 /4 + imm8 (SHL r/m64, imm8)
  *((*Buf)++) = 0x48;
  *((*Buf)++) = 0xC1;
  *((*Buf)++) = 0xE0 | Reg;
  *((*Buf)++) = Imm;
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
  UINT32  Inst = *ArmInstruction;
  UINT8   Buf[32];
  UINT8   *P  = Buf;
  UINT8   Op0 = (Inst >> 25) & 0xF;  // bits 28-25

  UINT8   Rd  = (Inst >> 0)  & 0x1F;
  UINT8   Rn  = (Inst >> 5)  & 0x1F;
  UINT8   Rm  = (Inst >> 16) & 0x1F;
  UINT8   Rt  = (Inst >> 0)  & 0x1F;
  // Rt2 for load/store pair
  UINT8   Rt2 = (Inst >> 10) & 0x1F;

  UINT8   Xd  = Arm64ToX86Reg (Rd);
  UINT8   Xn  = Arm64ToX86Reg (Rn);
  UINT8   Xm  = Arm64ToX86Reg (Rm);
  UINT8   Xt  = Arm64ToX86Reg (Rt);
  UINT8   Xt2 = Arm64ToX86Reg (Rt2);

  if (Op0 < 8) {
    //
    // 0xxx: Data processing - register, or data processing - immediate
    //
    UINT32  Op1 = (Inst >> 23) & 0x3;  // bits 24-23

    if ((Op1 & 2) == 0) {
      //
      // 00xx: Data processing - immediate
      //
      UINT32  Opi = (Inst >> 23) & 0x7;  // bits 25-23

      if (Opi == 0 || Opi == 1) {
        //
        // PC-relative addressing: ADR, ADRP
        //
        // Simplified: emit ADD reg, PC  (we handle PC value via DBT_ARM64_CONTEXT)
        INT64  PcOffset = (INT64)((Inst >> 5) & 0x7FFFF) << 2;
        PcOffset = (PcOffset << 43) >> 43;  // sign-extend 21-bit
        if (Opi == 1) {
          PcOffset <<= 12;  // ADRP: page offset
        }
        EmitMovImm64 (&P, Xd, PcOffset);
      } else if (Opi == 2 || Opi == 3) {
        //
        // ADD/SUB immediate
        //
        UINT32  Sh  = (Inst >> 22) & 1;
        UINT32  Imm = (Inst >> 10) & 0xFFF;
        if (Sh) {
          Imm <<= 12;
        }

        if (Opi == 2) {
          // ADD
          if (Imm == 0) {
            EmitMovRegReg (&P, Xd, Xn);
          } else {
            EmitAddImm32 (&P, Xn, Imm);
            if (Xd != Xn) {
              EmitMovRegReg (&P, Xd, Xn);
            }
          }
        } else {
          // SUB
          if (Imm == 0) {
            EmitMovRegReg (&P, Xd, Xn);
          } else {
            EmitSubImm32 (&P, Xn, Imm);
            if (Xd != Xn) {
              EmitMovRegReg (&P, Xd, Xn);
            }
          }
        }
      } else {
        EmitNop (&P);
      }
    } else {
      //
      // 01xx: Data processing - register
      //
      UINT32  Opc = (Inst >> 29) & 0x3;

      if (Opc == 0) {
        //
        // Logical (AND, BIC, ORR, ORN, EOR, EON, ANDS, BICS)
        //
        UINT32  Opc2 = (Inst >> 29) & 0x3;
        UINT32  N    = (Inst >> 21) & 1;

        if (N == 0) {
          switch (Opc2) {
            case 0: EmitAndRegReg (&P, Xd, Xn); break;  // AND
            case 1: EmitOrRegReg  (&P, Xd, Xn); break;  // ORR
            case 2: EmitXorRegReg (&P, Xd, Xn); break;  // EOR
            default: EmitNop (&P); break;
          }
        } else {
          switch (Opc2) {
            case 0: EmitAndRegReg (&P, Xd, Xn); break;  // ANDS -> same as AND (flags ignored)
            case 1: EmitOrRegReg  (&P, Xd, Xn); break;  // ORN not implemented
            default: EmitNop (&P); break;
          }
        }
      } else if (Opc == 1 || Opc == 3) {
        //
        // ADD/SUB (register)
        //
        UINT32  S = (Inst >> 29) & 1;

        if (Opc == 1) {
          EmitAddRegReg (&P, Xn, Xm);
          if (Xd != Xn) {
            EmitMovRegReg (&P, Xd, Xn);
          }
        } else {
          EmitSubRegReg (&P, Xn, Xm);
          if (Xd != Xn) {
            EmitMovRegReg (&P, Xd, Xn);
          }
        }

        if (S) {
          // Flags update (ADDS/SUBS) — we ignore flags but emit the result
        }
      } else if (Opc == 2) {
        //
        // CMP/CMN (SUBS/ADDS with XZR)
        //
        if (Rd == 31) {
          // SUBS XZR, Rn, ... -> CMP
          EmitCmpRegReg (&P, Xn, Xm);
        } else {
          EmitNop (&P);
        }
      } else {
        EmitNop (&P);
      }
    }
  } else if (Op0 >= 8 && Op0 <= 9) {
    //
    // 100x: Data processing - immediate (move wide, bitfield)
    //
    UINT32 Sub = (Inst >> 23) & 0x7;

    if (Sub == 5) {
      //
      // MOVN/MOVZ/MOVK
      //
      UINT32  Hw  = (Inst >> 21) & 3;
      UINT32  Imm = (Inst >> 5) & 0xFFFF;
      BOOLEAN Is64 = (Inst >> 31) & 1;
      UINT32  Opc = (Inst >> 29) & 3;

      if (Opc == 2) {
        // MOVZ
        UINT64  Val = (UINT64)Imm << (16 * Hw);
        EmitMovImm64 (&P, Xd, Val);
      } else {
        EmitNop (&P);
      }
    } else {
      EmitNop (&P);
    }
  } else if (Op0 >= 0xA && Op0 <= 0xB) {
    //
    // 101x: Branches and system instructions
    //
    UINT32  High3 = (Inst >> 25) & 0x7;

    if (High3 == 2 || High3 == 3) {
      //
      // Unconditional branch (B, BL) or conditional branch (B.cond)
      //
      UINT32  Op = (Inst >> 31) & 1;

      if (Op == 0) {
        // B.cond — skip for now, emit NOP
        EmitNop (&P);
      } else {
        // B or BL
        UINT32  Link = (Inst >> 31) & 1;
        // B: just emit JMP (address unknown at translation time)
        // For now emit NOP
        EmitNop (&P);
      }
    } else if (High3 == 6 || High3 == 7) {
      //
      // Unconditional branch register (BR, BLR, RET)
      //
      UINT32  Opc2 = (Inst >> 21) & 0x7;

      if (Opc2 == 0) {
        // BR
        EmitNop (&P);
      } else if (Opc2 == 1) {
        // BLR
        EmitCall (&P);
      } else if (Opc2 == 2) {
        // RET
        EmitRet (&P);
      } else {
        EmitNop (&P);
      }
    } else if (High3 == 0 || High3 == 1) {
      //
      // Compare and branch (CBZ, CBNZ) or test and branch (TBZ, TBNZ)
      //
      UINT32  Sub2 = (Inst >> 24) & 1;

      if (Sub2 == 0) {
        // CBZ/CBNZ
        UINT32  NonZero = (Inst >> 24) & 1;
        EmitTestRegReg (&P, Xt, Xt);

        if (Xt == 0 && NonZero == 0) {
          // CBZ XZR — always taken
          EmitJmpRel32 (&P, 0);
        }
        EmitNop (&P);
      } else {
        EmitNop (&P);
      }
    } else {
      EmitNop (&P);
    }
  } else if (Op0 >= 0xC && Op0 <= 0xF) {
    //
    // 11xx: Loads and stores
    //
    UINT32  Size = (Inst >> 30) & 0x3;
    UINT32  V   = (Inst >> 26) & 1;

    if (V == 0) {
      //
      // GPR loads/stores
      //
      UINT32  Opc2 = (Inst >> 22) & 0x7;

      if (Opc2 == 1 || Opc2 == 3) {
        //
        // LDR/STR immediate unsigned offset
        //
        UINT32  Imm12 = (Inst >> 10) & 0xFFF;
        INT32   Offset = (INT32)(Imm12 << Size);

        if (Opc2 == 1) {
          // STR
          EmitMovMemReg (&P, Xn, Offset, Xt);
        } else {
          // LDR
          EmitMovRegMem (&P, Xt, Xn, Offset);
        }
      } else if (Opc2 == 5) {
        //
        // LDNP/STNP (non-temporal pair) — emit as two LDR/STR
        //
        UINT32  Imm7 = (Inst >> 15) & 0x7F;
        INT32   Off  = (INT32)(Imm7 << 3);  // scale by 8 for 64-bit

        if (Opc2 == 5) {
          // Emit two loads
          EmitMovRegMem (&P, Xt, Xn, Off);
          EmitMovRegMem (&P, Xt2, Xn, Off + 8);
        }
      } else if (Opc2 == 2 || Opc2 == 4) {
        //
        // LDP/STP (load/store pair)
        //
        UINT32  Imm7 = (Inst >> 15) & 0x7F;
        INT32   Off  = (INT32)(Imm7 << 3);  // scale by 8 for 64-bit

        if (Opc2 == 2) {
          // STP
          EmitMovMemReg (&P, Xn, Off, Xt);
          EmitMovMemReg (&P, Xn, Off + 8, Xt2);
        } else {
          // LDP
          EmitMovRegMem (&P, Xt, Xn, Off);
          EmitMovRegMem (&P, Xt2, Xn, Off + 8);
        }
      } else {
        EmitNop (&P);
      }
    } else {
      // SIMD/FP — skip for now
      EmitNop (&P);
    }
  } else {
    EmitNop (&P);
  }

  CopyMem (X86Buffer, Buf, P - Buf);
  return (UINTN)(P - Buf);
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
