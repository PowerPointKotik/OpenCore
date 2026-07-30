/** @file
   Copyright (C) 2026. All rights reserved.
   Dynamic Binary Translation Library — ARM64 to x86_64 with memory regs, NZCV, sysregs
**/

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/OcMemoryLib.h>
#include "OcDbtLib.h"

#ifndef OFFSET_OF
#define OFFSET_OF(TYPE, Field)  ((UINTN)(&((TYPE *)0)->Field))
#endif

#define DBT_VERBOSE  1

#if DBT_VERBOSE
  #define DBG(...)  DEBUG (__VA_ARGS__)
#else
  #define DBG(...)
#endif

//
// =========== ARM64 instruction decode helpers ===========
//
STATIC UINT32 Arm64Op0 (UINT32 Inst) { return (Inst >> 25) & 0xF; }
STATIC UINT8  Arm64Rd  (UINT32 Inst) { return Inst & 0x1F; }
STATIC UINT8  Arm64Rn  (UINT32 Inst) { return (Inst >> 5) & 0x1F; }
STATIC UINT8  Arm64Rm  (UINT32 Inst) { return (Inst >> 16) & 0x1F; }
STATIC UINT8  Arm64Rt  (UINT32 Inst) { return Inst & 0x1F; }
STATIC UINT8  Arm64Rt2 (UINT32 Inst) { return (Inst >> 10) & 0x1F; }

//
// ARM64 register offset in DBT_ARM64_STATE
//
STATIC UINTN ArmRegXOff  (UINT8 R) { return (R < 31) ? OFFSET_OF(DBT_ARM64_STATE, X) + R*8 : 0; }
STATIC UINTN ArmRegSpOff (VOID)    { return OFFSET_OF(DBT_ARM64_STATE, SP); }
STATIC UINTN ArmRegPcOff (VOID)    { return OFFSET_OF(DBT_ARM64_STATE, PC); }
STATIC UINTN PstateOff   (VOID)    { return OFFSET_OF(DBT_ARM64_STATE, PSTATE); }

//
// =========== x86 code emitter helpers ===========
// RBX is permanently bound to &DBT_ARM64_STATE
//
STATIC VOID EmitByte  (UINT8 **P, UINT8 B)   { *((*P)++) = B; }
STATIC VOID EmitDword (UINT8 **P, UINT32 V)  { *(UINT32 *)(*P) = V; *P += 4; }
STATIC VOID EmitQword (UINT8 **P, UINT64 V)  { *(UINT64 *)(*P) = V; *P += 8; }

// REX.W prefix
STATIC VOID EmitRexW   (UINT8 **P) { EmitByte(P, 0x48); }

// MOV [RBX+off], RAX  — store scratch reg to memory
STATIC VOID EmitStoreRax  (UINT8 **P, UINT32 Off) {
  EmitRexW(P); EmitByte(P, 0x89);  // MOV r/m64, r64
  if (Off < 128) { EmitByte(P, 0x43); EmitByte(P, (UINT8)Off); }  // [RBX+disp8]
  else { EmitByte(P, 0x83); EmitDword(P, Off); }                  // [RBX+disp32]
}

// MOV RAX, [RBX+off]  — load from memory to scratch reg
STATIC VOID EmitLoadRax   (UINT8 **P, UINT32 Off) {
  EmitRexW(P); EmitByte(P, 0x8B);  // MOV r64, r/m64
  if (Off < 128) { EmitByte(P, 0x43); EmitByte(P, (UINT8)Off); }
  else { EmitByte(P, 0x83); EmitDword(P, Off); }
}

// ADD RAX, [RBX+off]
STATIC VOID EmitAddRaxMem (UINT8 **P, UINT32 Off) {
  EmitRexW(P); EmitByte(P, 0x03);  // ADD r64, r/m64
  if (Off < 128) { EmitByte(P, 0x43); EmitByte(P, (UINT8)Off); }
  else { EmitByte(P, 0x83); EmitDword(P, Off); }
}

// SUB RAX, [RBX+off]
STATIC VOID EmitSubRaxMem (UINT8 **P, UINT32 Off) {
  EmitRexW(P); EmitByte(P, 0x2B);  // SUB r64, r/m64
  if (Off < 128) { EmitByte(P, 0x43); EmitByte(P, (UINT8)Off); }
  else { EmitByte(P, 0x83); EmitDword(P, Off); }
}

// AND RAX, [RBX+off]
STATIC VOID EmitAndRaxMem (UINT8 **P, UINT32 Off) {
  EmitRexW(P); EmitByte(P, 0x23);
  if (Off < 128) { EmitByte(P, 0x43); EmitByte(P, (UINT8)Off); }
  else { EmitByte(P, 0x83); EmitDword(P, Off); }
}

// OR  RAX, [RBX+off]
STATIC VOID EmitOrRaxMem  (UINT8 **P, UINT32 Off) {
  EmitRexW(P); EmitByte(P, 0x0B);
  if (Off < 128) { EmitByte(P, 0x43); EmitByte(P, (UINT8)Off); }
  else { EmitByte(P, 0x83); EmitDword(P, Off); }
}

// XOR RAX, [RBX+off]
STATIC VOID EmitXorRaxMem (UINT8 **P, UINT32 Off) {
  EmitRexW(P); EmitByte(P, 0x33);
  if (Off < 128) { EmitByte(P, 0x43); EmitByte(P, (UINT8)Off); }
  else { EmitByte(P, 0x83); EmitDword(P, Off); }
}

#if 0  // reserved for future use
// CMP RAX, [RBX+off] — sets x86 flags
STATIC VOID EmitCmpRaxMem (UINT8 **P, UINT32 Off) {
  EmitRexW(P); EmitByte(P, 0x3B);
  if (Off < 128) { EmitByte(P, 0x43); EmitByte(P, (UINT8)Off); }
  else { EmitByte(P, 0x83); EmitDword(P, Off); }
}

STATIC VOID EmitStoreImm (UINT8 **P, UINT32 Off, UINT32 Val) {
  EmitByte(P, 0xC7);
  if (Off < 128) { EmitByte(P, 0x43); EmitByte(P, (UINT8)Off); }
  else { EmitByte(P, 0x83); EmitDword(P, Off); }
  EmitDword(P, Val);
}

STATIC VOID EmitSaveNzcv (UINT8 **P) {
  EmitByte(P, 0x9F);
}

STATIC VOID EmitRet (UINT8 **P) { EmitByte(P, 0xC3); }
#endif

// MOV RAX, imm64
STATIC VOID EmitMovImm   (UINT8 **P, UINT64 Val) {
  EmitRexW(P); EmitByte(P, 0xB8); EmitQword(P, Val);
}

// NOP
STATIC VOID EmitNop (UINT8 **P) { EmitByte(P, 0x90); }

// ADD RAX, imm32
STATIC VOID EmitAddImm (UINT8 **P, UINT32 Imm) {
  EmitRexW(P); EmitByte(P, 0x81); EmitByte(P, 0xC0); EmitDword(P, Imm);
}

// ADD RCX, imm32
STATIC VOID EmitAddRcxImm (UINT8 **P, UINT32 Imm) {
  EmitRexW(P); EmitByte(P, 0x81); EmitByte(P, 0xC1); EmitDword(P, Imm);
}

// SUB RAX, imm32
STATIC VOID EmitSubImm (UINT8 **P, UINT32 Imm) {
  EmitRexW(P); EmitByte(P, 0x81); EmitByte(P, 0xE8); EmitDword(P, Imm);
}

// MOV RCX, [RBX+off] — load RCX from context
STATIC VOID EmitLoadRcx (UINT8 **P, UINT32 Off) {
  EmitRexW(P); EmitByte(P, 0x8B);  // MOV r64, r/m64 (RCX has opcode extension 1)
  if (Off < 128) { EmitByte(P, 0x4B); EmitByte(P, (UINT8)Off); }  // [RBX+disp8], RCX
  else { EmitByte(P, 0x8B); EmitDword(P, Off); }
}

// MOV [RBX+off], RCX — store RCX to context
#if 0
STATIC VOID EmitStoreRcx (UINT8 **P, UINT32 Off) {
  EmitRexW(P); EmitByte(P, 0x89);  // MOV r/m64, r64
  if (Off < 128) { EmitByte(P, 0x4B); EmitByte(P, (UINT8)Off); }
  else { EmitByte(P, 0x8B); EmitDword(P, Off); }
}
#endif

// =========== Prologue / Epilogue ===========
STATIC UINTN EmitPrologue (UINT8 **P) {
  UINT8 *Start = *P;
  // push rbp
  EmitByte(P, 0x55);
  // mov rbp, rsp
  EmitRexW(P); EmitByte(P, 0x89); EmitByte(P, 0xE5);
  // push rbx (callee-saved, will hold &ArmState)
  EmitByte(P, 0x53);
  // push r12-r15 (callee-saved)
  EmitByte(P, 0x41); EmitByte(P, 0x54);  // push r12
  EmitByte(P, 0x41); EmitByte(P, 0x55);  // push r13
  EmitByte(P, 0x41); EmitByte(P, 0x56);  // push r14
  EmitByte(P, 0x41); EmitByte(P, 0x57);  // push r15
  // sub rsp, 0x100 (shadow space + alignment)
  EmitRexW(P); EmitByte(P, 0x81); EmitByte(P, 0xEC);
  EmitDword(P, 0x100);
  // RBX = RDI (first arg = DBT_ARM64_STATE*)
  EmitRexW(P); EmitByte(P, 0x89); EmitByte(P, 0xFB);  // mov rbx, rdi
  return (UINTN)(*P - Start);
}

STATIC UINTN EmitEpilogue (UINT8 **P) {
  UINT8 *Start = *P;
  // add rsp, 0x100
  EmitRexW(P); EmitByte(P, 0x81); EmitByte(P, 0xC4);
  EmitDword(P, 0x100);
  // pop r15, r14, r13, r12
  EmitByte(P, 0x41); EmitByte(P, 0x5F);
  EmitByte(P, 0x41); EmitByte(P, 0x5E);
  EmitByte(P, 0x41); EmitByte(P, 0x5D);
  EmitByte(P, 0x41); EmitByte(P, 0x5C);
  // pop rbx
  EmitByte(P, 0x5B);
  // leave (mov rsp, rbp; pop rbp)
  EmitByte(P, 0xC9);
  // ret
  EmitByte(P, 0xC3);
  return (UINTN)(*P - Start);
}

// =========== NZCV flag helper ===========
STATIC VOID EmitUpdateNzcv (UINT8 **P, UINT32 PstateOff) {
  // After arithmetic in RAX: compute N, Z, C, V and store to PSTATE[31:28]
  // TEST RAX, RAX → sets SF, ZF
  EmitRexW(P); EmitByte(P, 0x85); EmitByte(P, 0xC0);  // TEST RAX, RAX
  // LAHF → AH
  EmitByte(P, 0x9F);
  // ROL EAX, 8 → AH moves to AL
  EmitByte(P, 0xC1); EmitByte(P, 0xC0); EmitByte(P, 0x08);
  // Now AL = SF:ZF:0:AF:0:PF:1:CF
  // We want: N=SF(bit7), Z=ZF(bit6), C=CF(bit0), V=0
  // Store AL to [RBX+PSTATE+3] (top byte of PSTATE holds N,Z,C,V)
  EmitByte(P, 0x88);  // MOV r/m8, r8
  if (PstateOff + 3 < 128) { EmitByte(P, 0x43); EmitByte(P, (UINT8)(PstateOff + 3)); }
  else { EmitByte(P, 0x83); EmitDword(P, PstateOff + 3); }
}

// =========== Single instruction translator ===========
STATIC UINTN DbtTranslateOne (
  IN  UINT32  Inst,
  IN  UINT64  InstAddr,
  OUT UINT8  *X86Buf,
  IN  UINTN   BufSize
  )
{
  UINT8  *P   = X86Buf;
  UINT8   Op0 = Arm64Op0(Inst);
  UINT8   Rd  = Arm64Rd(Inst);
  UINT8   Rn  = Arm64Rn(Inst);
  UINT8   Rm  = Arm64Rm(Inst);
  UINT8   Rt  = Arm64Rt(Inst);
  UINT8   Rt2 = Arm64Rt2(Inst);

  UINTN   RdOff = ArmRegXOff(Rd);
  UINTN   RnOff = ArmRegXOff(Rn);
  UINTN   RmOff = ArmRegXOff(Rm);
  UINTN   RtOff = ArmRegXOff(Rt);
  UINTN   Rt2Off= ArmRegXOff(Rt2);
  UINTN   PcOff = ArmRegPcOff();
  UINTN   PsOff = PstateOff();
  UINTN   SpOff = ArmRegSpOff();

  if (DBT_VERBOSE) {
    DBG((DEBUG_INFO, "DBT_ASM:  0x%llx  %08x  decode op0=%x rd=%u rn=%u rm=%u\n",
             InstAddr, Inst, Op0, Rd, Rn, Rm));
  }

  //
  // Data processing — immediate (ADRP, ADD/SUB imm, MOVZ, MOVN, MOVK, bitfield)
  //
  if (Op0 == 8 || Op0 == 9) {
    UINT32 Sub = (Inst >> 23) & 7;

    if (Sub == 5) {
      // MOVZ / MOVN / MOVK
      UINT32 Hw  = (Inst >> 21) & 3;
      UINT16 Imm = (Inst >> 5) & 0xFFFF;
      UINT32 Opc = (Inst >> 29) & 3;

      if (Opc == 2) {
        // MOVZ
        UINT64 Val = (UINT64)Imm << (16 * Hw);
        DBG((DEBUG_INFO, "DBT_ASM:    MOVZ X%d, #0x%llx\n", Rd, Val));
        EmitMovImm(&P, Val);
        EmitStoreRax(&P, RdOff);
      } else {
        DBG((DEBUG_INFO, "DBT_ASM:    MOVK/MOVN (unsupported) -> NOP\n"));
        EmitNop(&P);
      }
    } else if (Sub == 6 || Sub == 7) {
      // Bitfield
      DBG((DEBUG_INFO, "DBT_ASM:    Bitfield -> NOP\n"));
      EmitNop(&P);
    } else {
      DBG((DEBUG_INFO, "DBT_ASM:    Unknown immediate -> NOP\n"));
      EmitNop(&P);
    }
    return (UINTN)(P - X86Buf);
  }

  //
  // Data processing — register (0x0A..0x0F) OR branches/system (0x14..0x17)
  // OR loads/stores
  //
  if (Op0 < 4) {
    // 0xxx: PC-rel addressing or ADD/SUB immediate
    UINT32 Op24 = (Inst >> 24) & 1;

    if (Op24 == 0) {
      // ADR / ADRP
      INT64 Off = ((Inst >> 5) & 0x7FFFF) << 2;
      INT64 Val = InstAddr + ((Off << 43) >> 43);
      if ((Inst >> 31) & 1) Val &= ~0xFFF;  // ADRP: page-align
      DBG((DEBUG_INFO, "DBT_ASM:    ADR%s X%d, 0x%llx\n", ((Inst>>31)&1)?"P":"", Rd, Val));
      EmitMovImm(&P, Val);
      EmitStoreRax(&P, RdOff);
    } else {
      // ADD/SUB immediate
      UINT32 Sh  = (Inst >> 22) & 1;
      UINT32 Imm = ((Inst >> 10) & 0xFFF) << (Sh ? 12 : 0);
      BOOLEAN IsSub = (Inst >> 30) & 1;
      BOOLEAN SetFlags = (Inst >> 29) & 1;

      DBG((DEBUG_INFO, "DBT_ASM:    %s X%d, X%d, #0x%x%s\n",
               IsSub ? "SUB" : "ADD", Rd, Rn, Imm, SetFlags ? " (flags)" : ""));

      if (Rn == 31) {
        // From SP or XZR
        if (IsSub && Rd == 31 && SetFlags) {
          // CMP SP, #imm — not implemented
          EmitNop(&P);
        } else {
          UINTN SrcOff = (Rn == 31) ? SpOff : RnOff;
          if (Rd == 31) {
            // Result to XZR — load, compute, discard
            EmitLoadRax(&P, SrcOff);
            if (IsSub) { EmitSubImm(&P, Imm); }
            else       { EmitAddImm(&P, Imm); }
            EmitNop(&P); // discard result
          } else {
            EmitLoadRax(&P, SrcOff);
            if (IsSub) { EmitSubImm(&P, Imm); }
            else       { EmitAddImm(&P, Imm); }
            EmitStoreRax(&P, RdOff);
          }
          if (SetFlags) EmitUpdateNzcv(&P, PsOff);
        }
      } else {
        EmitLoadRax(&P, RnOff);
        if (IsSub) { EmitSubImm(&P, Imm); }
        else       { EmitAddImm(&P, Imm); }
        if (Rd != 31) EmitStoreRax(&P, RdOff);
        if (SetFlags) EmitUpdateNzcv(&P, PsOff);
      }
    }
    return (UINTN)(P - X86Buf);
  }

  if (Op0 >= 4 && Op0 <= 7) {
    // 010x-011x: Data processing register OR load/store
    UINT32 Op25 = (Inst >> 25) & 1;

    if (Op25 == 0) {
      // Loads/stores (excluding SIMD)
      UINT32 Size = (Inst >> 30) & 3;
      UINT32 Opc2 = (Inst >> 22) & 7;
      INT32  Imm7 = ((Inst >> 15) & 0x7F) << (Size == 0 ? 0 : Size);  // scale

      if (Opc2 == 1) {
        // STR: store Rt to [Rn + offset]
        DBG((DEBUG_INFO, "DBT_ASM:    STR X%d, [X%d, #%d]\n", Rt, Rn, Imm7));
        EmitLoadRax(&P, RtOff);           // RAX = value to store
        EmitLoadRcx(&P, RnOff);           // RCX = base address
        if (Imm7) { EmitAddRcxImm(&P, (UINT32)Imm7); }  // RCX += offset
        // MOV [RCX], RAX
        EmitRexW(&P); EmitByte(&P, 0x89); EmitByte(&P, 0x01);
      } else if (Opc2 == 3) {
        // LDR: load Rt from [Rn + offset]
        DBG((DEBUG_INFO, "DBT_ASM:    LDR X%d, [X%d, #%d]\n", Rt, Rn, Imm7));
        EmitLoadRcx(&P, RnOff);           // RCX = base address
        if (Imm7) { EmitAddRcxImm(&P, (UINT32)Imm7); }  // RCX += offset
        // MOV RAX, [RCX]
        EmitRexW(&P); EmitByte(&P, 0x8B); EmitByte(&P, 0x01);
        EmitStoreRax(&P, RtOff);          // store to Rt
      } else if (Opc2 == 2 || Opc2 == 4) {
        // LDP/STP pair
        if (Opc2 == 4) {
          // LDP
          DBG((DEBUG_INFO, "DBT_ASM:    LDP X%d, X%d, [X%d, #%d]\n", Rt, Rt2, Rn, Imm7));
          EmitLoadRcx(&P, RnOff);                  // RCX = base
          if (Imm7) { EmitAddRcxImm(&P, (UINT32)Imm7); }  // RCX += offset
          // First load: MOV RAX, [RCX]
          EmitRexW(&P); EmitByte(&P, 0x8B); EmitByte(&P, 0x01);
          EmitStoreRax(&P, RtOff);
          // Second load at +8: MOV RAX, [RCX+8]
          EmitRexW(&P); EmitByte(&P, 0x8B); EmitByte(&P, 0x41); EmitByte(&P, 0x08);
          EmitStoreRax(&P, Rt2Off);
        } else {
          // STP
          DBG((DEBUG_INFO, "DBT_ASM:    STP X%d, X%d, [X%d, #%d]\n", Rt, Rt2, Rn, Imm7));
          EmitLoadRcx(&P, RnOff);                  // RCX = base
          if (Imm7) { EmitAddRcxImm(&P, (UINT32)Imm7); }  // RCX += offset
          EmitLoadRax(&P, RtOff);                  // RAX = first value
          EmitRexW(&P); EmitByte(&P, 0x89); EmitByte(&P, 0x01);  // MOV [RCX], RAX
          EmitLoadRax(&P, Rt2Off);                 // RAX = second value
          EmitRexW(&P); EmitByte(&P, 0x89); EmitByte(&P, 0x41); EmitByte(&P, 0x08);  // MOV [RCX+8], RAX
        }
      } else {
        DBG((DEBUG_INFO, "DBT_ASM:    Load/store (opc2=%d) -> NOP\n", Opc2));
        EmitNop(&P);
      }
    } else {
      // Data processing register
      UINT32 Opc = (Inst >> 29) & 3;
      BOOLEAN SetFlags = (Inst >> 29) & 1;

      if (Opc == 0 || Opc == 3) {
        // AND/ORR/EOR (Opc=0) or ANDS/... (Opc=3 with S)
        UINT32 LogicalOp = (Inst >> 29) & 3;

        if (LogicalOp == 0) {
          DBG((DEBUG_INFO, "DBT_ASM:    AND%s X%d, X%d, X%d\n", SetFlags ? " (flags)" : "", Rd, Rn, Rm));
          EmitLoadRax(&P, RnOff);
          EmitAndRaxMem(&P, RmOff);
          if (Rd != 31) EmitStoreRax(&P, RdOff);
          if (SetFlags) EmitUpdateNzcv(&P, PsOff);
        } else if (LogicalOp == 1) {
          DBG((DEBUG_INFO, "DBT_ASM:    ORR%s X%d, X%d, X%d\n", SetFlags ? " (flags)" : "", Rd, Rn, Rm));
          EmitLoadRax(&P, RnOff);
          EmitOrRaxMem(&P, RmOff);
          if (Rd != 31) EmitStoreRax(&P, RdOff);
          if (SetFlags) EmitUpdateNzcv(&P, PsOff);
        } else if (LogicalOp == 2) {
          DBG((DEBUG_INFO, "DBT_ASM:    EOR%s X%d, X%d, X%d\n", SetFlags ? " (flags)" : "", Rd, Rn, Rm));
          EmitLoadRax(&P, RnOff);
          EmitXorRaxMem(&P, RmOff);
          if (Rd != 31) EmitStoreRax(&P, RdOff);
          if (SetFlags) EmitUpdateNzcv(&P, PsOff);
        }
      } else if (Opc == 1 || Opc == 2) {
        // ADD/SUB register
        BOOLEAN IsSub = (Opc == 2);

        DBG((DEBUG_INFO, "DBT_ASM:    %s%s X%d, X%d, X%d\n",
                 IsSub ? "SUB" : "ADD", SetFlags ? " (flags)" : "", Rd, Rn, Rm));

        EmitLoadRax(&P, RnOff);
        if (IsSub) EmitSubRaxMem(&P, RmOff);
        else       EmitAddRaxMem(&P, RmOff);
        if (Rd != 31) EmitStoreRax(&P, RdOff);
        if (SetFlags) EmitUpdateNzcv(&P, PsOff);
      }
    }
    return (UINTN)(P - X86Buf);
  }

  //
  // 101x: Branches, exception, system
  //
  if (Op0 >= 0xA && Op0 <= 0xB) {
    UINT32 High3 = (Inst >> 25) & 7;

    if (High3 == 2 || High3 == 1) {
      // Conditional branch (B.cond)
      UINT32 Cond = Inst & 0xF;
      DBG((DEBUG_INFO, "DBT_ASM:    B.COND 0x%x (condition %u) -> NOP\n", Cond, Cond));
      EmitNop(&P);
    } else if (High3 == 4 || High3 == 5) {
      // Unconditional branch (B)
      INT64 Off = ((Inst >> 0) & 0x3FFFFFF) << 2;
      INT64 Target = InstAddr + ((Off << 36) >> 36);  // sign-extend 26-bit
      DBG((DEBUG_INFO, "DBT_ASM:    B 0x%llx\n", Target));
      // Update PC
      EmitMovImm(&P, Target);
      EmitStoreRax(&P, PcOff);
    } else if (High3 == 6 || High3 == 7) {
      // BR, BLR, RET
      UINT32 OpcR = (Inst >> 21) & 7;

      if (OpcR == 0) {
        // BR
        DBG((DEBUG_INFO, "DBT_ASM:    BR X%d\n", Rn));
        EmitLoadRax(&P, RnOff);
        EmitStoreRax(&P, PcOff);
      } else if (OpcR == 1) {
        // BLR (call)
        DBG((DEBUG_INFO, "DBT_ASM:    BLR X%d\n", Rn));
        // Save return address (PC+4) to LR (X30)
        EmitMovImm(&P, InstAddr + 4);
        EmitStoreRax(&P, ArmRegXOff(30));
        // Jump to target
        EmitLoadRax(&P, RnOff);
        EmitStoreRax(&P, PcOff);
      } else if (OpcR == 2) {
        // RET
        DBG((DEBUG_INFO, "DBT_ASM:    RET X%d\n", Rn));
        EmitLoadRax(&P, RnOff == ArmRegXOff(0) ? ArmRegXOff(30) : RnOff);
        EmitStoreRax(&P, PcOff);
      } else {
        DBG((DEBUG_INFO, "DBT_ASM:    Unknown branch reg -> NOP\n"));
        EmitNop(&P);
      }
    } else if (High3 == 0) {
      // CBZ / CBNZ
      INT64  Off    = ((Inst >> 5) & 0x7FFFF) << 2;
      INT64  Target = InstAddr + ((Off << 43) >> 43);
      BOOLEAN NonZero = (Inst >> 24) & 1;

      DBG((DEBUG_INFO, "DBT_ASM:    CB%s X%d, 0x%llx\n", NonZero ? "NZ" : "Z", Rt, Target));
      EmitLoadRax(&P, RtOff);
      EmitRexW(&P); EmitByte(&P, 0x85); EmitByte(&P, 0xC0);  // TEST RAX, RAX
      // If condition matches, branch to target
      // Simplified: just update PC if taken (no actual jump in generated code)
      EmitNop(&P); // TODO: conditional branch
    } else {
      EmitNop(&P);
    }
    return (UINTN)(P - X86Buf);
  }

  //
  // 0x0C-0x0D (110x): Advanced SIMD/FP loads/stores, or MSR/MRS
  //
  if (Op0 == 0xC || Op0 == 0xD) {
    UINT32 OpByte = (Inst >> 24) & 0xFF;

    if (OpByte == 0xD5) {
      //
      // MSR / MRS — system register access
      //
      BOOLEAN IsMsr = (Inst >> 21) & 1;
      UINT32  SysReg = ((Inst >> 5) & 0xFFFF) | (((Inst >> 19) & 0x3) << 14);

      // Extract op0/op1/CRn/CRm/op2
      UINT32  Op0   = (Inst >> 19) & 0x3;
      UINT32  Op1   = (Inst >> 16) & 0x7;
      UINT32  CRn   = (Inst >> 12) & 0xF;
      UINT32  CRm   = (Inst >> 8)  & 0xF;
      UINT32  Op2   = (Inst >> 5)  & 0x7;
      UINT32  Key   = (Op0 << 16) | (Op1 << 12) | (CRn << 8) | (CRm << 4) | Op2;

      DBG((DEBUG_INFO, "DBT_ASM:    %s sysreg=0x%x (o0=%d o1=%d cn=%d cm=%d o2=%d key=0x%x)\n",
           IsMsr ? "MSR" : "MRS", SysReg, Op0, Op1, CRn, CRm, Op2, Key));

      if (IsMsr) {
        //
        // MSR: write system register from Xt
        //
        EmitLoadRax(&P, RtOff);

        if (Op0 == 3 && Op1 == 0 && CRn == 2 && CRm == 0) {
          // TTBR0_EL1 — page table base
          DBG((DEBUG_INFO, "DBT_MMU:  MSR TTBR0_EL1 <- X%d\n", Rt));
          EmitStoreRax(&P, OFFSET_OF(DBT_ARM64_STATE, TTBR0_EL1));
        } else if (Op0 == 3 && Op1 == 0 && CRn == 2 && CRm == 1) {
          DBG((DEBUG_INFO, "DBT_MMU:  MSR TTBR1_EL1 <- X%d\n", Rt));
          EmitStoreRax(&P, OFFSET_OF(DBT_ARM64_STATE, TTBR1_EL1));
        } else if (Op0 == 3 && Op1 == 0 && CRn == 1 && CRm == 0) {
          DBG((DEBUG_INFO, "DBT_MMU:  MSR SCTLR_EL1 <- X%d\n", Rt));
          EmitStoreRax(&P, OFFSET_OF(DBT_ARM64_STATE, SCTLR_EL1));
        } else if (Op0 == 3 && Op1 == 0 && CRn == 2 && CRm == 0 && Op2 == 2) {
          DBG((DEBUG_INFO, "DBT_MMU:  MSR TCR_EL1 <- X%d\n", Rt));
          EmitStoreRax(&P, OFFSET_OF(DBT_ARM64_STATE, TCR_EL1));
        } else if (Op0 == 3 && Op1 == 0 && CRn == 10 && CRm == 2) {
          DBG((DEBUG_INFO, "DBT_MMU:  MSR MAIR_EL1 <- X%d\n", Rt));
          EmitStoreRax(&P, OFFSET_OF(DBT_ARM64_STATE, MAIR_EL1));
        } else if (Op0 == 3 && Op1 == 0 && CRn == 12 && CRm == 0) {
          DBG((DEBUG_INFO, "DBT_EXC: MSR VBAR_EL1 <- X%d (exception vector base)\n", Rt));
          EmitStoreRax(&P, OFFSET_OF(DBT_ARM64_STATE, VBAR_EL1));
        } else if (Op0 == 3 && Op1 == 0 && CRn == 4 && CRm == 0 && Op2 == 0) {
          DBG((DEBUG_INFO, "DBT_EXC: MSR SPSR_EL1 <- X%d\n", Rt));
          EmitStoreRax(&P, OFFSET_OF(DBT_ARM64_STATE, SPSR_EL1));
        } else if (Op0 == 3 && Op1 == 0 && CRn == 4 && CRm == 0 && Op2 == 1) {
          DBG((DEBUG_INFO, "DBT_EXC: MSR ELR_EL1 <- X%d\n", Rt));
          EmitStoreRax(&P, OFFSET_OF(DBT_ARM64_STATE, ELR_EL1));
        } else if (Op0 == 3 && Op1 == 0 && CRn == 14 && CRm == 0) {
          DBG((DEBUG_INFO, "DBT_EXC: MSR CNTFRQ_EL0 <- X%d\n", Rt));
          EmitStoreRax(&P, OFFSET_OF(DBT_ARM64_STATE, CNTFRQ_EL0));
        } else if (Op0 == 3 && Op1 == 3 && CRn == 10 && CRm == 14) {
          DBG((DEBUG_INFO, "DBT_SIMD: MSR CPACR_EL1 <- X%d (FP/SIMD enable)\n", Rt));
          EmitStoreRax(&P, OFFSET_OF(DBT_ARM64_STATE, CPACR_EL1));
        } else {
          DBG((DEBUG_INFO, "DBT_SYS:  MSR unknown (o0=%d o1=%d crn=%d crm=%d o2=%d)\n", Op0, Op1, CRn, CRm, Op2));
          EmitNop(&P);
        }
      } else {
        //
        // MRS: read system register into Xt
        //
        UINT32 Off = 0;
        BOOLEAN Known = TRUE;

        if (Op0 == 3 && Op1 == 0 && CRn == 0 && CRm == 0 && Op2 == 0) {
          Off = OFFSET_OF(DBT_ARM64_STATE, MIDR_EL1);
          DBG((DEBUG_INFO, "DBT_SYS:  MRS X%d, MIDR_EL1\n", Rt));
        } else if (Op0 == 3 && Op1 == 0 && CRn == 0 && CRm == 0 && Op2 == 5) {
          Off = OFFSET_OF(DBT_ARM64_STATE, MPIDR_EL1);
          DBG((DEBUG_INFO, "DBT_SYS:  MRS X%d, MPIDR_EL1\n", Rt));
        } else if (Op0 == 3 && Op1 == 0 && CRn == 1 && CRm == 0) {
          Off = OFFSET_OF(DBT_ARM64_STATE, SCTLR_EL1);
          DBG((DEBUG_INFO, "DBT_MMU:  MRS X%d, SCTLR_EL1\n", Rt));
        } else if (Op0 == 3 && Op1 == 0 && CRn == 2 && CRm == 0) {
          Off = OFFSET_OF(DBT_ARM64_STATE, TTBR0_EL1);
          DBG((DEBUG_INFO, "DBT_MMU:  MRS X%d, TTBR0_EL1\n", Rt));
        } else if (Op0 == 3 && Op1 == 0 && CRn == 2 && CRm == 1) {
          Off = OFFSET_OF(DBT_ARM64_STATE, TTBR1_EL1);
          DBG((DEBUG_INFO, "DBT_MMU:  MRS X%d, TTBR1_EL1\n", Rt));
        } else if (Op0 == 3 && Op1 == 0 && CRn == 14 && CRm == 0) {
          Off = OFFSET_OF(DBT_ARM64_STATE, CNTFRQ_EL0);
          DBG((DEBUG_INFO, "DBT_SYS:  MRS X%d, CNTFRQ_EL0\n", Rt));
        } else if (Op0 == 3 && Op1 == 3 && CRn == 14 && CRm == 0 && Op2 == 1) {
          Off = OFFSET_OF(DBT_ARM64_STATE, CNTVCT_EL0);
          DBG((DEBUG_INFO, "DBT_SYS:  MRS X%d, CNTVCT_EL0\n", Rt));
        } else if (Op0 == 3 && Op1 == 3 && CRn == 14 && CRm == 3 && Op2 == 1) {
          DBG((DEBUG_INFO, "DBT_SYS:  MRS X%d, CNTV_CVAL_EL0\n", Rt));
          Off = OFFSET_OF(DBT_ARM64_STATE, CNTV_CVAL_EL0);
        } else if (Op0 == 3 && Op1 == 3 && CRn == 14 && CRm == 3 && Op2 == 0) {
          DBG((DEBUG_INFO, "DBT_SYS:  MRS X%d, CNTV_CTL_EL0\n", Rt));
          Off = OFFSET_OF(DBT_ARM64_STATE, CNTV_CTL_EL0);
        } else if (Op0 == 3 && Op1 == 0 && CRn == 12 && CRm == 0) {
          Off = OFFSET_OF(DBT_ARM64_STATE, VBAR_EL1);
          DBG((DEBUG_INFO, "DBT_EXC: MRS X%d, VBAR_EL1\n", Rt));
        } else {
          Known = FALSE;
          DBG((DEBUG_INFO, "DBT_SYS:  MRS X%d, unknown sysreg (key=0x%x)\n", Rt, Key));
          EmitNop(&P);
        }

        if (Known) {
          EmitLoadRax(&P, Off);
          EmitStoreRax(&P, RtOff);
        }
      }
      return (UINTN)(P - X86Buf);
    }

    // Other 110x instructions — emit NOP with log
    DBG((DEBUG_INFO, "DBT_ASM:    Op0=0x%x advanced -> NOP\n", Op0));
    EmitNop(&P);
    return (UINTN)(P - X86Buf);
  }

  //
  // 0x0E-0x0F (111x): Advanced SIMD and floating-point
  //
  if (Op0 >= 0xE) {
    UINT32  SIMD_op = (Inst >> 24) & 0xF;  // bits 27-24

    if ((SIMD_op & 0xC) == 0x4) {
      //
      // SIMD/FP ALU operations
      //
      UINT32  SIMD_sub = (Inst >> 21) & 0x7;
      UINT8   Vd       = Arm64Rd(Inst);
      UINT8   Vn       = Arm64Rn(Inst);
      UINT8   Vm       = Arm64Rm(Inst);
      BOOLEAN IsScalar  = ((Inst >> 28) & 1) == 1;

      if (SIMD_sub == 1) {
        DBG((DEBUG_INFO, "DBT_SIMD: FADD %c%d, %c%d, %c%d\n",
             IsScalar ? 'S' : 'V', Vd, IsScalar ? 'S' : 'V', Vn, IsScalar ? 'S' : 'V', Vm));
      } else if (SIMD_sub == 5) {
        DBG((DEBUG_INFO, "DBT_SIMD: FMUL %c%d, %c%d, %c%d\n",
             IsScalar ? 'S' : 'V', Vd, IsScalar ? 'S' : 'V', Vn, IsScalar ? 'S' : 'V', Vm));
      } else if (SIMD_sub == 3) {
        DBG((DEBUG_INFO, "DBT_SIMD: FSUB %c%d, %c%d, %c%d\n",
             IsScalar ? 'S' : 'V', Vd, IsScalar ? 'S' : 'V', Vn, IsScalar ? 'S' : 'V', Vm));
      } else if (SIMD_sub == 0) {
        DBG((DEBUG_INFO, "DBT_SIMD: FMLA/FMUL by element %c%d, %c%d, %c%d\n",
             IsScalar ? 'S' : 'V', Vd, IsScalar ? 'S' : 'V', Vn, IsScalar ? 'S' : 'V', Vm));
      } else {
        DBG((DEBUG_INFO, "DBT_SIMD: ALU sub=%d %c%d, %c%d, %c%d -> NOP\n",
             SIMD_sub, IsScalar ? 'S' : 'V', Vd, IsScalar ? 'S' : 'V', Vn, IsScalar ? 'S' : 'V', Vm));
      }
      EmitNop(&P);
    } else if ((SIMD_op & 0xC) == 0x0) {
      //
      // SIMD/FP move, duplicate, insert
      //
      DBG((DEBUG_INFO, "DBT_SIMD: Move/dup/insert -> NOP\n"));
      EmitNop(&P);
    } else {
      DBG((DEBUG_INFO, "DBT_SIMD: SIMD op0=0x%X -> NOP\n", SIMD_op));
      EmitNop(&P);
    }
    return (UINTN)(P - X86Buf);
  }

  DBG((DEBUG_INFO, "DBT_ASM:   UNKNOWN op0=0x%X -> NOP\n", Op0));
  EmitNop(&P);
  return (UINTN)(P - X86Buf);
}

// =========== Public API ===========

EFI_STATUS DbtInitContext (OUT DBT_CONTEXT **Context, IN UINTN CodeSize) {
  EFI_STATUS Status;
  DBT_CONTEXT *Ctx;
  EFI_PHYSICAL_ADDRESS Addr;
  UINTN TotalSize;

  if (!Context || !CodeSize) return EFI_INVALID_PARAMETER;

  TotalSize = sizeof(DBT_CONTEXT) + CodeSize;
  Addr = BASE_4GB;

  Status = gBS->AllocatePages (AllocateAnyPages, EfiBootServicesData,
                               EFI_SIZE_TO_PAGES(TotalSize), &Addr);
  if (EFI_ERROR(Status)) return Status;

  Ctx = (DBT_CONTEXT *)(UINTN)Addr;
  ZeroMem(Ctx, TotalSize);

  Status = VmAllocateMemoryPool(&Ctx->VmContext, OC_DEFAULT_VMEM_PAGE_COUNT, NULL);
  if (EFI_ERROR(Status)) {
    gBS->FreePages(Addr, EFI_SIZE_TO_PAGES(TotalSize));
    return Status;
  }

  Ctx->CodeCapacity  = CodeSize;
  Ctx->TranslatedCode = (VOID *)((UINTN)Ctx + sizeof(DBT_CONTEXT));
  *Context = Ctx;

  //
  // Init ARM64 system state for identity-mapped boot
  //
  Ctx->ArmState.SCTLR_EL1 = 0x30D00800;   // MMU off, caches on, little-endian
  Ctx->ArmState.TCR_EL1   = 0;             // identity map
  Ctx->ArmState.TTBR0_EL1 = 0;             // no page table
  Ctx->ArmState.TTBR1_EL1 = 0;
  Ctx->ArmState.MAIR_EL1  = 0xFF;          // all memory types = normal
  Ctx->ArmState.CPACR_EL1 = 0x300000;      // FPEN=3 (FP/SIMD enabled)
  Ctx->ArmState.CNTFRQ_EL0= 24000000;      // 24 MHz timer
  Ctx->ArmState.VBAR_EL1  = 0;             // exception vector base (identity)
  Ctx->ArmState.SPSR_EL1  = 0x5;           // EL1, all exceptions masked
  // MIDR: Apple Icestorm core (ARMv8.5)
  Ctx->ArmState.MIDR_EL1  = 0x611F0240;
  Ctx->ArmState.MPIDR_EL1 = 0x80000000;    // single CPU

  DBG((DEBUG_INFO, "DBT: Init OK size=0x%x buf=%p ctx=%p MMU=%s SCTLR=0x%llx\n",
       CodeSize, Ctx->TranslatedCode, Ctx,
       (Ctx->ArmState.SCTLR_EL1 & 1) ? "ON" : "OFF", Ctx->ArmState.SCTLR_EL1));
  return EFI_SUCCESS;
}

EFI_STATUS DbtSetBootInfo (DBT_CONTEXT *Ctx, EFI_HANDLE Dev, CONST CHAR16 *Path) {
  UINTN Len;
  if (!Ctx || !Path) return EFI_INVALID_PARAMETER;
  if (Ctx->KernelPath) FreePool(Ctx->KernelPath);
  Len = StrSize(Path);
  Ctx->KernelPath = AllocateCopyPool(Len, (VOID *)Path);
  if (!Ctx->KernelPath) return EFI_OUT_OF_RESOURCES;
  Ctx->InstallerDevice = Dev;
  return EFI_SUCCESS;
}

EFI_HANDLE DbtGetInstallerDevice (DBT_CONTEXT *Ctx) {
  return Ctx ? Ctx->InstallerDevice : NULL;
}

CONST CHAR16 * DbtGetKernelPath (DBT_CONTEXT *Ctx) {
  return Ctx ? Ctx->KernelPath : NULL;
}

VOID DbtExecute (DBT_CONTEXT *Ctx, DBT_ARM64_STATE *ArmState) {
  if (!Ctx || !ArmState || !Ctx->TranslatedCode) return;

  DBG((DEBUG_INFO, "DBT: Execute entry=0x%llx SP=0x%llx code=%p size=%u\n",
           ArmState->PC, ArmState->SP, Ctx->TranslatedCode, Ctx->TranslatedSize));

  // Copy ARM state into context so translated code can access it
  CopyMem(&Ctx->ArmState, ArmState, sizeof(DBT_ARM64_STATE));

  // Call translated code with &ArmState as arg (already in RBX from prologue)
  VOID (*Entry)(DBT_ARM64_STATE *) = (VOID(*)(DBT_ARM64_STATE*))Ctx->TranslatedCode;
  Entry(&Ctx->ArmState);

  // Copy state back
  CopyMem(ArmState, &Ctx->ArmState, sizeof(DBT_ARM64_STATE));

  DBG((DEBUG_INFO, "DBT: Execute done — PC=0x%llx\n", ArmState->PC));
}

EFI_STATUS DbtTranslateBlock (DBT_CONTEXT *Ctx, VOID *ArmCode, UINTN CodeSize, VOID *X86Code) {
  if (!Ctx) return EFI_INVALID_PARAMETER;

  UINT8 *Buf  = X86Code ? (UINT8 *)X86Code : (UINT8 *)Ctx->TranslatedCode + Ctx->TranslatedSize;
  UINTN Max   = X86Code ? CodeSize : Ctx->CodeCapacity - Ctx->TranslatedSize;
  UINT8 *Start= Buf;

  DBG((DEBUG_INFO, "DBT: TranslateBlock arm=%p size=%u x86=%p\n", ArmCode, CodeSize, Buf));

  // Emit prologue on first call
  if (Ctx->TranslatedSize == 0 && !X86Code) {
    UINTN ProSize = EmitPrologue(&Buf);
    DBG((DEBUG_INFO, "DBT: Prologue %u bytes\n", ProSize));
  }

  UINT32 *Inst = (UINT32 *)ArmCode;
  UINT64  Addr = 0; // Address tracking needed for PC-relative
  UINTN   Count = 0;
  UINTN   Remaining = CodeSize / 4;

  while (Remaining-- && (UINTN)(Buf - Start) + 64 < Max) {
    UINTN Used = DbtTranslateOne(*Inst, Addr, Buf, 64);
    Buf  += Used;
    Inst++;
    Addr += 4;
    Count++;
  }

  // Emit epilogue on last call
  if (!X86Code) {
    UINTN EpiSize = EmitEpilogue(&Buf);
    DBG((DEBUG_INFO, "DBT: Epilogue %u bytes\n", EpiSize));
  }

  Ctx->TranslatedSize = (UINTN)(Buf - (UINT8 *)Ctx->TranslatedCode);

  DBG((DEBUG_INFO, "DBT: Translated %u instructions, %u x86 bytes\n", Count, Ctx->TranslatedSize));
  return EFI_SUCCESS;
}

VOID DbtFreeContext (DBT_CONTEXT *Ctx) {
  if (!Ctx) return;
  if (Ctx->VmContext.MemoryPool) {
    gBS->FreePages((UINTN)Ctx->VmContext.MemoryPool, Ctx->VmContext.FreePages);
  }
  if (Ctx->KernelPath) FreePool(Ctx->KernelPath);
  gBS->FreePages((UINTN)Ctx, EFI_SIZE_TO_PAGES(sizeof(DBT_CONTEXT) + Ctx->CodeCapacity));
}

//
// =========== MMU helpers ===========
//

/**
  Identity-map VA to PA (MMU is off or TCR_EL1 forces identity).
  Returns the physical address for a given virtual address.
**/
UINT64 DbtTranslateVaToPa (DBT_CONTEXT *Ctx, UINT64 Va) {
  if (!Ctx) return Va;

  //
  // If MMU is disabled (SCTLR_EL1.M = 0), use identity mapping
  //
  if ((Ctx->ArmState.SCTLR_EL1 & 1) == 0) {
    DBG((DEBUG_INFO, "DBT_MMU: MMU OFF — VA 0x%llx -> PA 0x%llx (identity)\n", Va, Va));
    return Va;
  }

  //
  // MMU enabled — walk page tables (stub: identity map for now)
  //
  DBG((DEBUG_INFO, "DBT_MMU: MMU ON — identity mapping VA 0x%llx -> PA 0x%llx (stub)\n", Va, Va));
  return Va;
}

/**
  Handle an ARM64 exception (sync, IRQ, FIQ, SError).
  Updates ESR_EL1, FAR_EL1, ELR_EL1, SPSR_EL1 in the context.
  Returns the exception vector address (VBAR + offset).
**/
UINT64 DbtHandleException (DBT_CONTEXT *Ctx, UINT64 ExceptionType, UINT64 FaultAddr, UINT64 CurrentPc) {
  if (!Ctx) return 0;

  UINT64  Vbar = Ctx->ArmState.VBAR_EL1;
  UINT64  VecOff;

  switch (ExceptionType) {
    case 0:  // Synchronous from current EL with SP_ELx
      VecOff = 0x000;
      break;
    case 1:  // IRQ from current EL
      VecOff = 0x080;
      break;
    case 2:  // FIQ from current EL
      VecOff = 0x100;
      break;
    case 3:  // SError from current EL
      VecOff = 0x180;
      break;
    default:
      VecOff = 0x000;
      break;
  }

  //
  // Save exception state
  //
  Ctx->ArmState.SPSR_EL1 = Ctx->ArmState.PSTATE;
  Ctx->ArmState.ELR_EL1  = CurrentPc;
  Ctx->ArmState.ESR_EL1  = (ExceptionType << 26);  // simplified
  Ctx->ArmState.FAR_EL1  = FaultAddr;

  DBG((DEBUG_WARN, "DBT_EXC: Exception type=%llu at PC=0x%llx FAR=0x%llx -> VBAR=0x%llx Vec=0x%llx\n",
       ExceptionType, CurrentPc, FaultAddr, Vbar, Vbar + VecOff));

  //
  // Mask PSTATE for EL1 handler entry
  //
  Ctx->ArmState.PSTATE = 0x5;  // EL1, all masked

  return Vbar + VecOff;
}