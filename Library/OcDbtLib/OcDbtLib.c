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
// State pointer for the translated prologue.  Delivered through a module
// global instead of a calling-convention argument register so the emitted
// code works regardless of the firmware toolchain ABI (MS x64: RCX,
// SysV: RDI).  Set by DbtExecute immediately before each Entry call.
//
STATIC DBT_ARM64_STATE *gDbtActiveState = NULL;

//
// =========== ARM64 instruction decode helpers ===========
//
STATIC UINT32 Arm64Op0 (UINT32 Inst) { return (Inst >> 25) & 0xF; }
STATIC UINT8  Arm64Rd  (UINT32 Inst) { return Inst & 0x1F; }
STATIC UINT8  Arm64Rn  (UINT32 Inst) { return (Inst >> 5) & 0x1F; }
STATIC UINT8  Arm64Rm  (UINT32 Inst) { return (Inst >> 16) & 0x1F; }
STATIC UINT8  Arm64Rt  (UINT32 Inst) { return Inst & 0x1F; }
STATIC UINT8  Arm64Rt2 (UINT32 Inst) { return (Inst >> 10) & 0x1F; }

STATIC CONST CHAR8 *CondNames[16] = {
  "EQ", "NE", "CS", "CC", "MI", "PL", "VS", "VC",
  "HI", "LS", "GE", "LT", "GT", "LE", "AL", "NV"
};

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

// CMP RAX, [RBX+off] — flags from RAX - mem
STATIC VOID EmitCmpRaxMem (UINT8 **P, UINT32 Off) {
  EmitRexW(P); EmitByte(P, 0x3B);  // CMP r64, r/m64
  if (Off < 128) { EmitByte(P, 0x43); EmitByte(P, (UINT8)Off); }
  else { EmitByte(P, 0x83); EmitDword(P, Off); }
}

// CMP RAX, imm32 (sign-extended)
STATIC VOID EmitCmpRaxImm32 (UINT8 **P, UINT32 Imm) {
  EmitRexW(P); EmitByte(P, 0x3D); EmitDword(P, Imm);
}

// CMP RAX, RCX
STATIC VOID EmitCmpRaxRcx (UINT8 **P) {
  EmitRexW(P); EmitByte(P, 0x3B); EmitByte(P, 0xC1);
}

// NEG RCX (clobbers flags; caller must re-establish them before reading)
STATIC VOID EmitNegRcx (UINT8 **P) {
  EmitRexW(P); EmitByte(P, 0xF7); EmitByte(P, 0xD9);
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
  // RBX = &Ctx->ArmState, loaded via the module global (ABI-agnostic)
  EmitMovImm(P, (UINT64)(UINTN)&gDbtActiveState);  // mov rax, &gDbtActiveState
  EmitRexW(P); EmitByte(P, 0x8B); EmitByte(P, 0x18);  // mov rbx, [rax]
  // DIAGNOSTIC: write exec marker into SP_EL0 (offset 0x110)
  EmitByte(P, 0xB8); EmitDword(P, 0xCAFEBABE);  // mov eax, marker (zero-extends)
  EmitRexW(P); EmitByte(P, 0x89); EmitByte(P, 0x83);         // mov [rbx+disp32], eax
  EmitDword(P, 0x110);
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

// JCC/JMP rel8 placeholder — patched later by PatchJcc
STATIC VOID EmitJccSlot (UINT8 **P, UINT8 Opcode, UINT8 **Slot) {
  *Slot = *P;
  EmitByte(P, Opcode);
  EmitByte(P, 0);
}

STATIC VOID PatchJcc (UINT8 **Slots, UINT8 *Targets, UINTN Num, UINT8 *End, UINT8 *TgtStart) {
  UINTN  I;

  for (I = 0; I < Num; I++) {
    UINT8 *To = (Targets[I] != 0) ? TgtStart : End;

    Slots[I][1] = (UINT8)(To - (Slots[I] + 2));
  }
}

//
// Emit an ARM64 conditional branch decision:
//   mov rax, Fallthrough; mov [rbx+PC], rax   — default: branch NOT taken
//   mov al, [rbx+PSTATE+3]                    — byte holds N=0x80, Z=0x40, C=0x01 (V never set)
//   <TEST AL, mask; Jcc_slot>...              — each Jcc fires when the branch is NOT taken,
//                                                jumping over the Target store (to End), or
//                                                straight to the Target store when the first
//                                                flag already decides "taken" (TgtStart)
//   mov rax, Target; mov [rbx+PC], rax        — overwrite when branch is taken
//
// NOTE: PSTATE is loaded into AL only AFTER the Fallthrough store, since
// EmitMovImm clobbers RAX (and therefore AL).
//
STATIC UINTN EmitCondBranch (UINT8 **P, UINT32 Cond, UINT64 Target, UINT64 Fallthrough) {
  UINT8  *Start = *P;
  UINT8   Seq[64];
  UINT8  *Q   = Seq;
  UINT8  *Slots[3];
  UINT8   Mask[3] = { 0, 0, 0 };
  UINT8   Jcc[3]  = { 0, 0, 0 };
  UINT8   Targets[3] = { 0, 0, 0 };
  UINTN   Num = 1;
  UINTN   I;
  UINT8  *TgtStart;

  EmitMovImm(&Q, Fallthrough);
  EmitStoreRax(&Q, (UINT32)ArmRegPcOff());

  // mov al, [rbx+PSTATE+3]
  EmitByte(&Q, 0x8A); EmitByte(&Q, 0x83); EmitDword(&Q, (UINT32)(PstateOff() + 3));

  switch (Cond) {
    case 0:   Mask[0] = 0x40; Jcc[0] = 0x74; break;                 // EQ  — skip when !Z (ZF=1)
    case 1:   Mask[0] = 0x40; Jcc[0] = 0x75; break;                 // NE  — skip when Z (ZF=0)
    case 2:   Mask[0] = 0x01; Jcc[0] = 0x74; break;                 // CS  — skip when !C (ZF=1)
    case 3:   Mask[0] = 0x01; Jcc[0] = 0x75; break;                 // CC  — skip when C (ZF=0)
    case 4:   Mask[0] = 0x80; Jcc[0] = 0x74; break;                 // MI  — skip when !N (ZF=1)
    case 5:   Mask[0] = 0x80; Jcc[0] = 0x75; break;                 // PL  — skip when N (ZF=0)
    case 6:   Mask[0] = 0x00; Jcc[0] = 0xEB; break;                 // VS  — never taken, always skip
    case 7:   Num = 0;         break;                               // VC  — always taken
    case 8:   Mask[0] = 0x40; Jcc[0] = 0x75;                       // HI  — skip when !C or Z
              Mask[1] = 0x01; Jcc[1] = 0x74; Num = 2; break;
    case 9:   Mask[0] = 0x40; Jcc[0] = 0x75; Targets[0] = 1;      // LS  — first flag decides taken
              Mask[1] = 0x01; Jcc[1] = 0x75; Num = 2; break;       //       (Z=1 -> taken, jump to Target)
    case 0xA: Mask[0] = 0x80; Jcc[0] = 0x75; break;                 // GE  — skip when N (ZF=0)
    case 0xB: Mask[0] = 0x80; Jcc[0] = 0x74; break;                 // LT  — skip when !N (ZF=1)
    case 0xC: Mask[0] = 0x40; Jcc[0] = 0x75;                       // GT  — skip when Z or N
              Mask[1] = 0x80; Jcc[1] = 0x75; Num = 2; break;
    case 0xD: Mask[0] = 0x40; Jcc[0] = 0x75; Targets[0] = 1;      // LE  — first flag decides taken
              Mask[1] = 0x80; Jcc[1] = 0x74; Num = 2; break;       //       (Z=1 -> taken, jump to Target)
    case 0xE: Num = 0;         break;                               // AL
    default:  Mask[0] = 0x00; Jcc[0] = 0xEB; break;                 // NV  — never taken, always skip
  }

  for (I = 0; I < Num; I++) {
    if (Mask[I] != 0) {
      EmitByte(&Q, 0xF6); EmitByte(&Q, 0xC0); EmitByte(&Q, Mask[I]);  // TEST AL, imm8
    }
    EmitJccSlot(&Q, Jcc[I], &Slots[I]);
  }

  TgtStart = Q;
  EmitMovImm(&Q, Target);
  EmitStoreRax(&Q, (UINT32)ArmRegPcOff());

  PatchJcc (Slots, Targets, Num, Q, TgtStart);

  CopyMem (*P, Seq, (UINTN)(Q - Seq));
  *P += (UINTN)(Q - Seq);
  return (UINTN)(*P - Start);
}

//
// CBZ/CBNZ: load Rt into RAX, TEST RAX,RAX, then PC-select.
// Emit Fallthrough store first (branch NOT taken), then the SkipJcc fires when
// the branch is NOT taken (CBZ: JNE, CBNZ: JE), jumping over the Target store.
//
STATIC UINTN EmitCompareBranch (UINT8 **P, UINTN RtOff, UINT64 Target, UINT64 Fallthrough, UINT8 SkipJcc) {
  UINT8  *Start = *P;
  UINT8  *Slot;

  EmitLoadRax(P, (UINT32)RtOff);
  EmitRexW(P); EmitByte(P, 0x85); EmitByte(P, 0xC0);  // TEST RAX, RAX

  EmitMovImm(P, Fallthrough);
  EmitStoreRax(P, (UINT32)ArmRegPcOff());
  EmitJccSlot(P, SkipJcc, &Slot);
  EmitMovImm(P, Target);
  EmitStoreRax(P, (UINT32)ArmRegPcOff());
  Slot[1] = (UINT8)((*P) - (Slot + 2));

  return (UINTN)(*P - Start);
}

//
// TBZ/TBNZ: load Rt into RAX, BT RAX,RCX, then PC-select.
// SkipJcc fires when the branch is NOT taken (TBZ: JC, TBNZ: JNC).
//
STATIC UINTN EmitTestBitBranch (UINT8 **P, UINTN RtOff, UINT32 Bit, UINT64 Target, UINT64 Fallthrough, UINT8 SkipJcc) {
  UINT8  *Start = *P;
  UINT8  *Slot;

  EmitLoadRax(P, (UINT32)RtOff);
  EmitByte(P, 0xB9); EmitDword(P, Bit);               // MOV ECX, imm32
  EmitRexW(P); EmitByte(P, 0x0F); EmitByte(P, 0xA3); EmitByte(P, 0xC8);  // BT RAX, RCX

  EmitMovImm(P, Fallthrough);
  EmitStoreRax(P, (UINT32)ArmRegPcOff());
  EmitJccSlot(P, SkipJcc, &Slot);
  EmitMovImm(P, Target);
  EmitStoreRax(P, (UINT32)ArmRegPcOff());
  Slot[1] = (UINT8)((*P) - (Slot + 2));

  return (UINTN)(*P - Start);
}

// =========== NZCV flag handling ===========
//
// Rosetta's flag emulation is only reliable for a single (producer, consumer)
// pair, so multi-bit SETcc/PUSHFQ captures cannot be validated in the harness.
// Flags are therefore tracked explicitly as data flow:
//   - same-block:  EmitRecordFlagSet records the setter's operands in
//                  Ctx->FlagSet; EmitCondBranchFromSet re-derives the branch
//                  condition from those operands via cmp/jcc (a second
//                  producer right next to its single consumer, which Rosetta
//                  handles correctly).
//   - cross-block: DbtComputeNzcv recomputes NZCV host-side from the recorded
//                  operands and the post-block register state, and writes the
//                  PSTATE byte.
//
STATIC VOID EmitRecordFlagSet (
  IN DBT_CONTEXT *Ctx,
  IN UINT8        Kind,
  IN BOOLEAN      IsSub,
  IN UINT8        LogicalOp,
  IN UINT8        Rd,
  IN UINT8        Rn,
  IN UINT8        Rm,
  IN BOOLEAN      HasReg2,
  IN UINT64       Imm
  )
{
  Ctx->FlagSet.HasSetter = TRUE;
  Ctx->FlagSet.Kind      = Kind;
  Ctx->FlagSet.IsSub     = IsSub;
  Ctx->FlagSet.LogicalOp = LogicalOp;
  Ctx->FlagSet.Rd        = Rd;
  Ctx->FlagSet.Rn        = Rn;
  Ctx->FlagSet.Rm        = Rm;
  Ctx->FlagSet.HasReg2   = HasReg2;
  Ctx->FlagSet.Imm       = Imm;
}

//
// Re-derive the NZCV condition of the recorded flag setter in x86 flags,
// then emit the branch decision as in EmitCondBranch but reading x86 flags
// (from the fresh compare) instead of the PSTATE byte.
//
// Compare emission (producer for the jccs below):
//   addsub-reg:  SUB: CMP RAX, [RBX+RmOff]         — flags = Rn - Rm
//                ADD: RCX = -Rm; CMP RAX, RCX      — flags = Rn + Rm
//   addsub-imm:  SUB: CMP RAX, imm32
//                ADD: CMP RAX, -imm32
//   logical:     AND/ORR/EOR RAX, [RBX+RmOff]      — flags = (Rn op Rm) result
//
STATIC UINTN EmitCondBranchFromSet (UINT8 **P, UINT32 Cond, UINT64 Target, UINT64 Fallthrough, DBT_FLAG_SET *Set) {
  UINT8  *Start = *P;
  UINT8   Seq[128];
  UINT8  *Q   = Seq;
  UINT8  *Slots[3];
  UINT8   Jcc[3]  = { 0, 0, 0 };
  UINT8   Targets[3] = { 0, 0, 0 };
  UINTN   Num = 1;
  UINTN   I;
  UINT8  *TgtStart;
  UINT32  RnOff;
  UINT32  RmOff;
  BOOLEAN IsLogical = (Set->Kind == FLAGKIND_LOGICAL);
  BOOLEAN Clobbered;

  EmitMovImm(&Q, Fallthrough);
  EmitStoreRax(&Q, (UINT32)ArmRegPcOff());

  // If the setter stored its result into Rn or Rm, the operands are gone and
  // we must reconstruct them.  For logical setters the result itself gives
  // exact N/Z (C/V are always clear), so a TEST on Rd suffices whenever the
  // result was stored; only the comparison forms (Rd == XZR) re-read
  // operands.  For add/sub, Z/N also equal the result's, but C/V need the
  // original operands: when Rd == Rn (Rd == XZR stores nothing and leaves
  // the operands intact), rebuild A = R -+ B from the result, then CMP.
  if (IsLogical) {
    Clobbered = FALSE;
    if (Set->Rd != 31) {
      EmitLoadRax(&Q, (UINT32)ArmRegXOff(Set->Rd));
      EmitRexW(&Q); EmitByte(&Q, 0x85); EmitByte(&Q, 0xC0);  // TEST RAX, RAX
    } else {
      // Rd == XZR: result discarded; re-read operands (logical: XZR is 31)
      EmitLoadRax(&Q, (UINT32)ArmRegXOff(Set->Rn));
      EmitAndRaxMem(&Q, (UINT32)ArmRegXOff(Set->Rm));
    }
  } else {
    Clobbered = (Set->Rd != 31) && (Set->Rd == Set->Rn)
                && (!Set->HasReg2 || (Set->Rm != Set->Rd));
    if (Set->Rn == 31 && !Clobbered) {
      RnOff = Set->HasReg2 ? (UINT32)ArmRegXOff(31) : (UINT32)ArmRegSpOff();
    } else {
      RnOff = (UINT32)ArmRegXOff(Set->Rn);
    }
    RmOff = (UINT32)ArmRegXOff(Set->Rm);

    if (Clobbered) {
      // Rd == Rn and the result was stored: A = R -+ B, then CMP against B.
      EmitLoadRax(&Q, (UINT32)ArmRegXOff(Set->Rd));
      if (Set->HasReg2) {
        if (Set->IsSub) { EmitAddRaxMem(&Q, RmOff); } else { EmitSubRaxMem(&Q, RmOff); }
      } else if (Set->IsSub) {
        EmitAddImm(&Q, (UINT32)Set->Imm);
      } else {
        EmitSubImm(&Q, (UINT32)Set->Imm);
      }
    } else {
      EmitLoadRax(&Q, RnOff);
    }

    if (Set->HasReg2) {
      if (Set->IsSub) {
        EmitCmpRaxMem(&Q, RmOff);
      } else {
        EmitLoadRcx(&Q, RmOff);
        EmitNegRcx(&Q);
        EmitCmpRaxRcx(&Q);
      }
    } else if (Set->IsSub) {
      EmitCmpRaxImm32(&Q, (UINT32)Set->Imm);
    } else {
      EmitCmpRaxImm32(&Q, (UINT32)(-(INT64)Set->Imm));
    }
  }

  // Jcc slots: each fires when the branch is NOT taken, jumping over the
  // Target store; a Targets[I]=1 entry jumps straight to TgtStart instead
  // (the first flag already decided "taken").  For logical setters C and V
  // are always clear, so CS/HI/VS never take and CC/LS/VC always take.
  switch (Cond) {
    case 0:   Jcc[0] = 0x75; break;                                  // EQ  — skip when ZF=0
    case 1:   Jcc[0] = 0x74; break;                                  // NE  — skip when ZF=1
    case 2:   Jcc[0] = IsLogical ? 0xEB : 0x72; break;               // CS  — skip when CF=1 (logical: never taken)
    case 3:   Jcc[0] = IsLogical ? 0x00 : 0x73; Num = IsLogical ? 0 : 1; break;  // CC  — skip when CF=0 (logical: always taken)
    case 4:   Jcc[0] = 0x79; break;                                  // MI  — skip when SF=0
    case 5:   Jcc[0] = 0x78; break;                                  // PL  — skip when SF=1
    case 6:   Jcc[0] = IsLogical ? 0xEB : 0x71; break;               // VS  — skip when OF=1 (logical: never taken)
    case 7:   Num = 0; break;                                        // VC  — always taken
    case 8:   Jcc[0] = IsLogical ? 0xEB : 0x72;                      // HI  — skip when CF=1 or ZF=1 (logical: never taken)
              Jcc[1] = 0x74; Num = IsLogical ? 1 : 2; break;
    case 9:   if (IsLogical) { Num = 0; }                            // LS  — logical: always taken
              else { Jcc[0] = 0x74; Targets[0] = 1;                  // ZF=1 -> taken
                     Jcc[1] = 0x73; Num = 2; }                       // CF=1 -> taken, else skip
              break;
    case 0xA: Jcc[0] = 0x7C; break;                                  // GE  — skip when N!=V (SF!=OF)
    case 0xB: Jcc[0] = 0x7D; break;                                  // LT  — skip when N==V
    case 0xC: Jcc[0] = 0x74;                                        // GT  — skip when ZF=1 or N!=V
              Jcc[1] = 0x7C; Num = 2; break;
    case 0xD: Jcc[0] = 0x74; Targets[0] = 1;                        // LE  — ZF=1 -> taken
              Jcc[1] = 0x7D; Num = 2; break;                         //       N==V -> taken, else skip
    case 0xE: Num = 0; break;                                        // AL
    default:  Jcc[0] = 0xEB; break;                                  // NV  — never taken, always skip
  }

  for (I = 0; I < Num; I++) {
    EmitJccSlot(&Q, Jcc[I], &Slots[I]);
  }

  TgtStart = Q;
  EmitMovImm(&Q, Target);
  EmitStoreRax(&Q, (UINT32)ArmRegPcOff());

  PatchJcc (Slots, Targets, Num, Q, TgtStart);

  CopyMem (*P, Seq, (UINTN)(Q - Seq));
  *P += (UINTN)(Q - Seq);
  return (UINTN)(*P - Start);
}

//
// Recompute NZCV from the recorded flag setter's operands and the current
// register state, and store it into PSTATE[31:24].  Called after each block
// runs, so that consumers in later blocks read the PSTATE byte.  The ARM
// PSTATE byte layout is: N=0x80, Z=0x40, V=0x10, C=0x01 (C complemented for
// subtract: ARM C means "no borrow").
//
STATIC VOID DbtComputeNzcv (IN DBT_CONTEXT *Ctx) {
  DBT_FLAG_SET *S   = &Ctx->FlagSet;
  UINT64        A, B, R;
  UINT8         Byte;
  BOOLEAN       N, Z, C, V;

  if (!S->HasSetter) {
    return;
  }

  // Rn==31 is SP in the immediate form, XZR in the register form.
  if (!S->HasReg2 && S->Rn == 31) {
    A = Ctx->ArmState.SP;
  } else {
    A = Ctx->ArmState.X[S->Rn];
  }
  if (S->HasReg2) {
    B = Ctx->ArmState.X[S->Rm];
  } else {
    B = S->Imm;
  }

  if (S->Kind == FLAGKIND_LOGICAL) {
    switch (S->LogicalOp) {
      case 1:  R = A | B; break;
      case 2:  R = A ^ B; break;
      default: R = A & B; break;
    }
    C = FALSE;
    V = FALSE;
  } else if (S->IsSub) {
    R = A - B;
    C = (A >= B);
    V = (((A ^ B) & ((UINT64)1 << 63)) != 0) && (((A ^ R) & ((UINT64)1 << 63)) != 0);
  } else {
    R = A + B;
    C = (R < A);
    V = ((((A ^ B) & ((UINT64)1 << 63)) == 0) && (((A ^ R) & ((UINT64)1 << 63)) != 0));
  }

  N = ((R & ((UINT64)1 << 63)) != 0);
  Z = (R == 0);

  Byte  = N ? 0x80 : 0;
  Byte |= Z ? 0x40 : 0;
  Byte |= V ? 0x10 : 0;
  Byte |= C ? 0x01 : 0;

  Ctx->ArmState.PSTATE = (Ctx->ArmState.PSTATE & 0x00FFFFFFULL) | ((UINT64)Byte << 24);

  // The setter's flags are now materialized; nothing stays pending.
  S->HasSetter = FALSE;
}

// =========== Single instruction translator ===========
STATIC UINTN DbtTranslateOne (
  IN  DBT_CONTEXT *Ctx,
  IN  UINT32       Inst,
  IN  UINT64       InstAddr,
  OUT UINT8       *X86Buf,
  IN  UINTN        BufSize
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
    } else if (Sub == 2) {
      //
      // ADD/SUB immediate: sf(31) op(30) S(29) 100010(28:23) sh(22) imm12(21:10)
      //
      UINT32   Sh       = (Inst >> 22) & 1;
      UINT32   Imm      = ((Inst >> 10) & 0xFFF) << (Sh ? 12 : 0);
      BOOLEAN  IsSub    = (Inst >> 30) & 1;
      BOOLEAN  SetFlags = (Inst >> 29) & 1;

      DBG((DEBUG_INFO, "DBT_ASM:    %s X%d, X%d, #0x%x%s\n",
               IsSub ? "SUB" : "ADD", Rd, Rn, Imm, SetFlags ? " (flags)" : ""));

      if (Rn == 31) {
        // From SP or XZR
        UINTN SrcOff = SpOff;
        EmitLoadRax(&P, SrcOff);
        if (IsSub) { EmitSubImm(&P, Imm); }
        else       { EmitAddImm(&P, Imm); }
        if (Rd == 31) {
          EmitNop(&P); // discard result
        } else {
          EmitStoreRax(&P, RdOff);
        }
        if (SetFlags) EmitRecordFlagSet(Ctx, FLAGKIND_ADDSUB, IsSub, 0, Rd, Rn, 0, FALSE, Imm);
      } else {
        EmitLoadRax(&P, RnOff);
        if (IsSub) { EmitSubImm(&P, Imm); }
        else       { EmitAddImm(&P, Imm); }
        if (Rd != 31) EmitStoreRax(&P, RdOff);
        if (SetFlags) EmitRecordFlagSet(Ctx, FLAGKIND_ADDSUB, IsSub, 0, Rd, Rn, 0, FALSE, Imm);
      }
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
      DBG((DEBUG_INFO, "DBT_ASM:    ADD/SUB immediate (unreachable) -> NOP\n"));
      EmitNop(&P);
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
      // Data processing register; bit 24 discriminates the families:
      //   logical (01010):  opc(30:29) 0=AND, 1=ORR, 2=EOR, 3=ANDS
      //   add/sub (01011):  op(30) S(29) 0=ADD/1=SUB, S sets flags
      UINT32  Bit24 = (Inst >> 24) & 1;
      UINT32  Opc   = (Inst >> 29) & 3;

      if (Bit24 == 0) {
        // AND/ORR/EOR (Opc 0..2) and ANDS (Opc 3)
        if (Opc == 0) {
          DBG((DEBUG_INFO, "DBT_ASM:    AND X%d, X%d, X%d\n", Rd, Rn, Rm));
          EmitLoadRax(&P, RnOff);
          EmitAndRaxMem(&P, RmOff);
          if (Rd != 31) EmitStoreRax(&P, RdOff);
        } else if (Opc == 1) {
          DBG((DEBUG_INFO, "DBT_ASM:    ORR X%d, X%d, X%d\n", Rd, Rn, Rm));
          EmitLoadRax(&P, RnOff);
          EmitOrRaxMem(&P, RmOff);
          if (Rd != 31) EmitStoreRax(&P, RdOff);
        } else if (Opc == 2) {
          DBG((DEBUG_INFO, "DBT_ASM:    EOR X%d, X%d, X%d\n", Rd, Rn, Rm));
          EmitLoadRax(&P, RnOff);
          EmitXorRaxMem(&P, RmOff);
          if (Rd != 31) EmitStoreRax(&P, RdOff);
        } else {
          // ANDS (always sets flags)
          DBG((DEBUG_INFO, "DBT_ASM:    ANDS X%d, X%d, X%d (flags)\n", Rd, Rn, Rm));
          EmitLoadRax(&P, RnOff);
          EmitAndRaxMem(&P, RmOff);
          if (Rd != 31) EmitStoreRax(&P, RdOff);
          EmitRecordFlagSet(Ctx, FLAGKIND_LOGICAL, FALSE, 0, Rd, Rn, Rm, TRUE, 0);
        }
      } else {
        // ADD/SUB register
        BOOLEAN IsSub     = (Inst >> 30) & 1;
        BOOLEAN SetFlags  = (Inst >> 29) & 1;

        DBG((DEBUG_INFO, "DBT_ASM:    %s%s X%d, X%d, X%d\n",
                 IsSub ? "SUB" : "ADD", SetFlags ? " (flags)" : "", Rd, Rn, Rm));

        EmitLoadRax(&P, RnOff);
        if (IsSub) EmitSubRaxMem(&P, RmOff);
        else       EmitAddRaxMem(&P, RmOff);
        if (Rd != 31) EmitStoreRax(&P, RdOff);
        if (SetFlags) EmitRecordFlagSet(Ctx, FLAGKIND_ADDSUB, IsSub, 0, Rd, Rn, Rm, TRUE, 0);
      }
    }
    return (UINTN)(P - X86Buf);
  }

  //
  // 101x: Branches, exception, system
  //
  if (Op0 >= 0xA && Op0 <= 0xB) {
    UINT32 TopByte = (Inst >> 24) & 0xFF;

    if (TopByte == 0x54) {
      // Conditional branch (B.cond)
      UINT32 Cond   = Inst & 0xF;
      INT64  Off    = ((Inst >> 5) & 0x7FFFF) << 2;
      INT64  Target = InstAddr + ((Off << 43) >> 43);

      DBG((DEBUG_INFO, "DBT_ASM:    B.%s 0x%llx\n", CondNames[Cond], Target));
      if (Ctx->FlagSet.HasSetter) {
        // Same-block setter: re-derive the condition from its operands.
        return EmitCondBranchFromSet(&P, Cond, (UINT64)Target, InstAddr + 4, &Ctx->FlagSet);
      }
      return EmitCondBranch(&P, Cond, (UINT64)Target, InstAddr + 4);
    } else if ((Inst & 0x7C000000) == 0x14000000) {
      // Unconditional branch B / BL
      INT64  Off    = ((INT64)(Inst & 0x03FFFFFF) << 2);  // imm26 = bits [25:0]
      INT64  Target = InstAddr + ((Off << 36) >> 36);  // sign-extend 26-bit
      BOOLEAN WithLink = ((Inst >> 31) & 1) != 0;

      if (WithLink) {
        DBG((DEBUG_INFO, "DBT_ASM:    BL 0x%llx\n", Target));
        // Save return address (PC+4) to LR (X30)
        EmitMovImm(&P, InstAddr + 4);
        EmitStoreRax(&P, ArmRegXOff(30));
      } else {
        DBG((DEBUG_INFO, "DBT_ASM:    B 0x%llx\n", Target));
      }
      EmitMovImm(&P, (UINT64)Target);
      EmitStoreRax(&P, PcOff);
      // Terminator: nothing after this instruction can consume the setter's
      // flags, and the block ends here, so drop the pending descriptor.
      Ctx->FlagSet.HasSetter = FALSE;
    } else if ((Inst & 0x7E000000) == 0x34000000) {
      // CBZ / CBNZ
      INT64  Off    = ((Inst >> 5) & 0x7FFFF) << 2;
      INT64  Target = InstAddr + ((Off << 43) >> 43);
      BOOLEAN NonZero = (Inst >> 24) & 1;

      DBG((DEBUG_INFO, "DBT_ASM:    CB%s X%d, 0x%llx\n", NonZero ? "NZ" : "Z", Rt, Target));
      return EmitCompareBranch(&P, RtOff, (UINT64)Target, InstAddr + 4, NonZero ? 0x74 : 0x75);
    } else if ((Inst & 0x7E000000) == 0x36000000) {
      // TBZ / TBNZ
      UINT32 Bit   = (((Inst >> 31) & 1) << 5) | ((Inst >> 19) & 0x1F);
      INT64  Off   = ((Inst >> 5) & 0x3FFF) << 2;
      INT64  Target = InstAddr + ((Off << 48) >> 48);  // sign-extend 14-bit
      BOOLEAN NonZero = (Inst >> 24) & 1;

      DBG((DEBUG_INFO, "DBT_ASM:    TB%s X%d, #%u, 0x%llx\n", NonZero ? "NZ" : "Z", Rt, Bit, Target));
      return EmitTestBitBranch(&P, RtOff, Bit, (UINT64)Target, InstAddr + 4, NonZero ? 0x73 : 0x72);
    } else if ((Inst & 0xFE000000) == 0xD6000000) {
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
      // BR/BLR/RET are terminators: the pending flag setter cannot be
      // consumed after them (and the block ends), so drop the descriptor.
      Ctx->FlagSet.HasSetter = FALSE;
    } else {
      DBG((DEBUG_INFO, "DBT_ASM:    Unhandled branch top=0x%02x -> NOP\n", TopByte));
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

  //
  // Allocate as executable code memory.  EfiBootServicesData pages are
  // non-executable (NX) on firmware with memory protection enabled, which
  // silently faults the first fetch of the translated code buffer.
  //
  Status = gBS->AllocatePages (AllocateAnyPages, EfiBootServicesCode,
                               EFI_SIZE_TO_PAGES(TotalSize), &Addr);
  if (EFI_ERROR(Status)) return Status;

  Ctx = (DBT_CONTEXT *)(UINTN)Addr;
  ZeroMem(Ctx, TotalSize);

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

  {
    //
    // DIAGNOSTIC: print the EFI memory descriptor covering the translated
    // code buffer so we can see whether the firmware marks it executable.
    //
    EFI_MEMORY_DESCRIPTOR *Map    = NULL;
    UINTN                 MapSize = 0, MapKey, DescSize;
    UINT32                DescVer;
    EFI_STATUS            MStatus = gBS->GetMemoryMap (&MapSize, Map, &MapKey, &DescSize, &DescVer);

    if (MStatus == EFI_BUFFER_TOO_SMALL) {
      Map = AllocatePool (MapSize + DescSize);
      if (Map) {
        MStatus = gBS->GetMemoryMap (&MapSize, Map, &MapKey, &DescSize, &DescVer);
        if (!EFI_ERROR (MStatus)) {
          for (UINTN I = 0; I < MapSize / DescSize; I++) {
            EFI_MEMORY_DESCRIPTOR *D = (EFI_MEMORY_DESCRIPTOR *)((UINT8 *)Map + I * DescSize);
            UINTN Start = D->PhysicalStart;
            UINTN End   = Start + (D->NumberOfPages << 12);
            if ((UINTN)Ctx->TranslatedCode >= Start && (UINTN)Ctx->TranslatedCode < End) {
              DBG((DEBUG_INFO, "DBT: code buffer type=0x%x attrs=0x%llx%s\n",
                   D->Type, (UINT64)D->Attribute,
                   (D->Attribute & EFI_MEMORY_XP) ? " XP-SET" : " executable"));
              break;
            }
          }
        }
        FreePool (Map);
      }
    }
  }

  // Copy ARM state into context so translated code can access it
  CopyMem(&Ctx->ArmState, ArmState, sizeof(DBT_ARM64_STATE));

  // Deliver the state pointer to the translated prologue (ABI-agnostic)
  gDbtActiveState = &Ctx->ArmState;

  // Call translated code with &ArmState as arg (already in RBX from prologue)
  VOID (*Entry)(DBT_ARM64_STATE *) = (VOID(*)(DBT_ARM64_STATE*))Ctx->TranslatedCode;
  Entry(&Ctx->ArmState);

  // Materialize NZCV from the last flag setter's operands and register state.
  DbtComputeNzcv (Ctx);

  // Copy state back
  CopyMem(ArmState, &Ctx->ArmState, sizeof(DBT_ARM64_STATE));

  DBG((DEBUG_INFO, "DBT: Execute done — PC=0x%llx X0=0x%llx PSTATE=0x%llx SP_EL0=0x%llx\n",
       ArmState->PC, ArmState->X[0], ArmState->PSTATE, ArmState->SP_EL0));
}

EFI_STATUS DbtTranslateBlock (DBT_CONTEXT *Ctx, VOID *ArmCode, UINTN CodeSize, UINT64 BaseAddr, VOID *X86Code) {
  if (!Ctx) return EFI_INVALID_PARAMETER;

  UINT8 *Buf  = X86Code ? (UINT8 *)X86Code : (UINT8 *)Ctx->TranslatedCode + Ctx->TranslatedSize;
  UINTN Max   = X86Code ? CodeSize : Ctx->CodeCapacity - Ctx->TranslatedSize;
  UINT8 *Start= Buf;

  DBG((DEBUG_INFO, "DBT: TranslateBlock arm=%p size=%u x86=%p\n", ArmCode, CodeSize, Buf));

  // Emit prologue on first call
  if (Ctx->TranslatedSize == 0 && !X86Code) {
    UINTN ProSize = EmitPrologue(&Buf);
    DBG((DEBUG_INFO, "DBT: Prologue %u bytes\n", ProSize));
    //
    // Reserve a jump slot after the prologue: E9 rel32.  Each new block
    // re-points it at the newest block, so DbtExecute only runs the latest
    // translation instead of replaying the whole buffer.
    //
    Ctx->JumpSlot = Buf;
    EmitByte(&Buf, 0xE9); EmitDword(&Buf, 0);
    DBG((DEBUG_INFO, "DBT: Jump slot at %p\n", Ctx->JumpSlot));
  }

  Ctx->LastBlockStart = Buf;

  // No flag setter is pending at the start of a block.
  Ctx->FlagSet.HasSetter = FALSE;

  UINT32 *Inst = (UINT32 *)ArmCode;
  UINT64  Addr = BaseAddr; // Address tracking needed for PC-relative
  UINTN   Count = 0;
  UINTN   Remaining = CodeSize / 4;

  while (Remaining-- && (UINTN)(Buf - Start) + 64 < Max) {
    UINTN Used = DbtTranslateOne(Ctx, *Inst, Addr, Buf, 64);
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

  if (!X86Code && Ctx->JumpSlot != NULL) {
    //
    // Point the jump slot at the newest block.  rel32 is measured from the
    // end of the JMP instruction.
    //
    INTN Rel = (INTN)(Ctx->LastBlockStart - (Ctx->JumpSlot + 5));
    *(INT32 *)(Ctx->JumpSlot + 1) = (INT32)Rel;
    DBG((DEBUG_INFO, "DBT: Jump slot -> %p (rel 0x%x)\n", Ctx->LastBlockStart, (UINT32)Rel));
  }

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