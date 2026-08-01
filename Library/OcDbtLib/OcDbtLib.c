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
// Context pointer and guest-address scratch slot for the host-side data
// translation helper (DbtMapHostAddr).  The translated LDR/STR code stores
// the guest effective address into gDbtHelperVa, calls DbtMapHostAddr with
// no arguments (again ABI-agnostic), and uses the returned host address.
// The guest VAs of the loaded kernel image are not mapped at the same
// addresses on the x86 host, so raw loads/stores would fault (silently
// swallowed by the firmware handler) and leave the guest register zeroed,
// e.g. the CBZ self-spin at 0xFFFFFE000C52C10C on the kernel boot path.
//
STATIC DBT_CONTEXT *gDbtActiveCtx = NULL;
STATIC UINT64       gDbtHelperVa  = 0;

//
// Host-side VA->host-address helper invoked by the translated LDR/STR
// code (forward declaration; defined in the MMU helpers section).
//
UINT64 DbtMapHostAddr (VOID);

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
// DecodeBitMasks — ARM ARM pseudocode "DecodeBitMasks" for logical
// immediate and bitfield instructions.  Computes wmask/tmask from the
// N:immr:imms fields.  "Immediate" selects the logical-immediate
// constraint (all-ones element value reserved).  Returns FALSE on
// UNDEFINED encodings.
//
STATIC BOOLEAN
Arm64DecodeBitMasks (
  UINT32   Inst,
  BOOLEAN  Immediate,
  UINT64   *Wmask,
  UINT64   *Tmask
  )
{
  UINT32  N, Imms, Immr;
  UINT32  Pattern, Length, Esize, Levels, S, R;
  UINT64  W, T, Full;

  N     = (Inst >> 22) & 1;
  Immr  = (Inst >> 16) & 0x3F;
  Imms  = (Inst >> 10) & 0x3F;

  //
  // len = HighestSetBitNZ(immN::NOT(imms));  '000000x' is UNDEFINED
  //
  Pattern = (N << 6) | ((~Imms) & 0x3F);
  if (Pattern == 0 || Pattern == 1) {
    return FALSE;
  }
  Length = 31 - (UINT32)__builtin_clz(Pattern);
  Esize  = 1u << Length;

  Levels = (1u << Length) - 1;
  if (Immediate && ((Imms & Levels) == Levels)) {
    // all-ones element value reserved (would give all-ones result)
    return FALSE;
  }
  S = Imms & Levels;
  R = Immr & Levels;

  W = (S + 1 == 64) ? ~0ULL : (((UINT64)1 << (S + 1)) - 1); // Ones{S+1}
  if (R != 0) {
    UINT64 Emask = (Esize == 64) ? ~0ULL : ((UINT64)1 << Esize) - 1;
    W = ((W >> R) | (W << (Esize - R))) & Emask;  // ROR within element
  }
  Full = W;
  while (Esize < 64) {
    Full |= Full << Esize;
    Esize <<= 1;
  }
  *Wmask = Full;

  // tmask = Replicate{Ones{d+1}}, d = (s - r) mod 2^len
  T = ((S + 64 - R) & Levels);                    // diff<len-1:0>
  *Tmask = (T + 1 == 64) ? ~0ULL : (((UINT64)1 << (T + 1)) - 1);
  return TRUE;
}

STATIC CONST CHAR8 *CondNames[16] = {
  "EQ", "NE", "CS", "CC", "MI", "PL", "VS", "VC",
  "HI", "LS", "GE", "LT", "GT", "LE", "AL", "NV"
};

STATIC CONST CHAR8 *ShiftNames[4] = { "lsl", "lsr", "asr", "ror" };

// x86 Jcc opcodes for each ARM condition (taken semantics), valid after a
// compare/test that mirrors the ARM flags; JccFalse is the inverse.  AL maps
// to JMP (always taken), NV to 0x00 (never fires).
// x86 CMP/SUB leave CF = borrow, i.e. CF = NOT ARM C; the CS/LO conditions
// follow that convention (CS -> JNC, LO -> JB), as do HI/LS via JA/JBE.
STATIC UINT8 CondJccTrue[16]  = { 0x74, 0x75, 0x73, 0x72, 0x78, 0x79, 0x70, 0x71,
                                  0x77, 0x76, 0x7D, 0x7C, 0x7F, 0x7E, 0xEB, 0x00 };
STATIC UINT8 CondJccFalse[16] = { 0x75, 0x74, 0x72, 0x73, 0x79, 0x78, 0x71, 0x70,
                                  0x76, 0x77, 0x7C, 0x7D, 0x7E, 0x7F, 0x00, 0xEB };
// EQ NE CS CC MI PL VS VC HI LS GE LT GT LE AL NV

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

//
// Emit:  gDbtHelperVa = RCX;  RAX = DbtMapHostAddr();
// The guest effective address is delivered to the host helper through the
// global instead of a register so the call needs no ABI.  RAX returns the
// host address corresponding to the guest VA (identity for non-image VAs).
//
STATIC VOID EmitCallMapHelper (UINT8 **P) {
  EmitMovImm(P, (UINT64)(UINTN)&gDbtHelperVa);   // RAX = &gDbtHelperVa
  EmitRexW(P); EmitByte(P, 0x89); EmitByte(P, 0x08);      // MOV [RAX], RCX
  EmitMovImm(P, (UINT64)(UINTN)DbtMapHostAddr);           // RAX = DbtMapHostAddr
  EmitByte(P, 0xFF); EmitByte(P, 0xD0);                   // CALL RAX
}

//
// Emit the load/store once RAX holds the mapped host address.
//   Size: 0=B, 1=H, 2=W, 3=X    Opc: 0=STR, 1=LDR, 2=LDRS (sign-extend),
//   3=PRFM (no access).  Sf is the 64-bit register form (W loads clear the
//   upper 32 bits).  RtOff holds the value for stores.
//
STATIC VOID EmitMemAccess (UINT8 **P, UINT32 Size, UINT32 Opc, BOOLEAN Sf, UINT32 RtOff) {
  if (Opc == 3) {          // PRFM — prefetch, no architectural effect
    EmitNop(P);
    return;
  }
  if (Opc == 0) {          // STR
    EmitLoadRcx(P, RtOff); // RCX = value
    if (Size == 0) { EmitByte(P, 0x88); EmitByte(P, 0x08); }              // MOV [RAX], CL
    else if (Size == 1) { EmitByte(P, 0x66); EmitByte(P, 0x89); EmitByte(P, 0x08); }  // MOV [RAX], CX
    else if (Size == 2) { EmitByte(P, 0x89); EmitByte(P, 0x08); }        // MOV [RAX], ECX
    else { EmitRexW(P); EmitByte(P, 0x89); EmitByte(P, 0x08); }          // MOV [RAX], RCX
    return;
  }
  // LDR / LDRSB / LDRSH / LDRSW
  if (Opc == 1) {
    if (Size == 0) { EmitByte(P, 0x0F); EmitByte(P, 0xB6); EmitByte(P, 0x00); }  // MOVZX EAX, [RAX]
    else if (Size == 1) { EmitByte(P, 0x0F); EmitByte(P, 0xB7); EmitByte(P, 0x00); }  // MOVZX EAX, [RAX]
    else if (Size == 2) { EmitByte(P, 0x8B); EmitByte(P, 0x00); }        // MOV EAX, [RAX]
    else { EmitRexW(P); EmitByte(P, 0x8B); EmitByte(P, 0x00); }          // MOV RAX, [RAX]
  } else {
    if (Size == 0) {
      if (Sf) { EmitRexW(P); }                                            // MOVSX r64, [RAX]
      EmitByte(P, 0x0F); EmitByte(P, 0xBE); EmitByte(P, 0x00);
    } else if (Size == 1) {
      if (Sf) { EmitRexW(P); }                                            // MOVSX r64, [RAX]
      EmitByte(P, 0x0F); EmitByte(P, 0xBF); EmitByte(P, 0x00);
    } else {
      EmitRexW(P); EmitByte(P, 0x63); EmitByte(P, 0x00);                  // MOVSX RAX, dword [RAX]
    }
  }
  EmitStoreRax(P, RtOff);
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
STATIC VOID EmitStoreRcx (UINT8 **P, UINT32 Off) {
  EmitRexW(P); EmitByte(P, 0x89);  // MOV r/m64, r64
  if (Off < 128) { EmitByte(P, 0x4B); EmitByte(P, (UINT8)Off); }
  else { EmitByte(P, 0x8B); EmitDword(P, Off); }
}

// =========== Extended integer emitters ===========

// MOV RCX, imm64
STATIC VOID EmitMovRcxImm (UINT8 **P, UINT64 Val) {
  EmitRexW(P); EmitByte(P, 0xB9); EmitQword(P, Val);
}

// AND/OR/XOR/ADD/SUB RAX, RCX
STATIC VOID EmitAndRaxRcx (UINT8 **P) { EmitRexW(P); EmitByte(P, 0x21); EmitByte(P, 0xC8); }
STATIC VOID EmitOrRaxRcx  (UINT8 **P) { EmitRexW(P); EmitByte(P, 0x09); EmitByte(P, 0xC8); }
STATIC VOID EmitXorRaxRcx (UINT8 **P) { EmitRexW(P); EmitByte(P, 0x31); EmitByte(P, 0xC8); }
STATIC VOID EmitAddRaxRcx (UINT8 **P) { EmitRexW(P); EmitByte(P, 0x01); EmitByte(P, 0xC8); }
STATIC VOID EmitSubRaxRcx (UINT8 **P) { EmitRexW(P); EmitByte(P, 0x29); EmitByte(P, 0xC8); }

// ADD RCX, RAX
STATIC VOID EmitAddRcxRax (UINT8 **P) { EmitRexW(P); EmitByte(P, 0x01); EmitByte(P, 0xC1); }

// AND RCX, [RBX+off]  /  AND RCX, RAX
STATIC VOID EmitAndRcxMem (UINT8 **P, UINT32 Off) {
  EmitRexW(P); EmitByte(P, 0x23);  // AND r64, r/m64
  if (Off < 128) { EmitByte(P, 0x4B); EmitByte(P, (UINT8)Off); }
  else { EmitByte(P, 0x8B); EmitDword(P, Off); }
}

// Shifts of RAX / RCX by immediate
STATIC VOID EmitShlRaxImm (UINT8 **P, UINT8 Cnt) { EmitRexW(P); EmitByte(P, 0xC1); EmitByte(P, 0xE0); EmitByte(P, Cnt); }
STATIC VOID EmitShrRaxImm (UINT8 **P, UINT8 Cnt) { EmitRexW(P); EmitByte(P, 0xC1); EmitByte(P, 0xE8); EmitByte(P, Cnt); }
STATIC VOID EmitSarRaxImm (UINT8 **P, UINT8 Cnt) { EmitRexW(P); EmitByte(P, 0xC1); EmitByte(P, 0xF8); EmitByte(P, Cnt); }
STATIC VOID EmitRorRaxImm (UINT8 **P, UINT8 Cnt) { EmitRexW(P); EmitByte(P, 0xC1); EmitByte(P, 0xC8); EmitByte(P, Cnt); }
STATIC VOID EmitShlRcxImm (UINT8 **P, UINT8 Cnt) { EmitRexW(P); EmitByte(P, 0xC1); EmitByte(P, 0xE1); EmitByte(P, Cnt); }
STATIC VOID EmitShrRcxImm (UINT8 **P, UINT8 Cnt) { EmitRexW(P); EmitByte(P, 0xC1); EmitByte(P, 0xE9); EmitByte(P, Cnt); }
STATIC VOID EmitSarRcxImm (UINT8 **P, UINT8 Cnt) { EmitRexW(P); EmitByte(P, 0xC1); EmitByte(P, 0xF9); EmitByte(P, Cnt); }
STATIC VOID EmitRorRcxImm (UINT8 **P, UINT8 Cnt) { EmitRexW(P); EmitByte(P, 0xC1); EmitByte(P, 0xC9); EmitByte(P, Cnt); }

// Apply a recorded register-form shift (1=LSL 2=LSR 3=ASR 4=ROR)
STATIC VOID EmitShiftRcx (UINT8 **P, UINT8 Kind, UINT8 Amt) {
  if (Kind == 0 || Amt == 0) { return; }
  if (Kind == 1) { EmitShlRcxImm(P, Amt); }
  else if (Kind == 2) { EmitShrRcxImm(P, Amt); }
  else if (Kind == 3) { EmitSarRcxImm(P, Amt); }
  else { EmitRorRcxImm(P, Amt); }
}

// Apply a recorded register-form shift to RAX (same kinds)
STATIC VOID EmitShiftRax (UINT8 **P, UINT8 Kind, UINT8 Amt) {
  if (Kind == 0 || Amt == 0) { return; }
  if (Kind == 1) { EmitShlRaxImm(P, Amt); }
  else if (Kind == 2) { EmitShrRaxImm(P, Amt); }
  else if (Kind == 3) { EmitSarRaxImm(P, Amt); }
  else { EmitRorRaxImm(P, Amt); }
}

// Variable shifts of RAX by CL
STATIC VOID EmitShlRaxCl (UINT8 **P) { EmitRexW(P); EmitByte(P, 0xD3); EmitByte(P, 0xE0); }
STATIC VOID EmitShrRaxCl (UINT8 **P) { EmitRexW(P); EmitByte(P, 0xD3); EmitByte(P, 0xE8); }
STATIC VOID EmitSarRaxCl (UINT8 **P) { EmitRexW(P); EmitByte(P, 0xD3); EmitByte(P, 0xF8); }
STATIC VOID EmitRorRaxCl (UINT8 **P) { EmitRexW(P); EmitByte(P, 0xD3); EmitByte(P, 0xC8); }

// NOT / NEG RAX, zero-extend EAX (32-bit truncation)
STATIC VOID EmitNotRax (UINT8 **P) { EmitRexW(P); EmitByte(P, 0xF7); EmitByte(P, 0xD0); }
STATIC VOID EmitNegRax (UINT8 **P) { EmitRexW(P); EmitByte(P, 0xF7); EmitByte(P, 0xD8); }
STATIC VOID EmitNotRcx (UINT8 **P) { EmitRexW(P); EmitByte(P, 0xF7); EmitByte(P, 0xD1); }
STATIC VOID EmitTrunc32 (UINT8 **P) { EmitByte(P, 0x89); EmitByte(P, 0xC0); }  // MOV EAX, EAX

// IMUL RAX, RCX  (64-bit signed) / SHRD RAX, RCX, imm
STATIC VOID EmitImulRaxRcx (UINT8 **P) { EmitRexW(P); EmitByte(P, 0x0F); EmitByte(P, 0xAF); EmitByte(P, 0xC1); }
STATIC VOID EmitShrdRaxRcxImm (UINT8 **P, UINT8 Cnt) { EmitRexW(P); EmitByte(P, 0x0F); EmitByte(P, 0xAC); EmitByte(P, 0xC1); EmitByte(P, Cnt); }

// ADC / SBB RAX, RCX  (reads/writes CF)
STATIC VOID EmitAdcRaxRcx (UINT8 **P) { EmitRexW(P); EmitByte(P, 0x11); EmitByte(P, 0xC8); }
STATIC VOID EmitSbbRaxRcx (UINT8 **P) { EmitRexW(P); EmitByte(P, 0x19); EmitByte(P, 0xC8); }
STATIC VOID EmitCmc (UINT8 **P) { EmitByte(P, 0xF5); }

// Signed/unsigned 64-bit division: RAX / RCX -> RAX (requires RDX pre-set)
STATIC VOID EmitCqo (UINT8 **P) { EmitRexW(P); EmitByte(P, 0x99); }
STATIC VOID EmitIdivRcx (UINT8 **P) { EmitRexW(P); EmitByte(P, 0xF7); EmitByte(P, 0xF9); }
STATIC VOID EmitDivRcx (UINT8 **P) { EmitRexW(P); EmitByte(P, 0xF7); EmitByte(P, 0xF1); }
STATIC VOID EmitXorRdxRdx (UINT8 **P) { EmitRexW(P); EmitByte(P, 0x31); EmitByte(P, 0xD2); }

// MOV DL, [RBX+off]  (PSTATE access), TEST RAX, RAX
STATIC VOID EmitLoadRdlMem (UINT8 **P, UINT32 Off) {
  EmitByte(P, 0x8A);
  if (Off < 128) { EmitByte(P, 0x53); EmitByte(P, (UINT8)Off); }
  else { EmitByte(P, 0x93); EmitDword(P, Off); }
}
STATIC VOID EmitTestRaxRax (UINT8 **P) { EmitRexW(P); EmitByte(P, 0x85); EmitByte(P, 0xC0); }

// CMOVcc RAX, RCX — cc is the Jcc encoding (0x44+z for CMOV)
STATIC VOID EmitCmovRaxRcx (UINT8 **P, UINT8 Jcc) {
  EmitRexW(P); EmitByte(P, 0x0F); EmitByte(P, (UINT8)(0x40 + (Jcc & 0x0F))); EmitByte(P, 0xC1);
}

// BT RAX, imm8 (CF = RAX<imm>) / SBB RDX, RDX (RDX = -CF)
STATIC VOID EmitBitTestRax (UINT8 **P, UINT8 Bit) {
  EmitRexW(P); EmitByte(P, 0x0F); EmitByte(P, 0xBA); EmitByte(P, 0xE0); EmitByte(P, Bit);
}
STATIC VOID EmitSbbRdxRdx (UINT8 **P) { EmitRexW(P); EmitByte(P, 0x19); EmitByte(P, 0xD2); }
STATIC VOID EmitAndRdxRcx (UINT8 **P) { EmitRexW(P); EmitByte(P, 0x21); EmitByte(P, 0xCA); }
STATIC VOID EmitOrRaxRdx  (UINT8 **P) { EmitRexW(P); EmitByte(P, 0x09); EmitByte(P, 0xD0); }

// =========== XMM (SIMD/FP) emitters ===========
// All scalar S/D ops operate on XMM0 with a memory operand in the state.
// Qlo[32]/Qhi[32] hold V0-V31; scalar S uses Qlo[Rt][31:0], D uses Qlo[Rt].

// MOVSD/MOVSS XMM0, [RBX+off]  and  [RBX+off], XMM0
STATIC VOID EmitMovsdXmm0Mem (UINT8 **P, UINT32 Off) {
  EmitByte(P, 0xF2); EmitByte(P, 0x0F); EmitByte(P, 0x10);
  if (Off < 128) { EmitByte(P, 0x43); EmitByte(P, (UINT8)Off); }
  else { EmitByte(P, 0x83); EmitDword(P, Off); }
}
STATIC VOID EmitMovsdMemXmm0 (UINT8 **P, UINT32 Off) {
  EmitByte(P, 0xF2); EmitByte(P, 0x0F); EmitByte(P, 0x11);
  if (Off < 128) { EmitByte(P, 0x43); EmitByte(P, (UINT8)Off); }
  else { EmitByte(P, 0x83); EmitDword(P, Off); }
}
STATIC VOID EmitMovssXmm0Mem (UINT8 **P, UINT32 Off) {
  EmitByte(P, 0xF3); EmitByte(P, 0x0F); EmitByte(P, 0x10);
  if (Off < 128) { EmitByte(P, 0x43); EmitByte(P, (UINT8)Off); }
  else { EmitByte(P, 0x83); EmitDword(P, Off); }
}
STATIC VOID EmitMovssMemXmm0 (UINT8 **P, UINT32 Off) {
  EmitByte(P, 0xF3); EmitByte(P, 0x0F); EmitByte(P, 0x11);
  if (Off < 128) { EmitByte(P, 0x43); EmitByte(P, (UINT8)Off); }
  else { EmitByte(P, 0x83); EmitDword(P, Off); }
}

// FADD/FSUB/FMUL/FDIV/FSQRT/FCMP XMM0, [RBX+off]
STATIC VOID EmitAddsdMem (UINT8 **P, UINT32 Off) {
  EmitByte(P, 0xF2); EmitByte(P, 0x0F); EmitByte(P, 0x58);
  if (Off < 128) { EmitByte(P, 0x43); EmitByte(P, (UINT8)Off); }
  else { EmitByte(P, 0x83); EmitDword(P, Off); }
}
STATIC VOID EmitSubsdMem (UINT8 **P, UINT32 Off) {
  EmitByte(P, 0xF2); EmitByte(P, 0x0F); EmitByte(P, 0x5C);
  if (Off < 128) { EmitByte(P, 0x43); EmitByte(P, (UINT8)Off); }
  else { EmitByte(P, 0x83); EmitDword(P, Off); }
}
STATIC VOID EmitMulsdMem (UINT8 **P, UINT32 Off) {
  EmitByte(P, 0xF2); EmitByte(P, 0x0F); EmitByte(P, 0x59);
  if (Off < 128) { EmitByte(P, 0x43); EmitByte(P, (UINT8)Off); }
  else { EmitByte(P, 0x83); EmitDword(P, Off); }
}
STATIC VOID EmitDivsdMem (UINT8 **P, UINT32 Off) {
  EmitByte(P, 0xF2); EmitByte(P, 0x0F); EmitByte(P, 0x5E);
  if (Off < 128) { EmitByte(P, 0x43); EmitByte(P, (UINT8)Off); }
  else { EmitByte(P, 0x83); EmitDword(P, Off); }
}
STATIC VOID EmitSqrtsdMem (UINT8 **P, UINT32 Off) {
  EmitByte(P, 0xF2); EmitByte(P, 0x0F); EmitByte(P, 0x51);
  if (Off < 128) { EmitByte(P, 0x43); EmitByte(P, (UINT8)Off); }
  else { EmitByte(P, 0x83); EmitDword(P, Off); }
}
STATIC VOID EmitComisdMem (UINT8 **P, UINT32 Off) {
  EmitByte(P, 0x66); EmitByte(P, 0x0F); EmitByte(P, 0x2F);
  if (Off < 128) { EmitByte(P, 0x43); EmitByte(P, (UINT8)Off); }
  else { EmitByte(P, 0x83); EmitDword(P, Off); }
}
// S-precision variants
STATIC VOID EmitAddssMem (UINT8 **P, UINT32 Off) {
  EmitByte(P, 0xF3); EmitByte(P, 0x0F); EmitByte(P, 0x58);
  if (Off < 128) { EmitByte(P, 0x43); EmitByte(P, (UINT8)Off); }
  else { EmitByte(P, 0x83); EmitDword(P, Off); }
}
STATIC VOID EmitSubssMem (UINT8 **P, UINT32 Off) {
  EmitByte(P, 0xF3); EmitByte(P, 0x0F); EmitByte(P, 0x5C);
  if (Off < 128) { EmitByte(P, 0x43); EmitByte(P, (UINT8)Off); }
  else { EmitByte(P, 0x83); EmitDword(P, Off); }
}
STATIC VOID EmitMulssMem (UINT8 **P, UINT32 Off) {
  EmitByte(P, 0xF3); EmitByte(P, 0x0F); EmitByte(P, 0x59);
  if (Off < 128) { EmitByte(P, 0x43); EmitByte(P, (UINT8)Off); }
  else { EmitByte(P, 0x83); EmitDword(P, Off); }
}
STATIC VOID EmitDivssMem (UINT8 **P, UINT32 Off) {
  EmitByte(P, 0xF3); EmitByte(P, 0x0F); EmitByte(P, 0x5E);
  if (Off < 128) { EmitByte(P, 0x43); EmitByte(P, (UINT8)Off); }
  else { EmitByte(P, 0x83); EmitDword(P, Off); }
}
STATIC VOID EmitSqrtssMem (UINT8 **P, UINT32 Off) {
  EmitByte(P, 0xF3); EmitByte(P, 0x0F); EmitByte(P, 0x51);
  if (Off < 128) { EmitByte(P, 0x43); EmitByte(P, (UINT8)Off); }
  else { EmitByte(P, 0x83); EmitDword(P, Off); }
}
STATIC VOID EmitComissMem (UINT8 **P, UINT32 Off) {
  EmitByte(P, 0x66); EmitByte(P, 0x0F); EmitByte(P, 0x2F);
  if (Off < 128) { EmitByte(P, 0x43); EmitByte(P, (UINT8)Off); }
  else { EmitByte(P, 0x83); EmitDword(P, Off); }
}

// CVTSS2SD / CVTSD2SS XMM0, XMM0  (in-place precision conversion)
STATIC VOID EmitCvtss2sd (UINT8 **P) { EmitByte(P, 0xF3); EmitByte(P, 0x0F); EmitByte(P, 0x5A); EmitByte(P, 0xC0); }
STATIC VOID EmitCvtsd2ss (UINT8 **P) { EmitByte(P, 0xF2); EmitByte(P, 0x0F); EmitByte(P, 0x5A); EmitByte(P, 0xC0); }

// CVTSI2SD XMM0, RAX (64-bit int -> double), CVTTSD2SI RAX, XMM0 (double -> int64)
STATIC VOID EmitCvtsi2sdRax (UINT8 **P) { EmitByte(P, 0xF2); EmitRexW(P); EmitByte(P, 0x0F); EmitByte(P, 0x2A); EmitByte(P, 0xC0); }
STATIC VOID EmitCvttsd2siRax (UINT8 **P) { EmitByte(P, 0xF2); EmitRexW(P); EmitByte(P, 0x0F); EmitByte(P, 0x2C); EmitByte(P, 0xC0); }

// MOVDQU XMM0, [RAX] / [RAX], XMM0  (128-bit guest memory access)
STATIC VOID EmitMovdquXmm0Rax (UINT8 **P) { EmitByte(P, 0x66); EmitByte(P, 0x0F); EmitByte(P, 0x6F); EmitByte(P, 0x00); }
STATIC VOID EmitMovdquRaxXmm0 (UINT8 **P) { EmitByte(P, 0x66); EmitByte(P, 0x0F); EmitByte(P, 0x7F); EmitByte(P, 0x00); }

// MOVQ XMM0, RAX / RAX, XMM0  (64-bit int <-> vector)
STATIC VOID EmitMovqXmm0Rax (UINT8 **P) { EmitByte(P, 0x66); EmitRexW(P); EmitByte(P, 0x0F); EmitByte(P, 0x6E); EmitByte(P, 0xC0); }
STATIC VOID EmitMovqRaxXmm0 (UINT8 **P) { EmitByte(P, 0x66); EmitRexW(P); EmitByte(P, 0x0F); EmitByte(P, 0x7E); EmitByte(P, 0xC0); }
// MOVQ XMM0, [RBX+off] / [RBX+off], XMM0  (context slot)
STATIC VOID EmitMovqXmm0Mem (UINT8 **P, UINT32 Off) {
  EmitByte(P, 0x66); EmitRexW(P); EmitByte(P, 0x0F); EmitByte(P, 0x6E);
  if (Off < 128) { EmitByte(P, 0x43); EmitByte(P, (UINT8)Off); }
  else { EmitByte(P, 0x83); EmitDword(P, Off); }
}
STATIC VOID EmitMovqMemXmm0 (UINT8 **P, UINT32 Off) {
  EmitByte(P, 0x66); EmitRexW(P); EmitByte(P, 0x0F); EmitByte(P, 0x7E);
  if (Off < 128) { EmitByte(P, 0x43); EmitByte(P, (UINT8)Off); }
  else { EmitByte(P, 0x83); EmitDword(P, Off); }
}
// MOVHPS [RBX+off], XMM0  (high 64 bits to context)
STATIC VOID EmitMovhpsMemXmm0 (UINT8 **P, UINT32 Off) {
  EmitByte(P, 0x0F); EmitByte(P, 0x17);
  if (Off < 128) { EmitByte(P, 0x43); EmitByte(P, (UINT8)Off); }
  else { EmitByte(P, 0x83); EmitDword(P, Off); }
}
STATIC VOID EmitMovhpsXmm0Mem (UINT8 **P, UINT32 Off) {
  EmitByte(P, 0x0F); EmitByte(P, 0x16);
  if (Off < 128) { EmitByte(P, 0x43); EmitByte(P, (UINT8)Off); }
  else { EmitByte(P, 0x83); EmitDword(P, Off); }
}

// PADDB/PADDW/PADDD/PADDQ and PSUBB.. XMM0, [RBX+off]
STATIC VOID EmitPaddbMem (UINT8 **P, UINT32 Off) {
  EmitByte(P, 0x66); EmitByte(P, 0x0F); EmitByte(P, 0xFC);
  if (Off < 128) { EmitByte(P, 0x43); EmitByte(P, (UINT8)Off); }
  else { EmitByte(P, 0x83); EmitDword(P, Off); }
}
STATIC VOID EmitPaddwMem (UINT8 **P, UINT32 Off) {
  EmitByte(P, 0x66); EmitByte(P, 0x0F); EmitByte(P, 0xFD);
  if (Off < 128) { EmitByte(P, 0x43); EmitByte(P, (UINT8)Off); }
  else { EmitByte(P, 0x83); EmitDword(P, Off); }
}
STATIC VOID EmitPadddMem (UINT8 **P, UINT32 Off) {
  EmitByte(P, 0x66); EmitByte(P, 0x0F); EmitByte(P, 0xFE);
  if (Off < 128) { EmitByte(P, 0x43); EmitByte(P, (UINT8)Off); }
  else { EmitByte(P, 0x83); EmitDword(P, Off); }
}
STATIC VOID EmitPaddqMem (UINT8 **P, UINT32 Off) {
  EmitByte(P, 0x66); EmitByte(P, 0x0F); EmitByte(P, 0xD4);
  if (Off < 128) { EmitByte(P, 0x43); EmitByte(P, (UINT8)Off); }
  else { EmitByte(P, 0x83); EmitDword(P, Off); }
}
STATIC VOID EmitPsubbMem (UINT8 **P, UINT32 Off) {
  EmitByte(P, 0x66); EmitByte(P, 0x0F); EmitByte(P, 0xF8);
  if (Off < 128) { EmitByte(P, 0x43); EmitByte(P, (UINT8)Off); }
  else { EmitByte(P, 0x83); EmitDword(P, Off); }
}
STATIC VOID EmitPsubwMem (UINT8 **P, UINT32 Off) {
  EmitByte(P, 0x66); EmitByte(P, 0x0F); EmitByte(P, 0xF9);
  if (Off < 128) { EmitByte(P, 0x43); EmitByte(P, (UINT8)Off); }
  else { EmitByte(P, 0x83); EmitDword(P, Off); }
}
STATIC VOID EmitPsubdMem (UINT8 **P, UINT32 Off) {
  EmitByte(P, 0x66); EmitByte(P, 0x0F); EmitByte(P, 0xFA);
  if (Off < 128) { EmitByte(P, 0x43); EmitByte(P, (UINT8)Off); }
  else { EmitByte(P, 0x83); EmitDword(P, Off); }
}
STATIC VOID EmitPsubqMem (UINT8 **P, UINT32 Off) {
  EmitByte(P, 0x66); EmitByte(P, 0x0F); EmitByte(P, 0xFB);
  if (Off < 128) { EmitByte(P, 0x43); EmitByte(P, (UINT8)Off); }
  else { EmitByte(P, 0x83); EmitDword(P, Off); }
}
// PAND/POR/PXOR/PANDN XMM0, [RBX+off]
STATIC VOID EmitPandMem (UINT8 **P, UINT32 Off) {
  EmitByte(P, 0x66); EmitByte(P, 0x0F); EmitByte(P, 0xDB);
  if (Off < 128) { EmitByte(P, 0x43); EmitByte(P, (UINT8)Off); }
  else { EmitByte(P, 0x83); EmitDword(P, Off); }
}
STATIC VOID EmitPorMem (UINT8 **P, UINT32 Off) {
  EmitByte(P, 0x66); EmitByte(P, 0x0F); EmitByte(P, 0xEB);
  if (Off < 128) { EmitByte(P, 0x43); EmitByte(P, (UINT8)Off); }
  else { EmitByte(P, 0x83); EmitDword(P, Off); }
}
STATIC VOID EmitPxorMem (UINT8 **P, UINT32 Off) {
  EmitByte(P, 0x66); EmitByte(P, 0x0F); EmitByte(P, 0xEF);
  if (Off < 128) { EmitByte(P, 0x43); EmitByte(P, (UINT8)Off); }
  else { EmitByte(P, 0x83); EmitDword(P, Off); }
}
STATIC VOID EmitPandnMem (UINT8 **P, UINT32 Off) {
  EmitByte(P, 0x66); EmitByte(P, 0x0F); EmitByte(P, 0xDF);
  if (Off < 128) { EmitByte(P, 0x43); EmitByte(P, (UINT8)Off); }
  else { EmitByte(P, 0x83); EmitDword(P, Off); }
}
// PSHUFB XMM0, XMM0, imm (SSSE3) / PUNPCKLBW XMM0, XMM0 / PUNPCKLDQ / PUNPCKLQDQ
STATIC VOID EmitPshufdXmm0Imm (UINT8 **P, UINT8 Imm) {
  EmitByte(P, 0x66); EmitByte(P, 0x0F); EmitByte(P, 0x70); EmitByte(P, 0xC0); EmitByte(P, Imm);
}
STATIC VOID EmitPunpcklbwXmm0Xmm0 (UINT8 **P) { EmitByte(P, 0x66); EmitByte(P, 0x0F); EmitByte(P, 0x60); EmitByte(P, 0xC0); }
STATIC VOID EmitPunpcklwdXmm0Xmm0 (UINT8 **P) { EmitByte(P, 0x66); EmitByte(P, 0x0F); EmitByte(P, 0x61); EmitByte(P, 0xC0); }
STATIC VOID EmitPunpckldqXmm0Xmm0 (UINT8 **P) { EmitByte(P, 0x66); EmitByte(P, 0x0F); EmitByte(P, 0x62); EmitByte(P, 0xC0); }
STATIC VOID EmitPunpcklqdqXmm0Xmm0 (UINT8 **P) { EmitByte(P, 0x66); EmitByte(P, 0x0F); EmitByte(P, 0x6C); EmitByte(P, 0xC0); }

// XORPS XMM0, XMM0  (zero)
STATIC VOID EmitXorpsXmm0Xmm0 (UINT8 **P) { EmitByte(P, 0x0F); EmitByte(P, 0x57); EmitByte(P, 0xC0); }

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
// Emit a decision on ARM condition Cond using the PSTATE byte already
// loaded into AL (N=0x80 Z=0x40 C=0x01; V is assumed clear, matching the
// boot kernel's usage): jumps to *Lfalse when Cond is FALSE, falls through
// when TRUE.  Uses EmitJccSlot so *Lfalse is patchable; internal skip
// labels are patched to local targets.
//
STATIC VOID EmitCondTrueFromPstate (UINT8 **P, UINT32 Cond, UINT8 **Lfalse) {
  UINT8 *Skip = NULL;
  UINT8  NoTargets[1] = { 0 };

  switch (Cond) {
    case 0:   EmitByte(P, 0xF6); EmitByte(P, 0xC0); EmitByte(P, 0x40);   // EQ  — TEST AL, Z
              EmitJccSlot(P, 0x74, Lfalse); break;
    case 1:   EmitByte(P, 0xF6); EmitByte(P, 0xC0); EmitByte(P, 0x40);   // NE
              EmitJccSlot(P, 0x75, Lfalse); break;
    case 2:   EmitByte(P, 0xF6); EmitByte(P, 0xC0); EmitByte(P, 0x01);   // CS  — TEST AL, C
              EmitJccSlot(P, 0x74, Lfalse); break;
    case 3:   EmitByte(P, 0xF6); EmitByte(P, 0xC0); EmitByte(P, 0x01);   // CC
              EmitJccSlot(P, 0x75, Lfalse); break;
    case 4:   EmitByte(P, 0xF6); EmitByte(P, 0xC0); EmitByte(P, 0x80);   // MI  — TEST AL, N
              EmitJccSlot(P, 0x74, Lfalse); break;
    case 5:   EmitByte(P, 0xF6); EmitByte(P, 0xC0); EmitByte(P, 0x80);   // PL
              EmitJccSlot(P, 0x75, Lfalse); break;
    case 6:   EmitJccSlot(P, 0xEB, Lfalse); break;                       // VS — never taken
    case 7:   break;                                                     // VC — always taken
    case 8:   EmitByte(P, 0xF6); EmitByte(P, 0xC0); EmitByte(P, 0x01);   // HI  — C && !Z
              EmitJccSlot(P, 0x74, Lfalse);
              EmitByte(P, 0xF6); EmitByte(P, 0xC0); EmitByte(P, 0x40);
              EmitJccSlot(P, 0x75, Lfalse); break;
    case 9:   EmitByte(P, 0xF6); EmitByte(P, 0xC0); EmitByte(P, 0x01);   // LS  — !C || Z
              EmitJccSlot(P, 0x74, &Skip);                               // C=0 -> true
              EmitByte(P, 0xF6); EmitByte(P, 0xC0); EmitByte(P, 0x40);
              EmitJccSlot(P, 0x74, Lfalse); break;                       // C=1 && Z=0 -> false
    case 0xA: EmitByte(P, 0xF6); EmitByte(P, 0xC0); EmitByte(P, 0x80);   // GE  — !N (V=0)
              EmitJccSlot(P, 0x75, Lfalse); break;
    case 0xB: EmitByte(P, 0xF6); EmitByte(P, 0xC0); EmitByte(P, 0x80);   // LT  — N
              EmitJccSlot(P, 0x74, Lfalse); break;
    case 0xC: EmitByte(P, 0xF6); EmitByte(P, 0xC0); EmitByte(P, 0x40);   // GT  — !Z && !N
              EmitJccSlot(P, 0x75, Lfalse);
              EmitByte(P, 0xF6); EmitByte(P, 0xC0); EmitByte(P, 0x80);
              EmitJccSlot(P, 0x75, Lfalse); break;
    case 0xD: EmitByte(P, 0xF6); EmitByte(P, 0xC0); EmitByte(P, 0x40);   // LE  — Z || N
              EmitJccSlot(P, 0x75, &Skip);
              EmitByte(P, 0xF6); EmitByte(P, 0xC0); EmitByte(P, 0x80);
              EmitJccSlot(P, 0x75, &Skip);
              EmitJccSlot(P, 0xEB, Lfalse); break;                       // Z=0 && N=0 -> false
    case 0xE: break;                                                     // AL — always taken
    default:  EmitJccSlot(P, 0xEB, Lfalse); break;                       // NV — never taken
  }

  if (Skip != NULL) {
    PatchJcc (&Skip, NoTargets, 1, *P, *P);
  }
}

// Set the x86 flags to the CCMP false-path NZCV constant (ARM layout
// N=8 Z=4 C=2 V=1).  Order: OF (add trick), then SF+ZF (mov+test), then CF
// (cmc); TEST does not modify OF or CF.
STATIC VOID EmitConstNzcv (UINT8 **P, UINT8 Nzcv) {
  if ((Nzcv & 1) != 0) {
    // OF = 1 via 0x8000000000000000 + 0x8000000000000000 overflow
    EmitRexW(P); EmitByte(P, 0xB8);
    EmitDword(P, 0); EmitDword(P, 0x80000000U);                          // mov rax, 0x8000000000000000
    EmitRexW(P); EmitByte(P, 0x05);
    EmitDword(P, 0); EmitDword(P, 0x80000000U);                          // add rax, 0x8000000000000000
  }
  EmitRexW(P); EmitByte(P, 0xB8);                                        // mov rax, imm64
  EmitDword(P, 0); EmitDword(P, 0);                                      // (patched below)
  {
    UINT8 *Patch = *P - 8;
    UINT64 Val = ((Nzcv & 8) != 0) ? 0x8000000000000000ULL
                 : (((Nzcv & 4) != 0) ? 0x0ULL : 0x1ULL);
    *((UINT64 *)Patch) = Val;
  }
  EmitRexW(P); EmitByte(P, 0x85); EmitByte(P, 0xC0);                     // test rax, rax -> SF=!N, ZF=Z
  if ((Nzcv & 2) != 0) {
    EmitByte(P, 0xF8);                                                   // clc -> CF=0 (ARM C=1)
  } else {
    EmitByte(P, 0xF9);                                                   // stc -> CF=1 (ARM C=0)
  }
}

//
// Recompute the NZCV flags of the recorded setter into the x86 flags.
// ADDSUB setters re-derive the operands (the result may have clobbered
// them); LOGICAL setters use TEST on the result, or AND of the operands
// for the XZR comparison forms.  CCMP setters first evaluate their gate
// condition from the previous setter (or PSTATE) and then either compare
// or materialize the constant NZCV.
//
STATIC VOID EmitComputeFlagsFromSet (UINT8 **Q, DBT_FLAG_SET *Set) {
  UINT32  RnOff;
  UINT32  RmOff;
  UINT8  *Lcmp = NULL;
  UINT8  *Ldone = NULL;
  UINT8   NoTargets[1] = { 0 };
  BOOLEAN IsLogical = (Set->Kind == FLAGKIND_LOGICAL);
  BOOLEAN Clobbered;

  if (Set->IsCcmp) {
    UINT8  *Lcmp        = NULL;
    UINT8  *Lconst      = NULL;
    UINT8  *LconstStart = NULL;
    UINT8  *Ldone1      = NULL;
    UINT8  *Ldone2      = NULL;
    UINT8  *CmpStart;
    UINT8   OneTargets[1] = { 1 };

    // Gate condition from the previous setter (recursively) or PSTATE.
    if (Set->HasPrev && Set->Prev != NULL && Set->Prev->HasSetter) {
      EmitComputeFlagsFromSet (Q, Set->Prev);
      EmitJccSlot (Q, CondJccTrue[Set->Cond], &Lcmp);
      // Gate FALSE: NZCV = constant, then done.
      EmitConstNzcv (Q, Set->Nzcv);
      EmitJccSlot (Q, 0xEB, &Ldone1);
    } else {
      EmitByte(Q, 0x8A); EmitByte(Q, 0x83); EmitDword(Q, (UINT32)(PstateOff() + 3));
      // Gate FALSE: jump to the constant (falls through to the compare when
      // the gate condition holds).
      EmitCondTrueFromPstate (Q, Set->Cond, &Lconst);
    }
    // Gate TRUE: compare the operands.
    CmpStart = *Q;
    if (Set->Rn == 31) { EmitMovImm(Q, 0); } else { EmitLoadRax(Q, (UINT32)ArmRegXOff(Set->Rn)); }
    if (Set->IsW) EmitTrunc32(Q);
    if (Set->HasReg2) {
      if (Set->Rm == 31) { EmitMovImm(Q, 0); } else { EmitLoadRcx(Q, (UINT32)ArmRegXOff(Set->Rm)); }
      if (Set->IsW) { EmitByte(Q, 0x89); EmitByte(Q, 0xC9); }
      EmitShiftRcx(Q, Set->ShiftKind, Set->ShiftAmt);
      if (Set->IsSub) { EmitCmpRaxRcx(Q); } else { EmitNegRcx(Q); EmitCmpRaxRcx(Q); EmitByte(Q, 0xF5); }
    } else if (Set->IsSub) {
      EmitCmpRaxImm32(Q, (UINT32)Set->Imm);
    } else {
      EmitCmpRaxImm32(Q, (UINT32)(-(INT64)Set->Imm));
      EmitByte(Q, 0xF5);
    }
    EmitJccSlot (Q, 0xEB, &Ldone2);
    if (Lconst != NULL) {
      LconstStart = *Q;
      EmitConstNzcv (Q, Set->Nzcv);
    }
    if (Lcmp != NULL) {
      PatchJcc (&Lcmp, OneTargets, 1, *Q, CmpStart);
    }
    if (Lconst != NULL) {
      PatchJcc (&Lconst, OneTargets, 1, *Q, LconstStart);
    }
    if (Ldone1 != NULL) {
      PatchJcc (&Ldone1, NoTargets, 1, *Q, *Q);
    }
    if (Ldone2 != NULL) {
      PatchJcc (&Ldone2, NoTargets, 1, *Q, *Q);
    }
    return;
  }

  // If the setter stored its result into Rn or Rm, the operands are gone and
  // we must reconstruct them.  For logical setters the result itself gives
  // exact N/Z (C/V are always clear), so a TEST on Rd suffices whenever the
  // result was stored; only the comparison forms (Rd == XZR) re-read
  // operands.  For add/sub, Z/N also equal the result's, but C/V need the
  // original operands: when Rd == Rn (Rd == XZR stores nothing and leaves
  // the operands intact), rebuild A = R -+ B from the result, then CMP.
  // W-form setters use 32-bit operations so N/V/C are computed on 32-bit
  // semantics.
  if (IsLogical) {
    Clobbered = FALSE;
    if (Set->Rd != 31) {
      EmitLoadRax(Q, (UINT32)ArmRegXOff(Set->Rd));
      if (Set->IsW) {
        EmitByte(Q, 0x85); EmitByte(Q, 0xC0);               // TEST EAX, EAX
      } else {
        EmitRexW(Q); EmitByte(Q, 0x85); EmitByte(Q, 0xC0);  // TEST RAX, RAX
      }
    } else {
      // Rd == XZR: result discarded; re-read operands (logical: XZR is 31)
      if (Set->Rn == 31) { EmitMovImm(Q, 0); } else { EmitLoadRax(Q, (UINT32)ArmRegXOff(Set->Rn)); }
      if (Set->Rm == 31) { EmitMovImm(Q, 0); } else { EmitLoadRcx(Q, (UINT32)ArmRegXOff(Set->Rm)); }
      EmitShiftRcx(Q, Set->ShiftKind, Set->ShiftAmt);
      if (Set->IsW) {
        EmitByte(Q, 0x21); EmitByte(Q, 0xC8);               // AND EAX, ECX
      } else {
        EmitAndRaxRcx(Q);
      }
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
      EmitLoadRax(Q, (UINT32)ArmRegXOff(Set->Rd));
      if (Set->HasReg2) {
        if (Set->Rm == 31) { EmitMovImm(Q, 0); } else { EmitLoadRcx(Q, RmOff); }
        EmitShiftRcx(Q, Set->ShiftKind, Set->ShiftAmt);
        if (Set->IsSub) {
          if (Set->IsW) { EmitByte(Q, 0x01); EmitByte(Q, 0xC8); }   // ADD EAX, ECX
          else { EmitAddRaxRcx(Q); }
        } else {
          if (Set->IsW) { EmitByte(Q, 0x29); EmitByte(Q, 0xC8); }   // SUB EAX, ECX
          else { EmitSubRaxRcx(Q); }
        }
      } else if (Set->IsSub) {
        if (Set->IsW) { EmitByte(Q, 0x05); EmitDword(Q, (UINT32)Set->Imm); }   // ADD EAX, imm32
        else { EmitAddImm(Q, (UINT32)Set->Imm); }
      } else {
        if (Set->IsW) { EmitByte(Q, 0x2D); EmitDword(Q, (UINT32)Set->Imm); }   // SUB EAX, imm32
        else { EmitSubImm(Q, (UINT32)Set->Imm); }
      }
    } else {
      EmitLoadRax(Q, RnOff);
    }

    if (Set->HasReg2) {
      if (Set->Rm == 31) { EmitMovImm(Q, 0); } else { EmitLoadRcx(Q, RmOff); }
      EmitShiftRcx(Q, Set->ShiftKind, Set->ShiftAmt);
      if (Set->IsSub) {
        if (Set->IsW) { EmitByte(Q, 0x39); EmitByte(Q, 0xC8); }   // CMP EAX, ECX
        else { EmitCmpRaxRcx(Q); }
      } else {
        if (Set->IsW) { EmitByte(Q, 0xF7); EmitByte(Q, 0xD9); }   // NEG ECX
        else { EmitNegRcx(Q); }
        if (Set->IsW) { EmitByte(Q, 0x39); EmitByte(Q, 0xC8); }
        else { EmitCmpRaxRcx(Q); }
        EmitByte(Q, 0xF5);                                       // cmc -> subtract convention
      }
    } else if (Set->IsSub) {
      if (Set->IsW) { EmitByte(Q, 0x3D); EmitDword(Q, (UINT32)Set->Imm); }   // CMP EAX, imm32
      else { EmitCmpRaxImm32(Q, (UINT32)Set->Imm); }
    } else {
      if (Set->IsW) { EmitByte(Q, 0x3D); EmitDword(Q, (UINT32)(-(INT64)Set->Imm)); }
      else { EmitCmpRaxImm32(Q, (UINT32)(-(INT64)Set->Imm)); }
      EmitByte(Q, 0xF5);                                       // cmc -> subtract convention
    }
  }
}

//
// Emit an ARM64 conditional branch decision from the recorded setter:
//   mov rax, Fallthrough; mov [rbx+PC], rax   — default: branch NOT taken
//   <flag reconstruction into x86 flags>
//   Jcc(skip) — fires when NOT taken, jumping over the Target store
//   mov rax, Target; mov [rbx+PC], rax        — overwrite when taken
//
STATIC UINTN EmitCondBranchFromSet (UINT8 **P, UINT32 Cond, UINT64 Target, UINT64 Fallthrough, DBT_FLAG_SET *Set) {
  UINT8  *Start = *P;
  UINT8   Seq[256];
  UINT8  *Q   = Seq;
  UINT8  *Ldone = NULL;
  UINT8   NoTargets[1] = { 0 };

  EmitMovImm(&Q, Fallthrough);
  EmitStoreRax(&Q, (UINT32)ArmRegPcOff());

  EmitComputeFlagsFromSet (&Q, Set);

  EmitJccSlot(&Q, CondJccFalse[Cond], &Ldone);

  EmitMovImm(&Q, Target);
  EmitStoreRax(&Q, (UINT32)ArmRegPcOff());

  PatchJcc (&Ldone, NoTargets, 1, Q, Q);

  CopyMem (*P, Seq, (UINTN)(Q - Seq));
  *P += (UINTN)(Q - Seq);
  return (UINTN)(*P - Start);
}

//
// Emit an ARM64 conditional branch decision from the PSTATE byte (no flag
// setter in the current block):
//   mov rax, Fallthrough; mov [rbx+PC], rax   — default: branch NOT taken
//   mov al, [rbx+PSTATE+3]                    — N=0x80, Z=0x40, C=0x01
//   <TEST AL, mask; Jcc>...                   — jump over the Target store
//                                              when the branch is NOT taken
//   mov rax, Target; mov [rbx+PC], rax        — overwrite when taken
//
STATIC UINTN EmitCondBranch (UINT8 **P, UINT32 Cond, UINT64 Target, UINT64 Fallthrough) {
  UINT8  *Start = *P;
  UINT8   Seq[64];
  UINT8  *Q   = Seq;
  UINT8  *Ldone = NULL;
  UINT8   NoTargets[1] = { 0 };

  EmitMovImm(&Q, Fallthrough);
  EmitStoreRax(&Q, (UINT32)ArmRegPcOff());

  // mov al, [rbx+PSTATE+3]
  EmitByte(&Q, 0x8A); EmitByte(&Q, 0x83); EmitDword(&Q, (UINT32)(PstateOff() + 3));

  EmitCondTrueFromPstate (&Q, Cond, &Ldone);

  EmitMovImm(&Q, Target);
  EmitStoreRax(&Q, (UINT32)ArmRegPcOff());

  PatchJcc (&Ldone, NoTargets, 1, Q, Q);

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
  IN UINT64       Imm,
  IN UINT8        ShiftKind,
  IN UINT8        ShiftAmt,
  IN BOOLEAN      IsW
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
  Ctx->FlagSet.ShiftKind = ShiftKind;
  Ctx->FlagSet.ShiftAmt  = ShiftAmt;
  Ctx->FlagSet.IsW       = IsW;
  Ctx->FlagSet.IsCcmp    = FALSE;
  Ctx->FlagSet.HasPrev   = FALSE;
}

//
// Record a CCMP/CCMN as the flag setter: its flags are the compare result
// when Cond holds against the previous setter's flags, or the constant
// NZCV otherwise.  Prev is the setter recorded before it, so same-block
// consumers can re-derive both paths.
//
STATIC VOID EmitRecordCcmp (
  IN DBT_CONTEXT *Ctx,
  IN BOOLEAN      IsSub,
  IN UINT8        Rd,
  IN UINT8        Rn,
  IN UINT8        Rm,
  IN BOOLEAN      HasReg2,
  IN UINT64       Imm,
  IN UINT8        ShiftKind,
  IN UINT8        ShiftAmt,
  IN BOOLEAN      IsW,
  IN UINT8        Cond,
  IN UINT8        Nzcv
  )
{
  if (Ctx->PrevCount < 8 && Ctx->FlagSet.HasSetter) {
    Ctx->PrevSlots[Ctx->PrevCount] = Ctx->FlagSet;
    Ctx->FlagSet.Prev = &Ctx->PrevSlots[Ctx->PrevCount++];
    Ctx->FlagSet.HasPrev = TRUE;
  } else {
    Ctx->FlagSet.Prev = NULL;
    Ctx->FlagSet.HasPrev = FALSE;
  }
  Ctx->FlagSet.HasSetter  = TRUE;
  Ctx->FlagSet.Kind       = FLAGKIND_ADDSUB;
  Ctx->FlagSet.IsSub      = IsSub;
  Ctx->FlagSet.LogicalOp  = 0;
  Ctx->FlagSet.Rd         = Rd;
  Ctx->FlagSet.Rn         = Rn;
  Ctx->FlagSet.Rm         = Rm;
  Ctx->FlagSet.HasReg2    = HasReg2;
  Ctx->FlagSet.Imm        = Imm;
  Ctx->FlagSet.ShiftKind  = ShiftKind;
  Ctx->FlagSet.ShiftAmt   = ShiftAmt;
  Ctx->FlagSet.IsW        = IsW;
  Ctx->FlagSet.IsCcmp     = TRUE;
  Ctx->FlagSet.Cond       = Cond;
  Ctx->FlagSet.Nzcv       = Nzcv;
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
// Host-side condition evaluation against a PSTATE-format flags byte
// (N=0x80, Z=0x40, V=0x10, C=0x01).  Returns TRUE when Cond holds.
STATIC BOOLEAN CondHolds (UINT32 Cond, UINT8 F) {
  switch (Cond) {
    case 0:   return (F & 0x40) != 0;
    case 1:   return (F & 0x40) == 0;
    case 2:   return (F & 0x01) != 0;
    case 3:   return (F & 0x01) == 0;
    case 4:   return (F & 0x80) != 0;
    case 5:   return (F & 0x80) == 0;
    case 6:   return FALSE;
    case 7:   return TRUE;
    case 8:   return (F & 0x01) != 0 && (F & 0x40) == 0;
    case 9:   return (F & 0x01) == 0 || (F & 0x40) != 0;
    case 0xA: return ((F & 0x80) != 0) == ((F & 0x10) != 0);  // GE: N==V
    case 0xB: return ((F & 0x80) != 0) != ((F & 0x10) != 0);  // LT: N!=V
    case 0xC: return (F & 0x40) == 0 && ((F & 0x80) != 0) == ((F & 0x10) != 0);  // GT
    case 0xD: return (F & 0x40) != 0 || ((F & 0x80) != 0) != ((F & 0x10) != 0);  // LE
    case 0xE: return TRUE;
    default:  return FALSE;
  }
}

// Convert an ARM-layout NZCV immediate (N=8 Z=4 C=2 V=1) to the PSTATE
// byte layout (N=0x80 Z=0x40 V=0x10 C=0x01).
STATIC UINT8 NzcvToPstate (UINT8 Nzcv) {
  UINT8 Byte = 0;
  Byte |= (Nzcv & 8) ? 0x80 : 0;
  Byte |= (Nzcv & 4) ? 0x40 : 0;
  Byte |= (Nzcv & 2) ? 0x01 : 0;
  Byte |= (Nzcv & 1) ? 0x10 : 0;
  return Byte;
}

//
// Compute NZCV for one flag set (recursively for CCMP) and return it as a
// PSTATE-format flags byte.
//
STATIC UINT8 DbtComputeNzcvSet (IN DBT_CONTEXT *Ctx, IN DBT_FLAG_SET *S) {
  UINT64        A, B, R, W;
  UINT8         Byte;
  BOOLEAN       N, Z, C, V;
  UINT8         PrevByte;
  BOOLEAN       CondTrue;

  if (!S->HasSetter) {
    return 0;
  }

  if (S->IsCcmp) {
    // Gate condition from the previous setter's flags (or the PSTATE byte);
    // the false path substitutes the constant NZCV.
    PrevByte = (S->HasPrev && S->Prev != NULL) ? DbtComputeNzcvSet (Ctx, S->Prev) : (UINT8)(Ctx->ArmState.PSTATE >> 24);
    CondTrue = CondHolds (S->Cond, PrevByte);
    if (!CondTrue) {
      return NzcvToPstate (S->Nzcv);
    }
  }

  // Rn==31 is SP in the immediate form, XZR in the register form.
  if (!S->HasReg2 && S->Rn == 31) {
    A = Ctx->ArmState.SP;
  } else {
    A = Ctx->ArmState.X[S->Rn];
  }
  if (S->HasReg2) {
    B = Ctx->ArmState.X[S->Rm];
    switch (S->ShiftKind) {
      case 1:  B = (S->ShiftAmt == 64) ? 0 : (B << S->ShiftAmt); break;
      case 2:  B = (S->ShiftAmt == 64) ? 0 : (B >> S->ShiftAmt); break;
      case 3:  B = (S->ShiftAmt == 64) ? (B >> 63) : ((INT64)B >> S->ShiftAmt); break;
      default: break;
    }
  } else {
    B = S->Imm;
  }

  if (S->IsW) {
    A &= 0xFFFFFFFFULL;
    B &= 0xFFFFFFFFULL;
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

  if (S->IsW) {
    R &= 0xFFFFFFFFULL;
    N = ((R & 0x80000000ULL) != 0);
    if (S->Kind != FLAGKIND_LOGICAL) {
      // V on a 32-bit result: overflow of the low 32 bits
      UINT64 W = S->IsSub ? (A - B) : (A + B);
      V = S->IsSub
          ? ((((A ^ B) & 0x80000000ULL) != 0) && (((A ^ W) & 0x80000000ULL) != 0))
          : (((((A ^ B) & 0x80000000ULL) == 0) && (((A ^ W) & 0x80000000ULL) != 0)));
    }
  } else {
    N = ((R & ((UINT64)1 << 63)) != 0);
  }
  Z = (R == 0);

  Byte  = N ? 0x80 : 0;
  Byte |= Z ? 0x40 : 0;
  Byte |= V ? 0x10 : 0;
  Byte |= C ? 0x01 : 0;

  return Byte;
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
  UINT8         Byte;

  if (!S->HasSetter) {
    return;
  }

  Byte = DbtComputeNzcvSet (Ctx, S);

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
      // MOVZ / MOVN / MOVK: opc(30:29) 0=MOVN 1=reserved 2=MOVZ 3=MOVK
      UINT32 Hw   = (Inst >> 21) & 3;
      UINT16 Imm  = (Inst >> 5) & 0xFFFF;
      UINT32 Opc  = (Inst >> 29) & 3;
      UINT64 Shift = (UINT64)16 * Hw;

      if (Opc == 2 || Opc == 0) {
        // MOVZ / MOVN
        UINT64 Val;
        if (Opc == 2) {
          Val = (UINT64)Imm << Shift;
        } else {
          Val = ~((UINT64)Imm << Shift);
          if (((Inst >> 31) & 1) == 0) {
            Val &= 0xFFFFFFFF;   // W-form: 32-bit result
          }
        }
        DBG((DEBUG_INFO, "DBT_ASM:    MOV%s X%d, #0x%llx\n", Opc == 2 ? "Z" : "N", Rd, Val));
        EmitMovImm(&P, Val);
        EmitStoreRax(&P, RdOff);
      } else if (Opc == 3) {
        // MOVK: Rd = (Rd & ~(0xFFFF << shift)) | (Imm << shift)
        UINT64 Mask = (UINT64)0xFFFF << Shift;
        DBG((DEBUG_INFO, "DBT_ASM:    MOVK X%d, #0x%x, lsl #%u\n", Rd, Imm, 16 * Hw));
        EmitLoadRax(&P, RdOff);
        EmitMovRcxImm(&P, ~Mask);
        EmitAndRaxRcx(&P);       // RAX = Rd & ~Mask
        EmitMovRcxImm(&P, (UINT64)Imm << Shift);
        EmitOrRaxRcx(&P);        // RAX = (Rd & ~Mask) | (Imm << shift)
        if (((Inst >> 31) & 1) == 0) {
          EmitTrunc32(&P);
        }
        EmitStoreRax(&P, RdOff);
      } else {
        DBG((DEBUG_INFO, "DBT_ASM:    MOV wide opc=%u -> NOP\n", Opc));
        EmitNop(&P);
      }
    } else if (Sub == 4) {
      //
      // Logical (immediate): AND/ORR/EOR/ANDS.  sf(31) opc(30:29)
      // 100100(28:23) N(22) immr(21:16) imms(15:10) Rn(9:5) Rd(4:0)
      //
      UINT32  Opc    = (Inst >> 29) & 3;
      UINT64  Mask, Unused;
      BOOLEAN Sf     = (Inst >> 31) & 1;
      BOOLEAN Ok     = Arm64DecodeBitMasks(Inst, TRUE, &Mask, &Unused);

      if (!Ok || (!Sf && (((Inst >> 22) & 1) != 0))) {
        DBG((DEBUG_INFO, "DBT_ASM:    Logical imm (N=%u imms=%u) UNALLOCATED -> NOP\n",
             (Inst >> 22) & 1, (Inst >> 10) & 0x3F));
        EmitNop(&P);
      } else {
        if (!Sf) {
          Mask &= 0xFFFFFFFF;
        }
        DBG((DEBUG_INFO, "DBT_ASM:    %s%s X%d, X%d, #0x%llx\n",
             Opc == 0 ? "AND" : Opc == 1 ? "ORR" : Opc == 2 ? "EOR" : "ANDS",
             Sf ? "" : "W", Rd, Rn, Mask));

        EmitMovRcxImm(&P, Mask);
        EmitLoadRax(&P, RnOff);
        if (Opc == 0) {
          EmitAndRaxRcx(&P);
        } else if (Opc == 1) {
          EmitOrRaxRcx(&P);
        } else if (Opc == 2) {
          EmitXorRaxRcx(&P);
        } else {
          EmitAndRaxRcx(&P);
          if (Rd != 31) {
            EmitStoreRax(&P, RdOff);
          }
          EmitRecordFlagSet(Ctx, FLAGKIND_LOGICAL, FALSE, 0, Rd, Rn, 0, TRUE, 0, 0, 0, !Sf);
        }
        if (Opc != 3 && Rd != 31) {
          EmitStoreRax(&P, RdOff);
        }
      }
    } else if (Sub == 6 || Sub == 7) {
      //
      // Bitfield: sf(31) opc(30:29) 100110/100111(28:23) N(22)
      // immr(21:16) Rm(20:16, EXTR only) imms(15:10) Rn(9:5) Rd(4:0)
      //   Sub==6 (100110): opc 0=SBFM, opc 2=UBFM
      //   Sub==7 (100111): opc 0=EXTR, opc 1=BFM
      //
      UINT32  Opc    = (Inst >> 29) & 3;
      UINT32  N      = (Inst >> 22) & 1;
      UINT32  Immr   = (Inst >> 16) & 0x3F;
      UINT32  Imms   = (Inst >> 10) & 0x3F;
      BOOLEAN Sf     = (Inst >> 31) & 1;
      UINT64  Wmask, Tmask;
      BOOLEAN IsExtr = (Sub == 7 && Opc == 0);

      if (Sf ? (N != 1) : (N != 0 || Immr >= 0x20 || Imms >= 0x20)) {
        DBG((DEBUG_INFO, "DBT_ASM:    Bitfield N=%u immr=%u imms=%u UNALLOCATED -> NOP\n",
             N, Immr, Imms));
        EmitNop(&P);
      } else if (IsExtr) {
        // Xd = concat(Xn : Xm)<lsb+datasize-1 : lsb>
        UINT8  Rm8  = (Inst >> 16) & 0x1F;
        UINT32 Lsb  = Imms;
        UINTN  RmOff = ArmRegXOff(Rm8);
        DBG((DEBUG_INFO, "DBT_ASM:    EXTR%s X%d, X%d, X%d, #%u\n",
             Sf ? "" : "W", Rd, Rn, Rm8, Lsb));
        if (Lsb == 0) {
          EmitLoadRax(&P, RnOff);
        } else {
          EmitLoadRax(&P, RnOff);
          if (!Sf) { EmitTrunc32(&P); }
          EmitShrRaxImm(&P, (UINT8)Lsb);           // Xn >> lsb
          EmitLoadRcx(&P, RmOff);
          if (!Sf) { EmitTrunc32(&P); }            // W: clear upper 32
          EmitShlRcxImm(&P, (UINT8)(Sf ? 64 - Lsb : 32 - Lsb)); // Xm << (size-lsb)
          EmitOrRaxRcx(&P);
        }
        if (!Sf) { EmitTrunc32(&P); }
        EmitStoreRax(&P, RdOff);
      } else {
        //
        // SBFM (opc 0, Sub 6), UBFM (opc 2, Sub 6), BFM (opc 1, Sub 7)
        //
        BOOLEAN IsSbfm = (Sub == 6 && Opc == 0);
        BOOLEAN IsBfm  = (Sub == 6 && Opc == 1);
        BOOLEAN IsUbfm = (Sub == 6 && Opc == 2);
        UINT32  W;

        if (!(IsSbfm || IsUbfm || IsBfm) ||
            (((Inst >> 22) & 1) != (UINT32)Sf) ||
            !Arm64DecodeBitMasks(Inst, FALSE, &Wmask, &Tmask)) {
          DBG((DEBUG_INFO, "DBT_ASM:    Bitfield opc=%u sub=%u N=%u sf=%u UNALLOCATED -> NOP\n",
               Opc, Sub, (Inst >> 22) & 1, Sf));
          EmitNop(&P);
        } else if (IsSbfm) {
          // bot = ROR(Rn, immr) & wmask; msb = (S - R) mod esize
          // Xd = (top & ~tmask) | (bot & tmask), top = replicate(bot[msb])
          UINT32 Msb = (Imms - Immr) & ((Sf ? 64 : 32) - 1);
          DBG((DEBUG_INFO, "DBT_ASM:    SBFM%s X%d, X%d, #%u, #%u\n",
               Sf ? "" : "W", Rd, Rn, Immr, Imms));
          EmitLoadRax(&P, RnOff);
          if (Immr) { EmitRorRaxImm(&P, (UINT8)Immr); }
          EmitMovRcxImm(&P, Wmask);
          EmitAndRaxRcx(&P);                       // RAX = bot
          EmitBitTestRax(&P, (UINT8)Msb);          // CF = bot<msb>
          EmitSbbRdxRdx(&P);                       // RDX = 0 or all-ones
          EmitMovRcxImm(&P, ~Tmask);
          EmitAndRdxRcx(&P);                       // RDX = top & ~tmask
          EmitMovRcxImm(&P, Tmask);
          EmitAndRaxRcx(&P);                       // RAX = bot & tmask
          EmitOrRaxRdx(&P);                        // RAX = (bot & tmask) | (top & ~tmask)
          if (!Sf) { EmitTrunc32(&P); }
          EmitStoreRax(&P, RdOff);
        } else if (IsUbfm) {
          // Xd = ROR(Rn, immr) & wmask & tmask
          DBG((DEBUG_INFO, "DBT_ASM:    UBFM%s X%d, X%d, #%u, #%u\n",
               Sf ? "" : "W", Rd, Rn, Immr, Imms));
          EmitLoadRax(&P, RnOff);
          if (Immr) { EmitRorRaxImm(&P, (UINT8)Immr); }
          EmitMovRcxImm(&P, Wmask & Tmask);
          EmitAndRaxRcx(&P);
          if (!Sf) { EmitTrunc32(&P); }
          EmitStoreRax(&P, RdOff);
        } else {
          // BFM: W = wmask & tmask
          //      Xd = (Rd & ~W) | (ROR(Rn, immr) & W)
          W = (UINT32)(Wmask & Tmask);
          DBG((DEBUG_INFO, "DBT_ASM:    BFM%s X%d, X%d, #%u, #%u\n",
               Sf ? "" : "W", Rd, Rn, Immr, Imms));
          EmitLoadRax(&P, RdOff);
          EmitByte(&P, 0x50);                      // PUSH Rd
          EmitLoadRax(&P, RnOff);
          if (Immr) { EmitRorRaxImm(&P, (UINT8)Immr); }
          EmitMovRcxImm(&P, Wmask & Tmask);
          EmitAndRaxRcx(&P);                       // RAX = ROR & W
          EmitMovRcxImm(&P, ~((UINT64)(Wmask & Tmask)));
          EmitByte(&P, 0x5A);                      // POP RDX (Rd)
          EmitAndRdxRcx(&P);                       // RDX = Rd & ~W
          EmitOrRaxRdx(&P);                        // RAX = bot
          if (!Sf) { EmitTrunc32(&P); }
          EmitStoreRax(&P, RdOff);
        }
      }
    } else if (Sub == 2) {
      //
      // ADD/SUB immediate: sf(31) op(30) S(29) 100010(28:23) sh(22) imm12(21:10)
      //
      UINT32   Sh       = (Inst >> 22) & 1;
      UINT32   Imm      = ((Inst >> 10) & 0xFFF) << (Sh ? 12 : 0);
      BOOLEAN  IsSub    = (Inst >> 30) & 1;
      BOOLEAN  SetFlags = (Inst >> 29) & 1;
      BOOLEAN  IsW      = ((Inst >> 31) & 1) == 0;

      DBG((DEBUG_INFO, "DBT_ASM:    %s X%d, X%d, #0x%x%s\n",
               IsSub ? "SUB" : "ADD", Rd, Rn, Imm, SetFlags ? " (flags)" : ""));

      if (Rn == 31) {
        // From SP or XZR
        UINTN SrcOff = SpOff;
        EmitLoadRax(&P, SrcOff);
        if (IsSub) { EmitSubImm(&P, Imm); }
        else       { EmitAddImm(&P, Imm); }
        if (IsW) EmitTrunc32(&P);
        if (Rd == 31) {
          EmitNop(&P); // discard result
        } else {
          EmitStoreRax(&P, RdOff);
        }
        if (SetFlags) EmitRecordFlagSet(Ctx, FLAGKIND_ADDSUB, IsSub, 0, Rd, Rn, 0, FALSE, Imm, 0, 0, IsW);
      } else {
        EmitLoadRax(&P, RnOff);
        if (IsSub) { EmitSubImm(&P, Imm); }
        else       { EmitAddImm(&P, Imm); }
        if (IsW) EmitTrunc32(&P);
        if (Rd != 31) EmitStoreRax(&P, RdOff);
        if (SetFlags) EmitRecordFlagSet(Ctx, FLAGKIND_ADDSUB, IsSub, 0, Rd, Rn, 0, FALSE, Imm, 0, 0, IsW);
      }
    } else if (Sub == 0 || Sub == 1) {
      //
      // ADR / ADRP.  Note bit 23 is immhi bit 20, so both Sub==0 and
      // Sub==1 land here: sf(31) immlo(30:29) 10000(28:24) immhi(23:5) Rd(4:0)
      //
      BOOLEAN IsAdrp = (Inst >> 31) & 1;
      INT64   Imm    = ((Inst >> 5) & 0x7FFFF) << 2;      // immhi << 2
      Imm           |= (Inst >> 29) & 3;                  // immlo
      if (Imm & (1LL << 20)) { Imm |= ~((INT64)0x1FFFFF); }  // sign-extend 21
      INT64   Val    = (INT64)InstAddr + (IsAdrp ? (Imm << 12) : Imm);
      if (IsAdrp) { Val &= ~((INT64)0xFFF); }             // page of PC
      DBG((DEBUG_INFO, "DBT_ASM:    ADR%s X%d, 0x%llx\n", IsAdrp ? "P" : "", Rd, Val));
      EmitMovImm(&P, (UINT64)Val);
      EmitStoreRax(&P, RdOff);
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
      //
      // LDP/STP register pairs.  Encoding (verified via clang arm64):
      //   [31:30]=opc (00 = W/S-pair, 10 = X/Q-pair 64-bit elements)
      //   [29:27]=101 [26]=VR (0 general / 1 SIMD)
      //   [25:23]=form (001 post-index, 010 signed-offset, 011 pre-index)
      //   [22]=L (1=load) [21:15]=imm7 (signed, x8 for 64-bit elements)
      //   [14:10]=Rt2 [9:5]=Rn [4:0]=Rt
      //
      UINT32 Size    = (Inst >> 30) & 3;
      UINT32 Form    = (Inst >> 23) & 7;
      UINT32 IsLoad  = (Inst >> 22) & 1;
      INT32  Imm     = (INT32)((Inst >> 15) & 0x7F);
      if (Imm & 0x40) { Imm |= ~0x7F; }  // sign-extend bit 6
      Imm <<= 3;                         // scale by element size (8 bytes)
      UINT8  Rt2     = (Inst >> 10) & 0x1F;
      UINTN  RnOffP  = (Rn == 31) ? SpOff : RnOff;

      if (Size == 2 && (Form == 1 || Form == 2 || Form == 3)) {
        // Compute guest address into RCX (pre-index also writes it back to Rn)
        if (Form == 1) {
          // post-index: address = Rn, writeback happens after the access
          EmitLoadRcx(&P, RnOffP);
        } else {
          EmitLoadRcx(&P, RnOffP);
          if (Imm) { EmitAddRcxImm(&P, (UINT32)Imm); }
          if (Form == 3) {
            // pre-index: Rn = address first
            EmitStoreRcx(&P, RnOffP);
          }
        }

        if (IsLoad) {
          DBG((DEBUG_INFO, "DBT_ASM:    LDP X%d, X%d, [X%d%s, #%d]%s\n", Rt, Rt2, Rn,
               Rn == 31 ? "31" : "", Imm, Form == 1 ? "!" : ""));
          EmitCallMapHelper(&P);                   // RAX = host base
          EmitByte(&P, 0x50);                      // PUSH host base
          // First load: MOV RAX, [RAX]
          EmitRexW(&P); EmitByte(&P, 0x8B); EmitByte(&P, 0x00);
          EmitStoreRax(&P, RtOff);
          // Second load at +8: MOV RAX, [RCX+8]
          EmitByte(&P, 0x59);                      // POP RCX (host base)
          EmitRexW(&P); EmitByte(&P, 0x8B); EmitByte(&P, 0x41); EmitByte(&P, 0x08);
          EmitStoreRax(&P, ArmRegXOff(Rt2));
        } else {
          DBG((DEBUG_INFO, "DBT_ASM:    STP X%d, X%d, [X%d%s, #%d]%s\n", Rt, Rt2, Rn,
               Rn == 31 ? "31" : "", Imm, Form == 1 ? "!" : ""));
          EmitCallMapHelper(&P);                   // RAX = host base
          EmitByte(&P, 0x50);                      // PUSH host base
          EmitLoadRax(&P, ArmRegXOff(Rt2));        // RAX = second value
          EmitByte(&P, 0x50);                      // PUSH second value
          EmitLoadRax(&P, RtOff);                  // RAX = first value
          EmitByte(&P, 0x50);                      // PUSH first value
          EmitByte(&P, 0x59);                      // POP RCX (first value)
          EmitByte(&P, 0x58);                      // POP RAX (second value)
          EmitByte(&P, 0x5A);                      // POP RDX (host base)
          // MOV [RDX], RCX   (48 89 0A)
          EmitRexW(&P); EmitByte(&P, 0x89); EmitByte(&P, 0x0A);
          // MOV [RDX+8], RAX (48 89 42 08)
          EmitRexW(&P); EmitByte(&P, 0x89); EmitByte(&P, 0x42); EmitByte(&P, 0x08);
        }

        if (Form == 1) {
          // post-index writeback: Rn += Imm
          EmitLoadRax(&P, RnOffP);
          EmitAddImm(&P, (UINT32)Imm);
          EmitStoreRax(&P, RnOffP);
        }
      } else {
        DBG((DEBUG_INFO, "DBT_ASM:    Pair (size=%d form=%d L=%d) -> NOP\n", Size, Form, IsLoad));
        EmitNop(&P);
      }
    } else {
      // Data processing register; bit 24 discriminates the families:
      //   logical (01010):  opc(30:29) 0=AND 1=ORR 2=EOR 3=ANDS,
      //                     inv(21) selects BIC/ORN/EON/BICS, shift(23:22)
      //                     kind and (15:10) amount apply to Rm
      //   add/sub (01011):  op(30) S(29) 0=ADD/1=SUB, same shift on Rm
      UINT32   Bit24   = (Inst >> 24) & 1;
      UINT32   Opc     = (Inst >> 29) & 3;
      UINT32   Inv     = (Inst >> 21) & 1;
      UINT32   ShKind  = (Inst >> 22) & 3;   // 0=LSL 1=LSR 2=ASR 3=ROR
      UINT32   ShAmt   = (Inst >> 10) & 0x3F;
      BOOLEAN  IsW     = ((Inst >> 31) & 1) == 0;   // sf = 0 -> 32-bit
      UINT8    ShiftKind = (ShKind == 0) ? 1 : (ShKind == 1) ? 2
                          : (ShKind == 2) ? 3 : 4;  // helper convention

      if (Bit24 == 0) {
        // Logical shifted register (AND/ORR/EOR/ANDS, BIC/ORN/EON/BICS).
        // Rn == 31 reads XZR (zero), never SP.
        if (Rn == 31) { EmitMovImm(&P, 0); } else { EmitLoadRax(&P, RnOff); }
        if (IsW) EmitTrunc32(&P);
        if (Rm == 31) { EmitMovImm(&P, 0); } else { EmitLoadRcx(&P, RmOff); }
        if (IsW) { EmitByte(&P, 0x89); EmitByte(&P, 0xC9); }   // MOV ECX, ECX
        EmitShiftRcx(&P, ShiftKind, (UINT8)ShAmt);
        if (Inv) EmitNotRcx(&P);

        if (Opc == 0) {
          DBG((DEBUG_INFO, "DBT_ASM:    %s%s X%d, X%d, X%d%s\n",
                   Inv ? "BIC" : "AND", IsW ? " (32-bit)" : "", Rd, Rn, Rm,
                   ShAmt ? " (shift)" : ""));
          EmitAndRaxRcx(&P);
        } else if (Opc == 1) {
          EmitOrRaxRcx(&P);
        } else if (Opc == 2) {
          EmitXorRaxRcx(&P);
        } else {
          EmitAndRaxRcx(&P);   // ANDS / BICS
        }
        if (IsW) EmitTrunc32(&P);
        if (Rd != 31) EmitStoreRax(&P, RdOff);
        if (Opc == 3) {
          EmitRecordFlagSet(Ctx, FLAGKIND_LOGICAL, FALSE, 0, Rd, Rn, Rm,
                            TRUE, 0, ShiftKind, (UINT8)ShAmt, IsW);
        }
      } else {
        // ADD/SUB shifted register
        BOOLEAN IsSub     = (Inst >> 30) & 1;
        BOOLEAN SetFlags  = (Inst >> 29) & 1;

        DBG((DEBUG_INFO, "DBT_ASM:    %s%s X%d, X%d, X%d%s\n",
                 IsSub ? "SUB" : "ADD", SetFlags ? " (flags)" : "", Rd, Rn, Rm,
                 ShAmt ? " (shift)" : ""));

        if (Rn == 31) { EmitMovImm(&P, 0); } else { EmitLoadRax(&P, RnOff); }
        if (IsW) EmitTrunc32(&P);
        if (Rm == 31) { EmitMovImm(&P, 0); } else { EmitLoadRcx(&P, RmOff); }
        if (IsW) { EmitByte(&P, 0x89); EmitByte(&P, 0xC9); }   // MOV ECX, ECX
        EmitShiftRcx(&P, ShiftKind, (UINT8)ShAmt);
        if (IsSub) EmitSubRaxRcx(&P);
        else       EmitAddRaxRcx(&P);
        if (IsW) EmitTrunc32(&P);
        if (Rd != 31) EmitStoreRax(&P, RdOff);
        if (SetFlags) {
          EmitRecordFlagSet(Ctx, FLAGKIND_ADDSUB, IsSub, 0, Rd, Rn, Rm,
                            TRUE, 0, ShiftKind, (UINT8)ShAmt, IsW);
        }
      }
    }
    return (UINTN)(P - X86Buf);
  }

  //
  // 1101: Conditional select / conditional compare
  //   [28:21] = 0xD4 -> CSEL family: op(30) S(29)? (discriminated by op2):
  //       op2=0, op=0: CSEL    op2=0, op=1: CSINV
  //       op2=1, op=0: CSINC   op2=1, op=1: CSNEG
  //   [28:21] = 0xD2 -> CCMP/CCMN: op(30)=1 CCMP / 0 CCMN, S(29)=1,
  //       op2=00 register form, op2=10 immediate (imm5), nzcv = bits[3:0]
  //
  if (Op0 == 0xD) {
    UINT32  Sub  = (Inst >> 21) & 0xFF;
    UINT32  Sf   = (Inst >> 31) & 1;
    BOOLEAN IsW  = !Sf;
    UINT32  Cond = (Inst >> 12) & 0xF;

    if (Sub == 0xD4) {
      UINT32  Op   = (Inst >> 30) & 1;
      UINT32  Op2  = (Inst >> 10) & 3;
      UINT32  Rn   = (Inst >> 5) & 0x1F;
      UINT8  *Ltrue = NULL;
      UINT8  *Ldone = NULL;
      UINT8  *QTrueStart = NULL;
      UINT8   NoTargets[1] = { 0 };
      UINT8   OneTargets[1] = { 1 };
      UINT8   Seq[128];
      UINT8  *Q = Seq;

      if (Op2 == 0 || Op2 == 1) {
        BOOLEAN IsInv = (Op == 1);
        BOOLEAN IsInc = (Op2 == 1);

        DBG((DEBUG_INFO, "DBT_ASM:    %s%s %s%d, %s%d, %s%d, %s%s\n",
                 IsInv ? (IsInc ? "CSNEG" : "CSINV") : (IsInc ? "CSINC" : "CSEL"),
                 IsW ? "W" : "X", IsW ? "W" : "X", Rd, IsW ? "W" : "X", Rn,
                 IsW ? "W" : "X", Rm, CondNames[Cond],
                 (Rn == 31 && Rm == 31) ? " (cset/cinc alias)" : ""));

        // Default (cond FALSE): Rm, transformed by the op.
        if (Rm == 31) { EmitMovImm(&Q, 0); } else { EmitLoadRax(&Q, (UINT32)ArmRegXOff(Rm)); }
        if (IsW) EmitTrunc32(&Q);
        if (IsInv) { EmitNotRax(&Q); }
        if (IsInc) { EmitAddImm(&Q, 1); }
        if (IsW) EmitTrunc32(&Q);
        if (Rd != 31) EmitStoreRax(&Q, (UINT32)ArmRegXOff(Rd));

        // Condition: recorded setter flags, or the PSTATE byte.
        if (Ctx->FlagSet.HasSetter) {
          EmitComputeFlagsFromSet (&Q, &Ctx->FlagSet);
          EmitJccSlot(&Q, CondJccTrue[Cond], &Ltrue);
        } else {
          EmitByte(&Q, 0x8A); EmitByte(&Q, 0x83); EmitDword(&Q, (UINT32)(PstateOff() + 3));
          EmitCondTrueFromPstate (&Q, Cond, &Ldone);
          EmitJccSlot(&Q, 0xEB, &Ltrue);
        }
        EmitJccSlot(&Q, 0xEB, &Ldone);   // cond FALSE: skip the true value

        // Cond TRUE: Rn (unmodified).
        QTrueStart = Q;
        if (Rn == 31) { EmitMovImm(&Q, 0); } else { EmitLoadRax(&Q, (UINT32)ArmRegXOff(Rn)); }
        if (IsW) EmitTrunc32(&Q);
        if (Rd != 31) EmitStoreRax(&Q, (UINT32)ArmRegXOff(Rd));

        PatchJcc (&Ltrue, OneTargets, 1, Q, QTrueStart);
        PatchJcc (&Ldone, NoTargets, 1, Q, Q);

        CopyMem (P, Seq, (UINTN)(Q - Seq));
        P += (UINTN)(Q - Seq);
        return (UINTN)(P - X86Buf);
      } else {
        DBG((DEBUG_INFO, "DBT_ASM:    CSEL family op2=%u -> NOP\n", Op2));
        EmitNop(&P);
        return (UINTN)(P - X86Buf);
      }
    } else if (Sub == 0xD2) {
      // CCMP / CCMN
      UINT32  Op   = (Inst >> 30) & 1;
      UINT32  Op2  = (Inst >> 10) & 3;
      UINT32  Imm  = (Inst >> 16) & 0x1F;
      UINT32  Nzcv = Inst & 0xF;
      UINT8   ShiftKind = 0, ShiftAmt = 0;

      DBG((DEBUG_INFO, "DBT_ASM:    %s %s%d, %s%u, #0x%x, %s\n",
               Op ? "CCMP" : "CCMN", IsW ? "W" : "X", Rn,
               (Op2 == 0) ? "X" : "#", (UINT32)Imm, Nzcv, CondNames[Cond]));

      // op=1 selects the subtract compare (CCMP), op=0 the add form (CCMN).
      EmitRecordCcmp (Ctx, (Op == 1), Rd, Rn, (UINT8)Imm, (Op2 == 0), (UINT64)((Op2 == 0) ? 0 : Imm),
                      ShiftKind, ShiftAmt, IsW, Cond, (UINT8)Nzcv);
      EmitNop(&P);
      return (UINTN)(P - X86Buf);
    } else {
      DBG((DEBUG_INFO, "DBT_ASM:    op0=d sub=0x%x -> NOP\n", Sub));
      EmitNop(&P);
      return (UINTN)(P - X86Buf);
    }
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
    } else if (TopByte == 0xD5) {
      //
      // MSR / MRS — system register access
      //
      // MRS has bit 21 set (11010101011), MSR has it clear (11010101000).
      BOOLEAN IsMsr = !((Inst >> 21) & 1);
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
        } else if (Op0 == 3 && Op1 == 3 && CRn == 14 && CRm == 0 && Op2 == 0) {
          Off = OFFSET_OF(DBT_ARM64_STATE, CNTFRQ_EL0);
          DBG((DEBUG_INFO, "DBT_SYS:  MRS X%d, CNTFRQ_EL0\n", Rt));
        } else if (Op0 == 3 && Op1 == 3 && CRn == 14 && CRm == 0 && Op2 == 2) {
          Off = OFFSET_OF(DBT_ARM64_STATE, CNTVCT_EL0);
          DBG((DEBUG_INFO, "DBT_SYS:  MRS X%d, CNTVCT_EL0\n", Rt));
        } else if (Op0 == 3 && Op1 == 3 && CRn == 14 && CRm == 3 && Op2 == 2) {
          DBG((DEBUG_INFO, "DBT_SYS:  MRS X%d, CNTV_CVAL_EL0\n", Rt));
          Off = OFFSET_OF(DBT_ARM64_STATE, CNTV_CVAL_EL0);
        } else if (Op0 == 3 && Op1 == 3 && CRn == 14 && CRm == 3 && Op2 == 1) {
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
    } else {
      DBG((DEBUG_INFO, "DBT_ASM:    Unhandled branch top=0x%02x -> NOP\n", TopByte));
      EmitNop(&P);
    }
    return (UINTN)(P - X86Buf);
  }

  //
  // 0x0C-0x0D (110x): Advanced SIMD/FP loads/stores, or MSR/MRS
  //
  //
  // 0x0C-0x0D (110x): LDR/STR family (unsigned-imm12, imm9 pre/post,
  // LDUR/STUR, register-offset).  0x0D: LDRSW/PRFM (NOP for now).
  //
  if (Op0 == 0xC || Op0 == 0xD) {
    UINT32 Size  = (Inst >> 30) & 3;
    UINT32 Opc   = (Inst >> 22) & 3;
    UINT8  Rn    = (Inst >> 5) & 0x1F;
    UINT8  Rt    = Inst & 0x1F;
    UINTN  RnOffL = (Rn == 31) ? SpOff : ArmRegXOff(Rn);

    if ((Inst >> 24) & 1) {
      //
      // 1111 1001 01xx: LDR/STR unsigned immediate (imm12, scaled by size)
      // opc: 0=STR, 1=LDR, 2=LDRSW/LDRSB/LDRSH, 3=PRFM; size: 0=B 1=H 2=W 3=X
      //
      if (Opc <= 2) {
        BOOLEAN Sf = (Inst >> 31) & 1;
        UINT32 Imm = ((Inst >> 10) & 0xFFF) << Size;
        CONST CHAR8 *Name = Opc == 1 ? "LDR" : Opc == 0 ? "STR" : "LDRS";

        DBG((DEBUG_INFO, "DBT_ASM:    %s%s X%d, [X%d, #%d]\n", Name,
             Size == 0 ? "B" : Size == 1 ? "H" : Size == 2 ? "W" : "",
             Rt, Rn == 31 ? 31 : Rn, Imm));
        EmitLoadRcx(&P, RnOffL);
        if (Imm) { EmitAddRcxImm(&P, Imm); }
        EmitCallMapHelper(&P);                 // RAX = host address
        EmitMemAccess(&P, Size, Opc, Sf, (UINT32)RtOff);
      } else {
        DBG((DEBUG_INFO, "DBT_ASM:    PRFM -> NOP\n"));
        EmitNop(&P);
      }
      return (UINTN)(P - X86Buf);
    }

    //
    // LDR literal: opc(31:30) 0=LDRW 1=LDRX 2=LDRSW 3=PRFM, 011000(27:22)
    // imm19 [23:5] signed, scaled by 4 (by 2 for LDRH literal)
    //
    if ((Inst & 0x3B000000) == 0x18000000) {
      UINT32 LitOpc = (Inst >> 30) & 3;
      if (LitOpc == 3) {
        DBG((DEBUG_INFO, "DBT_ASM:    PRFM literal -> NOP\n"));
        EmitNop(&P);
      } else {
        INT64  Imm = ((Inst >> 5) & 0x7FFFF) << 2;
        if (Imm & (1LL << 20)) { Imm |= ~((INT64)0x1FFFFF); }
        UINT64 Addr = InstAddr + (UINT64)Imm;
        DBG((DEBUG_INFO, "DBT_ASM:    LDR%s X%d, =0x%llx\n",
             LitOpc == 0 ? "W" : LitOpc == 1 ? "" : "SW", Rt, Addr));
        EmitMovImm(&P, Addr);                    // RAX = literal address
        EmitRexW(&P); EmitByte(&P, 0x89); EmitByte(&P, 0xC1);   // MOV RCX, RAX
        EmitCallMapHelper(&P);                   // RAX = host address
        if (LitOpc == 2) {
          EmitRexW(&P); EmitByte(&P, 0x63); EmitByte(&P, 0x00);  // MOVSX RAX, [RAX]
        } else if (LitOpc == 1) {
          EmitRexW(&P); EmitByte(&P, 0x8B); EmitByte(&P, 0x00);  // MOV RAX, [RAX]
        } else {
          EmitByte(&P, 0x8B); EmitByte(&P, 0x00);                // MOV EAX, [RAX]
        }
        EmitStoreRax(&P, RtOff);
      }
      return (UINTN)(P - X86Buf);
    }

    if ((Inst >> 21) & 1) {
      //
      // 1111 1001 011: LDR/STR (register) — option must be 3 (UXTX)
      // Rm [20:16], option [15:13], S [12] (S=1 shifts by size)
      //
      if (Opc <= 2) {
        UINT8 Rm   = (Inst >> 16) & 0x1F;
        UINT8 Opt  = (Inst >> 13) & 7;
        UINT8 S    = (Inst >> 12) & 1;

        if (Opt == 3) {
          UINTN RmOff = ArmRegXOff(Rm);
          DBG((DEBUG_INFO, "DBT_ASM:    %s X%d, [X%d, X%d%s]\n", Opc == 1 ? "LDR" : "STR",
               Rt, Rn, Rm, S ? ", lsl #3" : ""));
          EmitLoadRcx(&P, RnOffL);
          EmitLoadRax(&P, RmOff);
          if (S) { EmitRexW(&P); EmitByte(&P, 0xC1); EmitByte(&P, 0xE0); EmitByte(&P, 0x03); }  // SHL RAX, 3
          EmitRexW(&P); EmitByte(&P, 0x01); EmitByte(&P, 0xC1);        // ADD RCX, RAX
          EmitCallMapHelper(&P);
          EmitMemAccess(&P, Size, Opc, (Inst >> 31) & 1, (UINT32)RtOff);
          return (UINTN)(P - X86Buf);
        }
        DBG((DEBUG_INFO, "DBT_ASM:    Reg-offset (opc=%d opt=%d) -> NOP\n", Opc, Opt));
      } else {
        DBG((DEBUG_INFO, "DBT_ASM:    Reg-offset (opc=%d) -> NOP\n", Opc));
      }
      EmitNop(&P);
      return (UINTN)(P - X86Buf);
    }

    //
    // 1111 1001 010: LDUR/STUR (bit23=0) or LDR/STR imm9 pre/post (bit23=1)
    // imm9 [20:12] signed; pre-index has W[11]=0, post-index W[11]=1
    //
    if (Opc <= 2) {
      INT32  Imm9 = ((INT32)((Inst >> 12) & 0x1FF)) << 23 >> 23;
      UINT32 IsPost = (Inst >> 11) & 1;
      CONST CHAR8 *Name = Opc == 1 ? "LDR" : Opc == 0 ? "STR" : "LDRS";

      if ((Inst >> 23) & 1) {
        // pre/post index
        DBG((DEBUG_INFO, "DBT_ASM:    %s%s X%d, [X%d, #%d]%s\n", Name,
             Size == 0 ? "B" : Size == 1 ? "H" : Size == 2 ? "W" : "",
             Rt, Rn, Imm9, IsPost ? "!" : ""));
        EmitLoadRcx(&P, RnOffL);
        if (Imm9) { EmitAddRcxImm(&P, (UINT32)Imm9); }
        if (!IsPost) {
          // pre-index: Rn = address first
          EmitStoreRcx(&P, RnOffL);
        }
        EmitCallMapHelper(&P);
        EmitMemAccess(&P, Size, Opc, (Inst >> 31) & 1, (UINT32)RtOff);
        if (IsPost) {
          // post-index: Rn += Imm9 after the access
          EmitLoadRax(&P, RnOffL);
          EmitAddImm(&P, (UINT32)Imm9);
          EmitStoreRax(&P, RnOffL);
        }
        return (UINTN)(P - X86Buf);
      } else {
        // LDUR/STUR: unscaled, no writeback
        DBG((DEBUG_INFO, "DBT_ASM:    LD%s%s X%d, [X%d, #%d]\n",
             Opc == 1 ? "UR" : "U", Opc == 0 ? "R" : "",
             Rt, Rn, Imm9));
        EmitLoadRcx(&P, RnOffL);
        if (Imm9) { EmitAddRcxImm(&P, (UINT32)Imm9); }
        EmitCallMapHelper(&P);
        EmitMemAccess(&P, Size, Opc, (Inst >> 31) & 1, (UINT32)RtOff);
        return (UINTN)(P - X86Buf);
      }
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
  gDbtActiveCtx   = Ctx;

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
  Ctx->PrevCount = 0;

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
  Map a guest virtual address to the host address where the loaded kernel
  image holds it.  The kernel is linked at its VM addresses (e.g.
  0xFFFFFE0007004000) but loaded into a firmware pool buffer at a
  different host address, and the segments are contiguous in both the file
  and the VA space, so:  host = KernelBuffer + SegFileOff[i] + (Va - SegVmAddr[i]).

  Returns Va unchanged (identity) when no segment contains it; the caller
  (emitted load/store code) treats the result as a host pointer.
**/
UINT64 DbtTranslateVaToPa (DBT_CONTEXT *Ctx, UINT64 Va) {
  UINTN  I;

  if (Ctx != NULL) {
    for (I = 0; I < Ctx->SegCount; I++) {
      if (Va >= Ctx->SegVmAddr[I] && Va < Ctx->SegVmAddr[I] + Ctx->SegVmSize[I]) {
        return (UINT64)(UINTN)(Ctx->KernelBuffer
                               + Ctx->SegFileOff[I]
                               + (UINTN)(Va - Ctx->SegVmAddr[I]));
      }
    }
  }

  DBG((DEBUG_WARN, "DBT_MMU: VA 0x%llx outside image — identity\n", Va));
  return Va;
}

EFI_STATUS DbtSetSegments (DBT_CONTEXT *Ctx, UINTN SegCount, UINT64 *SegVmAddr,
                           UINT64 *SegVmSize, UINT64 *SegFileOff, VOID *KernelBuffer) {
  if (Ctx == NULL || (SegCount != 0 && (SegVmAddr == NULL || SegVmSize == NULL || SegFileOff == NULL || KernelBuffer == NULL))) {
    return EFI_INVALID_PARAMETER;
  }

  Ctx->SegCount     = SegCount;
  Ctx->SegVmAddr    = SegVmAddr;
  Ctx->SegVmSize    = SegVmSize;
  Ctx->SegFileOff   = SegFileOff;
  Ctx->KernelBuffer = KernelBuffer;

  DBG((DEBUG_INFO, "DBT_MMU: registered %u segments, kernel buffer 0x%llx\n",
       SegCount, (UINT64)(UINTN)KernelBuffer));
  return EFI_SUCCESS;
}

//
// Host-side helper invoked by the translated load/store code.  Takes no
// arguments (reads the globals) so the call is ABI-independent; the
// translated code preserves RBX and the saved registers across it.
//
UINT64 DbtMapHostAddr (VOID) {
  return DbtTranslateVaToPa (gDbtActiveCtx, gDbtHelperVa);
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