#include <Library/OcDbtLib.h>
#include <Library/OcMemoryLib.h>

//
// Descriptor of the last flag-setting (S=1) instruction in the current
// translated block.  The translator records it instead of capturing EFLAGS
// in emitted code: Rosetta's flag emulation is only reliable for a single
// (producer, consumer) pair, so multi-bit SETcc/PUSHFQ captures cannot be
// validated in the harness.  Flags are instead:
//   - re-derived from the setter's operands for same-block consumers
//     (EmitCondBranchFromSet emits cmp/jcc pairs), and
//   - computed host-side in DbtComputeNzcv after the block runs, for
//     consumers in subsequent blocks (PSTATE byte).
//
#define FLAGKIND_ADDSUB   0
#define FLAGKIND_LOGICAL  1

typedef struct DBT_FLAG_SET DBT_FLAG_SET;

typedef struct DBT_FLAG_SET {
  BOOLEAN  HasSetter;   // a flag-setting instruction is live in this block
  UINT8    Kind;        // FLAGKIND_ADDSUB or FLAGKIND_LOGICAL
  BOOLEAN  IsSub;       // ADD/SUB: subtract (carry semantics differ)
  UINT8    LogicalOp;   // FLAGKIND_LOGICAL: 0=AND, 1=ORR, 2=EOR
  UINT8    Rd;          // destination (31 = XZR)
  UINT8    Rn;          // first source (31 = SP for addsub-imm form)
  UINT8    Rm;          // second source register (register form)
  UINT64   Imm;         // immediate (addsub-imm form, imm12 shifted)
  BOOLEAN  HasReg2;     // TRUE: register form (Rm), FALSE: immediate (Imm)
  UINT8    ShiftKind;   // register form: 0=none 1=LSL 2=LSR 3=ASR (ROR)
  UINT8    ShiftAmt;    // register form: shift amount applied to Rm
  BOOLEAN  IsW;         // 32-bit (W-register) form: truncate operands/result
  BOOLEAN  IsCcmp;      // CCMP/CCMN setter: flags are cond-gated
  UINT8    Cond;        // CSEL family condition, or CCMP's gate condition
  UINT8    Nzcv;        // CCMP false path: NZCV immediate (N=8 Z=4 C=2 V=1)
  BOOLEAN  HasPrev;     // CCMP: Prev holds the setter before the CCMP
  DBT_FLAG_SET *Prev;   // setter whose flags gate the CCMP condition
} DBT_FLAG_SET;

typedef struct DBT_CONTEXT {
  OC_VMEM_CONTEXT  VmContext;
  EFI_HANDLE       InstallerDevice;
  CHAR16          *KernelPath;
  DBT_ARM64_STATE  ArmState;
  UINT64           SysRegs[256];
  UINTN            SegCount;
  UINT64          *SegVmAddr;
  UINT64          *SegVmSize;
  UINT64          *SegFileOff;
  UINT8           *KernelBuffer;
  //
  // Host-backed guest "physical memory" window.  The kernel's first accesses
  // (low global / boot shim structures) hit VAs that fall outside every
  // loaded segment; historically those identity-mapped straight onto the
  // x86 firmware's own pages (garbage) and the boot dereferenced a bogus
  // pointer.  Registering a host buffer here lets low guest accesses land
  // in deterministic memory instead (default: zeroed).
  //
  UINT64           PhysWinBase;
  UINTN            PhysWinSize;
  UINT8           *PhysWinBuffer;
  VOID            *TranslatedCode;
  UINTN            TranslatedSize;
  UINTN            CodeCapacity;
  UINT8           *JumpSlot;
  UINT8           *LastBlockStart;
  UINT32           ChainExitOff;  // offset of the chain-loop watchdog epilogue stub
  //
  // Guest PC -> translated-block cache (Rosetta 2 style).  BlockMapPc is a
  // sorted array of block-start guest PCs, BlockMapOff the parallel offsets
  // into TranslatedCode.  Direct branches whose target is already cached
  // chain straight into the cached block instead of returning to the
  // driver; DbtExecute re-points the jump slot at the cached block for the
  // current PC so already-translated blocks (e.g. loop bodies) are never
  // re-translated.
  //
  UINT64          *BlockMapPc;
  UINT32          *BlockMapOff;
  UINTN            BlockMapCount;
  UINTN            BlockMapCap;
  DBT_FLAG_SET     FlagSet;
  DBT_FLAG_SET     PrevSlots[8];  // CCMP gate-chain snapshot pool
  UINTN            PrevCount;
  UINT8            CodeBuffer[0];
} DBT_CONTEXT;