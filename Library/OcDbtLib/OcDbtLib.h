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

typedef struct {
  BOOLEAN  HasSetter;   // a flag-setting instruction is live in this block
  UINT8    Kind;        // FLAGKIND_ADDSUB or FLAGKIND_LOGICAL
  BOOLEAN  IsSub;       // ADD/SUB: subtract (carry semantics differ)
  UINT8    LogicalOp;   // FLAGKIND_LOGICAL: 0=AND, 1=ORR, 2=EOR
  UINT8    Rd;          // destination (31 = XZR)
  UINT8    Rn;          // first source (31 = SP for addsub-imm form)
  UINT8    Rm;          // second source register (register form)
  UINT64   Imm;         // immediate (addsub-imm form, imm12 shifted)
  BOOLEAN  HasReg2;     // TRUE: register form (Rm), FALSE: immediate (Imm)
} DBT_FLAG_SET;

typedef struct DBT_CONTEXT {
  OC_VMEM_CONTEXT  VmContext;
  EFI_HANDLE       InstallerDevice;
  CHAR16          *KernelPath;
  DBT_ARM64_STATE  ArmState;
  UINT64           SysRegs[256];
  VOID            *TranslatedCode;
  UINTN            TranslatedSize;
  UINTN            CodeCapacity;
  UINT8           *JumpSlot;
  UINT8           *LastBlockStart;
  DBT_FLAG_SET     FlagSet;
  UINT8            CodeBuffer[0];
} DBT_CONTEXT;