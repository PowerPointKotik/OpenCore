/** @file
  CPUID definitions for standalone builds.

  This is a compatibility header for OpenCore standalone builds.
**/

#ifndef REGISTER_CPUID_H
#define REGISTER_CPUID_H

#include <Uefi.h>

#pragma pack(push, 1)

///
/// CPUID version information in EAX.
///
typedef union {
  struct {
    UINT32  SteppingId:4;
    UINT32  Model:4;
    UINT32  FamilyId:4;
    UINT32  TypeId:2;
    UINT32  Reserved:2;
    UINT32  ExtendedModelId:4;
    UINT32  ExtendedFamilyId:8;
    UINT32  Reserved2:4;
    UINT32  FeatureBits:8;   ///< Software features provided by the CPU.
  } Bits;
  UINT32  Uint32;
} CPUID_VERSION_INFO_EAX;

///
/// CPUID version information in EBX.
///
typedef union {
  struct {
    UINT32  BrandIndex:8;
    UINT32  ClflushCacheLineSize:8;
    UINT32  MaximumSupportedAddressSize:8;
    UINT32  InitialApicId:8;
  } Bits;
  UINT32  Uint32;
} CPUID_VERSION_INFO_EBX;

///
/// CPUID version information in ECX.
///
typedef union {
  struct {
    UINT32  Sse3:1;
    UINT32  Reserved1:2;
    UINT32  Smtp3:1;
    UINT32  Reserved2:4;
    UINT32  Cmpxchg16b:1;
    UINT32  Aes:1;
    UINT32  Reserved3:1;
    UINT32  Avx:1;
    UINT32  Reserved4:14;
    UINT32  ProcessorTrace:1;
    UINT32  Reserved5:2;
    UINT32  Invpcid:1;
    UINT32  Reserved6:2;
    UINT32  RtM:1;
    UINT32  Reserved7:5;
  } Bits;
  UINT32  Uint32;
} CPUID_VERSION_INFO_ECX;

///
/// CPUID version information in EDX.
///
typedef union {
  struct {
    UINT32  Fpu:1;
    UINT32  Vme:1;
    UINT32  De:1;
    UINT32  Pse:1;
    UINT32  Tsc:1;
    UINT32  Msr:1;
    UINT32  Pae:1;
    UINT32  Mce:1;
    UINT32  Cx8:1;
    UINT32  Apic:1;
    UINT32  Reserved1:1;
    UINT32  Sep:1;
    UINT32  Mtrr:1;
    UINT32  Pge:1;
    UINT32  Mca:1;
    UINT32  Cmov:1;
    UINT32  PciBin:1;
    UINT32  Pse36:1;
    UINT32  Psn:1;
    UINT32  Clfs:1;
    UINT32  Reserved2:1;
    UINT32  Ds:1;
    UINT32  Acpi:1;
    UINT32  Mmx:1;
    UINT32  Fxsr:1;
    UINT32  Sse:1;
    UINT32  Sse2:1;
    UINT32  SelfSnoop:1;
    UINT32  Htt:1;
    UINT32  Reserved3:1;
    UINT32  AccPower:1;
    UINT32  Reserved4:1;
    UINT32  Pbe:1;
  } Bits;
  UINT32  Uint32;
} CPUID_VERSION_INFO_EDX;

///
/// CPUID extended CPU signature in ECX.
///
typedef union {
  struct {
    UINT32  Reserved:32;
  } Bits;
  UINT32  Uint32;
} CPUID_EXTENDED_CPU_SIG_ECX;

///
/// CPUID extended CPU signature in EDX.
///
typedef union {
  struct {
    UINT32  Reserved:32;
  } Bits;
  UINT32  Uint32;
} CPUID_EXTENDED_CPU_SIG_EDX;

#pragma pack(pop)

#endif // REGISTER_CPUID_H