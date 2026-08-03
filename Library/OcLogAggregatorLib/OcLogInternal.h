/** @file
  Copyright (C) 2016 - 2018, The HermitCrabs Lab. All rights reserved.

  All rights reserved.

  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
**/

#ifndef OC_LOG_INTERNAL_H
#define OC_LOG_INTERNAL_H

#include <Library/OcFlexArrayLib.h>

#include <Protocol/OcLog.h>
#include <Protocol/DataHub.h>

//
// 1 MB log buffer: the capture file is capped at the buffer size, and the
// 256 KB version only covered ~3.5 minutes of the DBT boot (the kernel was
// still running, mid-message).  The earlier 32 MB attempt was blamed for
// slow boots, but that slowness came from per-line FAT Write+Flush — now
// batched (OC_LOG_FILE_FLUSH_THRESHOLD below) — so a larger buffer only
// extends the capture at no boot-speed cost.
//
#define OC_LOG_BUFFER_SIZE            BASE_1MB
#define OC_LOG_LINE_BUFFER_SIZE       BASE_1KB
#define OC_LOG_NVRAM_BUFFER_SIZE      BASE_32KB
#define OC_LOG_FILE_PATH_BUFFER_SIZE  256
#define OC_LOG_TIMING_BUFFER_SIZE     64
//
// Batch the per-line log file writes: a FAT Write+Flush on every DebugPrint
// makes DBT-verbose boots crawl (each block emits several lines, each line
// costs one Write+Flush pair).  Instead flush to the file only once this many
// bytes have accumulated (or the buffer is about to fill).  At a hard
// hang the tail up to this threshold stays in RAM and is lost, but a stalled
// guest repeats identical lines, so the stall remains readable.
//
#define OC_LOG_FILE_FLUSH_THRESHOLD   BASE_2KB

#define OC_LOG_PRIVATE_DATA_SIGNATURE  SIGNATURE_32 ('O', 'C', 'L', 'G')

#define OC_LOG_PRIVATE_DATA_FROM_OC_LOG_THIS(a) \
  (CR (a, OC_LOG_PRIVATE_DATA, OcLog, OC_LOG_PRIVATE_DATA_SIGNATURE))

typedef struct {
  UINT64                   Signature;
  UINT64                   TscFrequency;
  UINT64                   TscStart;
  UINT64                   TscLast;
  CHAR8                    TimingTxt[OC_LOG_TIMING_BUFFER_SIZE];
  CHAR8                    LineBuffer[OC_LOG_LINE_BUFFER_SIZE];
  CHAR16                   UnicodeLineBuffer[OC_LOG_LINE_BUFFER_SIZE];
  CHAR8                    AsciiBuffer[OC_LOG_BUFFER_SIZE];
  UINTN                    AsciiBufferSize;
  UINTN                    AsciiBufferWrittenOffset;
  UINTN                    AsciiBufferFlushedOffset;
  CHAR8                    NvramBuffer[OC_LOG_NVRAM_BUFFER_SIZE];
  UINTN                    NvramBufferSize;
  UINT32                   LogCounter;
  CHAR16                   *LogFilePathName;
  EFI_DATA_HUB_PROTOCOL    *DataHub;
  OC_FLEX_ARRAY            *FlexFilters;
  BOOLEAN                  BlacklistFiltering;
  OC_LOG_PROTOCOL          OcLog;
} OC_LOG_PRIVATE_DATA;

OC_LOG_PROTOCOL *
InternalGetOcLog (
  VOID
  );

#endif // OC_LOG_INTERNAL_H
