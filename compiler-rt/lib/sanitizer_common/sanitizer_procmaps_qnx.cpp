//===-- sanitizer_procmaps.h ------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is shared between AddressSanitizer and ThreadSanitizer.
//
// Information about the process mappings for QNX.
//===----------------------------------------------------------------------===//
#include "sanitizer_platform.h"
#if SANITIZER_QNX

#  include "sanitizer_common.h"
#  include "sanitizer_procmaps.h"
#  include "sanitizer_qnx.h"

namespace __sanitizer {

void ReadProcMaps(ProcSelfMapsBuff *proc_maps) {
  // TODO
  Printf("ReadProcMaps not implemented for QNX\n");
  Die();
}

bool MemoryMappingLayout::Next(MemoryMappedSegment *segment) {
  // TODO
  Printf("MemoryMappingLayout::Next not implemented for QNX\n");
  Die();
}

}  // namespace __sanitizer

#endif  // SANITIZER_APPLE
