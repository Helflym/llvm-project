//=-- lsan_common_qnx.cpp -----------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of LeakSanitizer.
// Implementation of common leak checking functionality. QNX code.
//
//===----------------------------------------------------------------------===//

#include "lsan_common.h"
#include "sanitizer_common/sanitizer_platform.h"

#if CAN_SANITIZE_LEAKS && SANITIZER_QNX
#  include <pthread.h>
#  include <sys/link.h>

#  include "sanitizer_common/sanitizer_common.h"
#  include "sanitizer_common/sanitizer_flags.h"
#  include "sanitizer_common/sanitizer_getauxval.h"
#  include "sanitizer_common/sanitizer_posix.h"
#  include "sanitizer_common/sanitizer_stackdepot.h"

namespace __lsan {
__attribute__((tls_model("initial-exec"))) THREADLOCAL int disable_counter;
bool DisabledInThisThread() { return disable_counter > 0; }
void DisableInThisThread() { disable_counter++; }
void EnableInThisThread() {
  if (disable_counter == 0) {
    DisableCounterUnderflow();
  }
  disable_counter--;
}

LoadedModule *GetLinker() { return nullptr; }

void InitializePlatformSpecificModules() {}

static int ProcessGlobalRegionsCallback(const struct dl_phdr_info *info,
                                        size_t size, void *data) {
  Frontier *frontier = reinterpret_cast<Frontier *>(data);
  for (uptr j = 0; j < info->dlpi_phnum; j++) {
    const Elf64_Phdr *phdr = &(info->dlpi_phdr[j]);
    // We're looking for .data and .bss sections, which reside in writeable,
    // loadable segments.
    if (!(phdr->p_flags & PF_W) || (phdr->p_type != PT_LOAD) ||
        (phdr->p_memsz == 0))
      continue;
    uptr begin = info->dlpi_addr + phdr->p_vaddr;
    uptr end = begin + phdr->p_memsz;
    ScanGlobalRange(begin, end, frontier);
  }
  return 0;
}

// Scans global variables for heap pointers.
void ProcessGlobalRegions(Frontier *frontier) {
  if (!flags()->use_globals)
    return;
  dl_iterate_phdr(ProcessGlobalRegionsCallback, frontier);
}

void ProcessPlatformSpecificAllocations(Frontier *frontier) {}

struct DoStopTheWorldParam {
  StopTheWorldCallback callback;
  void *argument;
};

// While calling Die() here is undefined behavior and can potentially
// cause race conditions, it isn't possible to intercept exit on linux,
// so we have no choice but to call Die() from the atexit handler.
// TODO: unclear
void HandleLeaks() {
  if (common_flags()->exitcode)
    Die();
}

void LockStuffAndStopTheWorld(StopTheWorldCallback callback,
                              CheckForLeaksParam *argument) {
  ScopedStopTheWorldLock lock;
  StopTheWorld(callback, argument);
}

}  // namespace __lsan

#endif
