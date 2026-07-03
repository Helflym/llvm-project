//===-- asan_qnx.cpp ------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of AddressSanitizer, an address sanity checker.
//
// QNX-specific details.
//===----------------------------------------------------------------------===//

#include "sanitizer_common/sanitizer_platform.h"
#if SANITIZER_QNX

#  include <signal.h>

#  include "asan_interceptors.h"
#  include "asan_internal.h"
#  include "asan_mapping.h"
#  include "asan_report.h"
#  include "asan_stack.h"
#  include "asan_thread.h"
#  include "sanitizer_common/sanitizer_atomic.h"
#  include "sanitizer_common/sanitizer_libc.h"

namespace __asan {
void AsanApplyToGlobals(globals_op_fptr op, const void *needle) {
  UNIMPLEMENTED();
}

void InitializePlatformInterceptors() {}

void InitializePlatformExceptionHandlers() {}

// No-op. QNX does not support static linkage anyway.
void AsanCheckDynamicRTPrereqs() {}

// No-op. QNX does not support static linkage anyway.
void AsanCheckIncompatibleRT() {}

// No-op. QNX does not support static linkage anyway.
void *AsanDoesNotSupportStaticLinkage() { return 0; }

void FlushUnneededASanShadowMemory(uptr p, uptr size) {
  // Since asan's mapping is compacting, the shadow chunk may be
  // not page-aligned, so we only flush the page-aligned portion.
  ReleaseMemoryPagesToOS(MemToShadow(p), MemToShadow(p + size));
}

}  // namespace __asan

#endif  // SANITIZER_QNX
