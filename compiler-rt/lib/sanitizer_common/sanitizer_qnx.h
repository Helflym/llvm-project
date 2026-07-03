//===-- sanitizer_qnx.h -----------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is shared between various sanitizers' runtime libraries and
// provides definitions for QNX
//===----------------------------------------------------------------------===//
#ifndef SANITIZER_QNX_H
#define SANITIZER_QNX_H

#include "sanitizer_platform.h"
#if SANITIZER_QNX

#  include "sanitizer_platform_limits_posix.h"

namespace __sanitizer {

struct ProcSelfMapsBuff {
  char *data;
  uptr mmaped_size;
  uptr len;
};

struct MemoryMappingLayoutData {
  ProcSelfMapsBuff proc_self_maps;
  const char *current;
};

void ReadProcMaps(ProcSelfMapsBuff *proc_maps);

uptr internal_sigprocmask(int how, __sanitizer_sigset_t *set,
                          __sanitizer_sigset_t *oldset);

void SetSigProcMask(__sanitizer_sigset_t *set, __sanitizer_sigset_t *oldset);
void BlockSignals(__sanitizer_sigset_t *oldset = nullptr);
struct ScopedBlockSignals {
  explicit ScopedBlockSignals(__sanitizer_sigset_t *copy);
  ~ScopedBlockSignals();

  ScopedBlockSignals &operator=(const ScopedBlockSignals &) = delete;
  ScopedBlockSignals(const ScopedBlockSignals &) = delete;

 private:
  __sanitizer_sigset_t saved_;
};

}  // namespace __sanitizer

#endif  // SANITIZER_QNX
#endif  // SANITIZER_QNX_H
