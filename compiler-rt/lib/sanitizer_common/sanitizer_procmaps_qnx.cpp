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

#  include <sys/mman.h>

#  include "sanitizer_common.h"
#  include "sanitizer_procmaps.h"
#  include "sanitizer_qnx.h"

namespace __sanitizer {

void ReadProcMaps(ProcSelfMapsBuff *proc_maps) {
  if (!ReadFileToBuffer("/proc/self/pmap", &proc_maps->data,
                        &proc_maps->mmaped_size, &proc_maps->len)) {
    proc_maps->data = nullptr;
    proc_maps->mmaped_size = 0;
    proc_maps->len = 0;
  }

  // Remove first line and its \n.
  char *ndata =
      (char *)internal_memchr(proc_maps->data, '\n', proc_maps->len) + 1;
  proc_maps->len -= ndata - proc_maps->data;
  proc_maps->data = ndata;
}

// Parse a hexadecimal value in QNX /proc/self/pmap strings. Those start
// with "0x".
static uptr ParseProcSelfMapHex(const char **p) {
  CHECK_EQ(*(*p)++, '0');
  CHECK_EQ(*(*p)++, 'x');
  return ParseHex(p);
}

bool MemoryMappingLayout::Next(MemoryMappedSegment *segment) {
  if (Error())
    return false;  // simulate empty maps
  char *last = data_.proc_self_maps.data + data_.proc_self_maps.len;
  if (data_.current >= last)
    return false;

  char *next_line =
      (char *)internal_memchr(data_.current, '\n', last - data_.current);
  if (next_line == 0)
    next_line = last;

  // A line will be composed of the following fields:
  //   vaddr,size,flags,prot,maxprot,dev,ino,offset,rsv,guardsize,refcnt,
  //   mapcnt,path,asinfo
  //
  // Up to "path", each field is an hexadecimal number starting with 0x.
  // "path" and "asinfo" are strings.
  segment->start = ParseProcSelfMapHex(&data_.current);
  CHECK_EQ(*data_.current++, ',');
  segment->end = segment->start + ParseProcSelfMapHex(&data_.current);
  CHECK_EQ(*data_.current++, ',');

  segment->protection = 0;
  int l_flags = ParseProcSelfMapHex(&data_.current);
  CHECK_EQ(*data_.current++, ',');
  if ((l_flags & MAP_SHARED) != 0)
    segment->protection |= kProtectionShared;

  // The flags in pmap are right shifted by 8.
  int l_prot = ParseProcSelfMapHex(&data_.current) << 8;
  CHECK_EQ(*data_.current++, ',');

  if ((l_prot & PROT_READ) != 0)
    segment->protection |= kProtectionRead;
  if ((l_prot & PROT_WRITE) != 0)
    segment->protection |= kProtectionWrite;
  if ((l_prot & PROT_EXEC) != 0)
    segment->protection |= kProtectionExecute;

  // Ignore all fields up to "offset".
  ParseProcSelfMapHex(&data_.current);
  CHECK_EQ(*data_.current++, ',');
  ParseProcSelfMapHex(&data_.current);
  CHECK_EQ(*data_.current++, ',');
  ParseProcSelfMapHex(&data_.current);
  CHECK_EQ(*data_.current++, ',');

  segment->offset = ParseProcSelfMapHex(&data_.current);
  CHECK_EQ(*data_.current++, ',');

  // Ignore all fields up to "path".
  ParseProcSelfMapHex(&data_.current);
  CHECK_EQ(*data_.current++, ',');
  ParseProcSelfMapHex(&data_.current);
  CHECK_EQ(*data_.current++, ',');
  ParseProcSelfMapHex(&data_.current);
  CHECK_EQ(*data_.current++, ',');
  ParseProcSelfMapHex(&data_.current);
  CHECK_EQ(*data_.current++, ',');

  // Fill in the filename.
  if (segment->filename) {
    char *next_field =
        (char *)internal_memchr(data_.current, ',', last - data_.current);
    uptr len =
        Min((uptr)(next_field - data_.current), segment->filename_size - 1);
    internal_strncpy(segment->filename, data_.current, len);
    segment->filename[len] = 0;
  }

  data_.current = next_line + 1;
  return true;
}

}  // namespace __sanitizer

#endif  // SANITIZER_APPLE
