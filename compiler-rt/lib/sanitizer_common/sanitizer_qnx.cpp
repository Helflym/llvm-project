//===-- sanitizer_qnx.cpp -------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is shared between various sanitizers' runtime libraries and
// implements QNX-specific functions.
//===----------------------------------------------------------------------===//

#include "sanitizer_platform.h"

#if SANITIZER_QNX

#  include <dlfcn.h>
#  include <errno.h>
#  include <fcntl.h>
#  include <limits.h>
#  include <process.h>
#  include <pthread.h>
#  include <sched.h>
#  include <signal.h>
#  include <stddef.h>
#  include <stdio.h>
#  include <sys/link.h>
#  include <sys/mman.h>
#  include <sys/neutrino.h>
#  include <sys/procfs.h>
#  include <sys/stat.h>
#  include <sys/wait.h>
#  include <ucontext.h>
#  include <unistd.h>

#  include "sanitizer_common.h"
#  include "sanitizer_flags.h"
#  include "sanitizer_internal_defs.h"
#  include "sanitizer_libc.h"
#  include "sanitizer_placement_new.h"
#  include "sanitizer_platform_limits_posix.h"
#  include "sanitizer_posix.h"
#  include "sanitizer_procmaps.h"

namespace __sanitizer {

#  include "sanitizer_syscall_generic.inc"

static void *GetRealLibcAddress(const char *symbol) {
  void *real = dlsym(RTLD_NEXT, symbol);
  if (!real)
    real = dlsym(RTLD_DEFAULT, symbol);
  if (!real) {
    Printf("GetRealLibcAddress failed for symbol=%s\n", symbol);
    Die();
  }
  return real;
}

#  define _REAL(func, ...) real##_##func(__VA_ARGS__)
#  define DEFINE__REAL(ret_type, func, ...)                              \
    static ret_type (*real_##func)(__VA_ARGS__) = NULL;                  \
    if (!real_##func) {                                                  \
      real_##func = (ret_type(*)(__VA_ARGS__))GetRealLibcAddress(#func); \
    }                                                                    \
    CHECK(real_##func);

// --------------- sanitizer_libc.h

void internal__exit(int exitcode) {
  DEFINE__REAL(void, _exit, int exitcode);
  _REAL(_exit, exitcode);
  Die();  // Unreachable.
}

void internal_usleep(u64 useconds) {
  DEFINE__REAL(void, usleep, u64 useconds);
  _REAL(usleep, useconds);
}

uptr internal_getpid() {
  DEFINE__REAL(int, getpid);
  return _REAL(getpid);
}

uptr internal_getppid() {
  DEFINE__REAL(int, getppid);
  return _REAL(getppid);
}

uptr internal_sched_yield() {
  DEFINE__REAL(void, sched_yield);
  _REAL(sched_yield);
  return 0;
}

// --------------- sanitizer_posix.h

uptr internal_open(const char *filename, int flags, u32 mode) {
  DEFINE__REAL(int, open, const char *filename, int flags, u32 mode);
  return _REAL(open, filename, flags, mode);
}

uptr internal_open(const char *filename, int flags) {
  return internal_open(filename, flags, 0);
}

uptr internal_close(fd_t fd) {
  DEFINE__REAL(int, close, fd_t fd);
  return _REAL(close, fd);
}

uptr internal_read(fd_t fd, void *buf, uptr count) {
  sptr res;
  DEFINE__REAL(int, read, fd_t fd, void *buf, uptr count);
  HANDLE_EINTR(res, _REAL(read, fd, buf, count));
  return res;
}

uptr internal_write(fd_t fd, const void *buf, uptr count) {
  sptr res;
  DEFINE__REAL(int, write, fd_t fd, const void *buf, uptr count);
  HANDLE_EINTR(res, _REAL(write, fd, buf, count));
  return res;
}

uptr internal_mmap(void *addr, uptr length, int prot, int flags, int fd,
                   u64 offset) {
  DEFINE__REAL(void *, mmap, void *addr, uptr length, int prot, int flags,
               int fd, u64 offset);
  return (uptr)_REAL(mmap, addr, length, prot, flags, fd, offset);
}

uptr internal_munmap(void *addr, uptr length) {
  DEFINE__REAL(int, munmap, void *addr, uptr length);
  return _REAL(munmap, addr, length);
}

int internal_mprotect(void *addr, uptr length, int prot) {
  DEFINE__REAL(int, mprotect, void *addr, uptr length, int prot);
  return _REAL(mprotect, addr, length, prot);
}

int internal_madvise(uptr addr, uptr length, int advice) {
  DEFINE__REAL(int, posix_madvise, void *addr, uptr length, int advice);
  return _REAL(posix_madvise, (void *)addr, length, advice);
}

uptr internal_stat(const char *path, void *buf) {
  DEFINE__REAL(int, stat, const char *path, void *buf);
  return _REAL(stat, path, (struct stat *)buf);
}

uptr internal_lstat(const char *path, void *buf) {
  DEFINE__REAL(int, lstat, const char *path, void *buf);
  return _REAL(lstat, path, (struct stat *)buf);
}

uptr internal_fstat(fd_t fd, void *buf) {
  DEFINE__REAL(int, fstat, fd_t fd, void *buf);
  return _REAL(fstat, fd, (struct stat *)buf);
}

uptr internal_filesize(fd_t fd) {
  struct stat st;
  if (internal_fstat(fd, &st))
    return -1;
  return (uptr)st.st_size;
}

uptr internal_dup(int oldfd) {
  DEFINE__REAL(int, dup, int oldfd);
  return _REAL(dup, oldfd);
}

uptr internal_dup2(int oldfd, int newfd) {
  DEFINE__REAL(int, dup2, int oldfd, int newfd);
  return _REAL(dup2, oldfd, newfd);
}

uptr internal_readlink(const char *path, char *buf, uptr bufsize) {
  DEFINE__REAL(int, readlink, const char *path, char *buf, uptr bufsize);
  return _REAL(readlink, path, buf, bufsize);
}

uptr internal_unlink(const char *path) {
  DEFINE__REAL(int, unlink, const char *path);
  return _REAL(unlink, path);
}

uptr internal_rename(const char *oldpath, const char *newpath) {
  DEFINE__REAL(int, rename, const char *oldpath, const char *newpath);
  return _REAL(rename, oldpath, newpath);
}

uptr internal_lseek(fd_t fd, OFF_T offset, int whence) {
  DEFINE__REAL(int, lseek, fd_t fd, OFF_T offset, int whence);
  return _REAL(lseek, fd, offset, whence);
}

uptr internal_ptrace(int request, int pid, void *addr, void *data) {
  Printf("internal_ptrace not implemented for QNX\n");
  Die();
  return 0;
}

uptr internal_waitpid(int pid, int *status, int options) {
  DEFINE__REAL(int, waitpid, pid_t pid, int *status, int options);
  return _REAL(waitpid, pid, status, options);
}

int internal_fork() {
  DEFINE__REAL(int, fork);
  return _REAL(fork);
}

int internal_sigaction(int signum, const void *act, void *oldact) {
  DEFINE__REAL(int, sigaction, int signum, const void *act, void *oldact);
  return _REAL(sigaction, signum, (const struct sigaction *)act,
               (struct sigaction *)oldact);
}

uptr internal_execve(const char *filename, char *const argv[],
                     char *const envp[]) {
  DEFINE__REAL(int, execve, const char *filename, char *const argv[],
               char *const envp[]);
  return _REAL(execve, filename, argv, envp);
}

void internal_pthread_exit(void *ret) {
  DEFINE__REAL(void, pthread_exit, void *ret);
  return _REAL(pthread_exit, ret);
}

void internal_join_thread(void *th) { internal_pthread_join(th, nullptr); }

void *internal_start_thread(void *(*func)(void *arg), void *arg) {
  // Start the thread with signals blocked, otherwise it can steal user signals.
  ScopedBlockSignals block(nullptr);
  void *th;
  internal_pthread_create(&th, nullptr, func, arg);
  return (void *)(*(pthread_t *)(&th));
}

// --------------- sanitizer_common.h
static void ReadNullSepFileToArray(const char *path, char ***arr,
                                   int arr_size) {
  char *buff;
  uptr buff_size;
  uptr buff_len;
  *arr = (char **)MmapOrDie(arr_size * sizeof(char *), "NullSepFileArray");
  if (!ReadFileToBuffer(path, &buff, &buff_size, &buff_len, 1024 * 1024)) {
    (*arr)[0] = nullptr;
    return;
  }
  (*arr)[0] = buff;
  int count, i;
  for (count = 1, i = 1;; i++) {
    if (buff[i] == 0) {
      if (buff[i + 1] == 0)
        break;
      (*arr)[count] = &buff[i + 1];
      CHECK_LE(count, arr_size - 1);  // FIXME: make this more flexible.
      count++;
    }
  }
  (*arr)[count] = nullptr;
}

bool FileExists(const char *filename) {
  if (ShouldMockFailureToOpen(filename))
    return false;
  struct stat st;
  if (internal_stat(filename, &st))
    return false;
  // Sanity check: filename is a regular file.
  return S_ISREG(st.st_mode);
}

bool DirExists(const char *path) {
  struct stat st;
  if (internal_stat(path, &st))
    return false;
  return S_ISDIR(st.st_mode);
}

uptr GetPageSize() { return sysconf(_SC_PAGESIZE); }

ThreadID GetTid() {
  DEFINE__REAL(int, gettid);
  return _REAL(gettid);
}

char **GetArgv() {
  char **argv;
  static const int kMaxArgv = 2000;
  ReadNullSepFileToArray("/proc/self/cmdline", &argv, kMaxArgv);
  return argv;
}

char **GetEnviron() { return environ; }

const char *GetEnv(const char *name) {
  uptr NameLen = internal_strlen(name);
  for (char **Env = GetEnviron(); *Env != 0; Env++) {
    if (internal_strncmp(*Env, name, NameLen) == 0 && (*Env)[NameLen] == '=')
      return (*Env) + NameLen + 1;
  }
  return NULL;
}

uptr GetTlsSize() {
  // FIXME: is there any way to retrieve that information ?
  return 0;
}

void InitTlsSize() {}

void GetThreadStackTopAndBottom(bool, uptr *stack_top, uptr *stack_bottom) {
  *stack_bottom = (uptr)__tls()->__stackaddr;
  *stack_top = *stack_bottom + (uptr)__tls()->__stacksize;
}

void GetThreadStackAndTls(bool main, uptr *stk_begin, uptr *stk_end,
                          uptr *tls_begin, uptr *tls_end) {
  *stk_begin = (uptr)__tls()->__stackaddr;
  *stk_end = *stk_begin + (uptr)__tls()->__stacksize;
  *tls_begin = (uptr)__tls();
  *tls_end = *tls_begin + GetTlsSize();
}

u64 MonotonicNanoTime() {
  DEFINE__REAL(int, clock_gettime, int clock, timespec *ts);
  timespec ts;
  _REAL(clock_gettime, CLOCK_MONOTONIC, &ts);
  return (u64)ts.tv_sec * (1000ULL * 1000 * 1000) + ts.tv_nsec;
}

uptr ReadBinaryName(/*out*/ char *buf, uptr buf_len) {
  char *tmpbuf;
  uptr tmpsize;
  uptr tmplen;
  error_t err;
  if (ReadFileToBuffer("/proc/self/exefile", &tmpbuf, &tmpsize, &tmplen,
                       PATH_MAX, &err)) {
    internal_strncpy(buf, tmpbuf, buf_len);
    UnmapOrDie(tmpbuf, tmpsize);
    return internal_strlen(buf);
  }

  // Something went wrong: get value from argv.
  internal_strncpy(buf, GetArgv()[0], buf_len);
  return internal_strlen(buf);
}

uptr ReadLongProcessName(/*out*/ char *buf, uptr buf_len) {
  return ReadBinaryName(buf, buf_len);
}

static HandleSignalMode GetHandleSignalModeImpl(int signum) {
  switch (signum) {
    case SIGABRT:
      return common_flags()->handle_abort;
    case SIGILL:
      return common_flags()->handle_sigill;
    case SIGTRAP:
      return common_flags()->handle_sigtrap;
    case SIGFPE:
      return common_flags()->handle_sigfpe;
    case SIGSEGV:
      return common_flags()->handle_segv;
    case SIGBUS:
      return common_flags()->handle_sigbus;
  }
  return kHandleSignalNo;
}

HandleSignalMode GetHandleSignalMode(int signum) {
  HandleSignalMode result = GetHandleSignalModeImpl(signum);
  if (result == kHandleSignalYes && !common_flags()->allow_user_segv_handler)
    return kHandleSignalExclusive;
  return result;
}

void ListOfModules::init() {
  clearOrInit();
  MemoryMappingLayout memory_mapping(false);
  memory_mapping.DumpListOfModules(&modules_);
}

void ListOfModules::fallbackInit() { clear(); }

// FIXME
SignalContext::WriteFlag SignalContext::GetWriteFlag() const { return Unknown; }

void InitializePlatformEarly() {}
void InitializePlatformCommonFlags(CommonFlags *cf) {}

void SignalContext::InitPcSpBp() {
  ucontext_t *ucontext = (ucontext_t *)context;
  pc = GET_REGIP(&ucontext->uc_mcontext.cpu);
  sp = GET_REGSP(&ucontext->uc_mcontext.cpu);
  bp = ucontext->uc_mcontext.cpu.gpr[29];
}

bool SignalContext::IsTrueFaultingAddress() const {
  auto si = static_cast<const siginfo_t *>(siginfo);
  // "Real" SIGSEGV codes (e.g., SEGV_MAPERR, SEGV_MAPERR) are non-zero.
  return si->si_signo == SIGSEGV && si->si_code != 0;
}

void SignalContext::DumpAllRegisters(void *context) {
  // FIXME: Implement this.
}

void CheckASLR() {
  procfs_info pinfo;
  int fd;

  fd = open("/proc/self/ctl", (O_RDONLY | O_BINARY));
  if (fd == -1) {
    Printf("Failed to get /proc/self/ctl (errno %d).\n", errno);
    Die();
  }

  // Abort when ASLR is enabled.
  devctl(fd, DCMD_PROC_INFO, &pinfo, sizeof(pinfo), NULL);
  if (pinfo.flags & _NTO_PF_ASLR) {
    Printf("Sanitizers are not compatible with enabled ASLR.\n");
    Printf("To disable ASLR: \"on -ad <program>\".\n");
    Die();
  }
}

// FIXME implement on this platform.
void GetMemoryProfile(fill_profile_f cb, uptr *stats) {}

uptr GetUserVirtualAddress() {
  return (1ULL << 39) - 1;  // 0x0000007fffffffffUL
}

uptr GetMaxUserVirtualAddress() { return GetUserVirtualAddress(); }

// --------------- sanitizer_mutex.h

void FutexWait(atomic_uint32_t *p, u32 cmp) {
  // FIXME: implement actual blocking.
  internal_sched_yield();
}

void FutexWake(atomic_uint32_t *p, u32 count) {}

// --------------- sanitizer_qnx.h

uptr internal_sigprocmask(int how, __sanitizer_sigset_t *set,
                          __sanitizer_sigset_t *oldset) {
  DEFINE__REAL(int, pthread_sigmask, int how, __sanitizer_sigset_t *set,
               __sanitizer_sigset_t *oldset);
  return _REAL(pthread_sigmask, how, set, oldset);
}

void internal_sigfillset(__sanitizer_sigset_t *set) {
  DEFINE__REAL(int, sigfillset, __sanitizer_sigset_t *set);
  _REAL(sigfillset, set);
}

void internal_sigdelset(__sanitizer_sigset_t *set, int signum) {
  DEFINE__REAL(int, sigdelset, __sanitizer_sigset_t *set, int signum);
  _REAL(sigdelset, set, signum);
}

void SetSigProcMask(__sanitizer_sigset_t *set, __sanitizer_sigset_t *oldset) {
  CHECK_EQ(0, internal_sigprocmask(SIG_SETMASK, set, oldset));
}

void BlockSignals(__sanitizer_sigset_t *oldset) {
  __sanitizer_sigset_t set;
  internal_sigfillset(&set);
  // SIGSEGV is triggered when the shadow memory is access.
  internal_sigdelset(&set, 11);
  SetSigProcMask(&set, oldset);
}

ScopedBlockSignals::ScopedBlockSignals(__sanitizer_sigset_t *copy) {
  BlockSignals(&saved_);
  if (copy)
    internal_memcpy(copy, &saved_, sizeof(saved_));
}

ScopedBlockSignals::~ScopedBlockSignals() { SetSigProcMask(&saved_, nullptr); }

}  // namespace __sanitizer
#endif
