//===-- sanitizer_stoptheworld_qnx.cpp ------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// See sanitizer_stoptheworld.h for details.
//
//===----------------------------------------------------------------------===//

#include "sanitizer_platform.h"

#if SANITIZER_QNX

#  include <devctl.h>
#  include <fcntl.h>
#  include <pthread.h>
#  include <sys/neutrino.h>
#  include <sys/procfs.h>

#  include "sanitizer_mutex.h"
#  include "sanitizer_stoptheworld.h"

namespace __sanitizer {
typedef struct {
  ThreadID tid;
  procfs_status status;
} SuspendedThreadInfo;

class SuspendedThreadsListQnx final : public SuspendedThreadsList {
 public:
  SuspendedThreadsListQnx() = default;

  ThreadID GetThreadID(uptr index) const override;
  procfs_status GetStatus(uptr index) const;
  uptr ThreadCount() const override;
  void Append(procfs_status status);

  PtraceRegistersStatus GetRegistersAndSP(uptr index,
                                          InternalMmapVector<uptr> *buffer,
                                          uptr *sp) const override;

 private:
  InternalMmapVector<SuspendedThreadInfo> threads_;
};

struct StopThreadArgs {
  StopTheWorldCallback callback;
  void *argument;
};

void *StopThread(void *arg) {
  struct StopThreadArgs *run_args = (struct StopThreadArgs *)arg;
  SuspendedThreadsListQnx suspended_threads_list;
  int fd, err;
  ThreadID last_seen_tid = -1;

  fd = open("/proc/self/ctl", (O_RDONLY | O_BINARY));
  if (fd == -1) {
    VReport(1, "Failed to get /proc/self/ctl (errno %d).\n", errno);
    return nullptr;
  }

  // Stop all threads
  err = ThreadCtl(_NTO_TCTL_THREADS_HOLD, 0);
  if (err == -1) {
    VReport(1, "Failed to stop all threads (errno %d).\n", errno);
    return nullptr;
  }

  // Fetch threads status using "DCMD_PROC_TIDSTATUS". It will get the thread
  // matching tid or the next closest one up to ESRCH, when there is no more
  // threads.
  do {
    procfs_status thread_status = {};
    thread_status.tid = last_seen_tid + 1;
    int res = devctl(fd, DCMD_PROC_TIDSTATUS, &thread_status,
                     sizeof(thread_status), NULL);
    // No more threads
    if (res == ESRCH)
      break;
    else if (res != EOK) {
      VReport(1, "devctl failed (errno %d).\n", errno);
      return nullptr;
    }

    // Current threads
    if (thread_status.tid == pthread_self()) {
      last_seen_tid = thread_status.tid;
      continue;
    }

    suspended_threads_list.Append(thread_status);

    // Increment thread_status.tid to get the next thread.
    last_seen_tid = thread_status.tid;
  } while (true);

  run_args->callback(suspended_threads_list, run_args->argument);

  // Resume all threads
  err = ThreadCtl(_NTO_TCTL_THREADS_CONT, 0);
  if (err == -1) {
    VReport(1, "Failed to resume all threads (errno %d).\n", errno);
    return nullptr;
  }

  return nullptr;
}

// QNX's pthread_exit could, under unknown circonstances, perform malloc calls.
// Those calls, being intercepted, would lead to a deadlock as the sanitizer's
// allocator would be locked.
// Therefore, instead of using pthread_create/pthread_join, perform the
// synchronization between the StopThread and its caller through semaphores.
//  - stopthread_run is controlling when StopThread must be launched
//  - stopthread_join mimics pthread_join, the caller waits for StopThread to
//  wake it up.
void *run_thread = NULL;
static Semaphore stopthread_run;
static Semaphore stopthread_join;
struct StopThreadArgs stop_thread_args = {};

void *WrapperStopThread(void *arg) {
  while (true) {
    // Wait until a run is requested.
    stopthread_run.Wait();
    CHECK(stop_thread_args.callback);
    StopThread(&stop_thread_args);

    // Unlock the calling thread.
    stopthread_join.Post();
  }

  // pthread_exit could be intercepted resulting in a deadlock since the
  // objects holding thread's details are locked.
  UNREACHABLE("Stoptheworld cannot call pthread_exit");
  return nullptr;
}

void StopTheWorld(StopTheWorldCallback callback, void *argument) {
  stop_thread_args = {callback, argument};

  // Create the thread if this is the first call to StopTheWorld.
  if (!run_thread) {
    run_thread = internal_start_thread(WrapperStopThread, NULL);
  }

  // Trigger a run of stopthread and wait for its completion.
  stopthread_run.Post();
  stopthread_join.Wait();
}

ThreadID SuspendedThreadsListQnx::GetThreadID(uptr index) const {
  CHECK_LT(index, threads_.size());
  return threads_[index].tid;
}

procfs_status SuspendedThreadsListQnx::GetStatus(uptr index) const {
  CHECK_LT(index, threads_.size());
  return threads_[index].status;
}

uptr SuspendedThreadsListQnx::ThreadCount() const { return threads_.size(); }

void SuspendedThreadsListQnx::Append(procfs_status status) {
  threads_.push_back({status.tid, status});
}

PtraceRegistersStatus SuspendedThreadsListQnx::GetRegistersAndSP(
    uptr index, InternalMmapVector<uptr> *buffer, uptr *sp) const {
  const procfs_status status = GetStatus(index);

  *sp = status.sp;

  // procfs_status doesn't provide any way to retrieve registers.
  buffer->resize(0);

  return REGISTERS_AVAILABLE;
}

}  // namespace __sanitizer

#endif  // SANITIZER_QNX
