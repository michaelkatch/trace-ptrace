// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
/* Copyright (c) 2024 CHANGEME-Authors */

#include <vmlinux.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <gadget/buffer.h>
#include <gadget/macros.h>
#include <gadget/mntns_filter.h>
#include <gadget/types.h>

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

// Macro to handle request name assignment
#define ASSIGN_PTRACE_REQUEST_NAME(req_num, req_name) \
    case req_num: \
        bpf_probe_read_kernel_str(&event->request_name, sizeof(event->request_name), req_name); \
        break;

struct event {
  gadget_timestamp timestamp;
  gadget_mntns_id mntns_id;
  __u32 pid;
  char comm[TASK_COMM_LEN];
  char request_name[32];         // String representation of ptrace request
  __u32 target_pid;              // Target process's PID from ptrace

};


GADGET_TRACER_MAP(events, 1024 * 256);

GADGET_TRACER(ptrace, events, event);

SEC("tracepoint/syscalls/sys_enter_ptrace")
int tracepoint__sys_enter_ptrace(struct trace_event_raw_sys_enter *ctx) {
  struct event *event;
  __u64 pid_tgid = bpf_get_current_pid_tgid();

  event = gadget_reserve_buf(&events, sizeof(*event));
  if (!event)
    return 0;

  /* event data */
  event->timestamp = bpf_ktime_get_boot_ns();
  event->mntns_id = gadget_get_mntns_id();
  event->pid = pid_tgid >> 32;
  event->target_pid = ctx->args[1];
  bpf_get_current_comm(&event->comm, sizeof(event->comm));

  __u64 request_num = ctx->args[0];  // 'request' parameter

  switch (request_num) {
    ASSIGN_PTRACE_REQUEST_NAME(0, "PTRACE_TRACEME")
    ASSIGN_PTRACE_REQUEST_NAME(1, "PTRACE_PEEKTEXT")
    ASSIGN_PTRACE_REQUEST_NAME(2, "PTRACE_PEEKDATA")
    ASSIGN_PTRACE_REQUEST_NAME(3, "PTRACE_PEEKUSER")
    ASSIGN_PTRACE_REQUEST_NAME(4, "PTRACE_POKETEXT")
    default:
        goto end;
  }

  /* emit event */
  gadget_submit_buf(ctx, &events, event, sizeof(*event));
  return 0;

end:
  gadget_discard_buf(event);
  return 0;
}

char LICENSE[] SEC("license") = "GPL";
