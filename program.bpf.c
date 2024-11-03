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

struct event {
  gadget_timestamp timestamp;
  gadget_mntns_id mntns_id;
  __u32 pid;
  char comm[TASK_COMM_LEN];
  char request_name[32]; // String representation of ptrace request
  __u32 target_pid;      // Target process's PID from ptrace
};

GADGET_TRACER_MAP(events, 1024 * 256);

GADGET_TRACER(ptrace, events, event);

SEC("tracepoint/syscalls/sys_enter_ptrace")
int tracepoint__sys_enter_ptrace(struct trace_event_raw_sys_enter *ctx) {

  __u64 request_num = ctx->args[0]; // 'request' parameter

  if (request_num > 4)
    return 0;

  struct event *event;
  event = gadget_reserve_buf(&events, sizeof(*event));
  if (!event)
    return 0;

  const char *ptrace_request_names[] = {"PTRACE_TRACEME", "PTRACE_PEEKTEXT",
                                        "PTRACE_PEEKDATA", "PTRACE_PEEKUSER",
                                        "PTRACE_POKETEXT"};

  // bpf_core_read_str(event->request_name, sizeof(event->request_name),
  // ptrace_request_names[request_num]);
  __builtin_memcpy(event->request_name, ptrace_request_names[request_num],
                   sizeof(event->request_name));

  __u64 pid_tgid = bpf_get_current_pid_tgid();
  event->timestamp = bpf_ktime_get_boot_ns();
  event->mntns_id = gadget_get_mntns_id();
  event->pid = pid_tgid >> 32;
  event->target_pid = ctx->args[1];
  bpf_get_current_comm(&event->comm, sizeof(event->comm));

  /* emit event */
  gadget_submit_buf(ctx, &events, event, sizeof(*event));

  return 0;
}

char LICENSE[] SEC("license") = "GPL";
