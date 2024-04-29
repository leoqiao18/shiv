// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
/* Adapted by yanniszark in 2024 */

// All linux kernel type definitions are in vmlinux.h
#include "vmlinux.h"
// BPF helpers
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "shiv.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY); // map type
    __type(key, u32);                 // key type
    __type(value, u64);               // value type
    __uint(max_entries, 1);           // number of entries
} total_energy SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH); // map type
    __type(key, pid_t);              // key type
    __type(value, u64);              // value type
    __uint(max_entries, 10000);      // number of entries
} pid_to_energy SEC(".maps");

// SEC name is important! libbpf infers program type from it.
// See: https://docs.kernel.org/bpf/libbpf/program_types.html#program-types-and-elf
SEC("perf_event")
int handle_perf_event(struct bpf_perf_event_data *ctx)
{
    u32 zero = 0;
    u64 failure_value = 420;
    struct bpf_perf_event_value v;

    // get current energy from ctx
    if (bpf_perf_prog_read_value(ctx, &v, sizeof(struct bpf_perf_event_value))) {
        bpf_map_update_elem(&total_energy, &zero, &failure_value, BPF_ANY);
        bpf_printk("Map was not updated with new element: %d\n", v.counter);
    }
    bpf_map_update_elem(&total_energy, &zero, &v.counter, BPF_ANY);
    bpf_printk("Map updated with new element: %d\n", v.counter);

    return 0;
}
