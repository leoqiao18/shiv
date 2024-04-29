#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "shiv.h"


int main(int argc, char *argv[])
{
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link[2];
    int prog_fd;
    u_int32_t zero = 0;

    // Parse cli arguments
    if (argc != 2)
    {
        fprintf(stderr, "usage: %s\n", argv[0]);
        return 1;
    }

    // Load and verify BPF application
    fprintf(stderr, "Loading BPF code in memory\n");
    obj = bpf_object__open_file("shiv.bpf.o", NULL);
    if (libbpf_get_error(obj))
    {
        fprintf(stderr, "ERROR: opening BPF object file failed\n");
        return 1;
    }

    // Load BPF program
    fprintf(stderr, "Loading and verifying the code in the kernel\n");
    if (bpf_object__load(obj))
    {
        fprintf(stderr, "ERROR: loading BPF object file failed\n");
        return 1;
    }

    // Initialize total_energy map
    struct bpf_map *map;
    map = bpf_object__find_map_by_name(obj, "total_energy");
    if (libbpf_get_error(map))
    {
        fprintf(stderr, "ERROR: finding BPF map failed\n");
        return 1;
    }
    int map_fd = bpf_map__fd(map);

    // Attach BPF program: block_rq_insert
    fprintf(stderr, "Attaching BPF program to tracepoint\n");
    prog = bpf_object__find_program_by_name(obj, "handle_perf_event");
    if (libbpf_get_error(prog))
    {
        fprintf(stderr, "ERROR: finding BPF program failed\n");
        return 1;
    }
    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0)
    {
        fprintf(stderr, "ERROR: getting BPF program FD failed\n");
        return 1;
    }
    // Check it out at: /sys/kernel/debug/tracing/events/raw_syscalls/sys_enter
    link[0] = bpf_program__attach_perf_event(prog);
    if (libbpf_get_error(link[0]))
    {
        fprintf(stderr, "ERROR: Attaching BPF program to tracepoint failed\n");
        return 1;
    }

    // Print histogram every interval
    while (1)
    {
        sleep(1000);

        // Get total_energy
        u64 total_energy;
        if (bpf_map_lookup_elem(map_fd, &zero, &total_energy) < 0)
        {
            fprintf(stderr, "ERROR: Map total_energy lookup failed\n");
            break;
        }

        // Print histogram
        printf("Total energy: %d\n", total_energy);
    }

    // Cleanup
    bpf_link__destroy(link[0]);
    bpf_object__close(obj);

    return 0;
}
