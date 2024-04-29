#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <string.h>
#include "shiv.h"

struct bpf_object *load_bpf_obj(char *prog_name)
{
    // Load and verify BPF application
    fprintf(stderr, "Loading BPF code in memory\n");
    struct bpf_object *obj = bpf_object__open_file(prog_name, NULL);
    if (libbpf_get_error(obj))
    {
        fprintf(stderr, "ERROR: opening BPF object file failed\n");
        return NULL;
    }

    // Load BPF program
    fprintf(stderr, "Loading and verifying the code in the kernel\n");
    if (bpf_object__load(obj))
    {
        fprintf(stderr, "ERROR: loading BPF object file failed\n");
        return NULL;
    }

    return obj;
}

struct bpf_map *load_bpf_map(struct bpf_object *obj, char *map_name)
{
    struct bpf_map *map = bpf_object__find_map_by_name(obj, map_name);
    if (libbpf_get_error(map))
    {
        fprintf(stderr, "ERROR: finding BPF map failed\n");
        return NULL;
    }
    return map;
}

int create_perf_event()
{
    struct perf_event_attr attr;
    memset(&attr, 0x0, sizeof(attr));
    attr.type = PERF_TYPE_POWER;
    attr.config = PERF_COUNT_ENERGY_PKG;

    // TODO: only assuming a single socket at CPU "0"
    int perf_fd = syscall(__NR_perf_event_open, &attr, -1 /*pid*/, 0 /*cpu*/, -1, 0);
    if (perf_fd < 0)
    {
        fprintf(stderr, "ERROR: Failed to create perf event\n");
        return -1;
    }

    return perf_fd;
}

struct bpf_link *attach_bpf_prog_to_sched_switch(struct bpf_program *prog)
{
    struct bpf_link *link;
    link = bpf_program__attach_tracepoint(prog, "sched", "sched_switch");
    if (libbpf_get_error(link))
    {
        fprintf(stderr, "ERROR: Attaching perf event to BPF program failed\n");
        return NULL;
    }

    return link;
}

int main(int argc, char *argv[])
{
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link;
    int prog_fd;
    u_int32_t zero = 0;
    struct bpf_map *perf_event_descriptors_map;
    int perf_fd;

    // Parse cli arguments
    if (argc != 1)
    {
        fprintf(stderr, "usage: %s\n", argv[0]);
        return 1;
    }

    // load bpf object
    if ((obj = load_bpf_obj("shiv.bpf.o") == NULL)
    {
        return 1;
    }

    // load bpf map
    if ((perf_event_descriptors_map = load_bpf_map("perf_event_descriptors")) == NULL)
    {
        goto cleanup_obj;
    }

    // create perf events and put into bpf map
    // TODO: assuming only a single socket "0"
    if((perf_fd = create_perf_event()) < 0)
    {
        goto cleanup_obj;
    }
    
    // attach bpf program
    if ((link = attach_bpf_prog_to_sched_switch(prog)) == NULL)
    {
        goto cleanup_perf;
    }

    while (1)
    {
        sleep(1);
    }


cleanup_perf:
    close(perf_fd);
cleanup_obj:
    bpf_object__close(obj);
    return 0;
}