package main

import (
	"fmt"
	"os"
	"time"

	"github.com/iovisor/iomodules/hover/bpf"
)

const source string = `
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <net/net_namespace.h>
#include <bcc/proto.h>

#define TCP_EVENT_TYPE_CONNECT 1
#define TCP_EVENT_TYPE_ACCEPT  2
#define TCP_EVENT_TYPE_CLOSE   3

struct tcp_event_t {
        u32 type;
        u32 netns;
        u32 pid;
        u32 saddr;
        u32 daddr;
        u16 sport;
        u16 dport;
};

BPF_PERF_OUTPUT(tcp_event);

int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk)
{
        u64 pid = bpf_get_current_pid_tgid();

	bpf_trace_printk("tcp_v4_connect: called.\n");

        struct tcp_event_t evt = {
                .type = TCP_EVENT_TYPE_CONNECT,
                .pid = pid >> 32,
                .saddr = 0,
                .daddr = 0,
                .sport = ntohs(0),
                .dport = ntohs(0),
                .netns = 0,
        };

        tcp_event.perf_submit(ctx, &evt, sizeof(evt));

        return 0;
};

`

func main() {
	fmt.Printf("Hello, world.\n")

	for {
		m := bpf.NewBpfModule(source, []string{})

		ebpfFd, err := m.LoadKprobe("kprobe__tcp_v4_connect")
		if err != nil {
			fmt.Printf("Failed to LoadKprobe: %v\n", err)
			os.Exit(1)
		}

		err = m.AttachKprobe("tcp_v4_connect", ebpfFd)
		if err != nil {
			fmt.Printf("Failed to AttachKprobe: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Ready.\n")

		time.Sleep(time.Second * 2)

		m.Close()
	}
}
