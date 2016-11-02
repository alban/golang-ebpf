package main

import (
	"fmt"
	"os"
	"time"
	"unsafe"

	"github.com/iovisor/iomodules/hover/bpf"
)

/*
#cgo CFLAGS: -I/usr/include/bcc/compat
#cgo LDFLAGS: -lbcc
#include <bcc/bpf_common.h>
#include <bcc/libbpf.h>
int bpf_open_perf_event(uint32_t type, uint64_t config, int pid, int cpu);
*/
import "C"

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
        u64 pid;
        u64 dummy;
};

BPF_PERF_OUTPUT(myperfbuffer);

int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk)
{
        u64 pid = bpf_get_current_pid_tgid();

	bpf_trace_printk("tcp_v4_connect: called.\n");

        struct tcp_event_t evt = {
                .pid = pid,
                .dummy = 0,
        };

        myperfbuffer.perf_submit(ctx, &evt, sizeof(evt));

        return 0;
};

`

func initPerfMap(table *bpf.BpfTable) []*os.File {
	fd := table.Config()["fd"].(int)
	key_size := table.Config()["key_size"].(uint64)
	leaf_size := table.Config()["leaf_size"].(uint64)
	key := make([]byte, key_size)
	leaf := make([]byte, leaf_size)
	keyP := unsafe.Pointer(&key[0])
	leafP := unsafe.Pointer(&leaf[0])

	perfFiles := []*os.File{}

	cpu := 0
	res := 0
	for res == 0 {
		// Get a new perf fd
		// https://github.com/torvalds/linux/blob/v4.8/include/uapi/linux/perf_event.h
		// Type: PERF_TYPE_SOFTWARE = 1
		// config: PERF_COUNT_SW_BPF_OUTPUT = 10
		const PERF_TYPE_SOFTWARE uint32 = 1
		const PERF_COUNT_SW_BPF_OUTPUT uint64 = 10

		perfFd := C.bpf_open_perf_event(C.uint32_t(PERF_TYPE_SOFTWARE), C.uint64_t(PERF_COUNT_SW_BPF_OUTPUT), -1, C.int(cpu))

		perfFiles = append(perfFiles, os.NewFile(uintptr(perfFd), "perf"))

		fmt.Printf("perfFd=%v\n", perfFd)

		leaf[0] = byte(perfFd) // TODO: how does Go work again?
		leaf[1] = 0
		leaf[2] = 0
		leaf[3] = 0
		r, err := C.bpf_update_elem(C.int(fd), keyP, leafP, 0)
		if r != 0 {
			fmt.Printf("unable to initialize perf map: %s", err)
			os.Exit(1)
		}

		res = int(C.bpf_get_next_key(C.int(fd), keyP, keyP))
		cpu++
	}
	return perfFiles
}

func main() {
	fmt.Printf("Hello, world.\n")

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

	t := bpf.NewBpfTable(0, m)
	fmt.Printf("table: %q %q\n%v\n", t.ID(), t.Name(), t.Config())
	perfFiles := initPerfMap(t)

	fmt.Printf("Ready.\n")

	i := 0
	for {
		for _, f := range perfFiles {
			data := make([]byte, 1024)
			count, err := f.Read(data)
			if err != nil {
				fmt.Printf("Cannot read: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("iteration %d: read: count=%v data=%v %v %v %v\n", i, count, data[0], data[1], data[2], data[3])
		}
		time.Sleep(time.Second * 1)
		i++
	}

	time.Sleep(time.Second * 1000)

	//m.Close()
}
