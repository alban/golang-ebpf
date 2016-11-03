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
#include <bcc/perf_reader.h>
#include <stdio.h>
void *bpf_open_perf_buffer(perf_reader_raw_cb raw_cb, void *cb_cookie, int pid, int cpu);

struct tcp_event_t {
        unsigned long long pid;
        unsigned long long dummy;
};

void callback(int cpu, void *data, int size) {
	struct tcp_event_t *ev = (struct tcp_event_t *)data;
	uint32_t pid, tid;

	if (size != sizeof(*ev)) {
		printf("Invalid tcp_event_t event\n");
		return;
	}

	pid = ev->pid & 0xffffffff;
	tid = (ev->pid >>32) & 0xffffffff;

	printf("Hello bpf, my pid is %d and tid is %d\n", pid, tid);
}

void raw_cb(void *cb_cookie, void *raw, int raw_size) {
	// See src/cc/perf_reader.c:parse_sw()
	// struct {
	//     uint32_t size;
	//     char data[0];
	// };

	if (raw_size != sizeof(uint32_t) + sizeof(struct tcp_event_t)) {
		printf("Invalid perf event: raw_size=%d != %lu + %lu\n", raw_size, sizeof(uint32_t), sizeof(struct tcp_event_t));
		return;
	}

	callback(0, raw, raw_size - sizeof(uint32_t));
}
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

func initPerfMap(table *bpf.BpfTable) []*C.struct_perf_reader {
	fd := table.Config()["fd"].(int)
	key_size := table.Config()["key_size"].(uint64)
	leaf_size := table.Config()["leaf_size"].(uint64)
	key := make([]byte, key_size)
	leaf := make([]byte, leaf_size)
	keyP := unsafe.Pointer(&key[0])
	leafP := unsafe.Pointer(&leaf[0])

	readers := []*C.struct_perf_reader{}

	cpu := 0
	res := 0
	for res == 0 {
		// Get a new perf fd
		// https://github.com/torvalds/linux/blob/v4.8/include/uapi/linux/perf_event.h
		// Type: PERF_TYPE_SOFTWARE = 1
		// config: PERF_COUNT_SW_BPF_OUTPUT = 10
		const PERF_TYPE_SOFTWARE uint32 = 1
		const PERF_COUNT_SW_BPF_OUTPUT uint64 = 10

		reader := C.bpf_open_perf_buffer((*[0]byte)(C.raw_cb), nil, -1, C.int(cpu))
		if reader == nil {
			fmt.Printf("failed to get reader\n")
			os.Exit(1)
		}

		perfFd := C.perf_reader_fd(reader)

		readers = append(readers, (*C.struct_perf_reader)(reader))

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
	return readers

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
	readers := initPerfMap(t)

	fmt.Printf("Ready.\n")

	for {
		C.perf_reader_poll(4, &readers[0], -1)
	}

	time.Sleep(time.Second * 1000)

	//m.Close()
}
