package main

import (
	"fmt"
	"os"
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

extern void tcpEventCb();

#define TASK_COMM_LEN 16 // linux/sched.h

struct sizes_t {
        uint64_t struct_sock_size;
        uint64_t struct_inet_sock_size;
        uint64_t possible_net_t_size;
        uint64_t struct_net_size;
        uint64_t struct_ns_common_size;

	uint64_t offset_struct_inet_sock_inet_sport;
	uint64_t offset_struct_sock_skc_rcv_saddr;
	uint64_t offset_struct_sock_skc_daddr;
	uint64_t offset_struct_sock_skc_dport;
	uint64_t offset_struct_sock_skc_net;
	uint64_t offset_struct_sock_sk_protocol;

	uint64_t offset_possible_net_t_net;
	uint64_t offset_struct_net_ns;
	uint64_t offset_struct_ns_common_inum;
};

*/
import "C"

const source string = `
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <net/net_namespace.h>


#define SIZE_STRUCT_SOCK 728
#define SIZE_STRUCT_INET_SOCK 904
#define SIZE_POSSIBLE_NET_T 8

#define OFFSET_STRUCT_INET_SOCK_INET_SPORT 744
#define OFFSET_STRUCT_SOCK_SKC_RCV_SADDR 4
#define OFFSET_STRUCT_SOCK_SKC_DADDR 0
#define OFFSET_STRUCT_SOCK_SKC_DPORT 12
#define OFFSET_STRUCT_SOCK_SKC_NET 48
#define OFFSET_STRUCT_SOCK_SK_PROTOCOL 329

#define SIZE_STRUCT_NS_COMMON 42
#define OFFSET_POSSIBLE_NET_T_NET 0

struct sizes_t {
	u64 struct_sock_size;
	u64 struct_inet_sock_size;
        u64 possible_net_t_size;
        u64 struct_net_size;
        u64 struct_ns_common_size;

	u64 offset_struct_inet_sock_inet_sport;
	u64 offset_struct_sock_skc_rcv_saddr;
	u64 offset_struct_sock_skc_daddr;
	u64 offset_struct_sock_skc_dport;
	u64 offset_struct_sock_skc_net;
	u64 offset_struct_sock_sk_protocol;

	u64 offset_possible_net_t_net;
	u64 offset_struct_net_ns;
	u64 offset_struct_ns_common_inum;
};

BPF_PERF_OUTPUT(sizes_event);

int kprobe__tcp_v4_connect(struct pt_regs *ctx)
{
	bpf_trace_printk("tcp_v4_connect\n");

	struct sizes_t evt = {0,};

	evt.struct_sock_size = sizeof(struct sock);
	evt.struct_inet_sock_size = sizeof(struct inet_sock);
	evt.possible_net_t_size = sizeof(possible_net_t);
	evt.struct_net_size = sizeof(struct net);
	evt.struct_ns_common_size = sizeof(struct ns_common);

	evt.offset_struct_inet_sock_inet_sport = (u64)(&((struct inet_sock *)NULL)->inet_sport);
	evt.offset_struct_sock_skc_rcv_saddr = (u64)(&((struct sock *)NULL)->__sk_common.skc_rcv_saddr);
	evt.offset_struct_sock_skc_daddr = (u64)(&((struct sock *)NULL)->__sk_common.skc_daddr);
	evt.offset_struct_sock_skc_dport = (u64)(&((struct sock *)NULL)->__sk_common.skc_dport);
	evt.offset_struct_sock_skc_net = (u64)(&((struct sock *)NULL)->__sk_common.skc_net);
	evt.offset_struct_sock_sk_protocol = (u64)((void *)(&((struct sock *)NULL)->sk_wmem_queued) - 3);

	evt.offset_possible_net_t_net = (u64)((void *)(&((possible_net_t *)NULL)->net));
	evt.offset_struct_net_ns = (u64)((void *)(&((struct net *)NULL)->ns));
	evt.offset_struct_ns_common_inum = (u64)((void *)(&((struct ns_common *)NULL)->inum));

	sizes_event.perf_submit(ctx, &evt, sizeof(evt));

	return 0;
};

`

func tcpEventCallback(cpu int, sizes *C.struct_sizes_t) {
	fmt.Println(
		sizes.struct_sock_size,
		sizes.struct_inet_sock_size,
		sizes.possible_net_t_size,
		sizes.struct_net_size,
		sizes.struct_ns_common_size,

		sizes.offset_struct_inet_sock_inet_sport,
		sizes.offset_struct_sock_skc_rcv_saddr,
		sizes.offset_struct_sock_skc_daddr,
		sizes.offset_struct_sock_skc_dport,
		sizes.offset_struct_sock_skc_net,
		sizes.offset_struct_sock_sk_protocol,

		sizes.offset_possible_net_t_net,
		sizes.offset_struct_net_ns,
		sizes.offset_struct_ns_common_inum,
	)
}

//export tcpEventCb
func tcpEventCb(cb_cookie unsafe.Pointer, raw unsafe.Pointer, raw_size C.int) {
	// See src/cc/perf_reader.c:parse_sw()
	// struct {
	//     uint32_t size;
	//     char data[0];
	// };

	var sizes C.struct_sizes_t

	if int(raw_size) != 4+int(unsafe.Sizeof(sizes)) {
		fmt.Printf("Invalid perf event: raw_size=%d != %d + %d\n", raw_size, 4, unsafe.Sizeof(sizes))
		return
	}

	tcpEventCallback(0, (*C.struct_sizes_t)(raw))
}

func initPerfMap(table *bpf.BpfTable) []*C.struct_perf_reader {
	fd := table.Config()["fd"].(int)
	key_size := table.Config()["key_size"].(uint64)
	leaf_size := table.Config()["leaf_size"].(uint64)

	if key_size != 4 || leaf_size != 4 {
		fmt.Printf("Wrong size\n")
		os.Exit(1)
	}

	key := make([]byte, key_size)
	leaf := make([]byte, leaf_size)
	keyP := unsafe.Pointer(&key[0])
	leafP := unsafe.Pointer(&leaf[0])

	readers := []*C.struct_perf_reader{}

	cpu := 0
	res := 0
	for res == 0 {
		reader := C.bpf_open_perf_buffer((*[0]byte)(C.tcpEventCb), nil, -1, C.int(cpu))
		if reader == nil {
			fmt.Printf("failed to get reader\n")
			os.Exit(1)
		}

		perfFd := C.perf_reader_fd(reader)

		readers = append(readers, (*C.struct_perf_reader)(reader))

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
	m := bpf.NewBpfModule(source, []string{})

	connect_kprobe, err := m.LoadKprobe("kprobe__tcp_v4_connect")
	if err != nil {
		fmt.Printf("Failed to LoadKprobe: %v\n", err)
		os.Exit(1)
	}
	err = m.AttachKprobe("tcp_v4_connect", connect_kprobe)
	if err != nil {
		fmt.Printf("Failed to AttachKprobe: %v\n", err)
		os.Exit(1)
	}

	t := bpf.NewBpfTable(0, m)
	readers := initPerfMap(t)

	fmt.Printf("Ready.\n")

	for {
		C.perf_reader_poll(C.int(len(readers)), &readers[0], -1)
	}

	fmt.Printf("Terminated.\n")
	m.Close()
}
