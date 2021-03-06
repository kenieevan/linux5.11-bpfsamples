// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018 Facebook */

#include <stdlib.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/if_ether.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "test_select_reuseport_common.h"

int _version SEC("version") = 1;

#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} outer_map SEC(".maps");

#define GOTO_DONE(_result) ({			\
	result = (_result);			\
	goto done;				\
})

/* Helper macro to print out debug messages */
#define bpf_printk(fmt, ...)                            \
({                                                      \
        char ____fmt[] = fmt;                           \
        bpf_trace_printk(____fmt, sizeof(____fmt),      \
                         ##__VA_ARGS__);                \
})

SEC("sk_reuseport")
int _select_by_skb_data(struct sk_reuseport_md *reuse_md)
{
	__u32  index = 0, flags = 0, index_zero = 0;
	__u32 *result_cnt;
	struct data_check data_check = {};
	void *data, *data_end;
	void *reuseport_array;
	enum result result;
	int *index_ovr;
	int err;

	data = reuse_md->data;
	data_end = reuse_md->data_end;
	data_check.len = reuse_md->len;
	data_check.eth_protocol = reuse_md->eth_protocol;
	data_check.ip_protocol = reuse_md->ip_protocol;
	data_check.hash = reuse_md->hash;
	data_check.bind_inany = reuse_md->bind_inany;
	if (data_check.eth_protocol == bpf_htons(ETH_P_IP)) {
		if (bpf_skb_load_bytes_relative(reuse_md,
						offsetof(struct iphdr, saddr),
						data_check.skb_addrs, 8,
						BPF_HDR_START_NET))
			GOTO_DONE(DROP_MISC);
	} 
	/*
	 * The ip_protocol could be a compile time decision
	 * if the bpf_prog.o is dedicated to either TCP or
	 * UDP.
	 *
	 * Otherwise, reuse_md->ip_protocol or
	 * the protocol field in the iphdr can be used.
	 */
	if (data_check.ip_protocol == IPPROTO_TCP) {
		struct tcphdr *th = data;
		if (th + 1 > data_end)
			GOTO_DONE(DROP_MISC);
		data_check.skb_ports[0] = th->source;
		data_check.skb_ports[1] = th->dest;
                index = bpf_get_smp_processor_id();
                bpf_printk("sport %d, dport %d cpuid: %d\n", 
                      bpf_htons(th->source), 
                      bpf_htons(th->dest),
                      index);
		if (th->fin)
			/* The connection is being torn down at the end of a
			 * test. It can't contain a cmd, so return early.
			 */
			return SK_PASS;
	}  else {
		GOTO_DONE(DROP_MISC);
	}
	reuseport_array = bpf_map_lookup_elem(&outer_map, &index_zero);
	if (!reuseport_array)
		GOTO_DONE(DROP_ERR_INNER_MAP);
	err = bpf_sk_select_reuseport(reuse_md, reuseport_array, &index,
				      flags);
done:
	return SK_PASS;
}

char _license[] SEC("license") = "GPL";
