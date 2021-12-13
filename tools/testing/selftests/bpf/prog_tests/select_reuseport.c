// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018 Facebook */

#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/err.h>
#include <linux/types.h>
#include <linux/if_ether.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "bpf_rlimit.h"
#include "bpf_util.h"

#include "test_progs.h"
#include "test_select_reuseport_common.h"

#define MAX_TEST_NAME 80
#define MIN_TCPHDR_LEN 20
#define UDPHDR_LEN 8

#define TCP_SYNCOOKIE_SYSCTL "/proc/sys/net/ipv4/tcp_syncookies"
#define TCP_FO_SYSCTL "/proc/sys/net/ipv4/tcp_fastopen"
#define REUSEPORT_ARRAY_SIZE 3

static int result_map, tmp_index_ovr_map, linum_map, data_check_map;
static __u32 expected_results[NR_RESULTS];
static int sk_fds[REUSEPORT_ARRAY_SIZE];
static int reuseport_array = -1, outer_map = -1;
static enum bpf_map_type inner_map_type;
static int select_by_skb_data_prog;
static int saved_tcp_syncookie = -1;
static struct bpf_object *obj;
static int saved_tcp_fo = -1;
static __u32 index_zero;
static int epfd;

static union sa46 {
	struct sockaddr_in6 v6;
	struct sockaddr_in v4;
	sa_family_t family;
} srv_sa;

#define RET_IF(condition, tag, format...) ({				\
	if (CHECK_FAIL(condition)) {					\
		printf(tag " " format);					\
		return;							\
	}								\
})

#define RET_ERR(condition, tag, format...) ({				\
	if (CHECK_FAIL(condition)) {					\
		printf(tag " " format);					\
		return -1;						\
	}								\
})

static int create_maps(enum bpf_map_type inner_type)
{
	struct bpf_create_map_attr attr = {};

	inner_map_type = inner_type;

	/* Creating reuseport_array */
	attr.name = "reuseport_array";
	attr.map_type = inner_type;
	attr.key_size = sizeof(__u32);
	attr.value_size = sizeof(__u32);
	attr.max_entries = REUSEPORT_ARRAY_SIZE;

	reuseport_array = bpf_create_map_xattr(&attr);
	RET_ERR(reuseport_array == -1, "creating reuseport_array",
		"reuseport_array:%d errno:%d\n", reuseport_array, errno);

	/* Creating outer_map */
	attr.name = "outer_map";
	attr.map_type = BPF_MAP_TYPE_ARRAY_OF_MAPS;
	attr.key_size = sizeof(__u32);
	attr.value_size = sizeof(__u32);
	attr.max_entries = 1;
	attr.inner_map_fd = reuseport_array;
	outer_map = bpf_create_map_xattr(&attr);
	RET_ERR(outer_map == -1, "creating outer_map",
		"outer_map:%d errno:%d\n", outer_map, errno);

	return 0;
}

static int prepare_bpf_obj(void)
{
	struct bpf_program *prog;
	struct bpf_map *map;
	int err;

	obj = bpf_object__open("test_select_reuseport_kern.o");
	RET_ERR(IS_ERR_OR_NULL(obj), "open test_select_reuseport_kern.o",
		"obj:%p PTR_ERR(obj):%ld\n", obj, PTR_ERR(obj));

	map = bpf_object__find_map_by_name(obj, "outer_map");
	RET_ERR(!map, "find outer_map", "!map\n");
	err = bpf_map__reuse_fd(map, outer_map);
	RET_ERR(err, "reuse outer_map", "err:%d\n", err);

	err = bpf_object__load(obj);
	RET_ERR(err, "load bpf_object", "err:%d\n", err);

	prog = bpf_program__next(NULL, obj);
	RET_ERR(!prog, "get first bpf_program", "!prog\n");
	select_by_skb_data_prog = bpf_program__fd(prog);
	RET_ERR(select_by_skb_data_prog == -1, "get prog fd",
		"select_by_skb_data_prog:%d\n", select_by_skb_data_prog);

	map = bpf_object__find_map_by_name(obj, "result_map");
	RET_ERR(!map, "find result_map", "!map\n");
	result_map = bpf_map__fd(map);
	RET_ERR(result_map == -1, "get result_map fd",
		"result_map:%d\n", result_map);

	map = bpf_object__find_map_by_name(obj, "tmp_index_ovr_map");
	RET_ERR(!map, "find tmp_index_ovr_map\n", "!map");
	tmp_index_ovr_map = bpf_map__fd(map);
	RET_ERR(tmp_index_ovr_map == -1, "get tmp_index_ovr_map fd",
		"tmp_index_ovr_map:%d\n", tmp_index_ovr_map);

	map = bpf_object__find_map_by_name(obj, "linum_map");
	RET_ERR(!map, "find linum_map", "!map\n");
	linum_map = bpf_map__fd(map);
	RET_ERR(linum_map == -1, "get linum_map fd",
		"linum_map:%d\n", linum_map);

	map = bpf_object__find_map_by_name(obj, "data_check_map");
	RET_ERR(!map, "find data_check_map", "!map\n");
	data_check_map = bpf_map__fd(map);
	RET_ERR(data_check_map == -1, "get data_check_map fd",
		"data_check_map:%d\n", data_check_map);

	return 0;
}

static void sa46_init_loopback(union sa46 *sa, sa_family_t family)
{
	memset(sa, 0, sizeof(*sa));
	sa->family = family;
	if (sa->family == AF_INET6)
		sa->v6.sin6_addr = in6addr_loopback;
	else {
		sa->v4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        }
}

static void sa46_init_inany(union sa46 *sa, sa_family_t family)
{
	memset(sa, 0, sizeof(*sa));
	sa->family = family;
	if (sa->family == AF_INET6)
		sa->v6.sin6_addr = in6addr_any;
	else
		sa->v4.sin_addr.s_addr = INADDR_ANY;
}

static int read_int_sysctl(const char *sysctl)
{
	char buf[16];
	int fd, ret;

	fd = open(sysctl, 0);
	RET_ERR(fd == -1, "open(sysctl)",
		"sysctl:%s fd:%d errno:%d\n", sysctl, fd, errno);

	ret = read(fd, buf, sizeof(buf));
	RET_ERR(ret <= 0, "read(sysctl)",
		"sysctl:%s ret:%d errno:%d\n", sysctl, ret, errno);

	close(fd);
	return atoi(buf);
}

static int write_int_sysctl(const char *sysctl, int v)
{
	int fd, ret, size;
	char buf[16];

	fd = open(sysctl, O_RDWR);
	RET_ERR(fd == -1, "open(sysctl)",
		"sysctl:%s fd:%d errno:%d\n", sysctl, fd, errno);

	size = snprintf(buf, sizeof(buf), "%d", v);
	ret = write(fd, buf, size);
	RET_ERR(ret != size, "write(sysctl)",
		"sysctl:%s ret:%d size:%d errno:%d\n",
		sysctl, ret, size, errno);

	close(fd);
	return 0;
}

static void restore_sysctls(void)
{
	if (saved_tcp_fo != -1)
		write_int_sysctl(TCP_FO_SYSCTL, saved_tcp_fo);
	if (saved_tcp_syncookie != -1)
		write_int_sysctl(TCP_SYNCOOKIE_SYSCTL, saved_tcp_syncookie);
}

static int enable_fastopen(void)
{
	int fo;

	fo = read_int_sysctl(TCP_FO_SYSCTL);
	if (fo < 0)
		return -1;

	return write_int_sysctl(TCP_FO_SYSCTL, fo | 7);
}

static int enable_syncookie(void)
{
	return write_int_sysctl(TCP_SYNCOOKIE_SYSCTL, 2);
}

static int disable_syncookie(void)
{
	return write_int_sysctl(TCP_SYNCOOKIE_SYSCTL, 0);
}

static long get_linum(void)
{
	__u32 linum;
	int err;

	err = bpf_map_lookup_elem(linum_map, &index_zero, &linum);
	RET_ERR(err == -1, "lookup_elem(linum_map)", "err:%d errno:%d\n",
		err, errno);

	return linum;
}

static void check_data(int type, sa_family_t family, const struct cmd *cmd,
		       int cli_fd)
{
	struct data_check expected = {}, result;
	union sa46 cli_sa;
	socklen_t addrlen;
	int err;

	addrlen = sizeof(cli_sa);
	err = getsockname(cli_fd, (struct sockaddr *)&cli_sa,
			  &addrlen);
	RET_IF(err == -1, "getsockname(cli_fd)", "err:%d errno:%d\n",
	       err, errno);

	err = bpf_map_lookup_elem(data_check_map, &index_zero, &result);
	RET_IF(err == -1, "lookup_elem(data_check_map)", "err:%d errno:%d\n",
	       err, errno);

	if (type == SOCK_STREAM) {
		expected.len = MIN_TCPHDR_LEN;
		expected.ip_protocol = IPPROTO_TCP;
	} else {
		expected.len = UDPHDR_LEN;
		expected.ip_protocol = IPPROTO_UDP;
	}

        expected.eth_protocol = htons(ETH_P_IP);
        expected.bind_inany = !srv_sa.v4.sin_addr.s_addr;

        expected.skb_addrs[0] = cli_sa.v4.sin_addr.s_addr;
        expected.skb_addrs[1] = htonl(INADDR_LOOPBACK);
        expected.skb_ports[0] = cli_sa.v4.sin_port;
        expected.skb_ports[1] = srv_sa.v4.sin_port;


	if (memcmp(&result, &expected, offsetof(struct data_check,
						equal_check_end))) {
		printf("unexpected data_check\n");
		printf("  result: (0x%x, %u, %u)\n",
		       result.eth_protocol, result.ip_protocol,
		       result.bind_inany);
		printf("expected: (0x%x, %u, %u)\n",
		       expected.eth_protocol, expected.ip_protocol,
		       expected.bind_inany);
		RET_IF(1, "data_check result != expected",
		       "bpf_prog_linum:%ld\n", get_linum());
	}

	RET_IF(!result.hash, "data_check result.hash empty",
	       "result.hash:%u", result.hash);

	expected.len += cmd ? sizeof(*cmd) : 0;
	if (type == SOCK_STREAM)
		RET_IF(expected.len > result.len, "expected.len > result.len",
		       "expected.len:%u result.len:%u bpf_prog_linum:%ld\n",
		       expected.len, result.len, get_linum());
	else
		RET_IF(expected.len != result.len, "expected.len != result.len",
		       "expected.len:%u result.len:%u bpf_prog_linum:%ld\n",
		       expected.len, result.len, get_linum());
}

static const char *result_to_str(enum result res)
{
	switch (res) {
	case DROP_ERR_INNER_MAP:
		return "DROP_ERR_INNER_MAP";
	case DROP_ERR_SKB_DATA:
		return "DROP_ERR_SKB_DATA";
	case DROP_ERR_SK_SELECT_REUSEPORT:
		return "DROP_ERR_SK_SELECT_REUSEPORT";
	case DROP_MISC:
		return "DROP_MISC";
	case PASS:
		return "PASS";
	case PASS_ERR_SK_SELECT_REUSEPORT:
		return "PASS_ERR_SK_SELECT_REUSEPORT";
	default:
		return "UNKNOWN";
	}
}

static void check_results(void)
{
	__u32 results[NR_RESULTS];
	__u32 i, broken = 0;
	int err;

	for (i = 0; i < NR_RESULTS; i++) {
		err = bpf_map_lookup_elem(result_map, &i, &results[i]);
		RET_IF(err == -1, "lookup_elem(result_map)",
		       "i:%u err:%d errno:%d\n", i, err, errno);
	}

	for (i = 0; i < NR_RESULTS; i++) {
		if (results[i] != expected_results[i]) {
			broken = i;
			break;
		}
	}

	if (i == NR_RESULTS)
		return;

	printf("unexpected result\n");
	printf(" result: [");
	printf("%u", results[0]);
	for (i = 1; i < NR_RESULTS; i++)
		printf(", %u", results[i]);
	printf("]\n");

	printf("expected: [");
	printf("%u", expected_results[0]);
	for (i = 1; i < NR_RESULTS; i++)
		printf(", %u", expected_results[i]);
	printf("]\n");

	printf("mismatch on %s (bpf_prog_linum:%ld)\n", result_to_str(broken),
	       get_linum());

	CHECK_FAIL(true);
}

static int connect_srv(int type, sa_family_t family, int i,
		     enum result expected, int port)
{
	union sa46 cli_sa;
	int fd, err;

	memset(&cli_sa, 0, sizeof(cli_sa));
	fd = socket(family, type, 0);
	cli_sa.v4.sin_family = family;
        cli_sa.v4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        printf("client bind %d \n", port);
	cli_sa.v4.sin_port = htons(port);
        err = bind(fd, (struct sockaddr *)&cli_sa, sizeof(cli_sa));

	err = connect(fd, (struct sockaddr *)&srv_sa,
		     sizeof(srv_sa));
        if (err != 0)
           printf("connect failed\n");
	return fd;
}

static void do_test(int type, sa_family_t family, int i,
		    enum result expected)
{
	int nev, srv_fd, cli_fd;
	struct epoll_event ev;
	ssize_t nread;
        char buf[10];
        char clibuf[10];
        int ret;
        int port = 50000 + i;
        sprintf(buf, "%d", port);
        memset(clibuf, 0, sizeof clibuf);

	cli_fd = connect_srv(type, family, i, expected, port);
	nev = epoll_wait(epfd, &ev, 1, expected >= PASS ? 5 : 0);
	srv_fd = sk_fds[ev.data.u32];
        int new_fd;
	if (type == SOCK_STREAM) {
		new_fd = accept(srv_fd, NULL, NULL);
                printf("after accept server listen fd is %d, client port is %d, ev is %d \n",
                      srv_fd, port, ev.data.u32);
        } 
        printf("test write data %s from server to client\n", buf);
        write(new_fd, buf, 10);
        read(cli_fd, clibuf, 10);
        printf("client read data is %s \n", clibuf);
}
#define CLINUM 2
static void test_pass(int type, sa_family_t family)
{
	struct cmd cmd;
	int i;

	cmd.pass_on_failure = 0;
	for (i = 0; i < CLINUM; i++) {
		expected_results[PASS]++;
		do_test(type, family, i, PASS);
	}
}


#define SRVNUM 4
static void prepare_sk_fds(int type, sa_family_t family, bool inany)
{
	int i, err, optval = 1;
	struct epoll_event ev;
	socklen_t addrlen;

	struct sockaddr_in *v4 =(struct sockaddr_in *)(&srv_sa);
	if (inany)
		sa46_init_inany(&srv_sa, family);
	else
		sa46_init_loopback(&srv_sa, family);
	v4->sin_port = htons(8080);

	addrlen = sizeof(srv_sa);

	/*
	 * The sk_fds[] is filled from the back such that the order
	 * is exactly opposite to the (struct sock_reuseport *)reuse->socks[].
	 */
	for (i = 0; i < SRVNUM; i++) {
		sk_fds[i] = socket(family, type, 0);


		err = setsockopt(sk_fds[i], SOL_SOCKET, SO_REUSEPORT,
				 &optval, sizeof(optval));

		if (i == 0) {
			err = setsockopt(sk_fds[i], SOL_SOCKET,
					 SO_ATTACH_REUSEPORT_EBPF,
					 &select_by_skb_data_prog,
					 sizeof(select_by_skb_data_prog));
		}
		err = bind(sk_fds[i], (struct sockaddr *)&srv_sa, addrlen);

		if (type == SOCK_STREAM) {
			err = listen(sk_fds[i], 10);
			RET_IF(err == -1, "listen()",
			       "sk_fds[%d] err:%d errno:%d\n",
			       i, err, errno);
		}

                printf("reuseport_array[%d] fd is  %d\n", i, sk_fds[i]);
		err = bpf_map_update_elem(reuseport_array, &i, &sk_fds[i],
					  BPF_NOEXIST);

	}

	epfd = epoll_create(1);
	RET_IF(epfd == -1, "epoll_create(1)",
	       "epfd:%d errno:%d\n", epfd, errno);

	ev.events = EPOLLIN;
	for (i = 0; i < SRVNUM; i++) {
		ev.data.u32 = i;
		err = epoll_ctl(epfd, EPOLL_CTL_ADD, sk_fds[i], &ev);
		RET_IF(err, "epoll_ctl(EPOLL_CTL_ADD)", "sk_fds[%d]\n", i);
	}
}

static void setup_per_test(int type, sa_family_t family, bool inany,
			   bool no_inner_map)
{
	int ovr = -1, err;

	prepare_sk_fds(type, family, inany);
	err = bpf_map_update_elem(tmp_index_ovr_map, &index_zero, &ovr,
				  BPF_ANY);
	RET_IF(err == -1, "update_elem(tmp_index_ovr_map, 0, -1)",
	       "err:%d errno:%d\n", err, errno);

	/* Install reuseport_array to outer_map? */
	if (no_inner_map)
		return;

	err = bpf_map_update_elem(outer_map, &index_zero, &reuseport_array,
				  BPF_ANY);
	RET_IF(err == -1, "update_elem(outer_map, 0, reuseport_array)",
	       "err:%d errno:%d\n", err, errno);
}

static void cleanup_per_test(bool no_inner_map)
{
	int i, err, zero = 0;

	memset(expected_results, 0, sizeof(expected_results));

	for (i = 0; i < NR_RESULTS; i++) {
		err = bpf_map_update_elem(result_map, &i, &zero, BPF_ANY);
		RET_IF(err, "reset elem in result_map",
		       "i:%u err:%d errno:%d\n", i, err, errno);
	}

	err = bpf_map_update_elem(linum_map, &zero, &zero, BPF_ANY);
	RET_IF(err, "reset line number in linum_map", "err:%d errno:%d\n",
	       err, errno);

	for (i = 0; i < REUSEPORT_ARRAY_SIZE; i++)
		close(sk_fds[i]);
	close(epfd);

	/* Delete reuseport_array from outer_map? */
	if (no_inner_map)
		return;

	err = bpf_map_delete_elem(outer_map, &index_zero);
	RET_IF(err == -1, "delete_elem(outer_map)",
	       "err:%d errno:%d\n", err, errno);
}

static void cleanup(void)
{
	if (outer_map != -1) {
		close(outer_map);
		outer_map = -1;
	}

	if (reuseport_array != -1) {
		close(reuseport_array);
		reuseport_array = -1;
	}

	if (obj) {
		bpf_object__close(obj);
		obj = NULL;
	}

	memset(expected_results, 0, sizeof(expected_results));
}

static const char *maptype_str(enum bpf_map_type type)
{
	switch (type) {
	case BPF_MAP_TYPE_REUSEPORT_SOCKARRAY:
		return "reuseport_sockarray";
	case BPF_MAP_TYPE_SOCKMAP:
		return "sockmap";
	case BPF_MAP_TYPE_SOCKHASH:
		return "sockhash";
	default:
		return "unknown";
	}
}

static const char *family_str(sa_family_t family)
{
	switch (family) {
	case AF_INET:
		return "IPv4";
	case AF_INET6:
		return "IPv6";
	default:
		return "unknown";
	}
}

static const char *sotype_str(int sotype)
{
	switch (sotype) {
	case SOCK_STREAM:
		return "TCP";
	case SOCK_DGRAM:
		return "UDP";
	default:
		return "unknown";
	}
}

#define TEST_INIT(fn_, ...) { .fn = fn_, .name = #fn_, __VA_ARGS__ }

static void test_config(int sotype, sa_family_t family, bool inany)
{
	const struct test {
		void (*fn)(int sotype, sa_family_t family);
		const char *name;
		bool no_inner_map;
		int need_sotype;
	} tests[] = {
		//TEST_INIT(test_err_inner_map,
		//	  .no_inner_map = true),
	//	TEST_INIT(test_err_skb_data),
	//	TEST_INIT(test_err_sk_select_port),
		TEST_INIT(test_pass),
	//	TEST_INIT(test_syncookie,
	//		  .need_sotype = SOCK_STREAM),
	//	TEST_INIT(test_pass_on_err),
	//	TEST_INIT(test_detach_bpf),
	};
	char s[MAX_TEST_NAME];
	const struct test *t;

	for (t = tests; t < tests + ARRAY_SIZE(tests); t++) {
		if (t->need_sotype && t->need_sotype != sotype)
			continue; /* test not compatible with socket type */

		snprintf(s, sizeof(s), "%s %s/%s %s %s",
			 maptype_str(inner_map_type),
			 family_str(family), sotype_str(sotype),
			 inany ? "INANY" : "LOOPBACK", t->name);

		if (!test__start_subtest(s))
			continue;

		setup_per_test(sotype, family, inany, t->no_inner_map);
		t->fn(sotype, family);
		cleanup_per_test(t->no_inner_map);
	}
}

#define BIND_INANY true

static void test_all(void)
{
	const struct config {
		int sotype;
		sa_family_t family;
		bool inany;
	} configs[] = {
		{ SOCK_STREAM, AF_INET },
	//	{ SOCK_STREAM, AF_INET, BIND_INANY },
	//	{ SOCK_STREAM, AF_INET6 },
	//	{ SOCK_STREAM, AF_INET6, BIND_INANY },
	//	{ SOCK_DGRAM, AF_INET },
	//	{ SOCK_DGRAM, AF_INET6 },
	};
	const struct config *c;

	for (c = configs; c < configs + ARRAY_SIZE(configs); c++)
		test_config(c->sotype, c->family, c->inany);
}

void test_map_type(enum bpf_map_type mt)
{
	if (create_maps(mt))
		goto out;
	if (prepare_bpf_obj())
		goto out;

	test_all();
out:
	cleanup();
}

void test_select_reuseport(void)
{
        fprintf(stdout, "%s", "jm test begins\n");
	saved_tcp_fo = read_int_sysctl(TCP_FO_SYSCTL);
	if (saved_tcp_fo < 0)
		goto out;
	saved_tcp_syncookie = read_int_sysctl(TCP_SYNCOOKIE_SYSCTL);
	if (saved_tcp_syncookie < 0)
		goto out;

	if (enable_fastopen())
		goto out;
	if (disable_syncookie())
		goto out;

	test_map_type(BPF_MAP_TYPE_REUSEPORT_SOCKARRAY);
	//test_map_type(BPF_MAP_TYPE_SOCKMAP);
	//test_map_type(BPF_MAP_TYPE_SOCKHASH);
out:
	restore_sysctls();
}
