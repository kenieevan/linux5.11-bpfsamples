// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018 Facebook */

#define __USE_GNU  
#define _GNU_SOURCE
#include <sched.h>
#include <pthread.h>
#include <stdio.h>
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
#define REUSEPORT_ARRAY_SIZE 2

static __u32 expected_results[NR_RESULTS];
static int sk_fds[REUSEPORT_ARRAY_SIZE];
static int reuseport_array = -1, outer_map = -1;
static enum bpf_map_type inner_map_type;
static int select_by_skb_data_prog;
static struct bpf_object *obj;
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

static int connect_srv(int type, sa_family_t family, int i,
		     enum result expected)
{
	union sa46 cli_sa;
	int fd, err;

	memset(&cli_sa, 0, sizeof(cli_sa));
	fd = socket(family, type, 0);
	cli_sa.v4.sin_family = family;
        cli_sa.v4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
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
	int cli_fd;
	//ssize_t nread;
        char buf[10];
        memset(buf, 0, sizeof buf);

	cli_fd = connect_srv(type, family, i, expected);
        printf("client write cpuid  %s to server \n", buf);
        write(cli_fd, buf, 10);
}

#define CLINUM 2
static void test_pass(int type, sa_family_t family)
{
	int i;
        struct cmd cmd;
	cmd.pass_on_failure = 0;
	for (i = 0; i < CLINUM; i++) {
		expected_results[PASS]++;
		do_test(type, family, i, PASS);
	}
}
void * server_fn(void *arg)
{
   int ret;
   int err;
   int optval = 1;
   cpu_set_t cpuset;
   pthread_t thread;
   int i = (int)arg;
   thread = pthread_self();
   CPU_ZERO(&cpuset);
   CPU_SET(i, &cpuset);
   printf("set id %d\n", i);
   ret = pthread_setaffinity_np(thread, sizeof(cpuset), &cpuset);
   if (ret != 0) {
      printf("set affinity failed\n");
      exit(-1);
   }

   /* Check the actual affinity mask assigned to the thread */
   ret = pthread_getaffinity_np(thread, sizeof(cpuset), &cpuset);
   if (ret != 0) {
      printf("get affinity failed\n");
      exit(-1);
   }
   printf("Set returned by pthread_getaffinity_np() contained:\n");
   for (int j = 0; j < 8; j++)
      if (CPU_ISSET(j, &cpuset))
         printf("    CPU %d\n", j);
   // set cpu affinity
   sk_fds[i] = socket(AF_INET,SOCK_STREAM, 0);
   ret = setsockopt(sk_fds[i], SOL_SOCKET, SO_REUSEPORT,
         &optval, sizeof(optval));
   if (ret != 0) {
      printf("set SO_REUSEPORT failed\n");
      exit(-1);
   }
   int enable = 1;
   err = setsockopt(sk_fds[i], SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));
   if (err != 0) {
      printf("set SO_REUSEADDR failed\n");
      exit(-1);
   }
   if (i == 0) {
      err = setsockopt(sk_fds[i], SOL_SOCKET,
            SO_ATTACH_REUSEPORT_EBPF,
            &select_by_skb_data_prog,
            sizeof(select_by_skb_data_prog));
   }
   err = bind(sk_fds[i], (struct sockaddr *)&srv_sa, sizeof(srv_sa));
   if (err != 0) { 
      printf("server socket bind failed\n");
      exit(-1);
   }
   err = listen(sk_fds[i], 10);
   printf("reuseport_array[%d] fd is  %d\n", i, sk_fds[i]);
   err = bpf_map_update_elem(reuseport_array, &i, &sk_fds[i],
                             BPF_NOEXIST);

   int new_fd;
   new_fd = accept(sk_fds[i], NULL, NULL);
   if (new_fd == -1) {
        printf("server accept failed\n");
        exit(-1);
   }   
   char buf[10];
   memset(buf, 0, sizeof buf);
   //read data and compare its cpuid.  
   err = read(new_fd, buf, 10);
   if (err == -1) {
        printf("server read data failed\n");
        exit(-1);
   }
   printf("server on cpu %d get data %s\n", i, buf);
   // wait for the client threads to send some message.
   sleep(100);
   return NULL;
}
#define SRVNUM 2
pthread_t tid[SRVNUM];
static void setup_server(int type, sa_family_t family, bool inany)
{
	int i, err;
        struct sockaddr_in *v4 =(struct sockaddr_in *)(&srv_sa);
        sa46_init_loopback(&srv_sa, family);
        v4->sin_port = htons(8080);

	for (i = 0; i < SRVNUM; i++) {
             err = pthread_create(&tid[i], NULL, server_fn, (void *)i);
             if (err != 0) {
                printf("create pthread failed %d\n", i);
                return;
             }

        }
}

static void setup_per_test(int type, sa_family_t family, bool inany,
			   bool no_inner_map)
{
	int err;

	setup_server(type, family, inany);

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
	int i, err;

	memset(expected_results, 0, sizeof(expected_results));

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
		TEST_INIT(test_pass),
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
	test_map_type(BPF_MAP_TYPE_REUSEPORT_SOCKARRAY);
}
