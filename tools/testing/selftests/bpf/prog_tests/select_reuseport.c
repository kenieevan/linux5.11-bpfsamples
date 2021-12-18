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

#define SRVNUM 2
#define CLINUM 2
#define REUSEPORT_ARRAY_SIZE 2
pthread_t cli_tid[CLINUM];
pthread_t tid[SRVNUM];

static int sk_fds[REUSEPORT_ARRAY_SIZE];
static int reuseport_array = -1, outer_map = -1;
static enum bpf_map_type inner_map_type;
static int select_by_skb_data_prog;
static struct bpf_object *obj;
static __u32 index_zero;
struct sockaddr_in v4;

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
        if (reuseport_array == -1) {
                printf("creating reuseport_array");
                exit(-1);
        }

	/* Creating outer_map */
	attr.name = "outer_map";
	attr.map_type = BPF_MAP_TYPE_ARRAY_OF_MAPS;
	attr.key_size = sizeof(__u32);
	attr.value_size = sizeof(__u32);
	attr.max_entries = 1;
	attr.inner_map_fd = reuseport_array;
	outer_map = bpf_create_map_xattr(&attr);
	if(outer_map == -1) {
                printf("create outer_map failed\n");
                exit(-1);
        }

	return 0;
}

static int prepare_bpf_obj(void)
{
	struct bpf_program *prog;
	struct bpf_map *map;

	obj = bpf_object__open("test_select_reuseport_kern.o");

	map = bpf_object__find_map_by_name(obj, "outer_map");
	err = bpf_map__reuse_fd(map, outer_map);

	err = bpf_object__load(obj);

	prog = bpf_program__next(NULL, obj);
	select_by_skb_data_prog = bpf_program__fd(prog);

	return 0;
}

void* client_fn(void *arg)
{
   int ret;
   cpu_set_t cpuset;
   pthread_t thread;
   int i = (int)arg;
   char buf[10];
   int fd;

   thread = pthread_self();
   CPU_ZERO(&cpuset);
   CPU_SET(i, &cpuset);

   memset(buf, 0, sizeof buf);
   sprintf(buf, "%d", i);
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
   for (int j = 0; j < 8; j++)
      if (CPU_ISSET(j, &cpuset))
         printf("client %d starts\n", j);

   fd = socket(AF_INET, SOCK_STREAM, 0);
   ret = connect(fd, (struct sockaddr *)&v4, sizeof(v4));
   if (ret != 0)
      printf("connect failed\n");

   printf("client %d write %s to server \n", i, buf);
   ret = write(fd, buf, 10);
   if (ret == -1) {
        printf("client writes to server failed\n");
        exit(-1);
   }
  
   sleep(10);
   return NULL;
}

static void setup_client()
{
   int i, err;
   for (i = 0; i < CLINUM; i++) {
      err = pthread_create(&cli_tid[i], NULL, client_fn, (void *)i);
      if (err != 0) {
         printf("create client pthread failed %d\n", i);
         return;
      }
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
   for (int j = 0; j < 8; j++)
      if (CPU_ISSET(j, &cpuset))
         printf("server %d starts\n", j);
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
   err = bind(sk_fds[i], (struct sockaddr *)&v4, sizeof(v4));
   if (err != 0) { 
      printf("server %d socket bind failed %s\n", i, strerror(errno));
      exit(-1);
   }
   err = listen(sk_fds[i], 10);
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
   printf("server  %d read data %s\n", i, buf);
   // wait for the client threads to send some message.
   sleep(20);
   return NULL;
}
static void setup_server()
{
	int i, err;
        memset(&v4, 0, sizeof(v4));
        v4.sin_family = AF_INET;
        v4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        v4.sin_port = htons(8080);

	for (i = 0; i < SRVNUM; i++) {
             err = pthread_create(&tid[i], NULL, server_fn, (void *)i);
             if (err != 0) {
                printf("create pthread failed %d\n", i);
                return;
             }

        }
}

static void setup_test()
{
	int err;
	setup_server();
	err = bpf_map_update_elem(outer_map, &index_zero, &reuseport_array,
				  BPF_ANY);
        if (err == -1) {
                printf("update outer_map failed\n");
                exit(-1);
        }
        // wait for server thread to run
        sleep(2);

        setup_client();
        // wait for client thread to run
        sleep(50);
}

static void cleanup(void)
{
   int err;
   err = bpf_map_delete_elem(outer_map, &index_zero);
   if (err == -1) {
      printf("cleanup outer_map failed\n");
      exit(-1);
   }
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
}
void test_map_type(enum bpf_map_type mt)
{
	if (create_maps(mt))
		goto out;
	if (prepare_bpf_obj())
		goto out;

        setup_test();
out:
	cleanup();
}

void test_select_reuseport(void)
{
	test_map_type(BPF_MAP_TYPE_REUSEPORT_SOCKARRAY);
}
