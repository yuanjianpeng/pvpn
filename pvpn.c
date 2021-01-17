/* 
 * A tiny VPN server & client based on tun and UDP 
 *
 * Copyright (C) 2018 Yuan Jianpeng <yuanjp@hust.edu.cn>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include "pvpn.h"
#include "client.h"
#include "server.h"
#include "net.h"
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <fcntl.h>		// open
#include <sys/file.h>	// flock
#include <netinet/ip.h>	// iphdr
#include <arpa/inet.h>	// inet_ntoa

#define TX_EMPTY(ctx) ((ctx)->tx_head == (ctx)->tx_tail)
#define TX_FULL(ctx) ((ctx)->tx_head - (ctx)->tx_tail == FIFO_SZ)
#define RX_EMPTY(ctx) ((ctx)->rx_head == (ctx)->rx_tail)
#define RX_FULL(ctx) ((ctx)->rx_head - (ctx)->rx_tail == FIFO_SZ)

#define CLIENT_CONFIG	"/etc/pvpn/client.conf"
#define SERVER_CONFIG	"/etc/pvpn/server.conf"
#define DEF_PID			"/etc/pvpn/pvpn.pid"

static volatile int killed;
static const char *pid_file = DEF_PID;
static int pid_fd;
static struct context context;
static uint32_t seq;
int debug_level;

void usage()
{
	fprintf(stderr, 
		"pvpn <client|server> [options]\n"
		"\n"
		"options:\n"
		"    -D, don't run as daemon\n"
		"    -c config, config file path\n"
		"    -p pidfile, save pid to file\n"
		"    -P, don't save pid to file\n"
		"    -v, verbose debug\n"
		"\n"
		"default client config: " CLIENT_CONFIG "\n"
		"default server config: " SERVER_CONFIG "\n"
		"\n"
	);

	exit(1);
}

char *ipstr(uint32_t ip)
{
	static char str[3][16];
	static unsigned i;
	char *_ip = str[i++%3];
	strcpy(_ip, inet_ntoa(*(struct in_addr *)&ip));
	return _ip;
}

const char *typestr(int type)
{
	switch (type) {
	case REQ:
		return "REQ";
	case RES:
		return "RES";
	case KEEPALIVE:
		return "KEEPALIVE";
	case DATA:
		return "DATA";
	case BYE:
		return "BYE";
	}
	return "Unknown";
}

/* so that atexit can be called */
static void sig_handler(int signum)
{
	switch (signum)
	{
	case SIGINT:
	case SIGTERM:
		killed = 1;
		break;
	};
}

void cleanup()
{
	if (context.up)
		context.shutdown(&context);

	if (pid_file)
		unlink(pid_file);
}

int create_pid_file(const char *path)
{
	int fd;
	char buf[12];

	fd = open(path, O_CREAT|O_RDWR, S_IRUSR|S_IWUSR);
	if (fd == -1) {
		ERROR("open pid file failed: %s\n", strerror(errno));
		return -1;
	}

	if (flock(fd, LOCK_EX|LOCK_NB) < 0) {
		ERROR("flock pid file failed: %s\n", strerror(errno));
		goto errret;
	}

	sprintf(buf, "%d\n", getpid());
	if (write(fd, buf, strlen(buf)) <= 0) {
		ERROR("write pid file failed: %s\n", strerror(errno));
		goto errret;
	}

	return fd;

errret:
	close(fd);
	unlink(path);
	return -1;
}

void tx(struct context *context, struct packet *pkt, int len, struct sockaddr_in *addr)
{
	struct rc4_state state;
	int ret;

	pkt->seq = seq++;

	DEBUG("TX %d bytes seq %d type %s to: %s:%d\n",
			len, pkt->seq, typestr(pkt->type),
			ipstr(addr->sin_addr.s_addr), ntohs(addr->sin_port));

	memcpy(&state, &context->rc4_state, sizeof(state));
	rc4_crypt(&state, (unsigned char *)pkt, (unsigned char *)pkt, len);

	ret = sendto(context->sock, pkt, len, 0,
		(struct sockaddr *)addr, sizeof(*addr));
	if (ret <= 0)
		ERROR("sendto failed: %s\n", strerror(errno));
}

void push_tx(struct context *ctx, int type, char *data, int len,
		uint32_t dest_ip, uint16_t dest_port)
{
	int idx = ctx->tx_head++ % FIFO_SZ;

	if (ctx->type == SERVER) {
		ctx->tx[idx].addr.sin_addr.s_addr = dest_ip;
		ctx->tx[idx].addr.sin_port = dest_port;
	}
	ctx->tx[idx].pkt.type = type;
	ctx->tx[idx].len = HDR_LEN + len;
	if (data)
		memcpy(ctx->tx[idx].pkt.data, data, len);
}

static void push_rx(struct context *ctx, char *data, int len)
{
	int idx;

	if (len > MAX_MTU) {
		ERROR("this frame is bigger than MTU %d\n", len);
		return;
	}

	idx = ctx->rx_head++ % FIFO_SZ;
	ctx->rx[idx].len = len;
	memcpy(ctx->rx[idx].data, data, len);
}

static void event_process_tun_write(struct context *context)
{
	int ret, idx, len;
	char *buf;

	idx = context->rx_tail++ % FIFO_SZ;
	buf = context->rx[idx].data;
	len = context->rx[idx].len;

	DEBUG("Write to TUN %d bytes\n", len);

	ret = write(context->tunfd, buf, len);
	if (ret != len)
		ERROR("write tun failed ret %d: %s\n", ret, strerror(errno));
}

static void event_process_tun_read(struct context *context)
{
	unsigned char buf[MAX_MTU];
	int len;
	struct iphdr *iphdr = (struct iphdr *)buf;
	uint32_t dest_ip;
	uint16_t dest_port;
	int idx;

	len = read(context->tunfd, buf, sizeof(buf));
	if (len <= 0) {
		ERROR("read tun failed: %s\n", strerror(errno));
		return;
	}

	DEBUG("Read %d bytes from TUN, VPN %s -> %s\n",
			len,
			ipstr(iphdr->saddr), ipstr(iphdr->daddr));

	/* skip multicast address */
	if ((ntohl(iphdr->daddr) & 0xf0000000) == 0xe0000000) {
		DEBUG("SKip multicast frame from tun\n");
		return; 
	}
	
	if (context->type == SERVER) {
		if (server_find_dest(iphdr, &dest_ip, &dest_port) < 0) {
			DEBUG("No connection for this TUN frame, VPN %s -> %s\n",
					ipstr(iphdr->saddr), ipstr(iphdr->daddr));
			return;
		}
	}
	
	push_tx(context, DATA, buf, len, dest_ip, dest_port);
}

static void event_process_sock_send(struct context *context)
{
	int idx;
	struct packet *packet;
	int len;
	struct sockaddr_in *addr;
	struct rc4_state state;

	idx = context->tx_tail++%FIFO_SZ;
	packet = &context->tx[idx].pkt;
	len = context->tx[idx].len;

	/* For client, the server address is stored at first element of tx fifo address */
	if (context->type == CLIENT)
		idx = 0;

	addr = &context->tx[idx].addr;
	tx(context, packet, len, addr);
}

static void event_process_sock_recv(struct context *context)
{
	struct packet pkt;
	struct sockaddr_in addr;
	int addrlen = sizeof(addr);
	struct rc4_state state;
	int ret;

	ret = recvfrom(context->sock, &pkt, sizeof(pkt), 0, (struct sockaddr *)&addr, &addrlen);
	if (ret < HDR_LEN) {
		ERROR("recvfrom failed %d: %s\n", ret, strerror(errno));
		return;
	}

	memcpy(&state, &context->rc4_state, sizeof(state));
	rc4_crypt(&state, (unsigned char *)&pkt, (unsigned char *)&pkt, ret);

	DEBUG("recv %d bytes from %s:%d, seq %u, type %s\n",
			ret,
			ipstr(addr.sin_addr.s_addr), ntohs(addr.sin_port),
			pkt.seq, typestr(pkt.type));

	if (pkt.type == DATA) {
		if (context->verify_peer(context, &addr) < 0) {
			DEBUG("DATA frame from un-verfied endpoint %s:%d\n",
				ipstr(addr.sin_addr.s_addr), ntohs(addr.sin_port));
			return;
		}
		push_rx(context, pkt.data, ret - HDR_LEN);
	}
	else
		context->process_rx(context, &pkt, ret - HDR_LEN, &addr);
}

static inline int event_add_fd(struct context *context, fd_set *rfds, fd_set *wfds)
{
	int maxfd = 0;

	FD_ZERO(rfds);
	FD_ZERO(wfds);

	if (!RX_FULL(context))
		FD_SET(context->sock, rfds);
	if (!TX_EMPTY(context))
		FD_SET(context->sock, wfds);

	if (!RX_FULL(context) || !TX_EMPTY(context))
		maxfd = context->sock;

	if (context->tunfd != -1) {
		if (!RX_EMPTY(context))
			FD_SET(context->tunfd, wfds);
		if (!TX_FULL(context))
			FD_SET(context->tunfd, rfds);

		if (!RX_EMPTY(context) || !TX_FULL(context))
			if (context->tunfd > maxfd)
				maxfd = context->tunfd;
	}

	return maxfd;
}

static int get_pid()
{
	char pid[32];
	char cmdline[128];
	int p;
	char cmd[256];

	if (read_txt_file(DEF_PID, pid, sizeof(pid)) < 0
		|| (p = atoi(pid)) == 0) {
		printf("pvpn is not running\n");
		return 0;
	}

	sprintf(cmdline, "/proc/%d/cmdline", p);
	if (read_txt_file(cmdline, cmd, sizeof(cmd)) < 0
		|| !strstr(cmd, "pvpn")) {
		printf("pvpn exited abnormal\n");
		return 0;
	}

	return p;
}

static int status()
{
	if (get_pid() > 0)
		printf("pvpn is running\n");
	return 0;
}

static int stop()
{
	int ret;
	int pid = get_pid();
	if (pid <= 0) {
		printf("pvpn is not running\n");
		return 0;
	}

	ret = kill(pid, SIGTERM);
	if (ret != 0) {
		printf("kill failed: %s\n", strerror(errno));
		return 1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	char *cmd = argv[1];
	int daemonlize = 1;
	char *config = NULL;
	int opt;
	int maxfd, ret;
	struct timeval tv;
	fd_set rfds, wfds;

	if (argc < 2)
		usage();

	if (getuid() != 0) {
		if (setuid(0) != 0) {
			ERROR("need run as root\n");
			return 1;
		}
	}

	if (!strcmp(cmd, "client")) {
		config = CLIENT_CONFIG;
		context.type = CLIENT;
		context.init = client_init;
		context.shutdown = client_shutdown;
		context.process_timeout = client_process_timeout;
		context.process_rx = client_process_rx;
		context.verify_peer = client_verify_peer;
	}
	else if (!strcmp(cmd, "server")) {
		config = SERVER_CONFIG;
		context.type = SERVER;
		context.init = server_init;
		context.shutdown = server_shutdown;
		context.process_timeout = server_process_timeout;
		context.process_rx = server_process_rx;
		context.verify_peer = server_verify_peer;
	}
	else if (!strcmp(cmd, "status"))
		return status();
	else if (!strcmp(cmd, "stop"))
		return stop();
	else
		usage();

	argc--;
	argv++;
	while ((opt = getopt(argc, argv, "c:DPp:v")) != -1 ) {
		switch(opt) {
		case 'c':
			config = optarg;
			break;
		case 'p':
			pid_file = optarg;
			break;
		case 'P':
			pid_file = NULL;
			break;
		case 'D':
			daemonlize = 0;
			break;
		case 'v':
			debug_level++;
			break;
		default:
			usage();
		}
	}

	if (parse_config(config, &context.config)) {
		ERROR("parse config failed\n");
		return 1;
	}
	if (check_config(&context.config, context.type)) {
		ERROR("invalid config\n");
		return 1;
	}

	if (daemonlize && daemon(1, 0) < 0) {
		ERROR("daemon failed: %s\n", strerror(errno));
		return 1;
	}

	if (pid_file) {
		pid_fd = create_pid_file(pid_file);
		if (pid_fd == -1) {
			exit(EXIT_FAILURE);
		}
	}

	atexit(cleanup);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGTERM, sig_handler);
	signal(SIGINT, sig_handler);
	
	rc4_init(&context.rc4_state, context.config.password,
			strlen(context.config.password));

	if (context.init(&context))
		return 1;

	while (!killed) {
		tv.tv_sec = 1;
		tv.tv_usec = 0;

		context.process_timeout(&context);

		maxfd = event_add_fd(&context, &rfds, &wfds);

		ret = select(maxfd + 1, &rfds, &wfds, NULL, &tv);
		if (ret <= 0) {
			if (ret < 0 && errno != EINTR) {
				ERROR("select() failed: %s\n", strerror(errno));
				break;
			}
			continue;
		}

		if (context.tunfd != -1 && !RX_EMPTY(&context)
				&& FD_ISSET(context.tunfd, &wfds))
			event_process_tun_write(&context);

		if (!TX_EMPTY(&context) && FD_ISSET(context.sock, &wfds))
			event_process_sock_send(&context);

		if (!RX_FULL(&context) && FD_ISSET(context.sock, &rfds))
			event_process_sock_recv(&context);

		if (context.tunfd != -1 && !TX_FULL(&context)
				&& FD_ISSET(context.tunfd, &rfds))
			event_process_tun_read(&context);
	}

	DEBUG("PVPN exiting ...\n");
	return 1;
}
