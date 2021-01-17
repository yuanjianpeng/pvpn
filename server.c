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
#include "server.h"
#include "net.h"
#include <unistd.h>		// close
#include <stdlib.h>
#include <errno.h>
#include <string.h>

struct server
{
	struct {
		int state;

		uint32_t client_ip;
		uint16_t client_port;

		uint32_t vpn_ip;

		/* It's client's duty to keep alive,
			so server only maintain a last rx timestamp */
		unsigned rxts;

	} connects[8];
};

static struct server server;

static int find_connection(uint32_t ip, uint16_t port)
{
	int i;
	for (i = 0; i < sizeof(server.connects)/sizeof(server.connects[0]); i++) {
		if (server.connects[i].state == 0)
			continue;
		if (server.connects[i].client_ip == ip
			&& server.connects[i].client_port == port)
			return i;
	}
	return -1;
}

static int find_free_connection()
{
	int i;
	for (i = 0; i < sizeof(server.connects)/sizeof(server.connects[0]); i++) {
		if (server.connects[i].state == 0)
			return i;
	}
	return -1;
}

/* find the connection, while routing tun packets */
int server_find_dest(struct iphdr *iphdr, uint32_t *dest_ip, uint16_t *dest_port)
{
	int i;
	for (i = 0; i < sizeof(server.connects)/sizeof(server.connects[0]); i++) {
		if (server.connects[i].vpn_ip != iphdr->daddr)
			continue;
		/* this connection is not active now, drop all packets */
		if (server.connects[i].state == 0)
			return -1;

		*dest_ip = server.connects[i].client_ip;
		*dest_port = server.connects[i].client_port;
		return 0;
	}

	return -1;
}

int server_process_rx(struct context *ctx, struct packet *pkt, int len, struct sockaddr_in *addr)
{
	int idx;

	idx = find_connection(addr->sin_addr.s_addr, addr->sin_port);
	if (pkt->type != REQ && idx == -1) {
		DEBUG("Non-DATA frame from un-verfied endpoint %s:%d\n",
				ipstr(addr->sin_addr.s_addr), ntohs(addr->sin_port));
		return -1;
	}

	if (pkt->type == REQ) {
		struct ack ack = { 0 };

		if (len != sizeof(REQ_WORD) || memcmp(pkt->data, REQ_WORD, sizeof(REQ_WORD))) {
			DEBUG("invalid REQ\n");
			return -1;
		}

		/* connection is full */
		if (idx == -1) {
			idx = find_free_connection();
			/* new connection */
			if (idx != -1) {
				server.connects[idx].state = 1;
				server.connects[idx].client_ip = addr->sin_addr.s_addr;
				server.connects[idx].client_port = addr->sin_port;
				server.connects[idx].rxts = ts_ms();

				INFO("New connection (slot %d) client %s:%d, VPN %s\n",
					idx, ipstr(addr->sin_addr.s_addr), ntohs(addr->sin_port),
					ipstr(server.connects[idx].vpn_ip));
			}
		}

		if (idx == -1) {
			DEBUG("REQ is full, ack code %d\n", ack.code);
			ack.code = 1;
		}
		else {
			ack.ip = server.connects[idx].vpn_ip;
			ack.prefix = ctx->config.prefix;
			ack.gw = ctx->config.gw;
			ack.dns = ctx->config.dns;

			DEBUG("Ack to client, VPN IP %s, Gateway %s, DNS %s\n",
				ipstr(ack.ip), ipstr(ack.gw), ipstr(ack.dns));
		}

		push_tx(ctx, RES, (char *)&ack, sizeof(ack), addr->sin_addr.s_addr, addr->sin_port);
	}

	else if (pkt->type == KEEPALIVE) {
		DEBUG("KEEPALIVE (slot %d) client %s:%d, VPN %s\n",
				idx, ipstr(addr->sin_addr.s_addr), ntohs(addr->sin_port),
				ipstr(server.connects[idx].vpn_ip));
		server.connects[idx].rxts = ts_ms();
		push_tx(ctx, KEEPALIVE, NULL, 0, addr->sin_addr.s_addr, addr->sin_port);
	}

	else if (pkt->type == BYE) {
		DEBUG("BYE (slot %d) client %s:%d, VPN %s\n",
				idx, ipstr(addr->sin_addr.s_addr), ntohs(addr->sin_port),
				ipstr(server.connects[idx].vpn_ip));
		server.connects[idx].state = 0;
	}

	else
		DEBUG("Unknow Non-DATA frame from endpoint %s:%d\n",
			ipstr(addr->sin_addr.s_addr), ntohs(addr->sin_port));

	return 0;
}

int server_process_timeout(struct context *context)
{
	int i;
	unsigned ts = ts_ms();

	for (i = 0; i < sizeof(server.connects)/sizeof(server.connects[0]); i++) {
		if (server.connects[i].state == 0)
			continue;
		if (ts - server.connects[i].rxts > 60000) {
			INFO("KICK Timeout Connection (slot %d) client %s:%d, VPN %s\n",
					i,
					ipstr(server.connects[i].client_ip),
					ntohs(server.connects[i].client_port),
					ipstr(server.connects[i].vpn_ip));
			server.connects[i].state = 0;
		}
	}
}

int server_verify_peer(struct context *ctx, struct sockaddr_in *addr)
{
	int idx;

	idx = find_connection(addr->sin_addr.s_addr, addr->sin_port);
	if (idx == -1)
		return -1;

	server.connects[idx].rxts = ts_ms();
	return 0;
}

static int add_nat(struct context *context, int enable)
{
	struct config *config = &context->config;
	char cmd[128];
	struct ipv4_route routes[128];
	int i, n;
	uint32_t def_oif = 0;
	char ifname[IFNAMSIZ];

	n = get_ipv4_route(routes, sizeof(routes)/sizeof(routes[0]));
	if (n < 0) {
		ERROR("Get ipv4 route failed: %s\n", strerror(errno));
		return -1;
	}
	for (i = 0; i < n; i++) {
		if (routes[i].dst == 0) {
			def_oif = routes[i].oif;
			break;
		}
	}

	if (def_oif == 0) {
		ERROR("No default interface found\n");
		return -1;
	}
	if (if_indextoname(def_oif, ifname) == NULL) {
		ERROR("get ifname failed: %s\n", strerror(errno));
		return -1;
	}

	i = snprintf(cmd, sizeof(cmd),
		"iptables -t nat -%c POSTROUTING -s %s/%d -o %s -j MASQUERADE",
		enable ? 'A' : 'D',
		ipstr(config->subnet), config->prefix, ifname);
	if (i <= 0 || i >= sizeof(cmd)) {
		ERROR("cmd overflow %d\n", i);
		return -1;
	}

	i = system(cmd);
	if (i != 0) {
		ERROR("enable masquerade failed: %d\n", i);
		return -1;
	}

	return 0;
}

int server_shutdown(struct context *context)
{
	close_tun(context->tunfd);
	close(context->sock);
	add_nat(context, 0);
	return 0;
}

static inline void server_init_cfg(struct context *context)
{
	struct config *config = &context->config;
	int i;

	for (i = 0; i < sizeof(server.connects)/sizeof(server.connects[0]); i++) {
		server.connects[i].vpn_ip = htonl(ntohl(config->subnet) + i + 2);
	}

	for (i = 0; i < FIFO_SZ; i++) {
		context->tx[i].addr.sin_family = AF_INET;
	}
}

static int server_up(struct context *context)
{
	struct config *config = &context->config;

	int ifindex = if_nametoindex(config->dev);
	if (ifindex == 0) {
		ERROR("get %s ifindex failed: %s\n", config->dev, strerror(errno));
		return -1;
	}

	if (config->mtu && set_mtu(config->dev, config->mtu)) {
		ERROR("set mtu failed\n");
		close_tun(context->tunfd);
		return -1;
	}

	if (if_up(config->dev) < 0) {
		ERROR("ifconfig %s up failed: %s\n", config->dev, strerror(errno));
		close_tun(context->tunfd);
		return -1;
	}

	if (add_ipv4_addr(config->dev, config->gw, config->prefix, 0) < 0) {
		ERROR("set ipv4 addr %s failed: %s\n", config->dev, strerror(errno));
		return -1;
	}

	if (ipv4_fwd(1) < 0) {
		ERROR("enable ip forward failed\n");
		return -1;
	}

	if (add_nat(context, 1) < 0) {
		ERROR("add nat filed\n");
		return -1;
	}

	return 0;
}

int server_init(struct context *context)
{
	struct sockaddr_in addr;
	struct config *config = &context->config;

	server_init_cfg(context);

	context->tunfd = open_tun(config->dev);
	if (context->tunfd < 0)
		return -1;

	if (server_up(context) < 0)
		return -1;

	context->sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (context->sock == -1) {
		ERROR("socket() failed: %s\n", strerror(errno));
		close_tun(context->tunfd);
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = config->server_port;
	addr.sin_addr.s_addr = config->server_ip;

	if (-1 == bind(context->sock, (struct sockaddr *)&addr, sizeof(addr))) {
		ERROR("bind socket failed: %s\n", strerror(errno));
		close_tun(context->tunfd);
		close(context->sock);
		return 1;
	}

	DEBUG("Server Init OK\n");
	context->up = 1;
	return 0;
}

