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
#include "net.h"
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <stdlib.h>
#include <arpa/inet.h>

struct client
{
	int state;		/* 0, connecting, 1, connected */
	unsigned rxts, txts, kpts;

	uint32_t ip;
	int prefix;
	uint32_t gw;
	uint32_t dns;
	uint32_t ifindex;

	/* backup the default route */
	uint32_t def_src, def_oif, def_gw, def_metric; 
};
static struct client cli;

static uint32_t resolve_dns(char *domain)
{
	struct addrinfo hints;
	struct addrinfo *result;
	uint32_t addr;
	int s;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;    /* Allow IPv4 or IPv6 */
	hints.ai_socktype = SOCK_DGRAM; /* Datagram socket */
	hints.ai_flags = 0;    /* For wildcard IP address */
	hints.ai_protocol = 0;          /* Any protocol */

	s = getaddrinfo(domain, NULL, &hints, &result);
	if (s != 0) {
		ERROR("getaddrinfo: %s\n", gai_strerror(s));
		return 0;
	}

	if (result == NULL)
		return 0;

	addr = ((struct sockaddr_in *)result->ai_addr)->sin_addr.s_addr;
	freeaddrinfo(result);

	DEBUG("addr of %s: %s\n", domain, ipstr(addr));

	return addr;
}

static int client_update_dns(struct context *context, int up)
{
	char cmd[256];
	struct config *config = (struct config *)&context->config;
	char *tmp = up ? config->dns_up : config->dns_down;
	char *dns_rep;
	int ret;

	if (tmp[0] == '\0')
		return 0;
	
	dns_rep = strstr(tmp, "$dns");
	if (dns_rep) {
		memcpy(cmd, tmp, dns_rep - tmp);
		cmd[dns_rep - tmp] = '\0';
		strcat(cmd, ipstr(cli.dns));
		strcat(cmd, dns_rep + 4);
		tmp = cmd;
	}

	DEBUG("execute DNS command: %s\n", tmp);

	ret = system(tmp);
	if (ret != 0) {
		ERROR("execute DNS command %s failed: %d\n", tmp, ret);
		return -1;
	}
	
	return 0;
}

static int client_route_down(struct context *context)
{
	int err = 0;
	struct config *config = (struct config *)&context->config;

	if (cli.def_gw == 0)
		return 0;
	
	/* 1st, delete the default route */
	if (del_ipv4_route(0, 0, 0, cli.gw, cli.ifindex, cli.def_metric) < 0) {
		ERROR("Route down failed: delete default route failed: %s\n", strerror(errno));
		err = -1;
	}

	/* 2nd, restore default route */
	if (add_ipv4_route(0, 0, cli.def_src, cli.def_gw, cli.def_oif, cli.def_metric) < 0) {
		ERROR("Route down failed: restore default route failed: %s\n", strerror(errno));
		err = -1;
	}

	/* 3rd, delete the route to VPN server */
	if (del_ipv4_route(config->server_ip, 32, 0, cli.def_gw, cli.def_oif, 1) < 0) {
		ERROR("Route down failed: delete to server route failed: %s\n", strerror(errno));
		err = -1;
	}

	cli.def_gw = 0;
	return err;
}

static int client_route_up(struct context *context)
{
	struct config *config = (struct config *)&context->config;
	struct ipv4_route routes[128];
	int i, n;
	char ifname[IFNAMSIZ];

	/* all default route and delete it */
	n = get_ipv4_route(routes, sizeof(routes)/sizeof(routes[0]));
	if (n < 0) {
		ERROR("Get ipv4 route failed: %s\n", strerror(errno));
		return -1;
	}
	for (i = 0; i < n; i++) {
		if (routes[i].dst == 0) {
			if (cli.def_gw) {
				ERROR("FATAL: multiple default route\n");
				return -1;
			}
			if (routes[i].gw == 0) {
				ERROR("FATAL: default route not gateway\n");
				return -1;
			}
			cli.def_src = routes[i].prefsrc;
			cli.def_gw = routes[i].gw;
			cli.def_oif = routes[i].oif;
			cli.def_metric = routes[i].priority;
			DEBUG("Read default route: default via %s dev %s metric %d\n",
					ipstr(routes[i].gw),
					if_indextoname(routes[i].oif, ifname),
					routes[i].priority);
		}
	}
	if (cli.def_gw == 0) {
		ERROR("FATAL: no default route\n");
		return -1;
	}

	/* 1st, we add a route to VPN Server */
	if (add_ipv4_route(config->server_ip, 32, 0, cli.def_gw, cli.def_oif, 1) < 0) {
		ERROR("add route to VPN server failed: %s\n", strerror(errno));
		return -1;
	}

	/* 2nd, delete the default route */
	if (del_ipv4_route(0, 0, cli.def_src, cli.def_gw, cli.def_oif, cli.def_metric) < 0) {
		ERROR("delete default route failed: %s\n", strerror(errno));
		return -1;
	}

	/* 3rd, add new default route */
	if (add_ipv4_route(0, 0, 0, cli.gw, cli.ifindex, cli.def_metric) < 0) {
		ERROR("add default route failed: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

static int client_up(struct context *context)
{
	struct config *config = (struct config *)&context->config;

	context->tunfd = open_tun(config->dev);
	if (context->tunfd < 0) {
		ERROR("opn tun failed\n");
		return -1;
	}

	cli.ifindex = if_nametoindex(config->dev);
	if (cli.ifindex == 0) {
		ERROR("get %s ifindex failed: %s\n", config->dev, strerror(errno));
		return -1;
	}

	if (config->mtu && set_mtu(config->dev, config->mtu)) {
		ERROR("set mtu failed\n");
		return -1;
	}

	if (if_up(config->dev) < 0) {
		ERROR("ifconfig %s up failed: %s\n", config->dev, strerror(errno));
		return -1;
	}

	if (add_ipv4_addr(config->dev, cli.ip, cli.prefix, 0) < 0) {
		ERROR("set ipv4 addr %s failed: %s\n", config->dev, strerror(errno));
		return -1;
	}

	if (set_p2p_dst(config->dev, cli.gw) < 0) {
		ERROR("set ipv4 addr %s failed: %s\n", config->dev, strerror(errno));
		return -1;
	}

	return (client_route_up(context) || client_update_dns(context, 1)) ? -1 : 0;
}

int client_process_rx(struct context *ctx, struct packet *pkt, int len, struct sockaddr_in *addr)
{
	int ret;
	struct ack *ack;

	if (pkt->type == RES) {
		ack = (struct ack *)pkt->data;
		if (ack->code != 0) {
			INFO("ack failed: code %u\n", ack->code);
			return 0;
		}
		INFO("Dial ok: VPN IP %s/%d Gateway %s DNS %s\n",
			ipstr(ack->ip), ack->prefix, ipstr(ack->gw), ipstr(ack->dns));

		cli.state = 1;
		cli.rxts = ts_ms();
		cli.ip = ack->ip;
		cli.prefix = ack->prefix;
		cli.gw = ack->gw;
		cli.dns = ack->dns;

		if (client_up(ctx) < 0) {
			ERROR("client up failed, pvpn will exit\n");
			exit(1);
		}
	}
	else if (pkt->type == KEEPALIVE) {
		DEBUG("Recv KEEPALIVE reply\n");
		cli.rxts = ts_ms();
	}
	else
		DEBUG("Unknow Non-DATA frame from endpoint %s:%d\n",
			ipstr(addr->sin_addr.s_addr), ntohs(addr->sin_port));

	return 0;
}

int client_shutdown(struct context *context)
{
	client_route_down(context);
	if (context->tunfd != -1) {
		close_tun(context->tunfd);
		context->tunfd = -1;
	}
	client_update_dns(context, 0);
	return 0;
}

/* re-try send request in nego state
   send keepalive in data state
 */
int client_process_timeout(struct context *ctx)
{
	uint64_t ts = ts_ms();

	if (cli.state) {
		if (ts - cli.rxts > 60000) {
			INFO("redial (disconnected)\n");
			cli.state = 0;
			cli.txts = 0;
			client_shutdown(ctx);
		}
		else if (ts - cli.rxts > 15000 && ts - cli.kpts > 15000) {
			DEBUG("send KEEPALIVE (timeout)\n");
			cli.kpts = ts;
			push_tx(ctx, KEEPALIVE, NULL, 0, 0, 0);
		}
	}

	if (cli.state == 0) {
		if (ts - cli.txts > 3000) {
			INFO("send REQ to server %s:%d\n",
					ipstr(ctx->config.server_ip),
					ntohs(ctx->config.server_port));
			push_tx(ctx, REQ, REQ_WORD, sizeof(REQ_WORD), 0, 0);
			cli.txts = ts;
		}
	}

	return 0;
}

int client_verify_peer(struct context *ctx, struct sockaddr_in *addr)
{
	if (addr->sin_addr.s_addr != ctx->config.server_ip
		|| addr->sin_port != ctx->config.server_port)
		return -1;

	cli.rxts = ts_ms();
	return 0;
}

/* resolve server ip, init socket */
int client_init(struct context *context)
{
	struct config *config = &context->config;

	context->tunfd = -1;

	if (config->server_ip == 0) {
		config->server_ip = resolve_dns(config->server_domain);
		if (config->server_ip == 0) {
			ERROR("can't resolve server ip\n");
			return 1;
		}
	}

	context->sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (context->sock == -1) {
		ERROR("socket() failed: %s\n", strerror(errno));
		return 1;
	}

	/* Init the cached server address */
	context->tx[0].addr.sin_family = AF_INET;
	context->tx[0].addr.sin_port = config->server_port;
	context->tx[0].addr.sin_addr.s_addr = config->server_ip;

	DEBUG("Client Init OK\n");

	context->up = 1;
	return 0;
}

