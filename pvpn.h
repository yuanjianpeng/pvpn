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
#ifndef PVPN_H
#define PVPN_H

#include "config.h"
#include "rc4.h"
#include <netinet/in.h>		// sockaddr_in
#include <stdio.h>

#define REQ_WORD	"PVPNREQUEST"
#define CLIENT		0
#define SERVER		1
#define MAX_MTU     1500
#define FIFO_SZ		128
#define MAX_CONN    8
#define HDR_LEN		4

enum {
	REQ, RES, KEEPALIVE, BYE, DATA,
};

struct ack {
	uint32_t code;
	uint32_t ip;
	int prefix;
	uint32_t gw;
	uint32_t dns;
};

struct packet {
	uint32_t seq:28, type:4;
	char data[MAX_MTU];
};

struct context
{
	int type;
	struct config config;

	int (* init)(struct context *);
	int (* shutdown)(struct context *);
	int (* verify_peer)(struct context *, struct sockaddr_in *);
	int (* process_timeout)(struct context *);
	int (* process_rx)(struct context *, struct packet *, int len, struct sockaddr_in *addr);
	
	struct rc4_state rc4_state;

	int sock;
	int tunfd;

	int up;

	/* cache the frame buffer to be sent to tun */
	uint32_t rx_head;
	uint32_t rx_tail;
	struct {
		int len;
		char data[MAX_MTU];
	} rx[FIFO_SZ];

	uint32_t tx_head;
	uint32_t tx_tail;
	/* 
	   because server may send packets to different clients,
	   so cache the address for every packet
	 */
	struct {
		struct sockaddr_in addr;
		int len;
		struct packet pkt;
	} tx[FIFO_SZ];
};

void push_tx(struct context *ctx, int type, char *data, int len,
		uint32_t dest_ip, uint16_t dest_port);

extern int debug_level;

#define DEBUG(fmt, ...)	do { if (debug_level) printf(fmt, ##__VA_ARGS__); } while (0)
#define INFO(fmt, ...)	printf(fmt, ##__VA_ARGS__)
#define ERROR(fmt, ...)	fprintf(stderr, fmt, ##__VA_ARGS__)

char *ipstr(uint32_t ip);

#endif
