#ifndef SERVER_H
#define SERVER_H

#include "pvpn.h"
#include <netinet/ip.h>	// iphdr

int server_shutdown(struct context *context);
int server_init(struct context *context);
int server_process_timeout(struct context *);
int server_verify_peer(struct context *ctx, struct sockaddr_in *addr);
int server_process_rx(struct context *, struct packet *, int len, struct sockaddr_in *addr);
int server_find_dest(struct iphdr *iphdr, uint32_t *dest_ip, uint16_t *dest_port); 

#endif

