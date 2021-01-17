#ifndef CLIENT_H
#define CLIENT_H

#include "pvpn.h"

int client_shutdown(struct context *context);
int client_init(struct context *context);
int client_process_timeout(struct context *);
int client_verify_peer(struct context *ctx, struct sockaddr_in *addr);
int client_process_rx(struct context *, struct packet *, int len, struct sockaddr_in *addr);

#endif

