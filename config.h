#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>
#include <net/if.h>		// IFNAMSIZ

struct config {
	/* both server & client config */
	char server_domain[256];	
	uint32_t server_ip;        /* server domain or ip, 
				      client use this config to specify server address, 
				      server use this config to bind to specify address
				      optional for server */
	uint16_t server_port;   /* server listen port */
	char dev[IFNAMSIZ];     /* tun ifname, e.g. tun0 */
	uint16_t mtu;		/* set mtu size of tun interface, optional */
	char log_path[250];
	char password[256];

	/* server config */
	uint32_t gw;
	uint32_t subnet;
	int prefix;
	uint32_t dns;

	/* client config */
	char dns_up[256];
	char dns_down[256];
};

int parse_config(char *config_path, struct config *config);

int check_config(struct config *config, int is_server);

#endif

