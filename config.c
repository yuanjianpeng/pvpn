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

#include "config.h"
#include "pvpn.h"
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>			// isspace()
#include <netinet/in.h>		// struct in_addr
#include <stdlib.h>			// aoti
#include <arpa/inet.h>		// inet_aton

static void strip_tr_lf(char *c)
{
	while (*c) {
		if (*c == '\r' || *c == '\n') {
			*c = 0;
			break;
		}
		c++;
	}
}

static char* skip_space(char *c)
{
	while (*c) {
		if (!isspace(*c))
			break;
		c++;
	}
	return c;
}

static char *find_space(char *c)
{
	while (*c) {
		if (isspace(*c))
			break;
		c++;
	}
	return c;
}

static char *reverse_find_space(char *c)
{
	char *first_space = NULL;
	while (*c) {
		if (isspace(*c)) {
			if (first_space == NULL);
			first_space = c;
		}
		else
			first_space = NULL;
		c++;
	}
	return first_space;
}

static char *find_next_ent(char *c, char **next)
{
	char *a;

	while (*c) {
		if (!isspace(*c)) {
			break;
		}
		c++;
	}
	if (!*c)
		return NULL;
	a=c;
	while (*a) {
		if (isspace(*a))
			break;
		a++;
	}
	if (*a) {
		*a=0;
		*next = a+1;
	}
	else
		*next=0;
	return c;
}

/*
 * retval  -1: invalid
 *			0: ignored
 *			1: parsed
 */
static int set_config(struct config *config, char *name, char *value)
{
	int parsed = 0;

	/* server config */
	if (!strcmp(name, "subnet")) {
		struct in_addr addr;
		if (!value) {
			ERROR("subnet require an ip");
			return 1;
		}
		if (!inet_aton(value, &addr)) {
			ERROR("subnet require a valid ip");
			return 1;
		}
		config->subnet = addr.s_addr;
	}
	else if (!strcmp(name, "prefix")) {
		if (!value) {
			ERROR("prefix require an value");
			return 1;
		}
		config->prefix = atoi(value);
	}
	else if (!strcmp(name, "dns")) {
		struct in_addr addr;
		if (!value) {
			ERROR("dns require an ip");
			return 1;
		}
		if (!inet_aton(value, &addr)) {
			ERROR("dns require a valid ip");
			return 1;
		}
		config->dns = addr.s_addr;
	}

	/* common config */
	else if (!strcmp(name, "dev")) {
		if (!value) {
			ERROR("dev require an ifname\n");
			return 1;
		}
		strncpy(config->dev, value, sizeof(config->dev)  - 1);
	}
	else if (!strcmp(name, "server")) {
		struct in_addr addr;
		if (!value) {
			ERROR("server require an ip or domain\n");
			return 1;
		}
		if (!inet_aton(value, &addr)) {
			strncpy(config->server_domain, value, sizeof(config->server_domain) - 1);
		}
		else
			config->server_ip = addr.s_addr;
	}
	else if (!strcmp(name, "port")) {
		int port;
		if (!value) {
			ERROR("port require an value");
			return 1;
		}
		port = atoi(value);
		config->server_port = htons(port);
	}
	else if (!strcmp(name, "password")) {
		if (!value) {
			ERROR("password require an value");
			return 1;
		}
		strncpy(config->password, value, sizeof(config->password) -1);
	}
	else if (!strcmp(name, "mtu")) {
		if (!value) {
			ERROR("mtu require an integer value");
			return 1;
		}
		config->mtu = atoi(value);
	}
	else if (!strcmp(name, "dns_up")) {
		if (!value) {
			ERROR("dns_up require an string value");
			return 1;
		}
		strncpy(config->dns_up, value, sizeof(config->dns_up) -1);
	}
	else if (!strcmp(name, "dns_down")) {
		if (!value) {
			ERROR("dns_down require an string value");
			return 1;
		}
		strncpy(config->dns_down, value, sizeof(config->dns_down) -1);
	}
	else {
		ERROR("unknown config %s\n", name);
		return 1;
	}

	return 0;
}

int parse_config(char *config_path, struct config *config)
{
	char buf[1024];
	char *name = NULL;
	char *value = NULL;
	char *c;

	FILE *f = fopen(config_path, "r");
	if (f == NULL) {
		ERROR("open config file %s failed: %s\n",
				config_path, strerror(errno));
		return 1;
	}

	while (fgets(buf, sizeof(buf), f)) {
		name = NULL;
		value = NULL;
		buf[sizeof(buf)-1] = '\0';
		strip_tr_lf(buf);
		c = skip_space(buf);
		if (!*c)	/* an empty line */
			continue;
		if (*c == '#')	/* a comment line */
			continue;
		name = c;
		c = find_space(c);
		if (*c)  { /* an space after name */
			*c++ = 0;
			c = skip_space(c);
			if (*c) {
				value = c;
				c = reverse_find_space(c);
				if (c)
					*c = 0;
			}
		}
		/* else no space after name */

		if (set_config(config, name, value)) {
			ERROR("parse %s failed\n", name);
			fclose(f);
			return 1;
		}

	}

	fclose(f);
	return 0;
}

int check_config(struct config *config, int is_server)
{
	if (config->server_port == 0) {
		ERROR("no server port\n");
		return 1;
	}

	if (config->dev[0] == '\0') {
		ERROR("no dev\n");
		return 1;
	}

	if (is_server) {
		if (config->subnet == 0) {
			ERROR("no subnet\n");
			return 1;
		}
		if (config->prefix <= 0 || config->prefix > 30) {
			ERROR("no or invalid prefix\n");
			return 1;
		}
		config->gw = htonl(ntohl(config->subnet) + 1);
	}
	else {
		if (config->server_ip == 0 &&
				config->server_domain[0] == '\0') {
			ERROR("no server\n");
			return 1;
		}
	}

	return 0;
}

