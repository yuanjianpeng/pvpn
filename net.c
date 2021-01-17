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
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <net/if.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <linux/if_tun.h>
#include <netinet/in.h>		// IPPROTO_IP
#include <linux/netlink.h>	// sockaddr_nl
#include <linux/rtnetlink.h>
#include <stdint.h>
#include <time.h>
#include "net.h"

#define NLA_PUT_U32(buf, payload, type, data) \
	do { \
		struct nlattr *nla = (struct nlattr *)(buf + NLMSG_SPACE(payload)); \
		nla->nla_type = type; \
		nla->nla_len = RTA_LENGTH(4); \
		*(uint32_t *)RTA_DATA(nla) = data; \
		payload = NLMSG_ALIGN(payload) + RTA_LENGTH(4); \
	} while (0)

#define TUN_DEV     "/dev/net/tun"

unsigned ts_ms()
{
	struct timespec ts;
	if (-1 == clock_gettime(CLOCK_MONOTONIC, &ts)) {
		return 0;
	}
	return 1000 * (unsigned)ts.tv_sec + (unsigned)(ts.tv_nsec / 1000000);
}

uint32_t get_subnet(uint32_t ip, int prefixlen)
{
	uint32_t subnet_mask = (1 << (32 - prefixlen)) - 1;
	return htonl(ntohl(ip)&~subnet_mask);
}

int read_txt_file(const char *path, char *buf, int bufsize)
{
	char *end;
	int ret;
	int fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;
	ret = read(fd, buf, bufsize - 1);
	close(fd);

	if (ret < 0)
		return -2;

	buf[ret] = '\0';
	end = strchr(buf, '\n');
	if (end)
		*end = '\0';
	return end ? end - buf : ret;
}

int ipv4_fwd(int enable)
{
	int ret;
	int fd;

#define IPV4_FWD	"/proc/sys/net/ipv4/ip_forward"

	fd = open(IPV4_FWD, O_WRONLY);
	if (fd == -1) {
		fprintf(stderr, "open %s failed: %s\n", IPV4_FWD, strerror(errno));
		return -1;
	}
	ret = write(fd, enable ? "1" : "0", 1);
	if (ret <= 0) {
		fprintf(stderr, "write %s failed: %s\n", IPV4_FWD, strerror(errno));
		return -1;
	}
	return 0; 
}

int set_mtu(char *ifname, uint16_t mtu)
{
	char path[128];
	char mtustr[64];
	int fd;
	ssize_t ret;
	int len;

	snprintf(path, sizeof(path), "/sys/class/net/%s/mtu", ifname);
	fd = open(path, O_WRONLY);
	if (fd == -1) {
		fprintf(stderr, "open %s failed: %s\n",
			path, strerror(errno));
		return -1;
	}
	
	len = sprintf(mtustr, "%d\n", mtu);
	ret = write(fd, mtustr, len);
	if (ret != len) {
		fprintf(stderr, "write %s failed, ret %d, error: %s\n",
			path, (int)ret, strerror(errno));
		close(fd);
		return -1;
	}

	close(fd);
	return 0;
}

int open_tun(char *ifname)
{
	struct ifreq ifreq;
	int fd;

	fd = open(TUN_DEV, O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "open %s failed: %s\n", TUN_DEV, strerror(errno));
		return -1;
	}

	memset(&ifreq, 0, sizeof(ifreq));

	ifreq.ifr_flags = IFF_TUN | IFF_NO_PI;
	strcpy(ifreq.ifr_name, ifname);

	if (ioctl(fd, TUNSETIFF, &ifreq) < 0) {
		fprintf(stderr, "ioctl TUNSETIFF failed: %s\n", strerror(errno));
		close(fd);
		return -1;
	}

	return fd;
}

void close_tun(int fd)
{
	close(fd);
}

static void close2(int fd)
{
	int saved = errno;
	close(fd);
	if (errno != saved)
		errno = saved;
}

static int if_up_down(const char *ifname, int up)
{
	struct ifreq ifr = {0};
	int ret = 0;
	int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (sock < 0)
		return -1;
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);
	if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
		ret = -1;
		goto out;
	}
	if (up)
		ifr.ifr_flags |= IFF_UP;
	else
		ifr.ifr_flags &= ~ IFF_UP;
	if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
		ret = -1;
		goto out;
	}
out:
	close2(sock);
	return ret;
}

/* return
	-1: socket() failed
	-2: ioctl() get flags failed
	-3: ioctl() set flags failed
	0: ok
 */
int if_up(const char *ifname)
{
	return if_up_down(ifname, 1);
}

int if_down(const char *ifname)
{
	return if_up_down(ifname, 0);
}

int set_p2p_dst(const char *ifname, uint32_t dst)
{
	struct ifreq ifr = {0};
	int ret = 0;
	int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (sock < 0)
		return -1;
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);
	ifr.ifr_dstaddr.sa_family = AF_INET;
	((struct sockaddr_in *)&ifr.ifr_dstaddr)->sin_addr.s_addr = dst;
	ret = ioctl(sock, SIOCSIFDSTADDR, &ifr);
	close2(sock);
	return ret;
}

static int nl_sock_init(int proto)
{
	struct sockaddr_nl addr;
	int nlsock ;

	if ((nlsock = socket(AF_NETLINK, SOCK_RAW, proto)) < 0)
		return -1;

	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;

	if (bind(nlsock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		close2(nlsock);
		return -1;
	}

	return nlsock;
}

static int rtnl_dump(int family, uint32_t msg_type, char *buf, int bufsiz)
{
	int sock, ret;
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	struct iovec iov;
	struct msghdr msg;

	if ((sock = nl_sock_init(NETLINK_ROUTE)) < 0)
		return -1;

	nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtgenmsg));
	nlh->nlmsg_type = msg_type;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	nlh->nlmsg_seq = 0;
	nlh->nlmsg_pid = 0;
	((struct rtgenmsg *)NLMSG_DATA(nlh))->rtgen_family = family;

	ret = write(sock, nlh, NLMSG_LENGTH(sizeof(struct rtgenmsg)));
	if (ret != NLMSG_LENGTH(sizeof(struct rtgenmsg))) {
		close2(sock);
		return -1;
	}

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	iov.iov_base = (void *)buf;
	iov.iov_len = bufsiz;

	/* Actually we should receive multiple times
		util a NLMSG_DONE msg is received */
	ret = recvmsg(sock, &msg, 0);
	close2(sock);

	if (ret < 0)
		return -1;

	if (msg.msg_flags & MSG_TRUNC)
		return -1;

	return ret;
}

static int rtnl_req(int msg_type, char *buf, int bufsiz, int payload_len)
{
	int sock, ret;
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	struct iovec iov;
	struct msghdr msg;
	struct nlmsgerr *errmsg;

	if ((sock = nl_sock_init(NETLINK_ROUTE)) < 0)
		return -1;

	nlh->nlmsg_len = NLMSG_LENGTH(payload_len);
	nlh->nlmsg_type = msg_type;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq = 0;
	nlh->nlmsg_pid = 0;

	/* this guy require NLM_F_CREATE flag */
	if (msg_type == RTM_NEWROUTE)
		nlh->nlmsg_flags |= NLM_F_CREATE;

	ret = write(sock, buf, nlh->nlmsg_len);
	if (ret != nlh->nlmsg_len) {
		close2(sock);
		return -1;
	}

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	iov.iov_base = (void *)buf;
	iov.iov_len = bufsiz;

	ret = recvmsg(sock, &msg, 0);
	close2(sock);

	if (ret < 0)
		return -1;

	if (msg.msg_flags & MSG_TRUNC)
		return -1;

	if (!NLMSG_OK(nlh, (unsigned int)ret) || nlh->nlmsg_type != NLMSG_ERROR
		|| nlh->nlmsg_len - NLMSG_HDRLEN < sizeof(*errmsg))
		return -1;
	
	errmsg = NLMSG_DATA(nlh);
	if (errmsg->error) {
		errno = -errmsg->error;
		return -1;
	}

	return ret;
}

/* it's ugly to pass a pre-allocated addr buffer to it.
	but for almost 99.999% condition, a 10 entry buffer will hold all address */
int get_ipv4_addr(const char *ifname, struct ipv4_addr *addrs, int addr_n)
{
	char buf[2048];
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	int ret;
	int n = 0;
	unsigned ifindex = if_nametoindex(ifname);

	if (ifindex == 0)
		return -1;

	ret = rtnl_dump(AF_INET, RTM_GETADDR, buf, sizeof(buf));
	if (ret < 0)
		return ret;

	for (nlh = (struct nlmsghdr *)buf; NLMSG_OK(nlh, (unsigned int)ret);
			nlh = NLMSG_NEXT(nlh, ret))
	{
		struct ifaddrmsg *ifa;
		struct rtattr *rta;
		int rtasize;
		struct ipv4_addr *addr;

		if (nlh->nlmsg_type == NLMSG_DONE || nlh->nlmsg_type == NLMSG_ERROR)
			break;

		ifa = NLMSG_DATA(nlh);
		rta = (struct rtattr *)((char *)NLMSG_DATA(nlh) + NLMSG_ALIGN(sizeof(struct ifaddrmsg)));
		rtasize = NLMSG_PAYLOAD(nlh, sizeof(struct ifaddrmsg));

		if (ifindex && ifindex != ifa->ifa_index)
			continue;

		/* overflow */
		if (n >= addr_n)
			return -1;

		addr = &addrs[n++];
		memset(addr, 0, sizeof(*addr));

		addr->family = ifa->ifa_family;
		addr->prefixlen = ifa->ifa_prefixlen;
		addr->scope = ifa->ifa_scope;
		addr->flags = ifa->ifa_flags;

		for ( ; RTA_OK(rta, rtasize); rta = RTA_NEXT(rta, rtasize)) {
			switch (rta->rta_type) {
			case IFA_ADDRESS:
				addr->address = *(uint32_t *)RTA_DATA(rta);
				break;
			case IFA_LOCAL:
				addr->local = *(uint32_t *)RTA_DATA(rta);
				break;
			case IFA_BROADCAST:
				addr->broadcast = *(uint32_t *)RTA_DATA(rta);
				break;
			case IFA_FLAGS:
				addr->flags = *(uint32_t *)RTA_DATA(rta);
				break;
			case IFA_LABEL:
				strncpy(addr->label, RTA_DATA(rta), IFNAMSIZ-1);
				addr->label[IFNAMSIZ-1] = '\0';
				break;
			}
		}
	}

	return n;
}

/* For one request, kernel will delete all adddress match local (ignore prefixlen) 
 */
int del_ipv4_addr(const char *ifname, uint32_t ipv4)
{
	char buf[512];
	int payload = 0;
	struct ifaddrmsg *ifa = NLMSG_DATA((struct nlmsghdr *)buf);
	unsigned ifindex = if_nametoindex(ifname);

	if (ifindex == 0)
		return -1;

	memset(ifa, 0, sizeof(*ifa));
	ifa->ifa_family = PF_INET;
	ifa->ifa_index = ifindex;
	payload += NLMSG_ALIGN(sizeof(*ifa));

	if (ipv4)
		NLA_PUT_U32(buf, payload, IFA_LOCAL, ipv4);

	return rtnl_req(RTM_DELADDR, buf, sizeof(buf), payload);
}

/*
	note, kernel compare two if address using following keys
		same prefixlen
		same local address
		same (adress & netmask)
	see: find_matching_ifa() net/ipv4/devinet.c
 */
int add_ipv4_addr(const char *ifname, uint32_t ipv4, int prefixlen, int noprefixroute)
{
	char buf[512];
	int payload = 0;
	struct ifaddrmsg *ifa = NLMSG_DATA((struct nlmsghdr *)buf);
	unsigned ifindex = if_nametoindex(ifname);

	if (ifindex == 0)
		return -1;

	memset(ifa, 0, sizeof(*ifa));
	ifa->ifa_family = PF_INET;
	ifa->ifa_index = ifindex;
	ifa->ifa_scope = RT_SCOPE_UNIVERSE;
	ifa->ifa_prefixlen = prefixlen;
	payload += NLMSG_ALIGN(sizeof(*ifa));

	NLA_PUT_U32(buf, payload, IFA_LOCAL, ipv4);
	if (prefixlen < 32)
		NLA_PUT_U32(buf, payload, IFA_BROADCAST, htonl(ntohl(ipv4)|((1<<(32-prefixlen))-1)));
	if (noprefixroute)
		NLA_PUT_U32(buf, payload, IFA_FLAGS, IFA_F_NOPREFIXROUTE);

	return rtnl_req(RTM_NEWADDR, buf, sizeof(buf), payload);
}

int get_ipv4_route(struct ipv4_route *routes, int route_n)
{
	char buf[3000];
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	int ret;
	int n = 0;

	ret = rtnl_dump(AF_INET, RTM_GETROUTE, buf, sizeof(buf));
	if (ret < 0)
		return ret;

	for (nlh = (struct nlmsghdr *)buf; NLMSG_OK(nlh, (unsigned int)ret);
			nlh = NLMSG_NEXT(nlh, ret))
	{
		struct rtmsg *rtm;
		struct rtattr *rta;
		int rtasize;
		struct ipv4_route *route;

		if (nlh->nlmsg_type == NLMSG_DONE || nlh->nlmsg_type == NLMSG_ERROR)
			break;

		rtm = NLMSG_DATA(nlh);
		rta = (struct rtattr *)((char *)NLMSG_DATA(nlh) + NLMSG_ALIGN(sizeof(struct rtmsg)));
		rtasize = NLMSG_PAYLOAD(nlh, sizeof(struct rtmsg));

		/* overflow */
		if (n >= route_n)
			return -1;

		if (rtm->rtm_table == RT_TABLE_LOCAL)
			continue;

		route = &routes[n++];
		memset(route, 0, sizeof(*route));

		route->family = rtm->rtm_family;
		route->dst_len = rtm->rtm_dst_len;
		route->src_len = rtm->rtm_src_len;
		route->tos = rtm->rtm_tos;
		route->scope = rtm->rtm_scope;
		route->protocol = rtm->rtm_protocol;
		route->type = rtm->rtm_type;
		route->flags = rtm->rtm_flags;

		for ( ; RTA_OK(rta, rtasize); rta = RTA_NEXT(rta, rtasize)) {
			switch (rta->rta_type) {
			case RTA_TABLE:
				route->table = *(uint32_t *)RTA_DATA(rta);
				break;
			case RTA_DST:
				route->dst = *(uint32_t *)RTA_DATA(rta);
				break;
			case RTA_PRIORITY:
				route->priority = *(uint32_t *)RTA_DATA(rta);
				break;
			case RTA_PREFSRC:
				route->prefsrc = *(uint32_t *)RTA_DATA(rta);
				break;
			case RTA_GATEWAY:
				route->gw = *(uint32_t *)RTA_DATA(rta);
				break;
			case RTA_OIF:
				route->oif = *(uint32_t *)RTA_DATA(rta);
				break;
			}
		}
	}

	return n;
}

int add_ipv4_route(uint32_t dst, int dst_len, uint32_t src,
		uint32_t gw, uint32_t oif, uint32_t priority)
{
	char buf[512];
	int payload = 0;
	struct rtmsg *rtm = NLMSG_DATA((struct nlmsghdr *)buf);

	memset(rtm, 0, sizeof(*rtm));
	rtm->rtm_family = PF_INET;
	rtm->rtm_dst_len = dst_len;
	rtm->rtm_table = RT_TABLE_MAIN;
	rtm->rtm_protocol = RTPROT_BOOT;
	rtm->rtm_scope = gw ? RT_SCOPE_UNIVERSE : RT_SCOPE_LINK;
	rtm->rtm_type = RTN_UNICAST;
	payload += NLMSG_ALIGN(sizeof(*rtm));

	NLA_PUT_U32(buf, payload, RTA_DST, dst);
	if (priority)
		NLA_PUT_U32(buf, payload, RTA_PRIORITY, priority);
	if (src)
		NLA_PUT_U32(buf, payload, RTA_PREFSRC, src);
	if (gw)
		NLA_PUT_U32(buf, payload, RTA_GATEWAY, gw);
	NLA_PUT_U32(buf, payload, RTA_OIF, oif);

	return rtnl_req(RTM_NEWROUTE, buf, sizeof(buf), payload);
}

/* For one request, kernel only delete the first matched route entry
	match algorithm:
	required:
		dst, dst_len, table, tos must match
	optional (no consideration for multipath route)
		match type, if provided type is not 0
		match scope, if provided scope is not RT_SCOPE_NOWHERE (255)
		match prefsrc, if provided prefsrc is not 0
		match protocol, if provided protocol is not 0
		match priority, if provided priority is not 0
		match oif, if provided oif is no 0
		match gateway, if provided gw is no 0
 */
int del_ipv4_route(uint32_t dst, int dst_len, uint32_t src,
		uint32_t gw, uint32_t oif, uint32_t priority)
{
	char buf[512];
	int payload = 0;
	struct rtmsg *rtm = NLMSG_DATA((struct nlmsghdr *)buf);

	memset(rtm, 0, sizeof(*rtm));
	rtm->rtm_family = PF_INET;
	rtm->rtm_dst_len = dst_len;
	rtm->rtm_scope = RT_SCOPE_NOWHERE;
	rtm->rtm_table = RT_TABLE_MAIN;
	payload += NLMSG_ALIGN(sizeof(*rtm));

	NLA_PUT_U32(buf, payload, RTA_DST, dst);
	if (priority)
		NLA_PUT_U32(buf, payload, RTA_PRIORITY, priority);
	if (src)
		NLA_PUT_U32(buf, payload, RTA_PREFSRC, src);
	if (gw)
		NLA_PUT_U32(buf, payload, RTA_GATEWAY, gw);
	if (oif)
		NLA_PUT_U32(buf, payload, RTA_OIF, oif);

	return rtnl_req(RTM_DELROUTE, buf, sizeof(buf), payload);
}


