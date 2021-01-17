#ifndef NET_H
#define NET_H

unsigned ts_ms();
uint32_t get_subnet(uint32_t ip, int prefixlen);
int read_txt_file(const char *path, char *buf, int bufsize);
int ipv4_fwd(int enable);
int set_mtu(char *ifname, uint16_t mtu);
int open_tun(char *ifname);
void close_tun(int fd);
int if_up(const char *ifname);
int if_down(const char *ifname);

struct ipv4_addr
{
	uint8_t family, prefixlen ,scope;
	uint32_t ifindex;
	uint32_t local, address, broadcast;
	char label[IFNAMSIZ];
	uint32_t flags;
};

int get_ipv4_addr(const char *ifname, struct ipv4_addr *addrs, int addr_n);

/* add or del a ipv4 address */
int del_ipv4_addr(const char *ifname, uint32_t ipv4);

int add_ipv4_addr(const char *ifname, uint32_t ipv4, int prefixlen, int noprefixroute);

int set_p2p_dst(const char *ifname, uint32_t dst);

struct ipv4_route
{
	unsigned char family, dst_len, src_len, flags;
	/* The local routing table is maintained by the kernel.
		Normally, the local routing table should not be manipulated,
		but it is available for viewing 

	   view the local table: 
		ip route show table local		
	 */
	uint32_t table;			/* 254:RT_TABLE_MAIN, 255:RT_TABLE_LOCAL, etc */

	/* who installed this route */
	unsigned char protocol;	/* 2:RTPROT_KERNEL, 3:RTPROT_BOOT, 4:RTPROT_STATIC, etc */

	unsigned char scope;	/* 0:RT_SCOPE_UNIVERSE, 253:RT_SCOPE_LINK, 254:RT_SCOPE_HOST, etc */
	unsigned char type;		/* 1:RTN_UNICAST, 2:RTN_LOCAL, 3:RTN_BROADCAST. etc */

	/* Type of service, match ip header tos 
		RFC 1812 route select algorithm:
		* If one or more of those routes have a TOS that exactly matches the
			TOS specified in the packet,
		  the router chooses the route with the best metric.
		* Otherwise, the router repeats the above step, except looking at routes
			whose TOS is zero. 
	*/
	unsigned char tos;
	uint32_t priority;	/* metric */
	uint32_t dst, prefsrc, gw, oif;
};

/* get all ipv4 route */
int get_ipv4_route(struct ipv4_route *routes, int route_n);

/* add or del a ipv4 address */
int add_ipv4_route(uint32_t dst, int dst_len, uint32_t src,
		uint32_t gw, uint32_t oif, uint32_t priority);

int del_ipv4_route(uint32_t dst, int dst_len, uint32_t src,
		uint32_t gw, uint32_t oif, uint32_t priority);

#endif

