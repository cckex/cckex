#include "heur_filter.h"

#include <linux/string.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/ip.h>

#include "../common.h"
#include "dns.h"

int cckex_heur_is_tcp(struct sk_buff *skb) {
	
	// fetch ip header and check 
	struct iphdr *iph = ip_hdr(skb);

	// https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml -> TCP == 6
	return iph->protocol == 0x6;
}

static int cckex_heur_is_upd(struct sk_buff *skb) {
	
	// fetch ip header and check 
	struct iphdr *iph = ip_hdr(skb);

	// https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml -> UDP == 17
	return iph->protocol == 0x11;
}

#define FILTER_SOURCE	0
#define FILTER_DEST 	1

static uint8_t *cckex_filter_port(struct sk_buff *skb, int ip_proto, uint16_t port, unsigned filter) {

	if(ip_proto == IPPROTO_TCP) {

		struct tcphdr *tcph = tcp_hdr(skb);
		if(!tcph) {
			pr_warn("CCKEX_LKM [%s] failed to extract tcp header", __func__);
			return NULL;
		}

		if((filter == FILTER_SOURCE && ntohs(tcph->source) != port) ||
		   (filter == FILTER_DEST   && ntohs(tcph->dest)   != port)) {
			return NULL;
		}

		return (uint8_t*)tcph + tcph->doff * 4;

	} else if (ip_proto == IPPROTO_UDP) {

		struct udphdr *udph = udp_hdr(skb);
		if(!udph) {
			pr_warn("CCKEX_LKM [%s] failed to extract udp header", __func__);
			return NULL;
		}

		if((filter == FILTER_SOURCE && ntohs(udph->source) != port) ||
		   (filter == FILTER_DEST   && ntohs(udph->dest)   != port)) {
			return NULL;
		}

		return (uint8_t*)udph + sizeof(struct udphdr);

	} else {
		pr_warn("CCKEX_LKM [%s] unknown ip protocol: %i", __func__, ip_proto);
	}

	return NULL;
}

uint8_t *cckex_filter_source_port(struct sk_buff *skb, int ip_proto, uint16_t port) {
	return cckex_filter_port(skb, ip_proto, port, FILTER_SOURCE);
}

uint8_t *cckex_filter_dest_port(struct sk_buff *skb, int ip_proto, uint16_t port) {
	return cckex_filter_port(skb, ip_proto, port, FILTER_DEST);
}

void cckex_heur_test(struct sk_buff *skb) {
	struct iphdr *iph = NULL; 

	if (!skb) return;

	if(skb_is_nonlinear(skb)) {
		skb_linearize_cow(skb);
	}

	iph = ip_hdr(skb);
	//if(iph->protocol != IPPROTO_UDP) return;

	//pr_info	("CCKEX_LKM [%s] proto=%i", __func__, iph->protocol);

	if(iph->protocol == IPPROTO_UDP) {

	} else if(iph->protocol == IPPROTO_TCP) {

	}

	/*struct udphdr *udph = udp_hdr(skb);	

	uint8_t *data = (uint8_t*)udph + 8;
	uint8_t *tail = (uint8_t*)skb_tail_pointer(skb);
	unsigned data_len = (unsigned)((uint64_t)tail - (uint64_t)udph); // udph->len - 8

	//if(udph->dest != 53) return -1;

	//pr_info("CCKEX_LKM [%s]: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", __func__);
	//pr_info("print_udp: len=%i src=%pI4h:%i->dst=%pI4h:%i data=\n", data_len, ntohl(iph->saddr), udph->source, ntohl(iph->daddr), udph->dest);
    for (uint8_t* it = data; it != tail; ++it) {
        uint8_t c = *(uint8_t *)it;

       	//printk(KERN_CONT "%.02x", c);
    }
   	//printk("\n\n");*/
}

void cckex_heur_test6(struct sk_buff *skb) {
/*	struct ipv6hdr *iphdr = NULL;

	if(!skb) return;

	if(skb_is_nonlinear(skb)) {
		skb_linearize_cow(skb);
	}

	iphdr = ipv6_hdr(skb);

	//pr_info("CCKEX_LKM [%s] %pI6c -> %pI6c", __func__, iphdr->saddr, iphdr->daddr);
	//printk("CCKEX_LKM [%s] %pIS -> %pIS\n", __func__, iphdr->saddr, iphdr->daddr);**/

	(void)skb;
}

static int cckex_heur_is_dns(struct sk_buff *skb, int protocol) {

	uint8_t *data = NULL;
	uint8_t *tail = NULL;
	size_t data_len;
	uint16_t quest = 0;
	uint16_t ans = 0; 
	uint16_t auth = 0;

	data = cckex_filter_source_port(skb, protocol, 53);

	if(!data) return 0;

	// TODO: check size more thoroughly

	tail = (uint8_t*)skb_tail_pointer(skb);
	data_len = (size_t)((uint64_t)tail - (uint64_t)data);

	if((ssize_t)data_len < 0) {
		//pr_info("CCKEX_LKM [%s] error: negative package size = %i ", __func__, data_len);
		return -1;
	}

	/*pr_info("CCKEX_LKM [%s] xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", __func__);
	//pr_info("CCKEX_LKM [%s] skb_data_ptr=%p data_ptr=%p", __func__, skb->data, data);
	//pr_info("CCKEX_LKM [%s] possible DNS package detected (size=%i data=%p tail=%p): ", __func__, data_len, data, tail);
    for(uint8_t* it = data; it != tail; ++it) {
        uint8_t c = *(uint8_t *)it;

       	//printk(KERN_CONT "%.02x", c);
    }
   	//printk("\n\n");*/

	// TODO: better heuristics

	/*const uint16_t max_ans = 100;
  	const uint16_t max_auth = 10;
  	const uint16_t max_add = 10;

	if(data_len < DNS_HDRLEN) return 0;

	uint16_t flags = *(uint16_t*)(data + DNS_FLAGS_OFFSET);
	if((flags & DNS_F_OPCODE) != 0) {
		//pr_info("CCKEX_LKM [%s]: 1", __func__);
		return 0;
	}*/

	quest = ntohs(*(uint16_t*)(data + DNS_QUEST_OFFSET));
  	ans   = ntohs(*(uint16_t*)(data + DNS_ANS_OFFSET));
  	auth  = ntohs(*(uint16_t*)(data + DNS_AUTH_OFFSET));

	(void)quest;
	(void)ans;
	(void)auth;

  	/*if (!(flags & DNS_F_RESPONSE)) {
    	if (quest != 1 || ans != 0 || auth != 0) {
			//pr_info("CCKEX_LKM [%s]: 2", __func__);
     		return 0;
		}
  	} else {
    	if (quest > 1 || ans > max_ans || auth > max_auth) {
			//pr_info("CCKEX_LKM [%s]: 3", __func__);
      		return 0;
		}
  	}

  	uint16_t add = *(uint16_t*)(data + DNS_ADD_OFFSET);
  	if (add > max_add) {
		//pr_info("CCKEX_LKM [%s]: 4", __func__);
    	return 0;
	}*/

	//pr_info("CCKEX_LKM [%s]: Recognized DNS Query: quest=%i ans=%i auth=%i", __func__, quest, ans, auth);

	return 1;
}

int cckex_heur_is_dns_v4(struct sk_buff *skb, int *ip_proto) {
	struct iphdr* iph = ip_hdr(skb);
	*ip_proto = iph->protocol;
	return cckex_heur_is_dns(skb, iph->protocol);
}

int cckex_heur_is_dns_v6(struct sk_buff *skb, int *ip_proto) {
	struct ipv6hdr *iph = ipv6_hdr(skb);
	*ip_proto = iph->nexthdr;
	return cckex_heur_is_dns(skb, iph->nexthdr);
}

