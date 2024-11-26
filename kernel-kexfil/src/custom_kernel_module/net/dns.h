#pragma once

#include <uapi/linux/in6.h>
#include <linux/skbuff.h>

// https://github.com/wireshark/wireshark/blob/d9bd00a22fbdb65d01e93c0f67dde8ab8812f66e/epan/dissectors/packet-dns.c#L4769
#define DNS_HDRLEN 12

#define DNS_FLAGS_OFFSET 2
#define DNS_QUEST_OFFSET 4
#define DNS_ANS_OFFSET   6
#define DNS_AUTH_OFFSET  8
#define DNS_ADD_OFFSET   10

#define DNS_F_OPCODE   (0xf<<11)
#define DNS_F_RESPONSE (1<<15)

#define DNS_RR_TYPE_A		 1
#define DNS_RR_TYPE_AAAA	28
#define DNS_RR_TYPE_CNAME	 5

int cckex_parse_dns(struct sk_buff* skb, int ip_proto);

int cckex_ipv4_is_associated_with_signal_messenger(const uint32_t ip);
int cckex_ipv6_is_associated_with_signal_messenger(const struct in6_addr ip);

void cckex_reset_ip_list(void);
