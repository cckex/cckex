#pragma once

#include <linux/skbuff.h>

// layer 4
int cckex_heur_is_tcp(struct sk_buff *skb);
int cckex_heur_is_udp(struct sk_buff *skb);

uint8_t *cckex_filter_source_port(struct sk_buff *skb, int ip_proto, uint16_t port);
uint8_t *cckex_filter_dest_port(struct sk_buff *skb, int ip_proto, uint16_t port);

// layer 5
int cckex_heur_is_dns_v4(struct sk_buff *skb, int *ip_proto);
int cckex_heur_is_dns_v6(struct sk_buff *skb, int *ip_proto);

void cckex_heur_test(struct sk_buff *skb);
void cckex_heur_test6(struct sk_buff *skb);
