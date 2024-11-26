#pragma once

#include <linux/skbuff.h>

#include "../common.h"

typedef int (*cckex_cc_method_t)(const struct sk_buff *skb, cckex_key_list_entry_t *key_entry);

int cckex_cc_full_ttl(const struct sk_buff *skb, cckex_key_list_entry_t *key_entry);
int cckex_cc_iptos(const struct sk_buff *skb, cckex_key_list_entry_t *key_entry);
int cckex_cc_ipflags(const struct sk_buff *skb, cckex_key_list_entry_t *key_entry);
int cckex_cc_ipid(const struct sk_buff *skb, cckex_key_list_entry_t *key_entry);
int cckex_cc_ipfragment(const struct sk_buff *skb, cckex_key_list_entry_t *key_entry);
int cckex_cc_tcpurgent(const struct sk_buff *skb, cckex_key_list_entry_t *key_entry);
int cckex_cc_timing_ber(const struct sk_buff *skb, cckex_key_list_entry_t *key_entry);

int cckex_cc_inject_into_message(struct sk_buff *skb);
