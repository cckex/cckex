#pragma once

#include <linux/skbuff.h>
#include <linux/netfilter.h>

#define CCKEX_MSG_TYPE_TLS_RECORD 1

int cckex_filter_tls_hello_message_v4(struct sk_buff *skb, enum nf_inet_hooks hook_num);
int cckex_filter_tls_hello_message_v6(struct sk_buff *skb, enum nf_inet_hooks hook_num);

