#include "filter.h"

#include <linux/in.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/net.h>
#include <linux/string.h>
#include <linux/timekeeping.h>

#include "../common.h"
#include "../cc/cchandler.h"
#include "../cc/ccmethod.h"
#include "heur_filter.h"
#include "dns.h"
#include "tls.h"

static unsigned int out_nf_hookfn(void *priv,
		struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	struct iphdr *iph; 
	u64 timing_overhead;

	timing_overhead = ktime_get_ns();

	if(!skb) return NF_ACCEPT;

	if(skb_is_nonlinear(skb)) {
		skb_linearize_cow(skb);
	}

	iph = ip_hdr(skb);
	//pr_info("CCKEX_LKM [%s] CAPTURED PGK: ID=%04x TTL=%02x PROTO=%02x on %s from %pI4h to %pI4h", __func__, ntohs(iph->id), iph->ttl, iph->protocol, skb->dev->name, &iph->saddr, &iph->daddr);

	// only inject data into outgoing wlan interface
	if(strncmp(skb->dev->name, "wlan0", 5) == 0) {
		cckex_apply_cc(skb);
	}

	timing_overhead = ktime_get_ns() - timing_overhead;
	//pr_info("CCKEX_LKM [%s] overhead=%lldns", __func__, timing_overhead);

    return NF_ACCEPT;
}

static unsigned int out_nf_hookfn6(void *priv,
		struct sk_buff *skb,
		const struct nf_hook_state *state) {

	u64 timing_overhead = ktime_get_ns();

	if(!skb) return NF_ACCEPT;

	if(skb_is_nonlinear(skb)) {
		skb_linearize_cow(skb);
	}

	/*if(cckex_filter_tls_hello_message_v6(skb, NF_INET_POST_ROUTING) == CCKEX_MSG_TYPE_TLS_RECORD) {
		cckex_cc_inject_into_message(skb);
	}*/

	timing_overhead = ktime_get_ns() - timing_overhead;
	//pr_info("CCKEX_LKM [%s] overhead=%lldns", __func__, timing_overhead);

	return NF_ACCEPT;
}


static unsigned int in_nf_hookfn(void *priv,
		struct sk_buff *skb,
		const struct nf_hook_state *state) {

	u64 timing_overhead = ktime_get_ns();
	int ip_proto = 0;

	if(!skb) return NF_ACCEPT;

	if(skb_is_nonlinear(skb)) {
		skb_linearize_cow(skb);
	}

	ip_proto = 0;
	if(cckex_heur_is_dns_v4(skb, &ip_proto)) {
		cckex_parse_dns(skb, ip_proto);
	}

	cckex_filter_tls_hello_message_v4(skb, NF_INET_LOCAL_IN);

	timing_overhead = ktime_get_ns() - timing_overhead;
	//pr_info("CCKEX_LKM [%s] overhead=%lldns", __func__, timing_overhead);

	return NF_ACCEPT;
}

static unsigned int in_nf_hookfn6(void *priv,
		struct sk_buff *skb,
		const struct nf_hook_state *state) {

	u64 timing_overhead = ktime_get_ns();
	int ip_proto = 0;

	if(!skb) return NF_ACCEPT;

	if(skb_is_nonlinear(skb)) {
		skb_linearize_cow(skb);
	}

	ip_proto = 0;
	if(cckex_heur_is_dns_v6(skb, &ip_proto)) {
		cckex_parse_dns(skb, ip_proto);
	}

	cckex_filter_tls_hello_message_v6(skb, NF_INET_LOCAL_IN);

	timing_overhead = ktime_get_ns() - timing_overhead;
	//pr_info("CCKEX_LKM [%s] overhead=%lldns", __func__, timing_overhead);

	return NF_ACCEPT;
}


// OUTPUT HOOKS
static struct nf_hook_ops out_nfho = {
    .hook        = out_nf_hookfn,
    .hooknum     = NF_INET_POST_ROUTING, //LOCAL_OUT,
    .pf          = PF_INET,
    .priority    = NF_IP_PRI_LAST //FIRST
};

static struct nf_hook_ops out_nfho6 = {
    .hook        = out_nf_hookfn6,
    .hooknum     = NF_INET_POST_ROUTING, //LOCAL_OUT,
    .pf          = PF_INET6,
    .priority    = NF_IP_PRI_LAST //FIRST
};

// INPUT HOOKS
static struct nf_hook_ops in_nfho = {
    .hook        = in_nf_hookfn,
    .hooknum     = NF_INET_LOCAL_IN,
    .pf          = PF_INET,
    .priority    = NF_IP_PRI_FIRST
};

static struct nf_hook_ops in_nfho6 = {
    .hook        = in_nf_hookfn6,
    .hooknum     = NF_INET_LOCAL_IN,
    .pf          = PF_INET6,
    .priority    = NF_IP_PRI_FIRST
};

int cckex_register_filter(void) {
	nf_register_net_hooks(&init_net, &out_nfho6, 1);
	nf_register_net_hooks(&init_net, &out_nfho, 1);
	nf_register_net_hooks(&init_net, &in_nfho6, 1);
	nf_register_net_hooks(&init_net, &in_nfho, 1);

	return 0;
}

void cckex_unregister_filter(void) {
	nf_unregister_net_hooks(&init_net, &out_nfho6, 1);
	nf_unregister_net_hooks(&init_net, &out_nfho, 1);
	nf_unregister_net_hooks(&init_net, &in_nfho6, 1);
	nf_unregister_net_hooks(&init_net, &in_nfho, 1);
}
