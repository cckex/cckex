#include "dns.h"

#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/ipv6.h>
#include <linux/ip.h>

#include "../common.h"
#include "connection_list.h"

DEFINE_SPINLOCK(ip_list_slock);

typedef struct ip_list_entry {
	struct list_head list;
	uint8_t is_ipv4;
	uint32_t ipv4;
	struct in6_addr ipv6;
} ip_list_entry_t;

LIST_HEAD(ip_list);

void cckex_reset_ip_list(void) {

	ip_list_entry_t *entry;
	ip_list_entry_t *n;

	spin_lock_bh(&ip_list_slock);

	list_for_each_entry_safe(entry, n, &ip_list, list) {

		list_del(&entry->list);
		
		kfree(entry);
	}

	spin_unlock_bh(&ip_list_slock);
}

static void get_hostname_from_dns_query(uint8_t* data, char** buf, uint32_t *len) {
	
	unsigned offset = DNS_ADD_OFFSET + 2;
	uint8_t tmp_len = 0;

	*len = 0;

	// TODO: check data_len also and error handling
	
	// get length from request
	while(*(data + offset) != 0) {
		tmp_len = *(data + offset) + 1;
		*len += tmp_len;
		offset += tmp_len;
	}

	// alloc buffer
	*buf = kmalloc(*len, GFP_ATOMIC);

	// copy hostname to buffer
	offset = DNS_ADD_OFFSET + 2;
	*len = 0;

	while(*(data + offset) != 0) {
		tmp_len = *(data + offset) + 1;
		memcpy(*buf + *len, data + offset + 1, tmp_len);
		*len += tmp_len;
		offset += tmp_len;
		(*buf)[*len - 1] = '.';
	}

	(*buf)[*len - 1] = '\0';
}

static int add_new_iplist_entry(int is_ipv4, uint8_t *payload) {

	ip_list_entry_t* entry = NULL;
	uint32_t ip = 0;

	entry = kmalloc(sizeof(ip_list_entry_t), GFP_ATOMIC);
	if(entry == NULL) {
		pr_warn("CCKEX_LKM [%s] failed to allocate ip_list_entry_t", __func__);
		return -1;
	}

	if(is_ipv4) {
		ip = GET_U32H(payload, 0);
		pr_info("CCKEX_LKM [%s] DNS: %pI4h", __func__, &ip);

		if(cckex_ipv4_is_associated_with_signal_messenger(ip)) {
			//pr_info("CCKEX_LKM [%s]: -> already in ip list", __func__);
			kfree(entry);
			return 0;
		}

		entry->ipv4 = ip;
	}
	else {
		pr_info("CCKEX_LKM [%s] DNS: %pI6c", __func__, (payload));

		// TODO: implement deep copy of ipv6 address as current implementation is not valid
		pr_warn("CCKEX_LKM [%s] => CURRENTLY NOT ADDED TO IP LIST (TODO IMPLEMENT)", __func__);
		kfree(entry);
		return 0;

		/*entry->ipv6 = *(struct in6_addr*)(payload);

		if(cckex_ipv6_is_associated_with_signal_messenger(entry->ipv6)) {
			pr_info("CCKEX_LKM [%s]: -> already in ip list");
			kfree(entry);
			return 0;
		} */
	}

	spin_lock_bh(&ip_list_slock);

	list_add(&entry->list, &ip_list);

	spin_unlock_bh(&ip_list_slock);

	return 0;
}

int cckex_parse_dns(struct sk_buff* skb, int ip_proto) {

	// get pointer to payload data
	uint8_t *payload = cckex_get_ptr_to_payload(skb, ip_proto);
	uint16_t quest = 0;
	uint16_t ans = 0;
	char *hostname = NULL;
	unsigned hostname_len = 0;
	unsigned offset = 0;
	uint16_t data_len = 0;
	uint16_t type = 0;

	if(!payload) {
		pr_warn("CCKEX_LKM [%s] payload == NULL", __func__);
		return -1;
	}

	// TODO: size checks

	// check for queries and answers
	quest = ntohs(*(uint16_t*)(payload + DNS_QUEST_OFFSET));
	ans   = ntohs(*(uint16_t*)(payload + DNS_ANS_OFFSET));
	if(quest != 1 && ans == 0) {
		// more than one query or no answers are currently not supported
		pr_warn("CCKEX_LKM [%s] quest != 1 && ans == 0", __func__);
		return -1;
	}

	// extract hostname from payload
	get_hostname_from_dns_query(payload, &hostname, &hostname_len);
	if(hostname == NULL || hostname_len == 0) {
		// unable to parse hostname in query
		pr_warn("CCKEX_LKM [%s] hostname == NULL || hostname_len == 0", __func__);
		return -1;
	}

	// check if a signal server is contacted
	if(strstr(hostname, "signal") == NULL) {
		// hostname doesnt contain signal
		//pr_info("CCKEX_LKM [%s]", __func__);
		return -1;
	}

	// Set offset to the start of the Answer RRs Section
	offset = DNS_ADD_OFFSET + 2 + hostname_len + 1 + 4; // additional RR offset + add RR size + hostname length + 1 (first size field of hostname) + 4 query data

	// TODO: PARSE ALL DNS ANSWERS
	for(size_t answer_index = 0; answer_index < ans; answer_index++) {

		// TODO: check if answer pointer is set
		if((ntohs(*(uint16_t*)(payload + offset)) & 0xc000) != 0xc000) {
			// pointer in answer not set - something went wrong
			pr_warn("CCKEX_LKM [%s] answer pointer not set %.04x", __func__, ntohs(*(uint16_t*)(payload + offset)));
			return -1;
		}

		// advance to type, fetch RR type and test if it is a currently supported type
		offset += 2;
		type = GET_U16H(payload, offset);

		offset += 8; // advance to data length
		data_len = ntohs(*(uint16_t*)(payload + offset));

		offset += 2; // advance to data

		if(type == DNS_RR_TYPE_A) {		// found IPV4 address for a signal chat server -> add to ip list

			if(add_new_iplist_entry(1, payload + offset)) {
				pr_warn("CCKEX_LKM [%s] Failed to add DNS type A answer to ip list.", __func__);
			}

		} else if(type == DNS_RR_TYPE_AAAA) {	// found IPV6 address for a signal chat server -> add to ip list

			if(add_new_iplist_entry(0, payload + offset)) {
				pr_warn("CCKEX_LKM [%s] Failed to add DNS type AAAA answer to ip list.", __func__);
			}

		} else {	// type not supported - try to advance to the next RR entry
			//pr_info("CCKEX_LKM [%s] RR type not supported (%i). Trying to advance to next entry.", __func__, type);
		}

		// advance to next entry
		offset += data_len;
	}

	return 1;
}

int cckex_ipv4_is_associated_with_signal_messenger(const uint32_t ip) {
	ip_list_entry_t *entry;

	spin_lock_bh(&ip_list_slock);

	list_for_each_entry(entry, &ip_list, list) {
		if(ip == entry->ipv4) {
			spin_unlock_bh(&ip_list_slock);
			return 1;
		}
	}

	spin_unlock_bh(&ip_list_slock);

	return 0;
}

int cckex_ipv6_is_associated_with_signal_messenger(const struct in6_addr ip) {
	ip_list_entry_t *entry;

	spin_lock_bh(&ip_list_slock);

	list_for_each_entry(entry, &ip_list, list) {
		for(size_t i = 0; i < 4; i++) {
			if(ip.in6_u.u6_addr32[i] != entry->ipv6.in6_u.u6_addr32[i]) continue;
		}
		spin_unlock_bh(&ip_list_slock);
		return 1;
	}

	spin_unlock_bh(&ip_list_slock);

	return 0;
}
