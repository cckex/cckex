#pragma once

#include <linux/skbuff.h>

#include "connection_list.h"

#define TLS12_AAD_SIZE 13
#define TLS12_IV_SIZE  12

#define TLS13_AAD_SIZE 5
#define TLS13_IV_SIZE  TLS12_AAD_SIZE

typedef struct cckex_tls_crypto {
	uint8_t orig_tls_header[TLS12_AAD_SIZE];
	uint8_t iv[TLS12_IV_SIZE];
	uint8_t *payload_backup;
} cckex_tls_crypto_t;

void cckex_test_tls_crypto(void);
void cckex_test_tls_crypto_384(void);

int cckex_tls12_prf_gen_keys(cckex_conn_list_entry_t *entry, const char *label);
int cckex_tls12_decrypt_payload(struct sk_buff *skb, cckex_conn_list_entry_t *entry, 
		uint8_t *payload, size_t payload_len, cckex_tls_crypto_t **tls_crypto);
int cckex_tls12_encrypt_payload(struct sk_buff *skb, cckex_conn_list_entry_t *entry,
		uint8_t *payload, size_t payload_len, cckex_tls_crypto_t **tls_crypto);


int cckex_tls13_prf_gen_keys(cckex_conn_list_entry_t *entry);
int cckex_tls13_decrypt_payload(struct sk_buff *skb, cckex_conn_list_entry_t *entry,
		uint8_t *payload, size_t payload_len, cckex_tls_crypto_t **tls_crypto);
int cckex_tls13_encrypt_payload(struct sk_buff *skb, cckex_conn_list_entry_t *entry,
		uint8_t *payload, size_t payload_len, cckex_tls_crypto_t **tls_crypto);
