#pragma once

#include <linux/types.h>
#include "../common.h"

typedef struct signal_data {

	uint8_t *tls_record;
	size_t tls_record_len;

	char *base64_ptr;
	char *base64_endptr;

	uint8_t *request_data;
	size_t request_data_len;
	size_t request_data_offset;

	uint8_t *raw_data;
	size_t raw_data_len;
	size_t raw_data_with_padding_len;

	uint8_t *sealed_sender_data;
	size_t sealed_sender_data_size;
	uint8_t *sealed_sender_hmac;
	size_t sealed_sender_hmac_size;
	uint8_t *message_data;
	size_t message_data_size;

	cckex_key_list_entry_t *sealed_sender_key;
	cckex_key_list_entry_t *message_key;

} signal_data_t;

int cckex_signal_message_unpack_base64(signal_data_t *signal_data);
int cckex_signal_message_repack_base64(signal_data_t *signal_data);

int cckex_signal_message_decrypt_sealed_sender(signal_data_t * signal_data);
int cckex_signal_message_encrypt_sealed_sender(signal_data_t * signal_data);

int cckex_signal_message_decrypt_message(signal_data_t * signal_data);
int cckex_signal_message_encrypt_message(signal_data_t * signal_data);

int cckex_signal_message_recalc_hmac(signal_data_t *signal_data);
