#include "message_dissection/signalmessagedissectors.h"

#include <string.h>
#include <stdio.h>

#include <epan/guid-utils.h>
#include <wsutil/wsjson.h>
#include <wsutil/wmem/wmem.h>

#include "base64.h"
#include "message_dissection/signalmessagecrypto.h"
#include "extraction/ccdatamanager.h"
#include "ui/uihandler.h"
#include "common.h"

/*static void base64_to_buffer(const char *instr, uint8_t *outbuf) {
    //printf("instr: %s\n", instr);
    //printf("outbuf:");
    for(unsigned i = 0; i < strlen(instr) / 4; i++) {
        memcpy(outbuf + i * 3, unbase64(instr + i * 4), 3);
        //printf("%.2x%.2x%.2x", outbuf[i * 3], outbuf[i * 3 + 1], outbuf[i * 3 + 2]);
    }
    //printf("\n");
}*/

int dissect_websocket_layer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned start_offset, tvbuff_t** out_decrypted_sealed_sender_tvb) {
    (void) out_decrypted_sealed_sender_tvb;

    /*** extract json data from package ****/

    // find end of json buffer
    unsigned end_offset = start_offset;
    unsigned braket_count = 0;
    do {
        char cur = (char)tvb_get_uint8(tvb, end_offset);
        end_offset++;

        //printf("ccKex <pkg:%i> [info]: checked char=%c\n", pinfo->num, cur);

        if(cur == '{') braket_count++;
        if(cur == '}') braket_count--;
    } while(end_offset < tvb_reported_length(tvb) && braket_count != 0);

    printf("ccKex <pkg:%i> [info]: found json at end=%i\n", pinfo->num, end_offset);

    if(end_offset == tvb_reported_length(tvb)) {
        printf("%s: failed to parse root_token\n", __func__);
        return 0;
    }

    // get string from tvb, validate it and parse it
    char *msg_json_string = tvb_get_string_enc(NULL, tvb, start_offset, end_offset - start_offset + 1, ENC_ASCII);
    msg_json_string[end_offset - start_offset] = '\0';

    if(!json_validate(msg_json_string, strlen(msg_json_string))) {
        printf("%s: failed to validate json string: %s\n", __func__, msg_json_string);
        return 0;
    }
    proto_tree_add_string(tree, hf_websocket_json_text, tvb, start_offset, strlen(msg_json_string), msg_json_string);


    int root_token_count = json_parse(msg_json_string, NULL, 0);
    if(root_token_count <= 0) {
        printf("%s: root_token_count <= 0\n", __func__);
        return 0;
    }

    jsmntok_t *root_tokens = wmem_alloc_array(pinfo->pool, jsmntok_t, root_token_count);
    int ret = json_parse(msg_json_string, root_tokens, root_token_count);
    if(ret <= 0) {
        printf("%s: failed to parse root_token\n", __func__);
        return 0;
    }

    // parse simple fields
    char *dst_guid_str = json_get_string(msg_json_string, root_tokens, "destination");
    if(dst_guid_str) {
       proto_tree_add_string(tree, hf_websocket_dst_guid, tvb, 0, strlen(dst_guid_str), dst_guid_str);
    }

    double tmpDbl;
    if(json_get_double(msg_json_string, root_tokens, "online (not working)", &tmpDbl)) {
        proto_tree_add_boolean(tree, hf_websocket_online, tvb, 0, 1, (guint32)tmpDbl);
    }

    if(json_get_double(msg_json_string, root_tokens, "timestamp", &tmpDbl)) {
        uint64_t t = (time_t)tmpDbl;
        nstime_t time = {
            .secs = t / 1000,
            .nsecs = t % 1000
        };
        proto_tree_add_time(tree, hf_websocket_timestamp, tvb, 0, 1, &time);
    }

    if(json_get_double(msg_json_string, root_tokens, "urgent (not working)", &tmpDbl)) {
        proto_tree_add_boolean(tree, hf_websocket_urgent, tvb, 0, 1, (guint32)tmpDbl);
    }

    // parse out ciphertext
    char *base64_ciphertext;
    jsmntok_t *message_array = json_get_array(msg_json_string, root_tokens, "messages");
	size_t message_array_size = 0;
    if(message_array && (message_array_size = json_get_array_len(message_array)) > 0) {

		for(size_t i = 0; i < message_array_size; i++) {
	        jsmntok_t *message_data = json_get_array_index(message_array, i);
		    base64_ciphertext = json_get_string(msg_json_string, message_data, "content");

			unsigned decomp_base64_len = (strlen(base64_ciphertext) / 4) * 3;

	        uint8_t *sealed_sender_ciphertext = wmem_alloc_array(pinfo->pool, uint8_t, decomp_base64_len);

		    /*base64_to_buffer(base64_ciphertext, sealed_sender_ciphertext);

			// check for padding in base64
	        if(base64_ciphertext[strlen(base64_ciphertext) - 1] == '=') decomp_base64_len -= 1;
		    if(base64_ciphertext[strlen(base64_ciphertext) - 2] == '=') decomp_base64_len -= 1;

	        tvbuff_t *signal_message_layer_tvb = tvb_new_child_real_data(tvb, sealed_sender_ciphertext,
                                                decomp_base64_len, decomp_base64_len);*/

		    tvbuff_t *signal_message_layer_tvb = base64_to_tvb(tvb, base64_ciphertext);
			decomp_base64_len = tvb_reported_length(signal_message_layer_tvb);

	        /*printf("base64: %s\n", base64_ciphertext);
		    printf("raw: ");
			for(unsigned i = 0; i < decomp_base64_len; i++) {
				printf("%.02x", tvb_get_uint8(tvb, i));
	        }
		    printf("\n");*/

			tvb_memcpy(signal_message_layer_tvb, sealed_sender_ciphertext, 0, decomp_base64_len);

	        add_new_data_source(pinfo, signal_message_layer_tvb, "Signal Message Layer");

		    // decrypt sealed sender
			//printf("ccKex <pkg:%i> [info]: unpack sealed sender...\n", pinfo->num);

	        unsigned unsealed_sender_buf_len = decomp_base64_len - 84 - 10; //(decomp_base64_len - 84) - ((decomp_base64_len - 84) % 16);
		    // remove 32 byte hmac sha265
	//        unsealed_sender_buf_len -= 32;

		    uint8_t* unsealed_sender_buf = wmem_alloc_array(pinfo->pool, uint8_t, unsealed_sender_buf_len);
			memset(unsealed_sender_buf, 0, unsealed_sender_buf_len);
	        if(decrypt_sealed_sender(sealed_sender_ciphertext + 84, unsealed_sender_buf, unsealed_sender_buf_len)) {
		        CLOG_INFO("failed to decrypt sealed sender in message %lu in packet %u\n", i, pinfo->num);
				continue;
	        }


	        *out_decrypted_sealed_sender_tvb = tvb_new_child_real_data(tvb, unsealed_sender_buf,
                                               unsealed_sender_buf_len, unsealed_sender_buf_len);
		    //*out_decrypted_sealed_sender_tvb = tvb_new_real_data(unsealed_sender_buf,
			//                                        unsealed_sender_buf_len, unsealed_sender_buf_len);

	        /*printf("ccKex <pkg:%i> [info]: unpacked sealed sender ptr=%p!\n", pinfo->num, out_decrypted_sealed_sender_tvb);


		    uint8_t* msg_buf = wmem_alloc_array(pinfo->pool, uint8_t, 9 * 16);
			if(decrypt_message(unsealed_sender_buf + 325, msg_buf, 9 * 16)) {
				return 0;
	        }

		    printf("ccKex <pkg:%i> [info]: unpacked message signature=%lx !\n", pinfo->num, ((uint64_t*)msg_buf)[0]);

			if(msg_buf[0] == 0x0a) {
	            uint8_t len = msg_buf[3];
				char* message = wmem_alloc_array(pinfo->pool, char, len + 1);
		        memcpy(message, msg_buf + 4, len);
			    message[len] = '\0';
				printf("ccKex <pkg:%i> [info]: unpacked message (len=%.2x): %s\n", pinfo->num, len, message);
	        }*/
		}

    } else {
        printf("%s: failed to parse message array from json\n", __func__);
    }

    // decrypt sealed sender

    return tvb_captured_length(tvb);
}

int dissect_sealed_sender_layer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, tvbuff_t **out_decrypted_message_tvb) {
    (void) tvb;
    (void) pinfo;
    (void) tree;
    (void) out_decrypted_message_tvb;

    unsigned offset = 0;

    proto_item *ti_sender_cert;
    proto_tree *ccKex_sealed_sender_cert_tree;

    // Setup Sender Certificate Subtree
    //

    ti_sender_cert = proto_tree_add_item(tree, hf_sealedsender_cert, tvb, 0, -1, ENC_NA);
    ccKex_sealed_sender_cert_tree = proto_item_add_subtree(ti_sender_cert, ett_ccKex_sealed_sender_certificate);

    //uint32_t version = tvb_get_ntohl(tvb, offset);
    //(void) version;
    //offset += 4;

    // TODO: Parse start of pkg
    offset += 9;


    // Parse Sender Certificate
    //

    // parse phone number / e164
    uint8_t e164_str_len = tvb_get_uint8(tvb, offset);
    if(e164_str_len) {
		proto_tree_add_uint(ccKex_sealed_sender_cert_tree, hf_sealedsender_cert_e164_length, tvb, offset, 1, e164_str_len);
	}
    offset++;

    char *e164_str = tvb_get_string_enc(pinfo->pool, tvb, offset, e164_str_len, ENC_ASCII);
    if(e164_str) proto_tree_add_string(ccKex_sealed_sender_cert_tree, hf_sealedsender_cert_e164, tvb, offset, e164_str_len, e164_str);
    offset += e164_str_len;

    // parse sender uuid
    offset = 0xb0;
    uint8_t uuid_str_len = tvb_get_uint8(tvb, offset);
    if(uuid_str_len) proto_tree_add_uint(ccKex_sealed_sender_cert_tree, hf_sealedsender_cert_uuid_length, tvb, offset, 1, uuid_str_len);
    offset++;

    char *uuid_str = tvb_get_string_enc(pinfo->pool, tvb, offset, uuid_str_len, ENC_ASCII);
    if(uuid_str) proto_tree_add_string(ccKex_sealed_sender_cert_tree, hf_sealedsender_cert_uuid, tvb, offset, uuid_str_len, uuid_str);
    offset += uuid_str_len;

    // Parse and decrypt inner message ciphertext
    //

	size_t offsets[] = { 0x183, 0x137, 0x145, 0x194 };
	size_t offsets_length = 4;

	unsigned ciphertext_len = 0;

	uint8_t *encrypted_message_buf = NULL;
	uint8_t *decrypted_message_buf = NULL;

	int done = 0;
	for(size_t i = 0; i < offsets_length; i++) {

		offset = offsets[i];

	    //unsigned ciphertext_len = tvb_reported_length_remaining(tvb, offset);
		//ciphertext_len -= ciphertext_len % 16;
	    ciphertext_len = tvb_get_uint8(tvb, offset - 1) * 160;

		encrypted_message_buf = NULL;
	    decrypted_message_buf = NULL;
		if((int)ciphertext_len > tvb_reported_length_remaining(tvb, offset)) {
			ciphertext_len = 0;
	    } else {
		    encrypted_message_buf = tvb_memdup(pinfo->pool, tvb, offset, ciphertext_len);
			decrypted_message_buf = wmem_alloc_array(pinfo->pool, uint8_t, ciphertext_len);
	        if(!decrypted_message_buf) return 0;
	    }

		if(ciphertext_len == 0 || decrypt_message(encrypted_message_buf, decrypted_message_buf, ciphertext_len)) {
			continue;
		} else {
			done = 1;
			break;
		}
	}

	if (!done) return 0;

    proto_tree_add_bytes(tree, hf_sealedsender_message_ciphertext, tvb, offset, ciphertext_len, encrypted_message_buf);

    *out_decrypted_message_tvb = tvb_new_child_real_data(tvb, decrypted_message_buf, ciphertext_len, ciphertext_len);

    offset += ciphertext_len;

    // Parse ContentHint
    //

    if(tvb_reported_length_remaining(tvb, offset) < 4) return tvb_reported_length(tvb) - ciphertext_len;

    uint32_t content_hint = tvb_get_ntohl(tvb, offset);
    proto_tree_add_uint(tree, hf_sealedsender_content_hint, tvb, offset, 4, content_hint);

    // TODO: Parse Group Id
    //

    return 0;
}

int dissect_message_layer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {

    unsigned offset = 0;

    // check message type
    uint8_t type = tvb_get_uint8(tvb, offset);
    offset++;

    //
    char *type_str;
    if(type == 0x32) {
        type_str = "Typing Message";

		uihandler_add_message(pinfo->num, type, "");

    } else if (type == 0x0a) {
        type_str = "Text Message";

        // jump to offset of text message length
        offset = 3;

        // parse text length and text and display them
        uint8_t text_len = tvb_get_uint8(tvb, offset);
        proto_tree_add_uint(tree, hf_message_text_length, tvb, offset, 1, text_len);
        offset++;

        char *text = tvb_get_string_enc(pinfo->pool, tvb, offset, text_len, ENC_ASCII);
        proto_tree_add_string(tree, hf_message_text, tvb, offset, text_len, text);

		uihandler_add_message(pinfo->num, type, text);

    } else {
        type_str = "Unknown";

		uihandler_add_message(pinfo->num, type, "");
    }

    // display message type
    proto_tree_add_string(tree, hf_message_type, tvb, 0, strlen(type_str), type_str);

    offset = tvb_reported_length(tvb) - 2;

    uint8_t injected_data_size = tvb_get_uint8(tvb, offset);

    if(injected_data_size != 0) {
        proto_tree_add_uint(tree, hf_message_injected_data_length, tvb, offset, 1, injected_data_size);

        // find start offset of injected data
        int length = tvb_reported_length(tvb);
        if(length % 16) {
            printf("[%s] pkg_size mod 16 != 0 - something is very wrong here\n", __func__);
            return 0;
        }

        uint8_t tmp;
        unsigned tmp_offset = 0;
        for(length -= 1; length > 0; length -= 16) {
            for(int i = length; i >= 0 && i - length < 16; --i) {
                tmp = tvb_get_uint8(tvb, i);
                if(tmp == 0x80) { // possibly found start of buffer
                    // check alignment
                    tmp_offset = i + (16 - (i % 16));

                    // check length
                    if(tvb_reported_length_remaining(tvb, tmp_offset) - 2 < injected_data_size) {
                        // -> length to short with that offset -> false positive in the extracted data
                        break;
                    }

                    // check start and end of injected data -> high entropy should != 0 but can be 0
                    if(tvb_get_uint8(tvb, tmp_offset) == 0 || tvb_get_uint8(tvb, tmp_offset + injected_data_size - 1) == 0) {
                        printf("[%s] start/end of exfiltrated data starts with 0 .. aborting (%i -> %i)\n", __func__, tmp_offset, tmp_offset + injected_data_size -1);
                        goto out;
                    }

                    length = 0;
                    break;

                } else if(tmp != 0x00) {
                    break;
                }
            }
        }

        if(tmp_offset == 0) return 0;

        uint8_t *injected_data = tvb_memdup(pinfo->pool, tvb, tmp_offset, injected_data_size);
        proto_tree_add_bytes(tree, hf_message_injected_data, tvb, tmp_offset, injected_data_size, injected_data);

        //insert_data_from_sig_msg(pinfo->num, injected_data, injected_data_size, pinfo->rel_ts);
    }
out:
    return tvb_reported_length(tvb);
}
