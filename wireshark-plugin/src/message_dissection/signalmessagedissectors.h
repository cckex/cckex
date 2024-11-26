#pragma once

#include <epan/tvbuff.h>
#include <epan/packet.h>

extern int hf_websocket_json_text;
extern int hf_websocket_dst_guid;
extern int hf_websocket_online;
extern int hf_websocket_timestamp;
extern int hf_websocket_urgent;

extern int hf_sealedsender_cert;
extern int hf_sealedsender_cert_e164_length;
extern int hf_sealedsender_cert_e164;
extern int hf_sealedsender_cert_uuid_length;
extern int hf_sealedsender_cert_uuid;
extern int hf_sealedsender_message_ciphertext;
extern int hf_sealedsender_content_hint;

extern int hf_message_type;
extern int hf_message_text_length;
extern int hf_message_text;
extern int hf_message_injected_data_length;
extern int hf_message_injected_data;

/* Initialize the subtree pointers */
extern int ett_ccKex_websocket;
extern int ett_ccKex_sealed_sender;
extern int ett_ccKex_sealed_sender_certificate;
extern int ett_ccKex_message;
//static int ett_cckex_base_message;

extern const char* signal_message_fingerprint;

#define ccKex_MIN_LENGTH 1024

#define ccKex_MIN_LENGTH_FOR_HEURISTICS     strlen(signal_message_fingerprint)
#define ccKex_SKIP_BEFORE_HEURISTICS        7

int dissect_websocket_layer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned start_offset, tvbuff_t** out_decrypted_sealed_sender_tvb);
int dissect_sealed_sender_layer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, tvbuff_t **out_decrypted_message_tvb);
int dissect_message_layer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

