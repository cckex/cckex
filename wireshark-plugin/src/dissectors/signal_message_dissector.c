#include "signal_message_dissector.h"

#include <wireshark.h>
#include <string.h>

#include <epan/tvbuff.h>
#include <epan/packet.h>

#include "message_dissection/signalmessagecrypto.h"
#include "extraction/ccdatamanager.h"
#include "stats/cckex_stats.h"

static int proto_cckex_message = -1;

static dissector_handle_t cckex_message_handle;
static dissector_handle_t cckex_extract_cc_handle;

static int cckex_ett_clear_message = -1;

static int cckex_signal_dissect_message_encryption(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_);
static int cckex_signal_dissect_message_cc_injection(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_);

void cckex_register_signal_message_dissector(module_t *module) {
	(void)module;

	static int *ett[] = {
		&cckex_ett_clear_message
	};

	proto_cckex_message = proto_register_protocol("ccKex Message", "cckex.msg", "cckex.msg");

	cckex_message_handle = register_dissector("ccKex.message", cckex_signal_dissect_message_encryption,
									proto_cckex_message);
	cckex_extract_cc_handle = register_dissector("ccKex.message.extract_cc", cckex_signal_dissect_message_cc_injection,
									proto_cckex_message);

	proto_register_subtree_array(ett, array_length(ett));

}

void cckex_handoff_signal_message_dissector(void) {

	static bool initialized = false;

	if(!initialized) {

		dissector_add_string("protobuf_field", "signal.proto.sealed_sender.UnidentifiedSenderMessage.Message.content",
					   cckex_message_handle);
		dissector_add_string("protobuf_field", "signalservice.Content.cckex_msglvl_injection",
					   cckex_extract_cc_handle);

		initialized = true;
	}

}

static int cckex_signal_dissect_message_encryption(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
	(void)tree;

	// TODO: parse weird static data, which is in front of message ciphertext 

	unsigned offset = 0x2a;		// jump over weird static data in content field

	// calculate the ciphertext length of the message section (it is 160 byte aligned)
	const size_t ctext_len = tvb_get_uint8(tvb, offset) * 160;

	offset += 1;

	uint8_t *ctext = tvb_memdup(pinfo->pool, tvb, offset, ctext_len);
	DISSECTOR_ASSERT(ctext);

	const size_t raw_len = ctext_len;
	uint8_t *raw_data = wmem_alloc_array(pinfo->pool, uint8_t, raw_len);
	DISSECTOR_ASSERT(raw_data);

	// TODO: somehow cache encryption
	if(decrypt_message(ctext, raw_data, ctext_len) == -1) {
		CLOG_PKG_WARN("Failed to decrypt sealed sender data.");
		return 0;
	}

	tvbuff_t *decrypted_tvb = tvb_new_child_real_data(tvb, raw_data, raw_len, raw_len);
	add_new_data_source(pinfo, decrypted_tvb, "Decrypted Message Data");

	// find stop byte 0x80
	offset = tvb_reported_length(decrypted_tvb);
	while(offset > 0 && tvb_get_uint8(decrypted_tvb, --offset) != 0x80) { /* do nothing and advance to the next byte */ }

	cckex_stats_add_to_column("message_injection_payload_size", CCKEX_LEVEL_SIGNAL_MSG, pinfo->num, tvb_reported_length_remaining(decrypted_tvb, offset + 2 /* dont count 0x80 stop and 0x01 padding byte */ ));
	
	dissector_handle_t protobuf_handle = find_dissector("protobuf");

	return call_dissector_with_data(protobuf_handle,
			tvb_new_subset_length(decrypted_tvb, 0, offset),	// slice decrypted tvb to end before the 0x80 stop byte
			pinfo, proto_item_get_parent_nth(tree, 4),
			"message,signalservice.Content");
}

static int cckex_signal_dissect_message_cc_injection(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {

	(void)tree;

	const size_t ccdata_len = tvb_reported_length(tvb);
	uint8_t *ccdata = tvb_memdup(pinfo->pool, tvb, 0, ccdata_len);

	insert_data_buf(CCKEX_LEVEL_SIGNAL_MSG, pinfo->num, ccdata, ccdata_len, pinfo->rel_ts);

	return tvb_reported_length(tvb);
}

