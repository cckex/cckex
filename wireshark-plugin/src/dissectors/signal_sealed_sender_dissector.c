#include "signal_sealed_sender_dissector.h"

#include <wireshark.h>
#include <string.h>

#include <epan/tvbuff.h>
#include <epan/packet.h>

#include "message_dissection/signalmessagecrypto.h"

static int proto_cckex_sealed_sender = -1;

static dissector_handle_t cckex_sealed_sender_handle;

static int cckex_ett_clear_sealed_sender = -1;

static int cckex_signal_dissect_sealed_sender_encryption(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_);

void cckex_register_signal_sealed_sender_dissector(module_t *module) {
	(void)module;

	static int *ett[] = {
		&cckex_ett_clear_sealed_sender
	};

	proto_cckex_sealed_sender = proto_register_protocol("ccKex Sealed Sender", "cckex.ss", "cckex.ss");

	cckex_sealed_sender_handle = register_dissector("ccKex.sealed_sender", cckex_signal_dissect_sealed_sender_encryption,
proto_cckex_sealed_sender);

	proto_register_subtree_array(ett, array_length(ett));

}

void cckex_handoff_signal_sealed_sender_dissector(void) {

	static bool initialized = false;

	if(!initialized) {

		dissector_add_string("protobuf_field", "cckexsignal.UnidentifiedSealedSenderMessageV1.encrypted_message",
					   cckex_sealed_sender_handle);
		dissector_add_string("protobuf_field", "cckexsignal.UnidentifiedSealedSenderMessageV2.encrypted_message",
						cckex_sealed_sender_handle);

		initialized = true;
	}

}

static int cckex_signal_dissect_sealed_sender_encryption(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
	(void)tree;

	// TODO: implement and verify package checksum
	const size_t ctext_len = tvb_reported_length(tvb) - 10;		// Ignore the 10 byte checksum at the end for now
	uint8_t *ctext = tvb_memdup(pinfo->pool, tvb, 0, ctext_len);
	DISSECTOR_ASSERT(ctext);

	const size_t raw_len = ctext_len;
	uint8_t *raw_data = wmem_alloc_array(pinfo->pool, uint8_t, raw_len);
	DISSECTOR_ASSERT(raw_data);

	// TODO: somehow cache encryption
	if(decrypt_sealed_sender(ctext, raw_data, ctext_len) == -1) {
		CLOG_PKG_WARN("Failed to decrypt sealed sender data.");
		return 0;
	}

	tvbuff_t *decrypted_tvb = tvb_new_child_real_data(tvb, raw_data, raw_len, raw_len);
	add_new_data_source(pinfo, decrypted_tvb, "Decrypted Sealed Sender Data");

	dissector_handle_t protobuf_handle = find_dissector("protobuf");

	return call_dissector_with_data(protobuf_handle, decrypted_tvb, pinfo, proto_item_get_parent_nth(tree, 4),
				"message,signal.proto.sealed_sender.UnidentifiedSenderMessage.Message");
}
