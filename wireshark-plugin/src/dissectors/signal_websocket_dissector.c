#include "signal_websocket_dissector.h"

#include <wireshark.h>
#include <string.h>

#include <epan/tvbuff.h>
#include <epan/packet.h>

#include <wsutil/wsjson.h>

#include "common.h"
#include "stats/cckex_stats.h"
#include "extraction/ccdatamanager.h"

static int proto_cckex_websocket = -1;

static dissector_handle_t cckex_websocket_handle;
static dissector_handle_t cckex_request_body_handle;
static dissector_handle_t cckex_envelope_handle;
static dissector_handle_t cckex_envelope_injection_handle;

static dissector_table_t cckex_subdissector_table;

static int cckex_ett_websocket = -1;
static int cckex_ett_request_body = -1;
static int cckex_ett_envelope = -1;

static int hf_envelope_sealed_sender_version = -1;

static bool pref_ws_json_data_source = false;

static int cckex_signal_dissect_websocket_layer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_);
static int cckex_signal_dissect_request_body_layer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_);
static int cckex_signal_dissect_envelope_layer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);
static int cckex_signal_dissect_envelope_injection(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);

void cckex_register_signal_websocket_dissector(module_t *module) {

	// create the proto subtrees and header field arrays

	static hf_register_info hf[] = {
		{ &hf_envelope_sealed_sender_version,
			{	"Sealed Sender Version", "CCKEX_ENVELOPE_SS_VERSION",
				FT_UINT8, BASE_HEX, NULL, 0x0,
				"NULL", HFILL }
		}
	};

	static int *ett[] = {
		&cckex_ett_websocket,
		&cckex_ett_request_body,
		&cckex_ett_envelope
	};

	// Register the dissector for the Signal Websocket layer and the subdissector for the body field of the Signal
	// WebSocketRequestMessage ProtoBuffer. Additionally register a dissector for the base64 encoded envelope.

	proto_cckex_websocket = proto_register_protocol("ccKex Signal Websocket", "cckex.ws", "cckex.ws");

	cckex_websocket_handle = register_dissector("ccKex.websocket", cckex_signal_dissect_websocket_layer,
											proto_cckex_websocket);

	cckex_request_body_handle = register_dissector("ccKex.request.body", cckex_signal_dissect_request_body_layer,
											proto_cckex_websocket);

	cckex_envelope_handle = register_dissector("ccKex.envelope", cckex_signal_dissect_envelope_layer,
											proto_cckex_websocket);

	cckex_envelope_injection_handle = register_dissector("ccKex.envelope.injection", cckex_signal_dissect_envelope_injection,
											proto_cckex_websocket);

	// register proto subtrees and field header arrays
	proto_register_field_array(proto_cckex_websocket, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	// find the media_type subdissector table in order to call the json dissector and call additional custom
	// cckex dissectors

	cckex_subdissector_table = find_dissector_table("media_type");

	// register the preferences for the Signal websocket dissector

	prefs_register_bool_preference(module, "ws.json_data_source", "Request Body Data Source",
			"Create a new data source from the JSON body in a Signal Requst ProtoBuffer.", &pref_ws_json_data_source);
}

void cckex_handoff_signal_websocket_dissector(void) {
	static bool initialized = false;

	if(!initialized) {
		// register the cckex signal dissector for the websocket payload layer
		dissector_add_uint("ws.port", 443, cckex_websocket_handle);

		// register the cckex signal dissector for the body field of the request message
		dissector_add_string("protobuf_field", "signalservice.WebSocketRequestMessage.body", cckex_request_body_handle);

		dissector_add_string("protobuf_field", "cckexsignal.EnvelopeInjection.cckex_envelope_injection",
				cckex_envelope_injection_handle);

		initialized = true;
	}
}

static int cckex_signal_dissect_websocket_layer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {

	proto_item *ti_websocket;
	proto_tree *websocket_tree;

	dissector_handle_t protobuf_handle = find_dissector("protobuf");

	// create a new proto tree item for the Signal ProtoBuf Dissector / dissection of the WebSocketMessage
	ti_websocket = proto_tree_add_item(tree, proto_cckex_websocket, tvb, 0, -1, ENC_NA);
	websocket_tree = proto_item_add_subtree(ti_websocket, cckex_ett_websocket);
	proto_item_set_text(websocket_tree, "ccKex Signal Websocket Layer");

	return call_dissector_with_data(protobuf_handle, tvb, pinfo, websocket_tree, 
			"message,signalservice.WebSocketMessage");
}

static int cckex_signal_dissect_request_body_layer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {	
	(void)tree;

	dissector_handle_t json_handle;

	proto_item *ti_request_body;
	proto_tree *request_body_tree;

	// if enabled, add the json body as a new data source
	if(pref_ws_json_data_source) {
		add_new_data_source(pinfo, tvb, "Signal Request Body");
	}

	ti_request_body = proto_tree_add_item(proto_tree_get_root(tree), proto_cckex_websocket, tvb, 0, -1, ENC_NA);
	request_body_tree = proto_item_add_subtree(ti_request_body, cckex_ett_request_body);
	proto_item_set_text(request_body_tree, "ccKex Signal Request Body");
	
	// dissect the json request body with the json dissector in order to fill the proto tree

	json_handle = dissector_get_string_handle(cckex_subdissector_table, "application/json");
	if(json_handle) {
		call_dissector(json_handle, tvb, pinfo, request_body_tree);
	}

	// manually parse the json body in order to iterate over all content fields in the message array

	const size_t raw_json_buf_len = tvb_reported_length(tvb);
	uint8_t *raw_json_buf = tvb_get_string_enc(pinfo->pool, tvb, 0, raw_json_buf_len, ENC_ASCII);
	if(!json_validate(raw_json_buf, raw_json_buf_len)) {
		// TODO: error handling
		CLOG_PKG_WARN("Failed to validate json body of WebSocketRequestMessage.");
		return 0;
	}

	int root_token_count = json_parse(raw_json_buf, NULL, 0);
	if(root_token_count <= 0) {
		// TODO: error handling
		CLOG_PKG_WARN("Failed to determine root_token_count for body of WebSocketRequestMessage.");
		return 0;
	}

	// if the allocation fails, let the dissector sigsegv
	// TODO: handle failing allocations correctly
	jsmntok_t *root_tokens = wmem_alloc_array(pinfo->pool, jsmntok_t, root_token_count);
	if(json_parse(raw_json_buf, root_tokens, root_token_count) <= 0) {
		// TODO: error handling
		CLOG_PKG_WARN("Failed to parse body of WebSocketRequestMessage.");
		return 0;
	}

	jsmntok_t *message_array_token = json_get_array(raw_json_buf, root_tokens, "messages");
	if(!message_array_token) {
		// TODO: error handling
		CLOG_PKG_WARN("Failed to fetch messages array from body of WebSocketRequestMessage.");
		return 0;
	}

	const size_t message_array_len = json_get_array_len(message_array_token);
	jsmntok_t *message_token = NULL;
	for(size_t i = 0; i < message_array_len; i++) {

		message_token = json_get_array_index(message_array_token, i);

		// TODO: fix this
		// check message type and ignore everything which is not 6 == UNIDENTIFIED_SENDER
		/*if(strncmp("6", json_get_string(raw_json_buf, message_token, "type"), 1) != 0) {
			// skip this one as it is no unidentified sender message
			continue;
		}*/

		tvbuff_t *envelope_tvb = base64_to_tvb(tvb, json_get_string(raw_json_buf, message_token, "content"));

		char envelope_tvb_name[128];
		snprintf(envelope_tvb_name, 128, "Envelope %li", i);

		add_new_data_source(pinfo, envelope_tvb, envelope_tvb_name);

		// call subdissector for this specific envelope
		call_dissector_with_data(cckex_envelope_handle, envelope_tvb, pinfo, request_body_tree, &i);
	}

	return tvb_reported_length(tvb);
}

static int cckex_signal_dissect_envelope_layer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {

	(void)tree;
	(void)pinfo;

	proto_item *ti_envelope;
	proto_tree *envelope_tree;

	int index = -1;

	dissector_handle_t protobuf_handle = find_dissector("protobuf");

	// The envelope dissector accepts the index of the base64 encoded envelope in the message array via the data pointer.
	// If data is NULL then the index is unknown.
	if(data) {
		// downcast should be ok since the one Signal Message Websocket should not contain > 0xffffffff envelopes
		index = (int)*(size_t*)data;
	}

	// create a new proto tree item for the Signal ProtoBuf Dissector / dissection of the WebSocketMessage
	ti_envelope = proto_tree_add_item(tree, proto_cckex_websocket, tvb, 0, -1, ENC_NA);
	envelope_tree = proto_item_add_subtree(ti_envelope, cckex_ett_envelope);
	proto_item_set_text(envelope_tree, "ccKex Signal Envelope %i", index);

	uint8_t version = tvb_get_uint8(tvb, 0);
	proto_tree_add_uint(envelope_tree, hf_envelope_sealed_sender_version, tvb, 0, 1, version);

	if((version >> 4) == 0 || (version >> 4) == 1) {
		return call_dissector_with_data(protobuf_handle, tvb_new_subset_remaining(tvb, 1), pinfo, envelope_tree,
				"message,cckexsignal.UnidentifiedSealedSenderMessageV1");
	} else if ((version >> 4) == 2) {
		return call_dissector_with_data(protobuf_handle, tvb_new_subset_remaining(tvb, 1), pinfo, envelope_tree,
				"message,cckexsignal.UnidentifiedSealedSenderMessageV2");
	} else {
		CLOG_PKG_ERROR("Unknown UnidentifiedSealedSenderMessage Version => Trying ccKex Injection ProtoBuf");
		return call_dissector_with_data(protobuf_handle, tvb, pinfo, envelope_tree,
				"message,cckexsignal.EnvelopeInjection");
	}
}

static int cckex_signal_dissect_envelope_injection(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {

	(void)tree;

	const size_t ccdata_len = tvb_reported_length(tvb);
	uint8_t *ccdata = tvb_memdup(pinfo->pool, tvb, 0, ccdata_len);

	insert_data_buf(CCKEX_LEVEL_TLS, pinfo->num, ccdata, ccdata_len, pinfo->rel_ts);

	cckex_stats_add_to_column("envelope_injection_payload_size", CCKEX_LEVEL_TLS, pinfo->num, ccdata_len);

	return tvb_reported_length(tvb);
}
