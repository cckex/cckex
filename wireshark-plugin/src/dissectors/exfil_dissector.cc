#include "exfil_dissector.h"

#include <wireshark.h>
#include <string.h>

#include <wsutil/wmem/wmem.h>
#include <epan/proto.h>
#include <epan/tvbuff.h>
#include <epan/packet.h>

#include "extraction/ccdatamanager.h"
#include "stats/cckex_stats.h"

static int proto_cckex_exfil = -1;

static dissector_handle_t cckex_exfil_handle;

static int cckex_ett_exfil = -1;

static int hf_exfil_iphdr_full_ttl = -1;
static int hf_exfil_iphdr_iptos = -1;
static int hf_exfil_iphdr_ipflags = -1;
static int hf_exfil_iphdr_ipid = -1;
static int hf_exfil_iphdr_ipfragment = -1;
static int hf_exfil_tcphdr_urgentptr = -1;
static int hf_exfil_position = -1;

static void cckex_extract_full_ttl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void cckex_extract_iptos(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void cckex_extract_ipflags(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void cckex_extract_ipid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void cckex_extract_ipfragment(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void cckex_extract_tcpurgent(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

typedef void (*cckex_cc_method_t)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

std::array<cckex_cc_method_t, 6> ccmethods = {
    &cckex_extract_full_ttl,
    &cckex_extract_iptos,
    &cckex_extract_ipflags,
    &cckex_extract_ipid,
    &cckex_extract_ipfragment,
	&cckex_extract_tcpurgent
};

static const size_t _iphdr_offset = 14;

static int cckex_signal_dissect_exfil_encryption(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_);

CCKEX_API void cckex_register_exfil_dissector(module_t *module) {

	(void)module;

	static hf_register_info hf[] = {
		{ &hf_exfil_iphdr_full_ttl,
		  { "ip tos", "CCKEX_EXFIL_IPHDR_FULL_TTL",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			"NULL", HFILL }
		},
		{ &hf_exfil_iphdr_iptos,
		  { "ip tos", "CCKEX_EXFIL_IPHDR_IPTOS",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			"NULL", HFILL }
		},
		{ &hf_exfil_iphdr_ipflags,
		  { "ip flags", "CCKEX_EXFIL_IPHDR_IPFLAGS",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			"NULL", HFILL }
		},
		{ &hf_exfil_iphdr_ipid,
		  { "ip id", "CCKEX_EXFIL_IPHDR_IPID",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			"NULL", HFILL }
		},
		{ &hf_exfil_iphdr_ipfragment,
		  { "ip fragment offset", "CCKEX_EXFIL_IPHDR_IPFRAG",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			"NULL", HFILL }
		},
		{ &hf_exfil_tcphdr_urgentptr,
		  { "tcp urgent pointer", "CCKEX_EXFIL_TCPHDR_URGENT_PTR",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			"NULL", HFILL }
		},
		{ &hf_exfil_position,
		  { "position index", "CCKEX_EXFIL_POSITION",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"NULL", HFILL }
		}
	};

	static int *ett[] = {
		&cckex_ett_exfil
	};

	proto_cckex_exfil = proto_register_protocol("ccKex Exfil", "cckex.exfil", "cckex.exfil");

	cckex_exfil_handle = register_dissector("ccKex.exfil", cckex_signal_dissect_exfil_encryption,
								proto_cckex_exfil);

	proto_register_field_array(proto_cckex_exfil, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

CCKEX_API void cckex_handoff_exfil_dissector(void) {

	static bool initialized = false;

	if(!initialized) {

		register_postdissector(cckex_exfil_handle);

		initialized = true;
	}

}

static int cckex_signal_dissect_exfil_encryption(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
	json conf = get_config();

	// only parse tcp and upd packages
	if(tvb_get_uint8(tvb, _iphdr_offset + 9) != 0x06 && tvb_get_uint8(tvb, _iphdr_offset + 9) != 0x17) {
		LOG_PKG_WARN << "Not a TCP or UDP Package" << std::endl;
		return 0;
	}
	
	// dont extract cc data from fragmented packages to avoid double extraction
	if(pinfo->fragmented) {
		LOG_PKG_WARN << "Package fragmented." << std::endl;
		return 0;
	}

//	LOG_INFO << pinfo->num << " " << tvb_captured_length(tvb) << std::endl;

	// ignore reassembled packages
	//if(tvb_captured_length(tvb) >= conf["filter"]["length"]) return 0;

	/*gchar *text = wmem_strdup(pinfo->pool, col_get_text(pinfo->cinfo, COL_INFO));
	std::string col_info_str(text);

	LOG_INFO << "[" << pinfo->num << "] col_info=" << col_info_str << std::endl;

	if(col_info_str.find("TCP PDU reassembled in") != std::string::npos) {
		LOG_INFO << "[" << pinfo->num << "] FOUND PDU" << std::endl;
		return 0;

	}*/

    // TODO: check packet length etc.
	proto_item *ccKex_exfil_tree, *ti_ccKex_exfil;

	// setup cckex exfil subtree
	ti_ccKex_exfil = proto_tree_add_item(tree, proto_cckex_exfil, tvb, 0, -1, ENC_NA);
	ccKex_exfil_tree = proto_item_add_subtree(ti_ccKex_exfil, cckex_ett_exfil);
	proto_item_set_text(ccKex_exfil_tree, "ccKex Exfiltration Dissector");

	// check ip and ports
    if(conf["filter"]["src_ip"].is_string() && conf["filter"]["src_ip"] != "" &&
		get_ip_from_string(conf["filter"]["src_ip"]) != tvb_get_ipv4(tvb, _iphdr_offset + 12)) {
		//std::cout << "[" << __func__ << "] <" << pinfo->num << "> filtered by src_ip" << std::endl;
		return 0;
    }
    if(conf["filter"]["dst_ip"].is_string() && conf["filter"]["dst_ip"] != "" &&
		get_ip_from_string(conf["filter"]["dst_ip"]) != tvb_get_ipv4(tvb, _iphdr_offset + 16)) {
		//std::cout << "[" << __func__ << "] <" << pinfo->num << "> filtered by dst_ip" << std::endl;
		return 0;
    }
    if(tvb_get_uint8(tvb, _iphdr_offset + 9) == 0x06 &&
		conf["filter"]["src_port"].is_number() && conf["filter"]["src_port"] != 0 &&
		conf["filter"]["src_port"] != tvb_get_ntohs(tvb, _iphdr_offset + 0x14)) {
		//std::cout << "[" << __func__ << "] <" << pinfo->num << "> filtered by src_port" << std::endl;
		return 0;
    }
    if(tvb_get_uint8(tvb, _iphdr_offset + 9) == 0x06 &&
		conf["filter"]["dst_port"].is_number() && conf["filter"]["dst_port"] != 0 &&
		conf["filter"]["dst_port"] != tvb_get_ntohs(tvb, _iphdr_offset + 0x16)) {
		//std::cout << "[" << __func__ << "] <" << pinfo->num << "> filtered by dst_port" << std::endl;
		return 0;
    }

    //printf("ccKex-Key <pkg:%i> [info]: ttl= ip=%.08x\n", pinfo->num, tvb_get_ipv4(tvb, 12));

    //std::cout << "[" << __func__ << "] pkg exfiltration: " << std::endl;
    for(auto elem : conf["cc"]["methods"]) {

		// check if entry is malformed
		if(!elem["index"].is_number() || !elem["active"].is_boolean()) {
			//LOG_WARN << "possibly malformed cc method conf entry: \"" << elem << "\"" << std::endl;
		    continue;
		}

		// skip method if it is not active
		if(!elem["active"]) continue;

		std::cout << "[" << __func__ << "] <" << pinfo->num << "> running method " << elem["name"] << std::endl;

		ccmethods[elem["index"]](tvb, pinfo, ccKex_exfil_tree);
    }

//    if(check_new_key_count++ % 100 == 0) {
//	check_for_new_keys();
//    }

    return 0;

}

static void cckex_extract_full_ttl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
	(void) tree;
	size_t offset = _iphdr_offset + 8; 
    uint8_t ttl = tvb_get_uint8(tvb, offset);
    //printf("[%s] <%i> data=%.02x\n", __func__, pinfo->num, ttl);
	proto_tree_add_uint(tree, hf_exfil_iphdr_full_ttl, tvb, offset, 1, ttl);
	if(!entry_exists(CCKEX_LEVEL_CLEAR, pinfo->num)) insert_data(CCKEX_LEVEL_CLEAR, pinfo->num, ttl, offset, pinfo->rel_ts);
}

static void cckex_extract_iptos(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
	(void) tree;
	size_t offset = _iphdr_offset + 1;
    uint8_t data = tvb_get_uint8(tvb, offset);
    //printf("[%s] <%i> data=%.02x\n", __func__, pinfo->num, data);
	proto_tree_add_uint(tree, hf_exfil_iphdr_iptos, tvb, offset, 1, data);
    if(!entry_exists(CCKEX_LEVEL_CLEAR, pinfo->num)) insert_data(CCKEX_LEVEL_CLEAR, pinfo->num, data, 8, pinfo->rel_ts);
}

static void cckex_extract_ipflags(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
	(void) tree;
	size_t offset = _iphdr_offset + 6;
    uint8_t data = tvb_get_uint8(tvb, offset) >> 7;
    //printf("[%s] <%i> data=%.02x\n", __func__, pinfo->num, data);
	proto_tree_add_uint(tree, hf_exfil_iphdr_ipflags, tvb, offset, 1, data);
    if(!entry_exists(CCKEX_LEVEL_CLEAR, pinfo->num)) insert_data(CCKEX_LEVEL_CLEAR, pinfo->num, data, 1, pinfo->rel_ts);
}

static void cckex_extract_ipid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
	(void) tree;
	size_t offset = _iphdr_offset + 4;

	uint16_t full_data = 0;
	uint8_t data = tvb_get_uint8(tvb, offset + 1);
    //printf("[%s] <%i> data=%.02x", __func__, pinfo->num, data);
    if(!entry_exists(CCKEX_LEVEL_CLEAR, pinfo->num)) insert_data(CCKEX_LEVEL_CLEAR, pinfo->num, data, 8, pinfo->rel_ts);
	full_data = ((uint16_t)data) << 8;

    data = tvb_get_uint8(tvb, offset);
    //printf("%.02x\n", data);
    if(!entry_exists(CCKEX_LEVEL_CLEAR, pinfo->num)) insert_data(CCKEX_LEVEL_CLEAR, pinfo->num, data, 8, pinfo->rel_ts);
	full_data |= (uint16_t)data;

	proto_tree_add_uint(tree, hf_exfil_iphdr_ipid, tvb, offset, 2, full_data);
}

static void cckex_extract_ipfragment(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
	(void) tree;
	size_t offset = _iphdr_offset + 6;

	uint16_t full_data = 0;
	uint8_t data = tvb_get_uint8(tvb, offset) & 0x1f;
    if(!entry_exists(CCKEX_LEVEL_CLEAR, pinfo->num)) insert_data(CCKEX_LEVEL_CLEAR, pinfo->num, data, 5, pinfo->rel_ts);
	full_data = (uint16_t)data << 8;

	data = tvb_get_uint8(tvb, offset + 1);
    if(!entry_exists(CCKEX_LEVEL_CLEAR, pinfo->num)) insert_data(CCKEX_LEVEL_CLEAR, pinfo->num, data, 8, pinfo->rel_ts);
	full_data |= (uint16_t)data;

	proto_tree_add_uint(tree, hf_exfil_iphdr_ipfragment, tvb, offset, 2, full_data);
}

static void cckex_extract_tcpurgent(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {

	// calculate the tcp header offset
	size_t iphdr_length = (tvb_get_uint8(tvb, _iphdr_offset) & 0x0f) * 4;
	size_t tcphdr_offset = _iphdr_offset + iphdr_length;

	// check that the urgent flag is cleared
	uint8_t flags = tvb_get_uint8(tvb, tcphdr_offset + 13);
	if(flags & 0x20) return;

	// extract the index from the tos field
	int32_t index = (int32_t)tvb_get_uint8(tvb, _iphdr_offset  + 1);
	proto_tree_add_uint(tree, hf_exfil_position, tvb, _iphdr_offset + 1, 1, index);

	// extract the data from the tcp urgent pointer field
	uint16_t full_data = g_htons(tvb_get_ntohs(tvb, tcphdr_offset + 18));
	if(!entry_exists(CCKEX_LEVEL_CLEAR, pinfo->num)) insert_data_buf_with_position(CCKEX_LEVEL_CLEAR, pinfo->num, (uint8_t*)&full_data, 2, pinfo->rel_ts, index);

	cckex_stats_add_to_column("tcpurgptrcc_payload_size", CCKEX_LEVEL_CLEAR, pinfo->num, 3);
	cckex_stats_add_to_column("package_length", CCKEX_LEVEL_CLEAR, pinfo->num, pinfo->fd->pkt_len);

	proto_tree_add_uint(tree, hf_exfil_tcphdr_urgentptr, tvb, tcphdr_offset + 18, 2, full_data);
}
