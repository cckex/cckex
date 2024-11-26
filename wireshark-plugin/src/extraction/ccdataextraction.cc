#include "extraction/ccdataextraction.h"

#include <array>
#include <cstdint>

#include <wsutil/wmem/wmem.h>
#include <epan/reassemble.h>
#include <epan/column-utils.h>
#include <epan/proto.h>
#include <epan/tvbuff.h>

#include "extraction/ccdatamanager.h"

static void cckex_extract_full_ttl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void cckex_extract_iptos(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void cckex_extract_ipflags(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void cckex_extract_ipid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void cckex_extract_ipfragment(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

typedef void (*cckex_cc_method_t)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

std::array<cckex_cc_method_t, 5> ccmethods = {
    &cckex_extract_full_ttl,
    &cckex_extract_iptos,
    &cckex_extract_ipflags,
    &cckex_extract_ipid,
    &cckex_extract_ipfragment
};

static int _proto_ccKex_exfil;
static int _ett_ccKex_exfil;

extern int hf_exfil_iphdr_full_ttl;
extern int hf_exfil_iphdr_iptos;
extern int hf_exfil_iphdr_ipflags;
extern int hf_exfil_iphdr_ipid;
extern int hf_exfil_iphdr_ipfragment;

static const size_t _iphdr_offset = 0x10;

CCKEX_API void init_ccKex_extraction_dissector(int proto_ccKex_exfil, int ett_ccKex_exfil) {
	_proto_ccKex_exfil = proto_ccKex_exfil;
	_ett_ccKex_exfil = ett_ccKex_exfil;
}

//static int check_new_key_count = 0;

CCKEX_API int dissect_ccKex_key(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_)
{
    (void)tvb;
    (void)pinfo;
    (void)tree;
    (void)data;

	json conf = get_config();

	// only parse tcp and upd packages
	if(tvb_get_uint8(tvb, _iphdr_offset + 9) != 0x06 && tvb_get_uint8(tvb, _iphdr_offset + 9) != 0x17) {
		return 0;
	}
	
	// dont extract cc data from fragmented packages to avoid double extraction
	if(pinfo->fragmented) return 0;

//	LOG_INFO << pinfo->num << " " << tvb_captured_length(tvb) << std::endl;

	// ignore reassembled packages
	if(tvb_captured_length(tvb) >= conf["filter"]["length"]) return 0;

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
	ti_ccKex_exfil = proto_tree_add_item(tree, _proto_ccKex_exfil, tvb, 0, -1, ENC_NA);
	ccKex_exfil_tree = proto_item_add_subtree(ti_ccKex_exfil, _ett_ccKex_exfil);
	proto_item_set_text(ccKex_exfil_tree, "CCKex Exfiltration Dissector");

	// check ip and ports
    if(conf["filter"]["src_ip"].is_string() && conf["filter"]["src_ip"] != "" &&
		get_ip_from_string(conf["filter"]["src_ip"]) != tvb_get_ipv4(tvb, _iphdr_offset + 12)) {
		//std::cout << "[" << __func__ << "] <" << pinfo->num << "> filtered by src_ip" << std::endl;
		return 0;
    }
    if(conf["filter"]["dst_ip"].is_string() && conf["filter"]["dst_ip"] != "" &&
		get_ip_from_string(conf["filter"]["dst_ip"]) != tvb_get_ipv4(tvb, _iphdr_offset + 16)) {
		std::cout << "[" << __func__ << "] <" << pinfo->num << "> filtered by dst_ip" << std::endl;
		return 0;
    }
    if(tvb_get_uint8(tvb, _iphdr_offset + 9) == 0x06 &&
		conf["filter"]["src_port"].is_number() && conf["filter"]["src_port"] != 0 &&
		conf["filter"]["src_port"] != tvb_get_ntohs(tvb, _iphdr_offset + 0x14)) {
		std::cout << "[" << __func__ << "] <" << pinfo->num << "> filtered by src_port" << std::endl;
		return 0;
    }
    if(tvb_get_uint8(tvb, _iphdr_offset + 9) == 0x06 &&
		conf["filter"]["dst_port"].is_number() && conf["filter"]["dst_port"] != 0 &&
		conf["filter"]["dst_port"] != tvb_get_ntohs(tvb, _iphdr_offset + 0x16)) {
		std::cout << "[" << __func__ << "] <" << pinfo->num << "> filtered by dst_port" << std::endl;
		return 0;
    }

    //printf("ccKex-Key <pkg:%i> [info]: ttl= ip=%.08x\n", pinfo->num, tvb_get_ipv4(tvb, 12));

    //std::cout << "[" << __func__ << "] pkg exfiltration: " << std::endl;
    for(auto elem : conf["cc"]["methods"]) {

		// check if entry is malformed
		if(!elem["index"].is_number() || !elem["active"].is_boolean()) {
			LOG_WARN << "possibly malformed cc method conf entry: \"" << elem << "\"" << std::endl;
		    continue;
		}

		// skip method if it is not active
		if(!elem["active"]) continue;

		//std::cout << "[" << __func__ << "] <" << pinfo->num << "> running method " << elem["id"] << std::endl;

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
