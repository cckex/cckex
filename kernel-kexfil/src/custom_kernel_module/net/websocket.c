#include "websocket.h"

#include "../common.h"
#include "../cc/cchandler.h"

#define WS_MASK_FLAG_BIT_MASK		0b10000000
#define WS_PAYLOAD_LEN_BIT_MASK		0b01111111


int cckex_websocket_is_masked(uint8_t *payload, size_t payload_len) {

	unsigned offset = 1;

	if(payload_len < 2) return -1;

	return GET_U8H(payload, offset) & WS_MASK_FLAG_BIT_MASK;
}

/*static int get_start_of_websocket_payload(uint8_t *payload, size_t payload_len, uint8_t **ws_payload, uint64_t *ws_payload_len) {

	unsigned offset = 1;

	if(payload_len < 2) return -1;

	uint8_t mask    = GET_U8H(payload, offset) & WS_MASK_BIT_MASK;
	*ws_payload_len = GET_U8H(payload, offset) & WS_PAYLOAD_LEN_BIT_MASK;

	offset += 1;

	if(*ws_payload_len == 126) {
		
	} else if(*ws_payload_len == 127) {
		return -1; // not supported currently
	} else {

	}


}*/

/*	-- apply_mask --
 *
 *	Applys the websocket 32 bit mask over the websocket payload by xoring the integer with the payload.
 *	This functions returns the offset of the websocket payload.
 */
static int apply_mask(uint8_t *payload, size_t payload_len) {

	unsigned offset = 1;
	uint32_t mask = 0;
	size_t oct_off = 0;
	uint64_t ws_payload_len = 0;
	size_t ws_payload_len_size = 1;
	size_t expected_payload_len = 0;

	if(payload_len < 2) return -1;

	ws_payload_len = GET_U8H(payload, offset);
	ws_payload_len &= WS_PAYLOAD_LEN_BIT_MASK;
	offset += 1;

	if(ws_payload_len == 126) {
		ws_payload_len = GET_U16H(payload, offset);
		ws_payload_len_size = 2;
		offset += 2;
	} else if(ws_payload_len == 127) {
		ws_payload_len  = GET_U32H(payload, offset);
		offset += 4;
		ws_payload_len |= (uint64_t)GET_U32H(payload, offset) << 32;
		offset += 4;
		ws_payload_len_size = 8;
	}

	mask = GET_U32H(payload, offset);

	//pr_info("CCKEX_LKM [%s] mask:%04x", __func__, mask);

	offset += 4;

	//pr_info("CCKEX_LKM [%s] start:%04x end:%04x", __func__, GET_U32H(payload, offset), GET_U32H(payload, payload_len - 4));

	if(ws_payload_len != payload_len - offset) {

		// check if the http header injection is active
		if(cckex_http_header_injection_active()) {
			// if this is the case assume that the change in length is caused by this injection
			// TODO: CURRENTLY, THIS IS VERY UNSAFE BECAUSE THE CASE COULD OCCUR THAT WE ARE EXPANDING THE PACKAGE 
			//		 RIGHT AT THE LENGTH BORDER WHEN THE SIZE FIELD INCREASES IN THE WEBSOCKET HEADER. IN THIS CASE,
			//		 WE NEED TO EXPAND THE SKB AGAIN.

			// for now just try to overwrite the size field
			
			expected_payload_len = payload_len - offset;

			pr_info("CCKEX_LKM [%s] invalid length due to possible http injection detected .. updating websocket lenght from %llu to %zu", __func__, ws_payload_len, expected_payload_len);

			// step back over masking key and at the beginning of the size field
			offset -= (4 /* masking key */ + ws_payload_len_size);

			if(ws_payload_len_size == 1) {
				
				SET_U8H(payload, offset, (expected_payload_len & WS_PAYLOAD_LEN_BIT_MASK) | (GET_U8H(payload, offset) & ~WS_PAYLOAD_LEN_BIT_MASK));

			} else if(ws_payload_len_size == 2) {
				
				SET_U16H(payload, offset, expected_payload_len);

			} else if(ws_payload_len_size == 8) {
				pr_warn("CCKEX_LKM [%s] CURRENTLY NOT IMPLEMENTED", __func__);
				return -1;
			}

			offset += (4 /* masking key */ + ws_payload_len_size);

			// actually increase ws payload length
			ws_payload_len = expected_payload_len;

		} else {
			pr_warn("CCKEX_LKM [%s] invalid lengths: ws_payload_len=%llu payload_len=%zu offset=%u", __func__, ws_payload_len, payload_len, offset);
			return -1;
		}
	}

	oct_off = 0;
	for(size_t i = 0; i < ws_payload_len; i++) {
		oct_off = 3 - (i % 4);

		//pr_info("CCKEX_LKM [%s] test: %.02x ^ %.02x", __func__, *(payload + offset + i), (uint8_t)((mask >> (oct_off * 8)) & 0xff));

		*(payload + offset + i) ^= (uint8_t)((mask >> (oct_off * 8)) & 0xff);
	}

	return offset;
}

int cckex_websocket_unmask_payload(uint8_t *payload, size_t payload_len) {
	if(!cckex_websocket_is_masked(payload, payload_len)) {
		pr_warn("CCKEX_LKM [%s] websocket not masked", __func__);
		return 0;
	}

	return apply_mask(payload, payload_len);
}

int cckex_websocket_mask_payload(uint8_t *payload, size_t payload_len) {
	if(!cckex_websocket_is_masked(payload, payload_len)) return 0;

	return apply_mask(payload, payload_len);
}
