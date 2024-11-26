#include "protobuf.h"

#include <linux/string.h>

#include "../../common.h"

static int parse_varint(uint8_t* data, ssize_t max_size, uint64_t* out);
static int write_varint(uint8_t* data, ssize_t max_size, uint64_t value);
static int parse_protobuf_element(cckex_protobuf_handle_t* handle);

/*	-- cckex_init_protobuf --
 *
 *	Init a protobuf handle struct with the given buffer. Handle must already be allocated when calling the init function.
 */
int cckex_protobuf_init(cckex_protobuf_handle_t* handle, uint8_t* buf, size_t size) {

	memset(handle, 0, sizeof(cckex_protobuf_handle_t));

	handle->buffer = buf;
	handle->buffer_size = size;
	handle->buffer_offset = 0;

	// parse first element
	if(parse_protobuf_element(handle) < 0) {
		return -1;
	}

	return 0;
}

/*	-- cckex_protobuf_handle_t --
 *
 *	Advance protobuf handle to next protobuf element
 *	Return -1 in case of error, 0 in case of EOB/End of Buffer, and 1 in case of success
 */
int cckex_protobuf_next(cckex_protobuf_handle_t* handle) {

	handle->buffer_offset = handle->elem_offset + handle->elem_length;

	if(handle->buffer_offset > handle->buffer_size) {
		pr_warn("CCKEX_LKM [%s] offset > size -> buffer malformed", __func__);
		return -1;
	} else if(handle->buffer_offset == handle->buffer_size) {
		return 0;
	}

	if(parse_protobuf_element(handle) < 0) {
		pr_warn("CCKEX_LKM [%s] failed to parse element", __func__);
		return -1;
	}

	return 1;
}

int cckex_read_varint(uint8_t* data, ssize_t max_size, uint64_t* out) {
	return parse_varint(data, max_size, out);
}

int cckex_write_varint(uint8_t* data, ssize_t max_size, uint64_t value) {
	return write_varint(data, max_size, value);
}

/*	-- parse_protobuf_element --
 *
 *	Parse a protobuf wire type at the current position of the handle
 *	Return -1 in case of error, 0 otherwise.
 */
static int parse_protobuf_element(cckex_protobuf_handle_t* handle) {

	uint64_t tag = 0;
	int tag_size = 0;

	uint64_t length = 0;
	int	length_size = 0;

	uint64_t value = 0;
	int value_size = 0;

	if(handle->buffer_size <= handle->buffer_offset) {
		// stop overflows
		pr_warn("CCKEX_LKM [%s] stopping overflow", __func__);
		return -1;
	}

	// parse tag at current location
	if((tag_size = parse_varint(
			handle->buffer + handle->buffer_offset,		// advance buffer pointer to current offset
			handle->buffer_size - handle->buffer_offset,		// set max_size to the remaining space in the buffer
			&tag)) < 0) {
		pr_warn("CCKEX_LKM [%s] failed to parse tag.", __func__);
		return -1;
	}

	// extract id and type from tag
	handle->tag = tag;
	handle->tag_size = tag_size;
	handle->elem_id		= tag >> 3;
	handle->elem_type	= tag & 0x7;
	handle->elem_offset = handle->buffer_offset + tag_size;

	// parse length for LEN elements
	if(handle->elem_type == CCKEX_PB_LEN) {
		
		// parse length
		if((length_size = parse_varint(
				handle->buffer + handle->elem_offset,
				handle->buffer_size - handle->elem_offset,
				&length)) < 0) {
			pr_warn("CCKEX_LKM [%s] failed to parse length field", __func__);
			return -1;
		}

		handle->elem_length = length;
		handle->elem_offset += length_size;

	 } else if (handle->elem_type == CCKEX_PB_VARINT) {

		// parse varint
		if((value_size = parse_varint(
				handle->buffer + handle->elem_offset,
				handle->buffer_size - handle->buffer_offset,
				&value)) < 0) {
			pr_warn("CCKEX_LKM [%s] failed to parse value", __func__);
			return -1;
		}

		handle->elem_length = value_size;
		handle->elem_value = value;

	 } else {
		pr_warn("CCKEX_LKM [%s] ProtoBuf Field Type currently not supported: %u", __func__, handle->elem_type);
		return -1;
	 }

	return 0;
}

/*	-- parse_varint --
 *
 *	Parse n (up to max_size) bytes as varint.
 *	Returns -1 in case of error, or n.
 */
static int parse_varint(uint8_t* data, ssize_t max_size, uint64_t* out) {

	uint64_t output = 0;
	int ret_size = -1;

	if(max_size > 10) max_size = 10;

	for(size_t i = 0; i < max_size; i++) {

		// In the case that i == 9 this will just overflow and be equal to |= 0 .
		// So no need to catch the i == 9 edge case.
		output |= (uint64_t)(data[i] & 0x7f) << (7 * i);

		// check if msb is not set to signal the last byte
		if(!(data[i] & 0x80)) {
			ret_size = i + 1;
			break;
		}
	}

	if(ret_size == -1) {
		// Ret_size was not set -> that means max_size == 0 or no msb was set untill max_size was reached.
		// In any case the varint is malformed -> return error
		return -1;
	}

	// write results
	*out = output;
	return ret_size;
}

/*	-- write_varint --
 */
static int write_varint(uint8_t* data, ssize_t max_size, uint64_t value) {

	int ret_size = -1;

	if (max_size > 10) max_size = 10;

	for(size_t i = 0; i < max_size; i++) {
		
		// write data to byte (this automatically clears the msb)
		data[i] = (value & 0x7f);

		// remove written data
		value >>= 7;

		// set the msb if this was not the last data else terminate loop
		if(value) {
			data[i] |= 0x80;
		} else {
			ret_size = i + 1;
			break;
		}
	}

	if(ret_size == -1) {
		// same logic as in parse_varint
		return -1;
	}

	return ret_size;
}
