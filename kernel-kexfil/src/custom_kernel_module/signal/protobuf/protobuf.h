
#pragma once

#include <linux/types.h>

/*	Proto Buffer Wire Types
 *	
 *	see https://protobuf.dev/programming-guides/encoding/#structure
 */
enum cckex_protobuf_type {
	CCKEX_PB_VARINT	= 0,
	CCKEX_PB_I64	= 1,
	CCKEX_PB_LEN	= 2,
	CCKEX_PB_SGROUP = 3,
	CCKEX_PB_EGROUP = 4,
	CCKEX_PB_I32	= 5
};

typedef enum cckex_protobuf_type cckex_protobuf_type_t;

/*	CCKex Proto Buffer Handle Struct
 *
 *  This struct includes important information (e.g. pointer to buffer, size, etc.) for the cckex protobuf parser. It
 *  servers as a reference point for the parser while continously parsing a protobuf.
 */
struct cckex_protobuf_handle {

	/*	Byte buffer which includes the protobuf buffer. The buffer must start at the address the pointer is pointing to. 
	 */
	uint8_t* buffer;
	size_t buffer_size;
	size_t buffer_offset;

	/*	Type of element at offset buffer_offset
	 */
	cckex_protobuf_type_t elem_type;

	/* Tag and size of tag of element
	 */
	uint64_t tag;
	size_t tag_size;

	/*  Id of element at offset buffer_offset
	 */
	unsigned elem_id;

	/*	Length of element at offset buffer_offset
	 *	Currently only valid for fields of type LEN and VARINT
	 */
	size_t elem_length; 

	/*  Offset of the current element in the buffer
	 */
	size_t elem_offset;

	/*	Value of current element in the buffer 
	 *	Currently only valid for fields of type VARINT
	 */
	uint64_t elem_value;

};

typedef struct cckex_protobuf_handle cckex_protobuf_handle_t;


int cckex_protobuf_init(cckex_protobuf_handle_t* handle, uint8_t* buf, size_t size);

int cckex_protobuf_next(cckex_protobuf_handle_t* handle);

int cckex_read_varint(uint8_t* data, ssize_t max_size, uint64_t* out);
int cckex_write_varint(uint8_t* data, ssize_t max_size, uint64_t value);
