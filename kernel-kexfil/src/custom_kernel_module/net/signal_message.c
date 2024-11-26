#include "signal_message.h"

#include <crypto/skcipher.h>
#include <linux/string.h>
#include <linux/slab.h>

#include "../crypto/hmac/hmac_sha2.h"
#include "base64.h"

//#include <linux/base64.h>

static const char* signal_msg_websocket_searchstr = "{\"content\":\"";

#define SIGNAL_SEALED_SENDER_OFFSET 84
#define SIGNAL_SEALED_SENDER_HMAC_SIZE 10
#define SIGNAL_MESSAGE_OFFSET   0x145
#define SIGNAL_MESSAGE_OFFSET_2 0x194
#define SIGNAL_MESSAGE_OFFSET_3 0x137

static const size_t signal_message_offsets[] = { 0x183, 0x145, 0x194, 0x137 };
static const size_t signal_message_offsets_size = 4;

int cckex_signal_message_unpack_base64(signal_data_t *sdat) {

	if(sdat->request_data_offset >= sdat->request_data_len) {
		pr_warn("CCKEX_LKM [%s] request data offset (%zu) >= request data length (%zu)", __func__, sdat->request_data_offset, sdat->request_data_len);
		return -1;
	}

	// find start of base64 data
	sdat->base64_ptr = cckex_memmem(sdat->request_data + sdat->request_data_offset, sdat->request_data_len - sdat->request_data_offset, signal_msg_websocket_searchstr, strlen(signal_msg_websocket_searchstr));

	if(!sdat->base64_ptr) {
		//pr_info("CCKEX_LKM [%s] start of base64 string not found!", __func__);
		return 1;
	}

	sdat->base64_ptr += strlen(signal_msg_websocket_searchstr);
	sdat->request_data_offset = (size_t)((uint64_t)sdat->base64_ptr - (uint64_t)sdat->request_data);

	// find end of base64 data
	for(char *iter = sdat->base64_ptr; (uint8_t*)iter < sdat->request_data + sdat->request_data_len; iter++) {
		if(*iter == '\"') {
			sdat->base64_endptr = iter;
			break;
		}
	}

	if (!sdat->base64_endptr) {
		//pr_info("CCKEX_LKM [%s] end of base64 str not found - message possibly malformed!", __func__);
		return -1;
	}

	/*pr_info("CCKEX_LKM [%s] base64: ", __func__);
	//cckex_print_mem(sdat->base64_ptr, (size_t)(sdat->base64_endptr - sdat->base64_ptr));*/

	// calculate raw base64 buffer len and alloc buffer
	sdat->raw_data_with_padding_len = ((size_t)(sdat->base64_endptr - sdat->base64_ptr) / 4) * 3;
	sdat->raw_data = kmalloc(sdat->raw_data_with_padding_len, GFP_ATOMIC);
	if(!sdat->raw_data) {
		//pr_info("CCKEX_LKM [%s] failed to allocate raw_data buffer in signal_data struct", __func__);
		return -1;
	}

	/*pr_info("CCKEX_LKM [%s] base64 before: ", __func__);
	for(char* iter = sdat->base64_ptr; iter < sdat->base64_endptr; iter++) {
		//printk(KERN_CONT "%c", *iter);
	}*/

	// base64 decode
	/*for(size_t i = 0; i < (size_t)(sdat->base64_endptr - sdat->base64_ptr) / 4; i++) {
		memcpy(sdat->raw_data + i * 3, unbase64(sdat->base64_ptr + i * 4), 3);
	}*/

	if(base64_decode(sdat->base64_ptr, (sdat->base64_endptr - sdat->base64_ptr), sdat->raw_data) == -1) {
		//pr_info("CCKEX_LKM [%s] base64_decode failed", __func__);
		return -1;
	}

	sdat->raw_data_len = sdat->raw_data_with_padding_len;
	if(*(sdat->base64_endptr - 1) == '=') sdat->raw_data_len -= 1;
	if(*(sdat->base64_endptr - 2) == '=') sdat->raw_data_len -= 1;

	//pr_info("CCKEX_LKM [%s] %i %i", __func__, sdat->raw_data_len, sdat->raw_data_with_padding_len);

	return 0;
}

int cckex_signal_message_repack_base64(signal_data_t *sdat) {

	/*for(size_t i = 0; i < (size_t)(sdat->base64_endptr - sdat->base64_ptr) / 4; i++) {
		memcpy(sdat->base64_ptr + i * 4, base64(sdat->raw_data + i * 3), 4);
	}*/

	if(base64_encode(sdat->raw_data, sdat->raw_data_len, sdat->base64_ptr) == -1) {
		//pr_info("CCKEX_LKM [%s] base64_encode failed", __func__);
		return -1;
	}

	kfree(sdat->raw_data);

	return 0;
}

#define CRYPTO_MODE_ENC 1
#define CRYPTO_MODE_DEC 2

static int signal_message_crypt_sealed_sender(signal_data_t *sdat, unsigned mode) {
	int ret = 0;

	uint8_t *counter = NULL;
	size_t counter_size = 0;
	struct crypto_skcipher  *skc = NULL;
	struct skcipher_request *req = NULL;
	struct scatterlist sg_data;
	DECLARE_CRYPTO_WAIT(cwait);

	if(!sdat->sealed_sender_key) {
		pr_warn("CCKEX_LKM [%s] sealed_sender_key not set! Aborting..", __func__);
		ret = -1;
		goto out;
	}

	skc = crypto_alloc_skcipher("ctr(aes)", 0, 0);
	if(IS_ERR(skc)) {
		pr_warn("CCKEX_LKM [%s] crypto_alloc_aead failed with: %zu", __func__, PTR_ERR(skc));
		ret = -1;
		goto out;
	}

	if((ret = crypto_skcipher_setkey(skc, sdat->sealed_sender_key->key, sdat->sealed_sender_key->key_size)) != 0) {
		pr_warn("CCKEX_LKM [%s] crypto_skcipher_setkey failed with %i -> key (%zu): ", __func__, ret, sdat->sealed_sender_key->key_size);
		cckex_print_mem(sdat->sealed_sender_key->key, sdat->sealed_sender_key->key_size);
		ret = -1;
		goto out;
	}

	counter_size = crypto_skcipher_ivsize(skc);
	//pr_info("CCKEX_LKM [%s] ctr iv_size = %zu", __func__, counter_size);
	if(counter_size) {
		counter = kmalloc(counter_size, GFP_ATOMIC);
		if(!counter) {
			pr_warn("CCKEX_LKM [%s] failed to allocate counter", __func__);
			ret = -1;
			goto out;
		}
		memset(counter, 0, counter_size);
	}

	req = skcipher_request_alloc(skc, GFP_ATOMIC);
	if(!req) {
		pr_warn("CCKEX_LKM [%s] failed to allocate skcipher request", __func__);
		ret = -1;
		goto out;
	}

	sdat->sealed_sender_data = sdat->raw_data + SIGNAL_SEALED_SENDER_OFFSET;
//	sdat->sealed_sender_data_size = (sdat->raw_data_len - SIGNAL_SEALED_SENDER_OFFSET) - ((sdat->raw_data_len - SIGNAL_SEALED_SENDER_OFFSET - SIGNAL_SEALED_SENDER_HMAC_SIZE) % 16) - SIGNAL_SEALED_SENDER_HMAC_SIZE; 
	sdat->sealed_sender_data_size = sdat->raw_data_len - SIGNAL_SEALED_SENDER_OFFSET;
	//pr_info("CCKEX_LKM [%s] size = %i", __func__, sdat->sealed_sender_data_size);
	sdat->sealed_sender_data_size -= SIGNAL_SEALED_SENDER_HMAC_SIZE;
	//pr_info("CCKEX_LKM [%s] size = %i -> size mod 16 = %i", __func__, sdat->sealed_sender_data_size, sdat->sealed_sender_data_size % 16);

	//pr_info("CCKEX_LKM [%s] ctr data_size = %i", __func__, sdat->sealed_sender_data_size);

	sg_init_one(&sg_data, sdat->sealed_sender_data, sdat->sealed_sender_data_size);

	skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG, crypto_req_done, &cwait);
	skcipher_request_set_crypt(req, &sg_data, &sg_data, sdat->sealed_sender_data_size, counter);

	if(mode == CRYPTO_MODE_DEC) {
		if((ret = crypto_skcipher_decrypt(req)) == -EINPROGRESS || ret == -EBUSY) {
			if((ret = crypto_wait_req(ret, &cwait)) != 0) {
				pr_warn("CCKEX_LKM [%s] crypto_wait_req failed with %i", __func__, ret);
				ret = -1;
				goto out;
			}
		} else if(ret != 0) {
			pr_warn("CCKEX_LKM [%s] crypto_skcipher_decrypt failed with %i", __func__, ret);
			ret = -1;
			goto out;
		}
	} else {
		if((ret = crypto_skcipher_encrypt(req)) == -EINPROGRESS || ret == -EBUSY) {
			if((ret = crypto_wait_req(ret, &cwait)) != 0) {
				pr_warn("CCKEX_LKM [%s] crypto_wait_req failed with %i", __func__, ret);
				ret = -1;
				goto out;
			}
		} else if(ret != 0) {
			pr_warn("CCKEX_LKM [%s] crypto_skcipher_encrypt failed with %i", __func__, ret);
			ret = -1;
			goto out;
		}
	}

out:
	if(counter) kfree(counter);
	if(req) skcipher_request_free(req);
	if(skc) crypto_free_skcipher(skc);

	return ret;
}

int cckex_signal_message_decrypt_sealed_sender(signal_data_t * sdat) {

	sdat->sealed_sender_key = cckex_keylist_get_entry_by_id(sdat->raw_data + SIGNAL_SEALED_SENDER_OFFSET, CCKEX_ID_SIZE);
	if(!sdat->sealed_sender_key) {
		pr_info("CCKEX_LKM [%s] failed to find a suitable keylist entry for id: ", __func__);
		cckex_print_mem(sdat->raw_data + SIGNAL_SEALED_SENDER_OFFSET, CCKEX_ID_SIZE);
		return -1;
	}

	return signal_message_crypt_sealed_sender(sdat, CRYPTO_MODE_DEC);
}

int cckex_signal_message_encrypt_sealed_sender(signal_data_t * signal_data) {
	return signal_message_crypt_sealed_sender(signal_data, CRYPTO_MODE_ENC);
}

static int signal_message_crypt_message(signal_data_t *sdat, unsigned mode) {
	int ret = 0;

	uint8_t iv[CCKEX_IV_SIZE];
	struct crypto_skcipher  *skc = NULL;
	struct skcipher_request *req = NULL;
	struct scatterlist sg_data;
	DECLARE_CRYPTO_WAIT(cwait);

	if(!sdat->message_key) {
		//pr_info("CCKEX_LKM [%s] message_key not set! Aborting..", __func__);
		ret = -1;
		goto out;
	}

	//pr_info("CCKEX_LKM [%s] alloc skcipher", __func__);

	skc = crypto_alloc_skcipher("cbc(aes)", 0, 0);
	if(IS_ERR(skc)) {
		//pr_info("CCKEX_LKM [%s] crypto_alloc_aead failed with: %li", __func__, PTR_ERR(skc));
		ret = -1;
		goto out;
	}

	//pr_info("CCKEX_LKM [%s] setkey:", __func__);
	//cckex_print_mem(sdat->message_key->key, sdat->message_key->key_size);

	if((ret = crypto_skcipher_setkey(skc, sdat->message_key->key, sdat->message_key->key_size)) != 0) {
		pr_warn("CCKEX_LKM [%s] crypto_skcipher_setkey failed with %i -> key (%zu): ", __func__, ret, sdat->message_key->key_size);
		//cckex_print_mem(sdat->message_key->key, sdat->message_key->key_size);
		ret = -1;
		goto out;
	}

	//pr_info("CCKEX_LKM [%s] request alloc", __func__);

	req = skcipher_request_alloc(skc, GFP_ATOMIC);
	if(!req) {
		pr_warn("CCKEX_LKM [%s] failed to allocate skcipher request", __func__);		
		ret = -1;
		goto out;
	}

	sg_init_one(&sg_data, sdat->message_data, sdat->message_data_size);

	//pr_info("CCKEX_LKM [%s] set_callback", __func__);

	skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG, crypto_req_done, &cwait);

	//pr_info("CCKEX_LKM [%s] set_crypt iv:", __func__);
	//cckex_print_mem(sdat->message_key->iv, sdat->message_key->iv_size);

	memcpy(iv, sdat->message_key->iv, sdat->message_key->iv_size);
	skcipher_request_set_crypt(req, &sg_data, &sg_data, sdat->message_data_size, iv);

	//pr_info("CCKEX_LKM [%s] encrypt/decrpyt", __func__);

	//pr_info("CCKEX_LKM [%s] before op: ", __func__);
	//cckex_print_mem(sdat->message_data, sdat->message_data_size);

	if(mode == CRYPTO_MODE_DEC) {
		if((ret = crypto_skcipher_decrypt(req)) == -EINPROGRESS || ret == -EBUSY) {
			if((ret = crypto_wait_req(ret, &cwait)) != 0) {
				pr_warn("CCKEX_LKM [%s] crypto_wait_req failed with %i", __func__, ret);
				ret = -1;
				goto out;
			}
		} else if(ret != 0) {
			pr_warn("CCKEX_LKM [%s] crypto_skcipher_decrypt failed with %i", __func__, ret);
			ret = -1;
			goto out;
		}
	} else {
		if((ret = crypto_skcipher_encrypt(req)) == -EINPROGRESS || ret == -EBUSY) {
			if((ret = crypto_wait_req(ret, &cwait)) != 0) {
				pr_warn("CCKEX_LKM [%s] crypto_wait_req failed with %i", __func__, ret);
				ret = -1;
				goto out;
			}
		} else if(ret != 0) {
			pr_warn("CCKEX_LKM [%s] crypto_skcipher_encrypt failed with %i", __func__, ret);
			ret = -1;
			goto out;
		}
	}

	//pr_info("CCKEX_LKM [%s] after op: ", __func__);
	//cckex_print_mem(sdat->message_data, sdat->message_data_size);
	//pr_info("CCKEX_LKM [%s] iv: ", __func__);
	//cckex_print_mem(sdat->message_key->iv, sdat->message_key->iv_size);

out:
	if(req) skcipher_request_free(req);
	if(skc) crypto_free_skcipher(skc);

	return ret;
}

int cckex_signal_message_decrypt_message(signal_data_t * sdat) {

	// iterate through all known offsets of the encrypted signal message in the sealed sender layer
	for(size_t i = 0; i < signal_message_offsets_size; i++) {

		// try to find a matchin key for the current offset and abort loop if an entry is found
		sdat->message_key = cckex_keylist_get_entry_by_id(sdat->sealed_sender_data + signal_message_offsets[i], CCKEX_ID_SIZE);
		if(sdat->message_key) {
			sdat->message_data = sdat->sealed_sender_data + signal_message_offsets[i];
			break;
		}
	}

	// if no valid entry was found abort the function
	if(!sdat->message_key) {
		pr_warn("CCKEX_LKM [%s] failed to find a suitable keylist entry", __func__);
		return -1;
	}


	sdat->message_data_size = (size_t)(*(sdat->message_data - 1)) * 160;
	//sdat->message_data_size -= sdat->message_data_size % 16;

	return signal_message_crypt_message(sdat, CRYPTO_MODE_DEC);
}

int cckex_signal_message_encrypt_message(signal_data_t * signal_data) {
	return signal_message_crypt_message(signal_data, CRYPTO_MODE_ENC);
}

int cckex_signal_message_recalc_hmac(signal_data_t *sdat) {
	uint8_t test[10];

	sdat->sealed_sender_hmac = sdat->sealed_sender_data + sdat->sealed_sender_data_size;
	sdat->sealed_sender_hmac_size = SIGNAL_SEALED_SENDER_HMAC_SIZE;

	hmac_sha256(
		sdat->sealed_sender_key->mac_key, sdat->sealed_sender_key->mac_key_size,
		sdat->sealed_sender_data        , sdat->sealed_sender_data_size,
		sdat->sealed_sender_hmac        , sdat->sealed_sender_hmac_size);

	/*pr_info("CCKEX_LKM [%s]     hmac: ", __func__);
	//cckex_print_mem(sdat->sealed_sender_hmac, sdat->sealed_sender_hmac_size);
	//pr_info("CCKEX_LKM [%s] new hmac: ", __func__);
	//cckex_print_mem(test, 10);
	//pr_info("CCKEX_LKM [%s] mac key (%i): ", __func__, sdat->sealed_sender_key->mac_key_size);
	//cckex_print_mem(sdat->sealed_sender_key->mac_key, sdat->sealed_sender_key->mac_key_size);
	//pr_info("CCKEX_LKM [%s] ctext (%i): ", __func__, sdat->sealed_sender_data_size);
	//cckex_print_mem(sdat->sealed_sender_data, sdat->sealed_sender_data_size);*/

	return 0;
}
