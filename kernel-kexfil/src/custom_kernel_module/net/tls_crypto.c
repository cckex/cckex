#include "tls_crypto.h"

#include <linux/scatterlist.h>
#include <linux/string.h>
#include <crypto/aead.h>

#include "../common.h"
#include "../crypto/hmac/hmac_sha2.h"
#include "../crypto/hkdf/hkdf.h"
#include "websocket.h"

#define CCKEX_DEBUG_TLS_DECRYPTION_MAY_BREAK 1

// https://github.com/cisco/mercury/blob/main/python/pmercury/utils/tls_constants.py
#define MAC_KEY_LEN 0
#define ENC_KEY_LEN 32
#define IV_LEN      12

#define SHA256_SIZE 32
#define SHA384_SIZE 48

int cckex_tls12_prf_gen_keys(cckex_conn_list_entry_t* entry, const char *label) {
	int ret = 0;
	uint8_t *seed = NULL;
	uint8_t *a_seed_buf = NULL;
	size_t label_size = 0;
	size_t seed_size = 0;
	size_t a_seed_buf_size = 0;

	if(entry->client_random == NULL || entry->client_random_size == 0 ||
	   entry->server_random == NULL || entry->server_random_size == 0 ||
	   entry->master_secret == NULL || entry->master_secret_size == 0) {
		//pr_info("CCKEX_LKM [%s] client_random/server_random/master_secret not set", __func__);
		return -1;
	}
	
	// alloc key block
	entry->key_block = kmalloc(96, GFP_KERNEL);
	if(!entry->key_block) {
		//pr_info("CCKEX_LKM [%s] failed to alloc key_block", __func__);
		ret = -1;
		goto out;
	}

	// construct seed
	label_size = strlen(label);
	seed_size = entry->server_random_size + entry->client_random_size + label_size; 
	seed = kmalloc(seed_size, GFP_KERNEL);
	if(!seed) {
		//pr_info("CCKEX_LKM [%s] failed to alloc seed", __func__);
		ret = -1;
		goto out;
	}

	memcpy(seed, label, label_size);
	memcpy(seed + label_size, entry->server_random, entry->server_random_size);
	memcpy(seed + label_size + entry->server_random_size, entry->client_random, entry->client_random_size);

	/*pr_info("CCKEX_LKM [%s] master_secret: ", __func__);
	//cckex_print_mem(entry->master_secret, entry->master_secret_size);
	//pr_info("CCKEX_LKM [%s] seed: ", __func__);
	//cckex_print_mem(seed, seed_size);*/

	// construct a1
	a_seed_buf_size = SHA384_SIZE + seed_size;
	a_seed_buf = kmalloc(a_seed_buf_size, GFP_KERNEL);
	if(!a_seed_buf) {
		//pr_info("CCKEX_LKM [%s] failed to alloc a_seed_buf", __func__);
		ret = -1;
		goto out;
	}

	hmac_sha384(entry->master_secret, entry->master_secret_size, seed, seed_size, a_seed_buf, SHA384_SIZE);
	/*if(hmac_sha256(entry->master_secret, entry->master_secret_size, seed, seed_size, a_seed_buf, SHA256_SIZE) != SHA256_SIZE) {
		//pr_info("CCKEX_LKM [%s] hmac_sha256 failed (a1)", __func__);
		ret = -1;
		goto out;
	}*/
	memcpy(a_seed_buf + SHA384_SIZE, seed, seed_size);

	// calculate first part of keyblock
	hmac_sha384(entry->master_secret, entry->master_secret_size, a_seed_buf, a_seed_buf_size, entry->key_block, SHA384_SIZE);
	/*if(hmac_sha256(entry->master_secret, entry->master_secret_size, a_seed_buf, a_seed_buf_size, entry->key_block, SHA256_SIZE) != SHA256_SIZE) {
		//pr_info("CCKEX_LKM [%s] hmac_sha256 failed (first key_block block)", __func__);
		ret = -1;
		goto out;
	}*/

	// construct a2
	hmac_sha384(entry->master_secret, entry->master_secret_size, a_seed_buf, SHA384_SIZE, a_seed_buf, SHA384_SIZE);
	/*if(hmac_sha256(entry->master_secret, entry->master_secret_size, a_seed_buf, SHA256_SIZE, a_seed_buf, SHA256_SIZE) != SHA256_SIZE) {
		//pr_info("CCKEX_LKM [%s] hmac_sha256 failed (a2)", __func__);
		ret = -1;
		goto out;
	}*/

	// calculate second part of keyblock
	hmac_sha384(entry->master_secret, entry->master_secret_size, a_seed_buf, a_seed_buf_size, entry->key_block + SHA384_SIZE, SHA384_SIZE);
	/*if(hmac_sha256(entry->master_secret, entry->master_secret_size, a_seed_buf, a_seed_buf_size, entry->key_block + SHA256_SIZE, SHA256_SIZE) != SHA256_SIZE) {
		//pr_info("CCKEX_LKM [%s] hmac_sha256 failed (first key_block block)", __func__);
		ret = -1;
		goto out;
	}*/

	entry->client_write_key = entry->key_block;
	entry->client_write_key_size = ENC_KEY_LEN;
	entry->client_write_iv = entry->key_block + 2 * ENC_KEY_LEN;
	entry->client_write_iv_size = IV_LEN;
	entry->key_block_size = 96;

	//pr_info("CCKEX_LKM [%s] xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", __func__);
	//pr_info("CCKEX_LKM [%s] key_block=", __func__);
	//cckex_print_mem(entry->key_block, entry->key_block_size);
	//pr_info("CCKEX_LKM [%s] client_random=", __func__);
	//cckex_print_mem(entry->client_random, entry->client_random_size);
	//pr_info("CCKEX_LKM [%s] server_random=", __func__);
	//cckex_print_mem(entry->server_random, entry->server_random_size);
	//pr_info("CCKEX_LKM [%s] master_secret=", __func__);
	//cckex_print_mem(entry->master_secret, entry->master_secret_size);
	//pr_info("CCKEX_LKM [%s] client_write_key=", __func__);
	//cckex_print_mem(entry->client_write_key, entry->client_write_key_size);
	//pr_info("CCKEX_LKM [%s] client_write_iv=", __func__);
	//cckex_print_mem(entry->client_write_iv, entry->client_write_iv_size);
	//pr_info("CCKEX_LKM [%s] xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", __func__);

	out:

	if(seed) kfree(seed);
	if(a_seed_buf) kfree(a_seed_buf);

	return ret;
}

void cckex_test_tls_crypto(void) {
	// https://mailarchive.ietf.org/arch/msg/tls/fzVCzk-z3FShgGJ6DOXqM1ydxms/

	cckex_conn_list_entry_t entry;
	
	uint8_t master_secret[16] = { 0x9b, 0xbe, 0x43, 0x6b, 0xa9, 0x40, 0xf0, 0x17, 0xb1, 0x76, 0x52, 0x84, 0x9a, 0x71, 0xdb, 0x35 };

	uint8_t server_random[8]  = { 0xa0, 0xba, 0x9f, 0x93, 0x6c, 0xda, 0x31, 0x18 };
	uint8_t client_random[8]  = { 0x27, 0xa6, 0xf7, 0x96, 0xff, 0xd5, 0x19, 0x8c };

	entry.master_secret = master_secret;
	entry.master_secret_size = 16;
	entry.client_random = client_random;
	entry.client_random_size = 8;
	entry.server_random = server_random;
	entry.server_random_size = 8;

	cckex_tls12_prf_gen_keys(&entry, "test label");
	//pr_info("CCKEX_LKM [%s] cckex_tls12_prf_gen_keys test (size=%zu): ", __func__, entry.key_block_size);
	//cckex_print_mem(entry.key_block, entry.key_block_size);
}

void cckex_test_tls_crypto_384(void) {
	// https://mailarchive.ietf.org/arch/msg/tls/fzVCzk-z3FShgGJ6DOXqM1ydxms/

	cckex_conn_list_entry_t entry;
	
	uint8_t master_secret[16] = { 0xb8, 0x0b, 0x73, 0x3d, 0x6c, 0xee, 0xfc, 0xdc, 0x71, 0x56, 0x6e, 0xa4, 0x8e, 0x55, 0x67, 0xdf };

	uint8_t server_random[8]  = { 0xcd, 0x66, 0x5c, 0xf6, 0xa8, 0x44, 0x7d, 0xd6 };
	uint8_t client_random[8]  = { 0xff, 0x8b, 0x27, 0x55, 0x5e, 0xdb, 0x74, 0x65 };

	entry.master_secret = master_secret;
	entry.master_secret_size = 16;
	entry.client_random = client_random;
	entry.client_random_size = 8;
	entry.server_random = server_random;
	entry.server_random_size = 8;

	cckex_tls12_prf_gen_keys(&entry, "test label");
	//pr_info("CCKEX_LKM [%s] cckex_tls12_prf_gen_keys test (size=%zu): ", __func__, entry.key_block_size);
	//cckex_print_mem(entry.key_block, entry.key_block_size);
}

#define TLS12_IMPLICIT_NONCE_LEN 4 	// first 4 bytes of the write iv
#define TLS12_EXPLICIT_NONCE_LEN 8 	// seq number from tls record

#define TLS12_RECORD_TYPE_OFF    0
#define TLS12_RECORD_VERSION_OFF 1
#define TLS12_RECORD_LENGTH_OFF  3
#define TLS12_RECORD_SEQNUM_OFF  5

#define TLS12_AEAD_AUTH_SIZE 16

#define CRYPTO_MODE_ENC 1
#define CRYPTO_MODE_DEC 2

static int cckex_tls12_crypt_payload(struct sk_buff *skb, cckex_conn_list_entry_t *entry,
		uint8_t *payload, size_t payload_len, int crypto_mode, cckex_tls_crypto_t **tls_crypto) {

	int ret = 0;

	struct crypto_aead *caead = NULL;
	struct aead_request *req = NULL;
	struct scatterlist sg_data;
	DECLARE_CRYPTO_WAIT(cwait);

	//pr_info("CCKEX_LKM [%s] call crypto_alloc_aead", __func__);

/*	//pr_info("CCKEX_LKM [%s] ENCRYPTED PKG: ", __func__);
	//cckex_print_mem(payload, payload_len);*/

	// allocate cipher
	caead = crypto_alloc_aead("gcm(aes)", 0, 0);
	if(IS_ERR(caead)) {
		//pr_info("CCKEX_LKM [%s] crypto_alloc_aead failed with: %zu", __func__, PTR_ERR(caead));
		ret = -1;
		goto out;
	}

	if(entry->client_write_key_size != ENC_KEY_LEN || entry->client_write_key == NULL) {
		pr_warn("CCKEX_LKM [%s] client_write_key_size / client_write_key wrong value", __func__);
	}

	//pr_info("CCKEX_LKM [%s] call crypto_aead_setkey", __func__);

	// set cipher key
	if((ret = crypto_aead_setkey(caead, entry->client_write_key, entry->client_write_key_size)) != 0) {
		//pr_info("CCKEX_LKM [%s] crypto_aead_setkey failed with %d -> key (%zu): ", __func__, ret, entry->client_write_key_size);
		//cckex_print_mem(entry->client_write_key, entry->client_write_key_size);
		ret = -1;
		goto out;
	}

	//pr_info("CCKEX_LKM [%s] call crypto_aead_setauthsize", __func__);

	// set authentication size
	// TODO: check IF 16 byte is right
	// 16 Bytes should be ok: https://github.com/wireshark/wireshark/blob/8bffe8954ec949ed8a8a451a241c7480135c173f/epan/dissectors/packet-tls-utils.c#L5094
	if((ret = crypto_aead_setauthsize(caead, TLS12_AEAD_AUTH_SIZE)) != 0) {
		//pr_info("CCKEX_LKM [%s] crypto_aead_setauthsize failed with %i", __func__, ret);
		ret = -1;
		goto out;
	}

	//pr_info("CCKEX_LKM [%s] call aead_request_alloc", __func__);

	// allocate request
	req = aead_request_alloc(caead, GFP_ATOMIC);
	if(!req) {
		//pr_info("CCKEX_LKM [%s] aead_request_alloc failed", __func__);
		ret = -1;
		goto out;
	}

	//pr_info("CCKEX_LKM [%s] call aead_request_set_ad", __func__);

	aead_request_set_ad(req, TLS12_AAD_SIZE);

	//pr_info("CCKEX_LKM [%s] call sg_init_one payload=%p payload_len=%i", __func__, payload, payload_len);

	sg_init_one(&sg_data, payload, payload_len);

	//pr_info("CCKEX_LKM [%s] call aead_request_set_callback", __func__);

	aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG, crypto_req_done, &cwait);

	//pr_info("CCKEX_LKM [%s] call aead_request_set_crypt", __func__);
	if(crypto_mode == CRYPTO_MODE_DEC) {

		*tls_crypto = kmalloc(sizeof(cckex_tls_crypto_t), GFP_ATOMIC);
		if(!tls_crypto) {
			//pr_info("CCKEX_LKM [%s] failed to alloc tls_crypto struct", __func__);
			ret = -1;
			goto out;
		}
		// construct and set iv
		memcpy((*tls_crypto)->iv						     , entry->client_write_iv           , TLS12_IMPLICIT_NONCE_LEN);
		memcpy((*tls_crypto)->iv + TLS12_IMPLICIT_NONCE_LEN, payload + TLS12_RECORD_SEQNUM_OFF, TLS12_EXPLICIT_NONCE_LEN);

		// construct and set associated data information
		memcpy((*tls_crypto)->orig_tls_header, payload, TLS12_AAD_SIZE);
		memcpy(payload, (*tls_crypto)->orig_tls_header + TLS12_RECORD_SEQNUM_OFF, 8);
		memcpy(payload + 8, (*tls_crypto)->orig_tls_header, 5);
		*(uint16_t*)(payload + 11) = htons(GET_U16H(payload, 11) - TLS12_AEAD_AUTH_SIZE - 8); // subtract size of nonce and tag from record length
		
		/*pr_info("CCKEX_LKM [%s] aad:", __func__);
		//cckex_print_mem(payload, aad_size);*/

		aead_request_set_crypt(req, &sg_data, &sg_data, payload_len - TLS12_AAD_SIZE, (*tls_crypto)->iv);

		//pr_info("CCKEX_LKM [%s] call crypto_aead_decrypt iv=%p", __func__, iv);

		if((ret = crypto_aead_decrypt(req)) == -EINPROGRESS || ret == -EBUSY) {
			//pr_info("CCKEX_LKM [%s] call crypto_wait_req", __func__);
			if((ret = crypto_wait_req(ret, &cwait)) != 0) {
				pr_warn("CCKEX_LKM [%s] crypto_wait_req failed with %i", __func__, ret);
				ret = -1;
				goto out;
			}
		} else if(ret != 0) {
			pr_warn("CCKEX_LKM [%s] crypto_aead_decrypt failed with %i", __func__, ret);
			ret = -1;
			goto out;
		}
	} else {

		aead_request_set_crypt(req, &sg_data, &sg_data, payload_len - TLS12_AAD_SIZE - TLS12_AEAD_AUTH_SIZE, (*tls_crypto)->iv);

		//pr_info("CCKEX_LKM [%s] call crypto_aead_encrypt iv=%p", __func__, iv);

		// TODO: NULL pointer read while calling encrypt in some cases ????
		//		 The NULL read seems to occure when signal is closed
		if((ret = crypto_aead_encrypt(req)) == -EINPROGRESS || ret == -EBUSY) {
			//pr_info("CCKEX_LKM [%s] call crypto_wait_req", __func__);
			if((ret = crypto_wait_req(ret, &cwait)) != 0) {
				pr_warn("CCKEX_LKM [%s] crypto_wait_req failed with %i", __func__, ret);
				ret = -1;
				goto out;
			}
		} else if(ret != 0) {
			pr_warn("CCKEX_LKM [%s] crypto_aead_encrypt failed with %i", __func__, ret);
			ret = -1;
			goto out;
		}

		memcpy(payload, (*tls_crypto)->orig_tls_header, TLS12_AAD_SIZE);

		kfree(*tls_crypto);
	}

	//pr_info("CCKEX_LKM [%s] finished", __func__);

	out:

	if(req) aead_request_free(req);
	if(caead) crypto_free_aead(caead);

	return ret;
}

int cckex_tls12_decrypt_payload(struct sk_buff *skb, cckex_conn_list_entry_t *entry,
		uint8_t *payload, size_t payload_len, cckex_tls_crypto_t **tls_crypto) {
	return cckex_tls12_crypt_payload(skb, entry, payload, payload_len, CRYPTO_MODE_DEC, tls_crypto);
}

int cckex_tls12_encrypt_payload(struct sk_buff *skb, cckex_conn_list_entry_t *entry,
		uint8_t *payload, size_t payload_len, cckex_tls_crypto_t **tls_crypto) {
	return cckex_tls12_crypt_payload(skb, entry, payload, payload_len, CRYPTO_MODE_ENC, tls_crypto);
}

int cckex_tls13_prf_gen_keys(cckex_conn_list_entry_t *entry) {

	/*	HKDF Label format for the TLS1.3 HKDF-Expand-Label Function (RFC8446, 7.1)
	 *
	 *	HKDF-Expand-Label(Secret, Label, Context, Length) =
     *       HKDF-Expand(Secret, HkdfLabel, Length)
	 *
     *  Where HkdfLabel is specified as:
	 *
	 *  struct {
     *		uint16 length = Length;
	 *		opaque label<7..255> = "tls13 " + Label;
     *		opaque context<0..255> = Context;
     *  } HkdfLabel;
	 *
	 *  HkdfLabel is a ASCII String which does not include the trailing NUL
	 */
	//	char *key_hkdf_label = "\x00\x20\x08tls13key";
	//							 00  20  09  74  6c  73  31  33  20  6b  65  7900
	uint8_t *key_hkdf_label = "\x00\x20\x09\x74\x6c\x73\x31\x33\x20\x6b\x65\x79\x00";
	size_t key_hkdf_label_data_length = 13;
	//	char *iv_hkdf_label  = "\x00\x0c\x08tls13iv";
	//						    00  0c  08  74  6c  73  31  33  20  69  76  00
	uint8_t *iv_hkdf_label = "\x00\x0c\x08\x74\x6c\x73\x31\x33\x20\x69\x76\x00";
	size_t iv_hkdf_label_data_length = 12;

	if(entry->client_random == NULL || entry->client_random_size == 0 ||
	   entry->server_random == NULL || entry->server_random_size == 0 ||
	   entry->master_secret == NULL || entry->master_secret_size == 0) {
		pr_warn("CCKEX_LKM [%s] client_random/server_random/master_secret not set", __func__);
		return -1;
	}

	// TODO: make the used hash function dynamic depending on the individual connection
	
	entry->key_block = NULL;
	entry->key_block_size = 0;
	entry->client_write_key_size = ENC_KEY_LEN;
	entry->client_write_iv_size = IV_LEN;

	// Allocate Key and iv
	if((entry->client_write_key = kmalloc(entry->client_write_key_size, GFP_ATOMIC)) == NULL) {
		pr_warn("CCKEX_LKM [%s] failed to allocate client_write_key", __func__);
		return -2;
	}

	if((entry->client_write_iv = kmalloc(entry->client_write_iv_size, GFP_ATOMIC)) == NULL) {
		pr_warn("CCKEX_LKM [%s] failed to allocate client_write_iv", __func__);
		return -2;
	}

	cckex_hkdf_expand(CCKEX_HKDF_SHA384,
			entry->master_secret, entry->master_secret_size, 
			key_hkdf_label, key_hkdf_label_data_length,
			entry->client_write_key, entry->client_write_key_size);

	cckex_hkdf_expand(CCKEX_HKDF_SHA384,
			entry->master_secret, entry->master_secret_size, 
			iv_hkdf_label, iv_hkdf_label_data_length,
			entry->client_write_iv, entry->client_write_iv_size);

	pr_info("CCKEX_LKM [%s] xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", __func__);
	pr_info("CCKEX_LKM [%s] client_random(%zu)=", __func__, entry->client_random_size);
	cckex_print_mem(entry->client_random, entry->client_random_size);
	pr_info("CCKEX_LKM [%s] server_random(%zu)=", __func__, entry->server_random_size);
	cckex_print_mem(entry->server_random, entry->server_random_size);
	pr_info("CCKEX_LKM [%s] master_secret(%zu)=", __func__, entry->master_secret_size);
	cckex_print_mem(entry->master_secret, entry->master_secret_size);
	pr_info("CCKEX_LKM [%s] handshake_secret(%zu)=", __func__, entry->handshake_secret_size);
	cckex_print_mem(entry->handshake_secret, entry->handshake_secret_size);
	pr_info("CCKEX_LKM [%s] key_label(%zu)=", __func__, key_hkdf_label_data_length);
	cckex_print_mem(key_hkdf_label, key_hkdf_label_data_length);
	pr_info("CCKEX_LKM [%s] iv_label(%zu)=", __func__, iv_hkdf_label_data_length);
	cckex_print_mem(iv_hkdf_label, iv_hkdf_label_data_length);
	pr_info("CCKEX_LKM [%s] client_write_key(%zu)=", __func__, entry->client_write_key_size);
	cckex_print_mem(entry->client_write_key, entry->client_write_key_size);
	pr_info("CCKEX_LKM [%s] client_write_iv(%zu)=", __func__, entry->client_write_iv_size);
	cckex_print_mem(entry->client_write_iv, entry->client_write_iv_size);
	pr_info("CCKEX_LKM [%s] remote_ipv=%pI4h", __func__, entry->ip.remote_ipv4);
	pr_info("CCKEX_LKM [%s] local_port=%u", __func__, entry->local_port);
	pr_info("CCKEX_LKM [%s] xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", __func__);

	return 0;
}

#define TLS13_AEAD_AUTH_SIZE 16

static int cckex_tls13_crypt_payload(struct sk_buff *skb, cckex_conn_list_entry_t *entry,
		uint8_t *payload, size_t payload_len, int crypto_mode, cckex_tls_crypto_t **tls_crypto) {

	int ret = 0;

	struct crypto_aead *caead = NULL;
	struct aead_request *req = NULL;
	struct scatterlist sg_data;
	DECLARE_CRYPTO_WAIT(cwait);

	// allocate cipher
	// TODO: make this dependent on the actual choosen cipher in the tls handshake
	// TODO: crypto_alloc_aead uses crypto_create_tfm_node, which allocates with GFP_KERNEL -> this may lead to problems
	caead = crypto_alloc_aead("gcm(aes)", 0, 0);
	if(IS_ERR(caead)) {
		pr_warn("CCKEX_LKM [%s] crypto_alloc_aead failed with: %zu", __func__, PTR_ERR(caead));
		ret = -1;
		goto out;
	}

	if(entry->client_write_key_size != ENC_KEY_LEN || entry->client_write_key == NULL) {
		pr_warn("CCKEX_LKM [%s] client_write_key_size / client_write_key wrong value", __func__);
	}

	// set cipher key
	if((ret = crypto_aead_setkey(caead, entry->client_write_key, entry->client_write_key_size)) != 0) {
		pr_warn("CCKEX_LKM [%s] crypto_aead_setkey failed with %d -> key (%zu): ", __func__, ret, entry->client_write_key_size);
		cckex_print_mem(entry->client_write_key, entry->client_write_key_size);
		ret = -1;
		goto out;
	}

	// set authentication size
	// According to the wireshark source 16 bytes should be correct -> see auth_tag_len
	if((ret = crypto_aead_setauthsize(caead, TLS13_AEAD_AUTH_SIZE)) != 0) {
		pr_warn("CCKEX_LKM [%s] crypto_aead_setauthsize failed with %i", __func__, ret);
		ret = -1;
		goto out;
	}

	// allocate request
	req = aead_request_alloc(caead, GFP_ATOMIC);
	if(!req) {
		pr_warn("CCKEX_LKM [%s] aead_request_alloc failed", __func__);
		ret = -1;
		goto out;
	}

	aead_request_set_ad(req, TLS13_AAD_SIZE);

	sg_init_one(&sg_data, payload, payload_len);

	aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG, crypto_req_done, &cwait);

	if(crypto_mode == CRYPTO_MODE_DEC) {

		*tls_crypto = kmalloc(sizeof(cckex_tls_crypto_t), GFP_ATOMIC);
		if(!tls_crypto) {
			pr_warn("CCKEX_LKM [%s] failed to alloc tls_crypto struct", __func__);
			ret = -1;
			goto out;
		}

		pr_info("CCKEX_LKM [%s] tls13_seq_num = %llu", __func__, entry->tls13_seq_num);

		// construct and set iv, first the iv is set to the expanded iv (generated by the hkdf label expansion)
		memcpy((*tls_crypto)->iv, entry->client_write_iv, entry->client_write_iv_size);
		// then the sequence counter in network byte order is xored with the iv 
		// First add iv_size - 8 to the tls_crypto->iv pointer (currently this will yield a offset of 4). Then convert
		// this pointer to a u64 pointer and dereference it to then xor it with the sequence number (which is converted
		// to network order = big endian)
		*(uint64_t*)((uint8_t*)(*tls_crypto)->iv + entry->client_write_iv_size - 8) ^= cpu_to_be64(entry->tls13_seq_num);
		// increment the seqence counter for future packages
		entry->tls13_seq_num++;

		// The construction and assignment of the associated data information should be unnecessary in TLS1.3 as it 
		// consists of the normal TLS record header (type || version || length)
		
		aead_request_set_crypt(req, &sg_data, &sg_data, payload_len - TLS13_AAD_SIZE, (*tls_crypto)->iv);

#if CCKEX_DEBUG_TLS_DECRYPTION_MAY_BREAK
		// BACKUP PAYLOAD, only for debugging reasons to prevent tls alerts / mass retries
		(*tls_crypto)->payload_backup = kmalloc(payload_len, GFP_ATOMIC);
		if(!(*tls_crypto)->payload_backup) {
			pr_warn("CCKEX_LKM [%s] failed to alloc payload_backup", __func__);
			ret = -1;
			goto out;
		}
		memcpy((*tls_crypto)->payload_backup, payload, payload_len);
#endif

		if((ret = crypto_aead_decrypt(req)) == -EINPROGRESS || ret == -EBUSY) {
			//pr_info("CCKEX_LKM [%s] call crypto_wait_req", __func__);
			if((ret = crypto_wait_req(ret, &cwait)) != 0) {
				pr_warn("CCKEX_LKM [%s] crypto_wait_req failed with %i", __func__, ret);
				ret = -1;
				goto out;
			}
		} else if(ret != 0) {
			pr_warn("CCKEX_LKM [%s] crypto_aead_decrypt failed with %i", __func__, ret);
			ret = -1;
			// Restore payload from backup
			pr_info("CCKEX_LKM [%s] restoring payload from backup ..", __func__);

#if CCKEX_DEBUG_TLS_DECRYPTION_MAY_BREAK
			memcpy(payload, (*tls_crypto)->payload_backup, payload_len);
#endif

			goto out;
		}
	} else {

		aead_request_set_crypt(req, &sg_data, &sg_data, payload_len - TLS13_AAD_SIZE - TLS13_AEAD_AUTH_SIZE, (*tls_crypto)->iv);

		// TODO: NULL pointer read while calling encrypt in some cases ????
		//		 The NULL read seems to occure when signal is closed
		if((ret = crypto_aead_encrypt(req)) == -EINPROGRESS || ret == -EBUSY) {
			//pr_info("CCKEX_LKM [%s] call crypto_wait_req", __func__);
			if((ret = crypto_wait_req(ret, &cwait)) != 0) {
				pr_warn("CCKEX_LKM [%s] crypto_wait_req failed with %i", __func__, ret);
				ret = -1;
				goto out;
			}
		} else if(ret != 0) {
			pr_warn("CCKEX_LKM [%s] crypto_aead_encrypt failed with %i", __func__, ret);
			ret = -1;
			goto out;
		}

#if CCKEX_DEBUG_TLS_DECRYPTION_MAY_BREAK
		kfree((*tls_crypto)->payload_backup);
#endif

		kfree(*tls_crypto);
	}

	//pr_info("CCKEX_LKM [%s] finished", __func__);

	out:

	if(req) aead_request_free(req);
	if(caead) crypto_free_aead(caead);

	return ret;
}


int cckex_tls13_decrypt_payload(struct sk_buff *skb, cckex_conn_list_entry_t *entry,
		uint8_t *payload, size_t payload_len, cckex_tls_crypto_t **tls_crypto) {
	return cckex_tls13_crypt_payload(skb, entry, payload, payload_len, CRYPTO_MODE_DEC, tls_crypto);
}

int cckex_tls13_encrypt_payload(struct sk_buff *skb, cckex_conn_list_entry_t *entry,
		uint8_t *payload, size_t payload_len, cckex_tls_crypto_t **tls_crypto) {
	return cckex_tls13_crypt_payload(skb, entry, payload, payload_len, CRYPTO_MODE_ENC, tls_crypto);
}
