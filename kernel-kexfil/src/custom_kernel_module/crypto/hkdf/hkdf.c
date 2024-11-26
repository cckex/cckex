#include "hkdf.h"

#include <linux/string.h>
#include <linux/slab.h>

#include "../hmac/hmac_sha2.h"
#include "../../common.h"

/*	-- hmac_fptr_t --
 *
 *	Function pointer type for the hkdf_context_t struct for the sha_hmac functions
 *
 */
typedef void (*hmac_fptr_t)(const unsigned char *key, unsigned int key_size,
							const unsigned char *message, unsigned int message_len,
							unsigned char *mac, unsigned mac_size);

static hmac_fptr_t get_hmac(enum cckex_hkdf_hashlen_t hashlen) {
	switch(hashlen) {
		case CCKEX_HKDF_SHA224:
			return &hmac_sha224;
		case CCKEX_HKDF_SHA256:
			return &hmac_sha256;
		case CCKEX_HKDF_SHA384:
			return &hmac_sha384;
		case CCKEX_HKDF_SHA512:
			return &hmac_sha512;
		default:
			break;
	}

	return NULL;
}

int cckex_hkdf_extract(enum cckex_hkdf_hashlen_t hashlen,
						uint8_t *salt, size_t salt_size,
						uint8_t *ikm, size_t ikm_size,
						uint8_t *prk, size_t prk_size)
{
	uint8_t null_salt[hashlen];
	hmac_fptr_t hmac_fn = get_hmac(hashlen);

	// IKM is used as the hmac input not the key in the HKDF implementation

	// if salt == NULL or salt_size = 0 are not set, then set salt to hashlen long 0 buffer
	if(!salt || !salt_size) {
				memset(null_salt, 0, hashlen);
		hmac_fn(null_salt, hashlen, ikm, ikm_size, prk, hashlen); 
	} else {
		hmac_fn(salt, salt_size, ikm, ikm_size, prk, hashlen);
	}

	//pr_info("PRK: ");
	//cckex_print_mem(prk, hashlen);

	return 0;
}

/*
 */
int cckex_hkdf_expand(enum cckex_hkdf_hashlen_t hashlen,
						uint8_t *prk,  size_t prk_size,
						uint8_t *info, size_t info_size,
						uint8_t *okm,  size_t okm_size)
{
	uint8_t i;
	
	hmac_fptr_t hmac_fn = get_hmac(hashlen);

	// calculate N = ceil(L/okm_size) -> L = okm_size
	size_t N = okm_size % hashlen ? (okm_size / hashlen) + 1 : (okm_size / hashlen);
	
	size_t out_buf_size = N * hashlen;
	uint8_t *out_buf;

	// TODO: This may be wrong because the digest size and not block size is used in hashlen.
	//		 The RFC states that hashlen denotes the length of the hash function output in octets. However the 
	//		 block sizes of SHA224 and SHA382 are equal to the block sizes of SHA256 and SHA512 respectively.
	//		 It is not realy clear if "length of [..] output in octets" means the digest or block size.
	// create input buffer (output of previous hmac + info + counter)
	size_t in_buf_size = hashlen + info_size + 1;
	size_t cur_in_buf_size = info_size + 1;
	uint8_t in_buf[in_buf_size];

	if (N > 255) return -1;

	// alloc temporary output buffer
	out_buf = kmalloc(out_buf_size, GFP_ATOMIC);
	if(!out_buf) {
		return -2;
	}

	// create the first input for T(1) with T(0) = empty string | info | 0x01
	memcpy(in_buf, info, info_size);
	in_buf[info_size] = 0x01;

	// Do N steps
	for(i = 0; i < N; i++) {
		// calculate T(i+1)
		hmac_fn(prk, hashlen, in_buf, cur_in_buf_size, out_buf + i * hashlen, hashlen);
		cur_in_buf_size = in_buf_size;
		// create input buffer for the next step input_buffer = T(i+1) | info | i + 2
		memcpy(in_buf          , out_buf + i * hashlen, hashlen);
		memcpy(in_buf + hashlen, info                 , info_size);
		in_buf[hashlen + info_size] = i + 2;
	}

	// copy contents from output buffer
	memcpy(okm, out_buf, okm_size);

	// free temporary output buffer
	kfree(out_buf);

	return 0;
}

/*	cckex_hkdf
 *
 *	
 *	
 */
int cckex_hkdf(enum cckex_hkdf_hashlen_t hashlen,
				uint8_t *salt, size_t salt_size,
				uint8_t *ikm , size_t ikm_size,
				uint8_t *info, size_t info_size,
 				uint8_t *okm , size_t okm_size)
{
	uint8_t prk[hashlen];
	return cckex_hkdf_extract(hashlen, salt, salt_size, ikm, ikm_size, prk, hashlen) ||
		   cckex_hkdf_expand(hashlen, prk, hashlen, info, info_size, okm, okm_size);
}

void cckex_test_hkdf(void) {

	/*size_t L1 = 42;
	uint8_t okm1[L1];
	const size_t ikm1_size = 22;
	uint8_t ikm1[ikm1_size] = { 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b };
	const size_t salt1_size = 13;
	uint8_t salt1[salt1_size] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c };
	const size_t info1_size = 10;
	uint8_t info1[info1_size] = { 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9 };

	//pr_info("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx HKDF TEST 1 xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
	//pr_info("IKM: ");
	//cckex_print_mem(ikm1, ikm1_size);
	//pr_info("SALT: ");
	//cckex_print_mem(salt1, salt1_size);
	//pr_info("INFO: ");
	//cckex_print_mem(info1, info1_size);

	cckex_hkdf(CCKEX_HKDF_SHA256, salt1, salt1_size, ikm1, ikm1_size, info1, info1_size, okm1, L1);

	//pr_info("OKM: ");
	//cckex_print_mem(okm1, L1);

	size_t L2 = 42;
	uint8_t okm2[L2];
	const size_t ikm2_size = 22;
	uint8_t ikm2[ikm2_size] = { 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b };
	const size_t salt2_size = 0;
	uint8_t *salt2 = NULL;
	const size_t info2_size = 0;
	uint8_t *info2 = NULL;

	//pr_info("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx HKDF TEST 2 xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
	//pr_info("IKM: ");
	//cckex_print_mem(ikm2, ikm2_size);
	//pr_info("SALT: NULL");
	//pr_info("INFO: NULL");

	cckex_hkdf(CCKEX_HKDF_SHA256, salt2, salt2_size, ikm2, ikm2_size, info2, info2_size, okm2, L2);

	//pr_info("OKM: ");
	//cckex_print_mem(okm2, L2);*/
}
