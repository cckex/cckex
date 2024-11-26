/*
 *	hkdf.h/c contain the implementation of the RFC5869 HKDF functions for the CCKex Framework.
 *	This implementation uses RFC6234 Section 8.4 as a loose reference.
 */


#pragma once

#include<linux/types.h>

#include "../hmac/sha2.h"

/*	cckex_hkdf_hashlen_t
 *
 *
 */
enum cckex_hkdf_hashlen_t {
	CCKEX_HKDF_SHA224 = SHA224_DIGEST_SIZE,
	CCKEX_HKDF_SHA256 = SHA256_DIGEST_SIZE,
	CCKEX_HKDF_SHA384 = SHA384_DIGEST_SIZE,
	CCKEX_HKDF_SHA512 = SHA512_DIGEST_SIZE
};

/*	-- cckex_hkdf_extract --
 *
 *	TODO: update comment
 *
 *	RFC 5869 HKDF extraction function implementation.
 *
 *	@param ctx		: Current HKDF execution context.
 *	@param salt		: Salt to use in the extract step (if NULL is given salt will be 
 *					  expanded to a string of hashlen zeros)
 *	@param salt_size: Size of salt (if 0 is given the salt will also be expanded)
 *	@param ikm		: Input key material (see RFC)
 *	@param ikm_size	: Size of the IKM.
 *	@param prk		: Output of the HKDF extraction step (Pseudorandom key of HashLen octets)
 *	@param hashlen	: Length of the PRK and used SHA digest size.
 *
 *	@return: error-code or 0 (currently no errors are returned / are to be expected)
 */
int cckex_hkdf_extract(enum cckex_hkdf_hashlen_t hashlen,
						uint8_t *salt, size_t salt_size,
						uint8_t *ikm, size_t ikm_size,
						uint8_t *prk, size_t prk_size);

int cckex_hkdf_expand(enum cckex_hkdf_hashlen_t hashlen,
						uint8_t *prk,  size_t prk_size,
						uint8_t *info, size_t info_size,
						uint8_t *okm,  size_t okm_size);

/*	cckex_hkdf
 *
 *
 *	@param hashlen:
 *
 *	@return: error-code 
 *
 */
int cckex_hkdf(enum cckex_hkdf_hashlen_t hashlen,
				uint8_t *salt, size_t salt_size,
				uint8_t *ikm , size_t ikm_size,
				uint8_t *info, size_t info_size,
				uint8_t *okm , size_t okm_size);

void cckex_test_hkdf(void);
