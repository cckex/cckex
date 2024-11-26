#pragma once

#include <stddef.h>
#include <stdint.h>

#if __cplusplus
#include <vector>
#endif

#include "common.h"
#include "ui/uihandler.h"
#include "extraction/ccdatamanager.h"

/*  -- decrypt_sealed_sender / decrypt_message --
 *
 *  Decrypt the sealed sender / message envelope via AES 256 CTR / CBC
 *
 *  @param inbuf: input byte buffer to decrypt
 *  @param outbuf: output byte buffer to save decrypted bytes
 *  @param size: size of bytebuffer
 *  @return 0 on success, -1 unable to decrypt
 */
CCKEX_API int decrypt_sealed_sender(const void *inbuf, void *outbuf, size_t size);
CCKEX_API int decrypt_message(const void *inbuf, void *outbuf, size_t size);

/*  -- load_keys_from_file --
 *
 *  Load extracted ids, keys and ivs from file and save them in the internal key list to
 *  later decrypt signal packages
 *
 *  @param filepath: path to file containing lines with id and key (and iv) to load
 *  @return: 0 on success, -1 unable to open file, -2 malformed file, -3 param error
 */
CCKEX_API int load_keys_from_file(const char *filepath);

CCKEX_API void enable_key_file(void);
CCKEX_API void disable_key_file(void);

/*  -- reset_keys --
 *
 *  Function deletes the current content of the keylist
 */
CCKEX_API void reset_keys(void);

CCKEX_API void dump_tls_keys_to_file(void);

/*  The next section is only available in the other c++ files of the cckex plugin
 */
#if __cplusplus

/*  -- load_keys_from_byte_vector --
 *
 *  Load ids, keys and ivs from byte vector and save them in the internal key list
 *  to later decrypt signal packages
 *
 *  @param vec        : Byte vector to parse
 *  @param ccdata_list: Corresponing cc data list of the ccdatamanager
 */
void load_keys_from_byte_vector(const std::vector<uint8_t> &vec, ccdata_list_t &ccdata_list);

#endif
