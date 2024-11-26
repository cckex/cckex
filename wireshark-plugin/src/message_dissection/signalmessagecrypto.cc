#include "message_dissection/signalmessagecrypto.h"

#include <algorithm>
#include <iterator>
#include <iostream>
#include <stdint.h>
#include <stdio.h>
#include <fstream>
#include <cstdint>
#include <cstdlib>
#include <vector>
#include <array>
#include <map>

#include <gcrypt.h>

#include "extraction/keytypes/signal_common.h"
#include "extraction/keytypes/signal_message_key.h"
#include "extraction/keytypes/signal_sealed_sender_key.h"
#include "extraction/keytypes/tls_client_traffic_secret.h"
#include "extraction/keytypes/tls_server_traffic_secret.h"
#include "message_dissection/keylist.h"
#include "ui/uihandler.h"
#include "common.h"


ccData::ccbuffer_list_map_t _keymap;

static bool _key_file_enabled = false;

template<std::size_t SIZE>
static std::string print_byte_array_as_hex(std::array<uint8_t, SIZE> &arr) {
    for(auto& e : arr) {
	printf("%.2x", e);
    }
    std::cout << std::flush;
    return "";
}

static ccData::Signal::SignalKey find_signal_key_entry(const void *buf, const uint16_t delimiter) {

	if (!buf) return ccData::Signal::SignalKey();

    // get first 8 bytes from buffer
	ccData::Signal::id_t id;
    for(unsigned i = 0; i < id.size(); i++) id[i] = ((uint8_t*)buf)[i];

    // try to find entry
	ccData::ccbuffer_list_map_t::iterator map_iter = _keymap.find(delimiter);
	if(map_iter == _keymap.end()) {
		LOG_WARN << "Unable to find list with delimiter: " << std::hex << delimiter << std::endl;
		return ccData::Signal::SignalKey{};
	}

	uint32_t keyid = ccData::byteBufferToId(id.begin(), id.end());
	ccData::ccbuffer_list_t::iterator iter = map_iter->second.find(keyid);

	if(iter == map_iter->second.end()) {
		LOG_WARN << "Unable to find key in list " << std::hex << delimiter << ": " << keyid << std::dec << std::endl;
		return ccData::Signal::SignalKey{};
	} else {
		return ccData::Signal::SignalKey{iter->second};
	}
}

CCKEX_API int decrypt_sealed_sender(const void *inbuf, void *outbuf, size_t size) {

    check_for_new_keys();

    if(!inbuf || !outbuf || !size) return -1;

    // get decryption keys from list
	ccData::Signal::SignalSealedSenderKey entry = find_signal_key_entry(inbuf, ccData::Signal::SignalSealedSenderKey::getCCStreamDelimiter());

	LOG_INFO << "checking key: " << ccData::byteBufferToString(entry.begin(), entry.end()) << std::endl;
	if(!entry.dataValid()) {
		printf("%s: failed to find key for id=", __func__);
		for(size_t i = 0; i < ccData::Signal::ID_BYTE_SIZE; i++) {
			printf("%.02x", *((uint8_t*)inbuf + i));
		}
		printf("\n");
		return -1;
    }

    // decrypt content
    gcry_cipher_hd_t cipher_hd;
    long ret = 0;
    if((ret = gcry_cipher_open(&cipher_hd, gcry_cipher_algos::GCRY_CIPHER_AES256, gcry_cipher_modes::GCRY_CIPHER_MODE_CTR, 0)) != 0) {
		printf("%s: cipher open failed\n", __func__);
		return -1;
    }

	if((ret = gcry_cipher_setkey(cipher_hd, entry.getKey().data(), ccData::Signal::KEY_BYTE_SIZE)) != 0) {
		gcry_cipher_close(cipher_hd);
		printf("%s: setkey failed\n", __func__);
		return -1;
    }

    if((ret = gcry_cipher_setctr(cipher_hd, nullptr, 0)) != 0) {
		gcry_cipher_close(cipher_hd);
		printf("%s: setctr failed\n", __func__);
		return -1;
    }

    if((ret = gcry_cipher_decrypt(cipher_hd, outbuf, size, inbuf, size)) != 0) {
		gcry_cipher_close(cipher_hd);
		printf("%s: decrypt failed\n", __func__);
		return -1;
    }

    gcry_cipher_close(cipher_hd);

    return 0;
}

CCKEX_API int decrypt_message(const void *inbuf, void *outbuf, size_t size) {

    if(!inbuf || !outbuf || !size) {
		printf("%s: param invalid", __func__);
		return -1;
    }

    // get decryption keys from list
	ccData::Signal::SignalMessageKey entry = find_signal_key_entry(inbuf, ccData::Signal::SignalMessageKey::getCCStreamDelimiter());
	if(!entry.dataValid()) {
    	printf("%s: failed to find key for id=", __func__);
		for(size_t i = 0; i < ccData::Signal::ID_BYTE_SIZE; i++) {
			printf("%.02x", *((uint8_t*)inbuf + i));
		}
		printf("\n");
		return -1;
    }

    // decrypt content
    gcry_cipher_hd_t cipher_hd;
    long ret;
    if((ret = gcry_cipher_open(&cipher_hd, gcry_cipher_algos::GCRY_CIPHER_AES256, gcry_cipher_modes::GCRY_CIPHER_MODE_CBC, 0)) != 0) {
		printf("%s: cipher open failed\n", __func__);
		return -1;
    }

	if((ret = gcry_cipher_setkey(cipher_hd, entry.getKey().data(), ccData::Signal::KEY_BYTE_SIZE)) != 0) {
		gcry_cipher_close(cipher_hd);
		printf("%s: setkey failed\n", __func__);
		return -1;
    }

	if((ret = gcry_cipher_setiv(cipher_hd, entry.getIv().data(), ccData::Signal::IV_BYTE_SIZE)) != 0) {
		gcry_cipher_close(cipher_hd);
		printf("%s: setiv failed\n", __func__);
		return -1;
    }

    if((ret = gcry_cipher_decrypt(cipher_hd, outbuf, size, inbuf, size)) != 0) {
		gcry_cipher_close(cipher_hd);
		printf("%s: decrypt failed\n", __func__);
		return -1;
    }

    gcry_cipher_close(cipher_hd);

    return 0;
}

CCKEX_API void enable_key_file(void)
{
	_key_file_enabled = true;
	load_keys_from_file(config_get_signal_key_file());
}

CCKEX_API void disable_key_file(void)
{
	_key_file_enabled = false;
	Ui::UiHandler::getInstance()->doResetKeyList();
}

CCKEX_API int load_keys_from_file(const char *filepath) {

	LOG_INFO << "Loading keys from file: " << filepath << std::endl;

	(void)filepath;

	if(!_key_file_enabled) return 0;

    // catch invalid params
    if(!filepath) return -3;
    if(std::string(filepath) == "") return 0;

    // open file
    std::ifstream file(filepath, std::ios::in);
    if(!file.is_open()) {
		LOG_WARN << "Failed to open key file: " << filepath << std::endl;
		return -1;
	}

	std::string line;
	std::vector<uint8_t> byteVec;
	while(std::getline(file, line)) {

		byteVec.clear();

		line.erase(std::remove(line.begin(), line.end(), '\n'), line.end());
		line.erase(std::remove(line.begin(), line.end(), ' '), line.end());

		if(line.size() % 2) {
			LOG_WARN << "Line malformed - skipping: " << line << std::endl;
			continue;
		}

		for(size_t i = 0; i < line.size(); i += 2) {
			byteVec.push_back(strtol(line.substr(i, 2).c_str(), NULL, 16));
		}

		LOG_INFO << "expected: " << ccData::Signal::SignalSealedSenderKey::expectedSize() << " size: " << byteVec.size() << std::endl;

		if(byteVec.size() == ccData::Signal::SignalSealedSenderKey::expectedSize()) {
			ccData::Signal::SignalSealedSenderKey keyData(byteVec);
			LOG_INFO << "Loaded Key: " << keyData.toString() << std::endl;
			_keymap[ccData::Signal::SignalSealedSenderKey::getCCStreamDelimiter()][keyData.getKeyId()] = keyData;
		} else if(byteVec.size() == ccData::Signal::SignalMessageKey::expectedSize()) {
			ccData::Signal::SignalMessageKey keyData(byteVec);
			LOG_INFO << "Loaded Key: " << keyData.toString() << std::endl;
			_keymap[ccData::Signal::SignalMessageKey::getCCStreamDelimiter()][keyData.getKeyId()] = keyData;
		} else {
			LOG_WARN << "Unknown Key Format: " << line << std::endl;
		}
	}
   
    return 0;
}

//
// NOTE: This function is no longer used. In the early development stages of the CCKex framework, payload data was 
//		 encrypted asynchronously. However, this functionality was later removed.
//

/*const size_t cipher_buf_size = 256;
uint8_t cipher_buf[cipher_buf_size];

static size_t _out_enc_key_size = 16;
static uint8_t *_out_enc_key = NULL;
static size_t _out_enc_iv_size = 8;
static uint8_t *_out_enc_iv = NULL;
static const size_t _out_enc_auth_size = 16;
static const size_t _out_enc_aad_size = 3;
//static const size_t _out_enc_hmac_size = 32;
//static uint8_t *_out_enc_hmac = NULL;

static int _decrypt_outgoing_key_data(unsigned state, ccData::Signal::id_t &id, ccData::Signal::key_t &key, ccData::Signal::iv_t &iv) {

    uint8_t inbuf[8 + 32 + 16];
    uint8_t outbuf[8 + 32 + 16];
    size_t size = 0;

    unsigned index = 0;
    for(uint8_t i : id) {
		inbuf[index] = i;
		index++;
    }
    for(uint8_t i : key) {
		inbuf[index] = i;
		index++;
    }
    if(state == 2) {
		size = 8 + 32 + 16;
		for(uint8_t i : iv) {
			inbuf[index] = i;
			index++;
		}
    } else {
		size = 8 + 32;
    }

    // decrypt content
    gcry_cipher_hd_t cipher_hd;
    long ret;
    if((ret = gcry_cipher_open(&cipher_hd, gcry_cipher_algos::GCRY_CIPHER_AES256, gcry_cipher_modes::GCRY_CIPHER_MODE_GCM, 0)) != 0) {
		printf("%s: cipher open failed\n", __func__);
		return -1;
    }

    if((ret = gcry_cipher_setkey(cipher_hd, _out_enc_key, _out_enc_key_size)) != 0) {
		gcry_cipher_close(cipher_hd);
		printf("%s: setkey failed\n", __func__);
		return -1;
    }

    if((ret = gcry_cipher_setiv(cipher_hd, _out_enc_iv, _out_enc_iv_size)) != 0) {
		gcry_cipher_close(cipher_hd);
		printf("%s: setiv failed\n", __func__);
		return -1;
    }

    if((ret = gcry_cipher_decrypt(cipher_hd, outbuf, size, inbuf, size)) != 0) {
		gcry_cipher_close(cipher_hd);
		printf("%s: decrypt failed\n", __func__);
		return -1;
    }

    gcry_cipher_close(cipher_hd);

    for(unsigned i = 0; i < ccData::Signal::ID_BYTE_SIZE; i++) {
		id[i] = outbuf[i];
    }
    for(unsigned i = 0; i < ccData::Signal::KEY_BYTE_SIZE; i++) {
		key[i] = outbuf[i + 8];
    }
    for(unsigned i = 0; i < ccData::Signal::IV_BYTE_SIZE; i++) {
		iv[i] = outbuf[i + 8 + 32];
    }

    return 0;

}*/

//
// NOTE: This function is no longer used. It was replaced by ccBuffer.
//

/*static int load_key_from_byte_vector(const std::vector<uint8_t> &vec, std::vector<uint8_t>::const_iterator iter, size_t size, Ui::UiCCType type) {

    json conf = get_config();

    unsigned state = 0;
    ccData::Signal::id_t id = { };
    ccData::Signal::id_t::iterator id_iter = id.begin();
    ccData::Signal::key_t key = { };
    ccData::Signal::key_t::iterator key_iter = key.begin();
    ccData::Signal::iv_t iv = { };
    ccData::Signal::iv_t::iterator iv_iter = iv.begin();

    for(;iter != vec.end(); ++iter) {

		//printf("state=%i read=%i\n", state, *iter);

		// check if id is currently extracted
		if(state == 0) {

			*id_iter = *iter;
		    ++id_iter;

		    if(id_iter == id.end()) state = 1; // read complete id -> advance to key

		} else if(state == 1) { // check if key is currently extracted

		    *key_iter = *iter;
			++key_iter;

		    if(key_iter == key.end()) state = 2; // read complete key -> advance to iv if necessary

		} else {

			if (size == ccData::Signal::ID_BYTE_SIZE + ccData::Signal::KEY_BYTE_SIZE) {
				state = 1;
				break;
			}

		    *iv_iter = *iter;
		    ++iv_iter;

			if(iv_iter == iv.end()) break;
		}
    }

    std::cout << "cckex [" << __func__ << "] reading keys: " << print_byte_array_as_hex(id) << " " << print_byte_array_as_hex(key) << " " << print_byte_array_as_hex(iv) << std::endl;

    if (conf["crypto"]["enabled"]) {
		if(_decrypt_outgoing_key_data(state, id, key, iv) == -1) {
			std::cout << "[" << __func__ << "] failed to decrypt key data" << std::endl;
		    return -1;
		}
		 std::cout << "cckex [" << __func__ << "] reading decrypted keys: " << print_byte_array_as_hex(id) << " " << print_byte_array_as_hex(key) << " " << print_byte_array_as_hex(iv) << std::endl;

		LOG_ERROR << "Permessage Encryption currently not implemented." << std::endl;

	}

	cckex_key_entry_t entry =  {
        .type = (state == 2 ? ccData::Signal::key_type_t::MESSAGE_KEY : ccData::Signal::key_type_t::SEALED_SENDER_V1),
		.id = id,
		.key = key,
		.iv = iv
    };

	if(type == Ui::UiCCType::CLASSIC) {
		LOG_INFO << "loading classic type" << std::endl;
		Ui::UiHandler::getInstance()->addNewCChannelKeyEntry(entry);
	} else if (type == Ui::UiCCType::SIGNAL) {
		LOG_INFO << "loading signal type" << std::endl;
		Ui::UiHandler::getInstance()->addNewSignalKeyEntry(entry);
	} else {
		LOG_INFO << "loading tls type" << std::endl;
	}

    _keymap.insert({ id, entry });

    return 0;
}*/

CCKEX_API void reset_keys() {
    _keymap.clear();
}

CCKEX_API void dump_tls_keys_to_file() {

	std::ofstream file(config_get_tls_keylog_file(), std::ios::out | std::ios::app);

	if(!file.is_open()) {
		LOG_ERROR << "Failed to open TLS key file: " << config_get_tls_keylog_file() << std::endl;
		return;
	}

	// Dump Client Secrets

	ccData::ccbuffer_list_map_t::iterator map_iter = _keymap.find(ccData::TLS::TLSClientTrafficSecret::getCCStreamDelimiter());
	if(map_iter == _keymap.end()) {
		LOG_WARN << "No Client TLS Keys found." << std::endl;
		return;
	}

	ccData::TLS::TLSClientTrafficSecret traffic_secret;
	for(ccData::ccbuffer_list_t::iterator list_iter = map_iter->second.begin(); list_iter != map_iter->second.end(); ++list_iter) {

		traffic_secret = ccData::TLS::TLSClientTrafficSecret(list_iter->second);

		if(!traffic_secret.dataValid()) {
			LOG_WARN << "Invalid client key: '" << ccData::byteBufferToString(traffic_secret.begin(), traffic_secret.end()) << "'" << std::endl;
			continue;
		}

		file << traffic_secret.toHandshakeTrafficSecret();
		file << traffic_secret.toClientTrafficSecret();
	}

	// Dump Server Secrets
	
	map_iter = _keymap.find(ccData::TLS::TLSServerTrafficSecret::getCCStreamDelimiter());
	if(map_iter == _keymap.end()) {
		LOG_WARN << "No Server TLS Keys found." << std::endl;
		return;
	}

	ccData::TLS::TLSServerTrafficSecret server_traffic_secret;
	for(ccData::ccbuffer_list_t::iterator list_iter = map_iter->second.begin(); list_iter != map_iter->second.end(); ++list_iter) {

		server_traffic_secret = ccData::TLS::TLSServerTrafficSecret(list_iter->second);

		if(!server_traffic_secret.dataValid()) {
			LOG_WARN << "Invalid server key: '" << ccData::byteBufferToString(server_traffic_secret.begin(), server_traffic_secret.end()) << "'" << std::endl;
			continue;
		}

		file << server_traffic_secret.toHandshakeTrafficSecret();
		file << server_traffic_secret.toServerTrafficSecret();
	}

	// TODO: reload package dissection
}

//
// NOTE: This function is not used anymore. It is part of the payload encryption.
//

/*extern "C" {

#include <wsutil/wsgcrypt.h>
#include <wsutil/rsa.h>

static void _decrypt_and_set_out_key(uint8_t *cipher_buf, size_t cipher_buf_size) {

    size_t cipher_buf_size = 256;
    uint8_t cipher_buf[] = {
	0x73, 0x33, 0x58, 0xa6, 0x8a, 0x8f, 0xe7, 0xd2, 0xf5, 0x6c, 0x82, 0xfc,
        0xb7, 0x79, 0xc3, 0x78, 0x01, 0xc6, 0x77, 0x46, 0x37, 0xc4, 0x7a, 0xed,
	0xb0, 0xdd, 0x27, 0x0a, 0x9b, 0x3e, 0xb3, 0x43, 0x7c, 0xba, 0x53, 0xbb,
	0x10, 0xa5, 0x4f, 0xe1, 0xdf, 0x36, 0x33, 0x08, 0x5e, 0xbb, 0x65, 0x2d,
	0xf8, 0x66, 0xf0, 0xb0, 0xbd, 0xd9, 0x96, 0x72, 0xf6, 0x19, 0x53, 0xdf,
	0x31, 0x94, 0x3a, 0x82, 0xc2, 0xc5, 0xf7, 0x03, 0x76, 0x6c, 0x98, 0xda,
	0x4f, 0x90, 0xd3, 0x13, 0x50, 0x72, 0xab, 0x96, 0x58, 0xe3, 0x13, 0xd2,
	0xd4, 0xec, 0xae, 0x07, 0xa0, 0xea, 0x76, 0xa6, 0x64, 0x03, 0x82, 0x01,
	0xec, 0xbc, 0x28, 0xf3, 0x31, 0xc5, 0x96, 0x79, 0xa8, 0xea, 0x4f, 0xcd,
	0x51, 0xd9, 0x28, 0x2b, 0xf8, 0xd9, 0xb4, 0x17, 0x92, 0x40, 0x15, 0x54,
	0xd5, 0x28, 0xc0, 0xc6, 0x10, 0xee, 0x71, 0xf7, 0xf9, 0xcd, 0x2b, 0x7f,
	0x88, 0xf1, 0x9c, 0x5b, 0x63, 0xf8, 0xa7, 0x70, 0xc2, 0xc0, 0x76, 0x69,
	0x3a, 0x64, 0xd8, 0xf4, 0xa7, 0xa4, 0xf6, 0x50, 0x46, 0x0b, 0x56, 0x4d,
	0x80, 0x94, 0x1d, 0x2a, 0x96, 0xb0, 0xad, 0x14, 0x0c, 0x3a, 0xda, 0xe3,
	0xd1, 0x5f, 0xc7, 0x45, 0x1b, 0x7e, 0xb7, 0x41, 0xcb, 0x05, 0xbc, 0xfc,
	0xbc, 0x3d, 0xa6, 0x24, 0x7c, 0xf6, 0xf9, 0xa6, 0xcc, 0x27, 0xd2, 0x5e,
	0x93, 0xbb, 0xbe, 0x40, 0x15, 0xd5, 0xed, 0xae, 0x1c, 0xbc, 0x6d, 0xe8,
	0xe4, 0x5c, 0x15, 0x95, 0x89, 0xd4, 0x8a, 0xeb, 0x87, 0x1a, 0x57, 0x5a,
	0xc4, 0x5a, 0xc3, 0x8b, 0xd2, 0x0e, 0xb4, 0x25, 0xed, 0x33, 0x2e, 0xbb,
	0xde, 0xc9, 0xa6, 0x42, 0xdc, 0xe7, 0x1b, 0xa7, 0xa1, 0x4c, 0xaf, 0x05,
	0xdd, 0x27, 0x44, 0xbf, 0x6b, 0xe6, 0xa4, 0x8e, 0x05, 0xa4, 0xea, 0x73,
	0x82, 0x20, 0x8a, 0xaf
    };

    char *err_msg = (char*)"\0";

    FILE *pk_pem_fp = fopen("/home/sven/Dokumente/Uni/BA/kernel-kexfil/src/custom_kernel_module/keys/priv.pem", "r");
    if(!pk_pem_fp) {
	printf("[%s] unable to open pk pem file\n", __func__);
	return;
    }

    gnutls_x509_privkey_t pk_x509 = rsa_load_pem_key(pk_pem_fp, &err_msg);
    if(err_msg) {
	printf("[%s] privkey to sexp failed: %s\n", __func__, err_msg);
	return;
    }

    fclose(pk_pem_fp);

    err_msg = (char*)"\0";
    gcry_sexp_t pk = rsa_privkey_to_sexp(pk_x509, &err_msg);

    if(err_msg) {
	printf("[%s] privkey to sexp failed: %s\n", __func__, err_msg);
	return;
    }

    err_msg = (char*)"\0";
    rsa_decrypt_inplace(cipher_buf_size, cipher_buf, pk, false, &err_msg);

    if(err_msg) {
	printf("[%s] rsa decryption failed: %s\n", __func__, err_msg);
	return;
    }

    printf("[%s] decrypted out key buf: ", __func__);
    for(size_t i = 0; i < cipher_buf_size; i++) {
	printf("%.02x", cipher_buf[i]);
    }
    printf("\n");

    _out_enc_key = cipher_buf;
    _out_enc_iv = cipher_buf + _out_enc_key_size;

}

}*/

static void _log_key(ccData::CCBuffer &buf) {
	if(buf.dataValid()) {
		//LOG_INFO << "Found key: " << buf.toString() << std::endl;
	} else {
		LOG_INFO << "Found invalid data: " << ccData::byteBufferToString(buf.begin(), buf.end()) << std::endl;
	}
}

void load_keys_from_byte_vector(const std::vector<uint8_t> &vec, ccdata_list_t &ccdata_list) {

    //_decrypt_and_set_out_key();

    unsigned state = 0;
    //unsigned crypto_state = 0;
    size_t size_to_extract = 0;

    ccdata_list_t::iterator ccdata_iter = ccdata_list.begin();
    ccdata_list_t::iterator tmp_ccdata_iter;
    unsigned cur_byte_index = 0;
    unsigned pkg_counter = 0;
	(void)pkg_counter;
    nstime_t delta_time;
	(void)delta_time;
	uint16_t current_delimiter;



    std::vector<uint8_t>::const_iterator iter = vec.begin();
    for(; iter != vec.end(); ++iter) {

		if(cur_byte_index == ccdata_iter->second.end_index) {
		    ++ccdata_iter;
		}

		// disable per payload encryption for now
		/*if(*iter == 0xcc) {
		    crypto_state += 1;
		} else if(crypto_state >= 2) {

		    std::vector<uint8_t>::const_iterator tmp_iter = iter;
		    std::cout << "[" << __func__ << "] reading rsa encrypted out key: ";
			for(size_t i = 0; i < cipher_buf_size; i++) {
				cipher_buf[i] = *tmp_iter++;
				printf("%02x", cipher_buf[i]);
			}
		    std::cout << std::endl;

			//_decrypt_and_set_out_key(cipher_buf, cipher_buf_size);

		    crypto_state = 0;
		} else {
		    crypto_state = 0;
		}*/

		//LOG_INFO << "iter = " << *iter << " state = " << state << std::endl;

		if(state == 0 && *iter == 0xff) {
			state += 1;
			current_delimiter = 0xff00;
		} else if(state == 1 && (*iter == 0xff || *iter == 0xfe || *iter == 0xfd || *iter == 0xfc)) {
			state += 1;
			current_delimiter |= (uint16_t)*iter;
		} else if(state >= 2) {
		    size_to_extract = *iter;
			++iter;
		    if(iter == vec.end()) break;


			size_t size_to_copy = std::min(size_to_extract, static_cast<size_t>(std::distance(iter, vec.end())));

			ccData::CCBuffer ccbuf;
			ccbuf.resize(size_to_extract);
			std::copy_n(iter, size_to_copy, ccbuf.begin());

			// depending on delimiter load different key
			if(current_delimiter == ccData::Signal::SignalSealedSenderKey::getCCStreamDelimiter()) {
				ccData::Signal::SignalSealedSenderKey keyData(ccbuf);
				_log_key(keyData);
				_keymap[current_delimiter][keyData.getKeyId()] = keyData;
			} else if(current_delimiter == ccData::Signal::SignalMessageKey::getCCStreamDelimiter()) {
				ccData::Signal::SignalMessageKey keyData(ccbuf);
				_log_key(keyData);
				_keymap[current_delimiter][keyData.getKeyId()] = keyData;
			} else if(current_delimiter == ccData::TLS::TLSClientTrafficSecret::getCCStreamDelimiter()) {
				ccData::TLS::TLSClientTrafficSecret keyData(ccbuf);
				_log_key(keyData);
				_keymap[current_delimiter][keyData.getKeyId()] = keyData;
			} else if(current_delimiter == ccData::TLS::TLSServerTrafficSecret::getCCStreamDelimiter()) {
				ccData::TLS::TLSServerTrafficSecret keyData(ccbuf);
				_log_key(keyData);
				_keymap[current_delimiter][keyData.getKeyId()] = keyData;
			} else {
				LOG_ERROR << "Unknown cc stream delimiter: " << std::hex << current_delimiter << std::dec << std::endl;
				// TODO: catch cases where the delimiter is malformed e.g. 0xff 0ff 0xfe should not be recognized
				//		 right now because of the reset of state to 0
				state = 0;
				continue;
			}


			// key was extracted -> find last relevant ccdata entry
	    	/*pkg_counter = 3;
			tmp_ccdata_iter = ccdata_iter;
			while(tmp_ccdata_iter != ccdata_list.end() && tmp_ccdata_iter->second.end_index <= cur_byte_index + size_to_extract) {
			    std::cout << pkg_counter << " -> ";
				for(unsigned i = 0; i < tmp_ccdata_iter->second.data.size(); i++)
				std::cout << std::hex << (int)tmp_ccdata_iter->second.data[i] << std::dec;
				std::cout << std::endl;
			    ++tmp_ccdata_iter;
				++pkg_counter;
			}

			if(tmp_ccdata_iter == ccdata_list.end()) {
			    std::cout << "[" << __func__ << "] tmp_ccdata_item == end() .. something broke" << std::endl;
			    return;
			}

			nstime_delta(&delta_time, &tmp_ccdata_iter->second.rel_time, &ccdata_iter->second.rel_time);

			std::cout << "cckex [" << __func__ << "] pkg_count=" << std::dec << pkg_counter << " s_delta=" << delta_time.secs << " ns_delta=" << delta_time.nsecs << std::endl;*/

		    state = 0;
		} else {
		    state = 0;
		}

		cur_byte_index++;
    }

}
