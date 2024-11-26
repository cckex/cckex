#include "signal_message_key.h"

#include <algorithm>

namespace ccData {
namespace Signal {

id_t SignalMessageKey::getId() {
	id_t id;
	std::copy_n(this->begin(), ID_BYTE_SIZE, id.begin());
	return id;
}

key_t SignalMessageKey::getKey() {
	key_t key;
	std::copy_n(this->begin() + ID_BYTE_SIZE, KEY_BYTE_SIZE, key.begin());
	return key;
}

iv_t SignalMessageKey::getIv() {
	iv_t iv;
	std::copy_n(this->begin() + ID_BYTE_SIZE + KEY_BYTE_SIZE, IV_BYTE_SIZE, iv.begin());
	return iv;
}

std::string SignalMessageKey::toString() {

	id_t id = getId();
	key_t key = getKey();
	iv_t iv = getIv();

	return byteBufferToString(id.begin(), id.end()) + " " +
		   byteBufferToString(key.begin(), key.end()) + " " +
		   byteBufferToString(iv.begin(), iv.end());
}

}	// namespace Signal
}	// namespace ccData
