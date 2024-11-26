#include "signal_sealed_sender_key.h"

#include <algorithm>

namespace ccData {
namespace Signal {

id_t SignalSealedSenderKey::getId() {
	id_t id;
	std::copy_n(this->begin(), ID_BYTE_SIZE, id.begin());
	return id;
}

key_t SignalSealedSenderKey::getKey() {
	key_t key;
	std::copy_n(this->begin() + ID_BYTE_SIZE, KEY_BYTE_SIZE, key.begin());
	return key;
}

std::string SignalSealedSenderKey::toString() {

	id_t id = getId();
	key_t key = getKey();

	return byteBufferToString(id.begin(), id.end()) + " " + byteBufferToString(key.begin(), key.end());
}

}	// namespace Signal
}	// namespace ccData
