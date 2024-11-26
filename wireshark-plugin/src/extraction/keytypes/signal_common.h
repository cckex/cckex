
#pragma once

#include "ccbuffer.h"

namespace ccData {
namespace Signal {

const size_t ID_BYTE_SIZE  = 4;
const size_t KEY_BYTE_SIZE = 32;
const size_t IV_BYTE_SIZE  = 16;

// specific types for the keylist
typedef std::array<uint8_t, ID_BYTE_SIZE>  id_t;
typedef std::array<uint8_t, KEY_BYTE_SIZE> key_t;
typedef std::array<uint8_t, IV_BYTE_SIZE>  iv_t;

class SignalKey : public CCBuffer {
 public:

	SignalKey() {}
	SignalKey(const CCBuffer &ccbuffer) : CCBuffer(ccbuffer) {}

	virtual ~SignalKey() {}

	id_t getId() const { return id_t{}; }
};

}
}		// namespace ccData
