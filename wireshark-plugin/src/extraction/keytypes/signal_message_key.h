
#pragma once

#include "ccbuffer.h"

#include <array>

#include "message_dissection/keylist.h"
#include "signal_common.h"


namespace ccData {
namespace Signal {

class SignalMessageKey : public SignalKey {
 public:

	SignalMessageKey() : SignalKey() {}
	SignalMessageKey(const CCBuffer &ccbuffer) : SignalKey(ccbuffer) {}
	SignalMessageKey(const SignalKey &signalKey) : SignalKey(signalKey) {}

	~SignalMessageKey() {}

	bool	dataValid() override { return this->size() >= this->expectedSize(); }

	id_t getId();
	key_t getKey();
	iv_t getIv();

	static size_t	expectedSize() { return ID_BYTE_SIZE + KEY_BYTE_SIZE + IV_BYTE_SIZE; }	
	static uint16_t getCCStreamDelimiter() { return 0xffff; }

	std::string toString() override;

 protected:

};

}	// namespace Signal
}	// namespace ccData
