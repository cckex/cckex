
#pragma once

#include <array>

#include "message_dissection/keylist.h"
#include "signal_common.h"

namespace ccData {
namespace Signal {

class SignalSealedSenderKey : public SignalKey {
 public:

	SignalSealedSenderKey() : SignalKey() {}
	SignalSealedSenderKey(const CCBuffer &ccbuffer) : SignalKey(ccbuffer) {}
	SignalSealedSenderKey(const SignalKey &signalKey) : SignalKey(signalKey) {}

	~SignalSealedSenderKey() {}
	
	bool	dataValid() override { return this->size() >= this->expectedSize(); }

	id_t getId();
	key_t getKey();

	static size_t	expectedSize() { return ID_BYTE_SIZE + KEY_BYTE_SIZE; }	
	static uint16_t getCCStreamDelimiter() { return 0xfffe; }

	std::string toString() override;

 protected:

};

}	// namespace Signal
}	// namespace ccData
