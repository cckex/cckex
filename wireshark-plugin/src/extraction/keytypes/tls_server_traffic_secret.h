
#pragma once

#include "ccbuffer.h"

#include <array>

#include "message_dissection/keylist.h"
#include "tls_common.h"

namespace ccData {
namespace TLS {

class TLSServerTrafficSecret : public CCBuffer {
 public:

	TLSServerTrafficSecret() : CCBuffer() {}
	TLSServerTrafficSecret(const CCBuffer &buffer) : CCBuffer(buffer) {}

	~TLSServerTrafficSecret() {}

	bool dataValid() override { return this->size() >= this->expectedSize(); }

	client_random_t getClientRandom();
	traffic_secret_t getTrafficSecret();
	handshake_secret_t getHandshakeSecret();

	static size_t	expectedSize() { return CLIENT_RANDOM_SIZE + TRAFFIC_SECRET_SIZE; }	
	static uint16_t getCCStreamDelimiter() { return 0xfffc; }

	std::string toString() override;
	std::string toServerTrafficSecret();
	std::string toHandshakeTrafficSecret();

 protected:

};

}	// namespace TLS 
}	// namespace ccData
