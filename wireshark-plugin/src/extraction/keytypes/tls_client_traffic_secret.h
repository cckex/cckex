
#pragma once

#include "ccbuffer.h"

#include <array>

#include "message_dissection/keylist.h"
#include "tls_common.h"

namespace ccData {
namespace TLS {

class TLSClientTrafficSecret : public CCBuffer {
 public:

	TLSClientTrafficSecret() : CCBuffer() {}
	TLSClientTrafficSecret(const CCBuffer &buffer) : CCBuffer(buffer) {}

	~TLSClientTrafficSecret() {}

	bool	dataValid() override { return this->size() >= this->expectedSize(); }

	client_random_t getClientRandom();
	traffic_secret_t getTrafficSecret();
	handshake_secret_t getHandshakeSecret();

	static size_t	expectedSize() { return CLIENT_RANDOM_SIZE + TRAFFIC_SECRET_SIZE; }	
	static uint16_t getCCStreamDelimiter() { return 0xfffd; }

	std::string toString() override;
	std::string toClientTrafficSecret();
	std::string toHandshakeTrafficSecret();

 protected:

};

}	// namespace TLS 
}	// namespace ccData
