#include "tls_client_traffic_secret.h"

#include <algorithm>

namespace ccData {
namespace TLS {

client_random_t TLSClientTrafficSecret::getClientRandom() {
	client_random_t crandom;
	std::copy_n(this->begin(), CLIENT_RANDOM_SIZE, crandom.begin());
	return crandom;
}

traffic_secret_t TLSClientTrafficSecret::getTrafficSecret() {
	traffic_secret_t secret;
	std::copy_n(this->begin() + CLIENT_RANDOM_SIZE, TRAFFIC_SECRET_SIZE, secret.begin());
	return secret;
}

handshake_secret_t TLSClientTrafficSecret::getHandshakeSecret() {
	handshake_secret_t secret;
	std::copy_n(this->begin() + CLIENT_RANDOM_SIZE + TRAFFIC_SECRET_SIZE, HANDSHAKE_SECRET_SIZE, secret.begin());
	return secret;
}	

std::string TLSClientTrafficSecret::toString() {

	client_random_t random = getClientRandom();
	traffic_secret_t secret = getTrafficSecret();
	handshake_secret_t hsecret = getHandshakeSecret();

	return byteBufferToString(random.begin(), random.end()) + " " +
		   byteBufferToString(secret.begin(), secret.end()) + " " +
		   byteBufferToString(hsecret.begin(), hsecret.end());
}

std::string TLSClientTrafficSecret::toClientTrafficSecret() {
	client_random_t random = getClientRandom();
	traffic_secret_t secret = getTrafficSecret();
	return "CLIENT_TRAFFIC_SECRET_0 " +
		   byteBufferToString(random.begin(), random.end()) + " " +
		   byteBufferToString(secret.begin(), secret.end()) + "\n";
}

std::string TLSClientTrafficSecret::toHandshakeTrafficSecret() {
	client_random_t random = getClientRandom();
	handshake_secret_t hsecret = getHandshakeSecret();
	return "CLIENT_HANDSHAKE_TRAFFIC_SECRET " +
		   byteBufferToString(random.begin(), random.end()) + " " +
		   byteBufferToString(hsecret.begin(), hsecret.end()) + "\n";
}


}	// namespace TLS 
}	// namespace ccData
