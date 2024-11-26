#include "tls_server_traffic_secret.h"

#include <algorithm>

namespace ccData {
namespace TLS {

client_random_t TLSServerTrafficSecret::getClientRandom() {
	client_random_t crandom;
	std::copy_n(this->begin(), CLIENT_RANDOM_SIZE, crandom.begin());
	return crandom;
}

traffic_secret_t TLSServerTrafficSecret::getTrafficSecret() {
	traffic_secret_t secret;
	std::copy_n(this->begin() + CLIENT_RANDOM_SIZE, TRAFFIC_SECRET_SIZE, secret.begin());
	return secret;
}

handshake_secret_t TLSServerTrafficSecret::getHandshakeSecret() {
	handshake_secret_t secret;
	std::copy_n(this->begin() + CLIENT_RANDOM_SIZE + TRAFFIC_SECRET_SIZE, HANDSHAKE_SECRET_SIZE, secret.begin());
	return secret;
}	

std::string TLSServerTrafficSecret::toString() {

	client_random_t random = getClientRandom();
	traffic_secret_t secret = getTrafficSecret();
	handshake_secret_t hsecret = getHandshakeSecret();

	return byteBufferToString(random.begin(), random.end()) + " " +
		   byteBufferToString(secret.begin(), secret.end()) + " " +
		   byteBufferToString(hsecret.begin(), hsecret.end());
}

std::string TLSServerTrafficSecret::toServerTrafficSecret() {
	client_random_t random = getClientRandom();
	traffic_secret_t secret = getTrafficSecret();
	return "SERVER_TRAFFIC_SECRET_0 " +
		   byteBufferToString(random.begin(), random.end()) + " " +
		   byteBufferToString(secret.begin(), secret.end()) + "\n";
}

std::string TLSServerTrafficSecret::toHandshakeTrafficSecret() {
	client_random_t random = getClientRandom();
	handshake_secret_t hsecret = getHandshakeSecret();
	return "SERVER_HANDSHAKE_TRAFFIC_SECRET " +
		   byteBufferToString(random.begin(), random.end()) + " " +
		   byteBufferToString(hsecret.begin(), hsecret.end()) + "\n";
}


}	// namespace TLS 
}	// namespace ccData
