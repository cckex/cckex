
#pragma once

#include <array>

namespace ccData {
namespace TLS {

const size_t CLIENT_RANDOM_SIZE    = 32;
const size_t TRAFFIC_SECRET_SIZE   = 48;
const size_t HANDSHAKE_SECRET_SIZE = 48;

typedef std::array<uint8_t, CLIENT_RANDOM_SIZE> client_random_t;
typedef std::array<uint8_t, TRAFFIC_SECRET_SIZE> traffic_secret_t;
typedef std::array<uint8_t, HANDSHAKE_SECRET_SIZE> handshake_secret_t;

}	// namespace TLS
}	// namespace ccData
