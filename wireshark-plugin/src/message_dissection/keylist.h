#pragma once

#ifdef __cplusplus

#include<stdint.h>
#include<array>
#include<map>

#include "extraction/keytypes/ccbuffer.h"

namespace ccData {

// can contain any type of CCBuffer
typedef std::map<uint32_t, CCBuffer> ccbuffer_list_t;
// can contain multiple different CCBuffer lists differentiated by their respective delimiter
typedef std::map<uint16_t, ccbuffer_list_t> ccbuffer_list_map_t;

}	// namespace ccData

#endif
