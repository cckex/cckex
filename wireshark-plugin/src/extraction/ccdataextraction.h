#pragma once

#include <epan/tvbuff.h>
#include <epan/packet.h>

#include "common.h"

CCKEX_API void init_ccKex_extraction_dissector(int proto_ccKex_exfil, int ett_ccKex_exfil);

CCKEX_API int dissect_ccKex_key(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_);

