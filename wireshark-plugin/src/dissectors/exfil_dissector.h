
#pragma once

#include <epan/prefs.h>

#include "common.h"

CCKEX_API void cckex_register_exfil_dissector(module_t *module);
CCKEX_API void cckex_handoff_exfil_dissector(void);
