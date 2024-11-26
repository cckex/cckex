
#pragma once

#include <epan/prefs.h>

void cckex_register_signal_websocket_dissector(module_t *module);
void cckex_handoff_signal_websocket_dissector(void);
