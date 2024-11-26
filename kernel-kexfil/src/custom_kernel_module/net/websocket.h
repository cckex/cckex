#pragma once

#include <linux/skbuff.h>

int cckex_websocket_is_masked(uint8_t *payload, size_t payload_len);
int cckex_websocket_unmask_payload(uint8_t *payload, size_t payload_len);
int cckex_websocket_mask_payload(uint8_t *payload, size_t payload_len);
