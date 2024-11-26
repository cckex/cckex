#pragma once

#include <linux/skbuff.h>

#include "../chardev.h"

long cckex_change_cc(const cckex_ioctl_cc_mode_t *cc_mode);
int cckex_signal_message_injection_active(void);
int cckex_http_header_injection_active(void);

int cckex_apply_cc(struct sk_buff *skb);
