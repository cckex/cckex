#pragma once

#include "cc/cc_common.h"

int cckex_register_chardev(void);
void cckex_unregister_chardev(void);

#define IOCTL_CMD_CHNG_FILTER 	30

typedef struct cckex_ioctl_filter_mode {

} cckex_ioctl_filter_mode_t;
