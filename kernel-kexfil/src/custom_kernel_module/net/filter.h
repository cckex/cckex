#pragma once

#include "../chardev.h"

int cckex_register_filter(void);
void cckex_unregister_filter(void);

long cckex_change_filter (const cckex_ioctl_filter_mode_t *filter_mode);
