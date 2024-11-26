#pragma once

#define IOCTL_CMD_RESET			00

#define IOCTL_CMD_CHNG_CC_MODE	10

#define CCKEX_CC_MODE_ACTION_ADD    		1
#define CCKEX_CC_MODE_ACTION_REMOVE 		2

typedef struct cckex_ioctl_cc_mode {
	unsigned int action;
	unsigned int method_index;
} cckex_ioctl_cc_mode_t;

#define IOCTL_CMD_CHNG_CIPHER 	20

#define CCKEX_CIPHER_OUT_ENCRYPTION_ENABLE  1
#define CCKEX_CIPHER_OUT_ENCRYPTION_DISABLE 2

typedef struct cckex_ioctl_cipher_mode {
	unsigned int action;
} cckex_ioctl_cipher_mode_t;

#define CC_METHOD_IPHDR_FULL_TTL   0
#define CC_METHOD_IPHDR_TOS        1
#define CC_METHOD_IPHDR_IPFLAGS    2
#define CC_METHOD_IPHDR_IPID       3
#define CC_METHOD_IPHDR_IPFRAGMENT 4
#define CC_METHOD_TCPHDR_URGENT    5
#define CC_METHOD_TIMING_BER       6
#define CC_METHOD_MSG_INJ		   7

