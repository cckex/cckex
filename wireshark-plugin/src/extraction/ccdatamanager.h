#pragma once

#include <stdint.h>
#include <wsutil/nstime.h>

#include "common.h"

#define CCKEX_LEVEL_CLEAR			0

#define CCKEX_LEVEL_TLS				1

#define CCKEX_LEVEL_SIGNAL_SSNDR	2
#define CCKEX_LEVEL_SIGNAL_MSG		3

typedef uint32_t cckex_level_t;

#if __cplusplus

#include <vector>
#include <map>

typedef struct {
    std::vector<uint8_t> data;
    size_t data_bits_size;
    size_t data_size;

    nstime_t rel_time;

    unsigned start_index;
    unsigned end_index;

	std::vector<int32_t> position;

} ccdata_t;

typedef std::map<uint32_t, ccdata_t> ccdata_list_t;
typedef std::map<uint32_t, ccdata_list_t> ccdata_lists_t;


#endif

CCKEX_API void insert_data(uint32_t level, uint32_t num, uint8_t data, uint8_t bits_size, nstime_t time);
CCKEX_API void insert_data_buf(uint32_t level, uint32_t num, uint8_t* buf, size_t buf_len, nstime_t time);
CCKEX_API void insert_data_with_position(uint32_t level, uint32_t num, uint8_t data, uint8_t bits_size, nstime_t time, int32_t pos);
CCKEX_API void insert_data_buf_with_position(uint32_t level, uint32_t num, uint8_t* buf, size_t buf_len, nstime_t time, int32_t pos);

CCKEX_API void delete_data(uint32_t level, uint32_t num);

CCKEX_API int entry_exists(uint32_t level, uint32_t num);

CCKEX_API void check_for_new_keys(void);
CCKEX_API void reset_ccdata(void);
