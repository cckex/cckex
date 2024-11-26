
#pragma once

#include "common.h"
#include "extraction/ccdatamanager.h"

#ifdef __cplusplus

#include <memory>
#include <string>
#include <vector>
#include <map>

namespace ccStats {

typedef struct {
	uint64_t data;
} stats_cell_data_t;

typedef std::shared_ptr<stats_cell_data_t> stats_cell_data_ptr_t;

typedef std::map<uint32_t, stats_cell_data_ptr_t> stats_pnum_lut_t;
typedef std::map<cckex_level_t, stats_pnum_lut_t> stats_level_lut_t;
typedef std::map<std::string, stats_level_lut_t> stats_column_lut_t;

stats_cell_data_ptr_t stats_get_or_create_data(std::string column_name, cckex_level_t level, uint32_t pnum);
void stats_set_data(std::string column_name, cckex_level_t level, uint32_t pnum, stats_cell_data_t data);

void dump_to_csv_file();

}	// namespace ccStats

#endif	// __cplusplus

CCKEX_API void cckex_stats_add_to_column(const char* column_name, cckex_level_t, uint32_t pnum, uint32_t data); 
