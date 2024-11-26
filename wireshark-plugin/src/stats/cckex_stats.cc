#include "cckex_stats.h"

#include <fstream>
#include <set>

namespace ccStats {

uint32_t default_data_value = 0;

stats_column_lut_t stats_map;

stats_cell_data_ptr_t stats_get_or_create_data(std::string column_name, cckex_level_t level, uint32_t pnum) {
	if(stats_map[column_name][level][pnum] == nullptr) {
		stats_set_data(column_name, level, pnum, {});
	}
	return stats_map[column_name][level][pnum];
}

void stats_set_data(std::string column_name, cckex_level_t level, uint32_t pnum, stats_cell_data_t data) {
	stats_map[column_name][level][pnum] = std::make_shared<stats_cell_data_t>(data);
}

void dump_to_csv_file() {

	std::string filepath = config_get_stats_file();

	std::ofstream file(filepath, std::ios::out);
	if(!file.is_open()) {
		LOG_WARN << "Failed to open or create file: " << filepath << std::endl;
		return;
	}

	std::map<uint32_t, std::map<std::string, stats_cell_data_ptr_t>> csv_map;
	std::map<uint32_t, std::map<std::string, stats_cell_data_ptr_t>>::iterator csv_row_iter;
	std::map<std::string, stats_cell_data_ptr_t>::iterator csv_row_col_iter;

	std::set<std::string> available_columns;
	std::set<std::string>::iterator available_column;
	std::string column_name;

	stats_level_lut_t level_map;
	stats_pnum_lut_t pkg_map;
	stats_cell_data_ptr_t data_ptr;

	// create csv as a c++ datastructure and collect all available column names
	for(stats_column_lut_t::iterator col_iter = stats_map.begin(); col_iter != stats_map.end(); ++col_iter) {
		level_map = col_iter->second;
		for(stats_level_lut_t::iterator lvl_iter = level_map.begin(); lvl_iter != level_map.end(); ++lvl_iter) {
			pkg_map = lvl_iter->second;
			for(stats_pnum_lut_t::iterator pkg_iter = pkg_map.begin(); pkg_iter != pkg_map.end(); ++pkg_iter) {
				data_ptr = pkg_iter->second;

				column_name = col_iter->first + "_" + std::to_string(lvl_iter->first);
				available_columns.insert(column_name);

				csv_map[pkg_iter->first][column_name] = data_ptr;
			}
		}
	}

	// dump csv data to actual file
	
	// dump column names
	file << "index, package_num";
	for(available_column = available_columns.begin(); available_column != available_columns.end(); ++available_column) {
		file << ", " << *available_column;
	}
	file << '\n';

	// dump data rows
	size_t row_counter = 0;
	for(csv_row_iter = csv_map.begin(); csv_row_iter != csv_map.end(); ++csv_row_iter) {
		
		// dump package_num first
		file << row_counter++ << ", " << csv_row_iter->first;

		// try all available columns
		for(available_column = available_columns.begin(); available_column != available_columns.end(); ++available_column) {
		
			file << ", ";

			csv_row_col_iter = csv_row_iter->second.find(*available_column);
			if(csv_row_col_iter == csv_row_iter->second.end()) {
				// no entry for this column found -> dump default value
				file << default_data_value;
			} else {
				file << csv_row_col_iter->second->data;
			} 
		}

		file << '\n';
	}

}

}	// namespace ccStats

CCKEX_API void cckex_stats_add_to_column(const char* column_name, cckex_level_t level, uint32_t pnum, uint32_t data) {
	LOG_WARN << "adding to column: " << column_name << std::endl;
	ccStats::stats_get_or_create_data(column_name, level, pnum)->data = data;
} 
