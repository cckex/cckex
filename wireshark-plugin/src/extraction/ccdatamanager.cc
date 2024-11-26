#include "extraction/ccdatamanager.h"

#include <algorithm>
#include <iterator>
#include <cstdio>
#include <vector>
#include <array>
#include <map>

#include "message_dissection/signalmessagecrypto.h"
#include "ui/uihandler.h"

// TODO: wrap this stuff in a namespace

ccdata_lists_t ccdata_lists;

ccdata_list_t get_or_create_ccdata_list(uint32_t level) {
	
	// check if list already exists ..
	ccdata_lists_t::iterator iter = ccdata_lists.find(level);
	if(iter != ccdata_lists.end()) {
		return iter->second;
	}

	// .. or create list
	return ccdata_list_t{};
}

ccdata_t get_or_create_ccdata(ccdata_list_t list, uint32_t pkgnum, nstime_t time) {

    ccdata_t ccdata = { .data = { }, .data_bits_size = 0, .data_size = 0, .rel_time = time, .start_index = 0,
		.end_index = 0, .position = std::vector<int32_t> {} };

    // check if entry for this packet already exists
    ccdata_list_t::iterator iter = list.find(pkgnum);
    if(iter != list.end()) {
		ccdata = iter->second;
    }

	return ccdata;
}

ccdata_t get_or_create_ccdata(uint32_t level, uint32_t pkgnum, nstime_t time) {
	return get_or_create_ccdata(get_or_create_ccdata_list(level), pkgnum, time);
}

void save_ccdata(uint32_t level, uint32_t pkgnum, ccdata_t data) {
	ccdata_lists[level][pkgnum] = data;	
}

bool ccdata_exists(uint32_t level, uint32_t num) {
	ccdata_lists_t::iterator list_iter = ccdata_lists.find(level);
	if(list_iter == ccdata_lists.end()) return false;
	ccdata_list_t::iterator iter = list_iter->second.find(num);
	if(iter == list_iter->second.end()) return false;
	return true;
}

CCKEX_API void insert_data(uint32_t level, uint32_t num, uint8_t newdata, uint8_t bits_size, nstime_t time) {
	return insert_data_with_position(level, num, newdata, bits_size, time, -1);
}

CCKEX_API void insert_data_with_position(uint32_t level, uint32_t num, uint8_t newdata, uint8_t bits_size, nstime_t time, int32_t pos) {

    (void) newdata;
    (void) bits_size;

	if(bits_size != 8) {
		CLOG_ERROR("bits_size != 8 currently not supported (bits_size=%u)", bits_size);
		return;
	}

	ccdata_t ccdata = get_or_create_ccdata(level, num, time);
	
	if (pos >= 0) ccdata.position.push_back(pos);

    // add new bits to the saved cc data (checking for byte overflow)
    /*size_t size = ccdata.data_bits_size % 8;
    if(size + bits_size > 8) { // check for overflow to next byte
	// fill up last byte
	ccdata.data.back() |= newdata << size;
	// add new byte
	ccdata.data.push_back(0);
	newdata >>= size;
	size = 0;
    }

    ccdata.data.back() |= newdata;
    ccdata.data_bits_size += bits_size;*/

    //std::cout << "[" << __func__ << "] cur_data: ";
    //for(uint8_t i : ccdata.data) printf("%02x", i);
    //printf(" newdata=%02x\n", newdata);

    ccdata.data.push_back(newdata);

    // write changes to list
	save_ccdata(level, num, ccdata);
}

CCKEX_API void insert_data_buf(uint32_t level, uint32_t num, uint8_t* buf, size_t buf_len, nstime_t time) {
	return insert_data_buf_with_position(level, num, buf, buf_len, time, -1);
}

CCKEX_API void insert_data_buf_with_position(uint32_t level, uint32_t num, uint8_t* buf, size_t buf_len, nstime_t time, int32_t pos) {

    // check if entry for this packet already exists (which would mean that it was already extracted)
    if(ccdata_exists(level, num)) return;

    ccdata_t ccdata = get_or_create_ccdata(level, num, time);

    // add new bits to the saved cc
    for(size_t i = 0; i < buf_len; i++) {
		ccdata.data.push_back(buf[i]);
		if(pos >= 0) ccdata.position.push_back(pos++);
    }

	save_ccdata(level, num, ccdata);
}

CCKEX_API void delete_data(uint32_t level, uint32_t num) {
	if(entry_exists(level, num)) {
		ccdata_lists[level].erase(ccdata_lists[level].find(num));
		reset_ccdata();
	}
}


CCKEX_API int entry_exists(uint32_t level, uint32_t num) {
	return ccdata_exists(level, num) ? 1 : 0; 
}

size_t merge_byte_vector_helper(std::vector<uint8_t> &v1, size_t v1_bits_size,
			      std::vector<uint8_t> &v2, size_t v2_bits_size) {

    if(v1_bits_size % 8 == 0) {
		v1.insert(v1.end(), v2.begin(), v2.end());
    } else {
		size_t bit_offset = v1_bits_size % 8;

		for(std::vector<uint8_t>::iterator iter = v2.begin(); iter != v2.end(); ++iter) {
			v1.back() |= *iter << bit_offset;
			v1.push_back(0);
			v1.back() |= *iter >> bit_offset;
		}

		if(bit_offset + (v2_bits_size % 8) <= 8) v1.pop_back();
    }

    return v1_bits_size + v2_bits_size;
}

CCKEX_API void check_for_new_keys() {

    size_t extracted_data_bits_size = 0;
    std::vector<uint8_t> extracted_data;

	LOG_INFO << "Checking for new Keys .." << std::endl;

    // check the normal cc data

    // merge all extracted data into one big vector
    /*iter = ccdata_per_packet.begin();
    for(; iter != ccdata_per_packet.end(); ++iter) {
	iter->second.start_index = extracted_data.size();
	printf("test:%i %i\n", iter->first, iter->second.data[0]);

	std::cout << "merge: v1=";
	for(size_t i = 0; i < extracted_data.size(); i++) {
	    std::cout << std::setfill('0') << std::setw(2) << std::hex << (int)extracted_data.at(i) << std::dec;
	}
	std::cout << " v2=";
	for(size_t i = 0; i < iter->second.data.size(); i++) {
	    std::cout << std::setfill('0') << std::setw(2) << std::hex << (int)iter->second.data.at(i) << std::dec;
	}
	std::cout << std::endl;

	extracted_data_bits_size = merge_byte_vector_helper(
	    extracted_data, extracted_data_bits_size,
	    iter->second.data, iter->second.data_bits_size);
	iter->second.end_index = extracted_data.size();
    }

    if(extracted_data.size()) {
		for(size_t byte_offset = 0; byte_offset < 8; byte_offset++) {
		    std::cout << "[" << __func__ << "] extracted_data byte_offset=" << byte_offset << std::endl;

		    // print vector
			printf("[%s] cc extracted data: ", __func__);
		    for(std::vector<uint8_t>::iterator viter = extracted_data.begin(); viter != extracted_data.end(); ++viter) {
				printf("%.02x", *viter);
		    }
		    printf("\n");

			if(byte_offset == 0) Ui::UiHandler::getInstance()->addRawCCData(Ui::UiCCType::CLASSIC, extracted_data);

		    load_keys_from_byte_vector(extracted_data, ccdata_per_packet, Ui::UiCCType::CLASSIC);

		    // move buffer left one byte
			for(size_t i = 1; i < extracted_data.size(); i++) {
				extracted_data[i] >>= 1;
				extracted_data[i] &= ~0x80;
				extracted_data[i] |= extracted_data[i + 1] << 7;
		    }
        }
    }*/


	// TODO: this breaks with payloads which size is not 8 byte aligned
	// for now assume that the size of all extracted payloads from all packages are byte aligned

	ccdata_lists_t::iterator list_iter = ccdata_lists.begin();
	ccdata_list_t current_list;

	std::vector<uint8_t> last_data;

	std::vector<ccdata_t> ccdata_vector;
	std::vector<ccdata_t> ccdata_subvec;
	std::vector<ccdata_t>::iterator iter;

	for(; list_iter != ccdata_lists.end(); ++list_iter) {
		
		extracted_data.clear();
		extracted_data_bits_size = 0;

		ccdata_vector.clear();
		last_data.clear();

		current_list = list_iter->second;

		// TODO: activate / deactivate position sorting

		// sort current list -> always sort sections from index = 0 to the next index = 0
		// TODO: catch edgecast last index of previous section and index = 0 entry are swapped
		iter = ccdata_vector.begin();
		for(ccdata_list_t::iterator cur_iter = current_list.begin(); cur_iter != current_list.end(); ++cur_iter) {

			if(cur_iter->second.position.size() == 0 || cur_iter->second.position[0] == 0) {
				std::sort(ccdata_subvec.begin(), ccdata_subvec.end(), [](const ccdata_t &d1, const ccdata_t &d2){
						//LOG_INFO << "compare call: " << d1.position.size() << " " << d2.position.size() << std::endl;
						int32_t i1 = d1.position.size() ? d1.position[0] : 0;
						int32_t i2 = d2.position.size() ? d2.position[0] : 0;
						return i1 < i2;
					});
				ccdata_vector.insert(ccdata_vector.end(), ccdata_subvec.begin(), ccdata_subvec.end());
				ccdata_subvec.clear();
			}

			ccdata_subvec.insert(ccdata_subvec.end(), cur_iter->second);

		}

		// merge extracted data which was injected into signal packets
		iter = ccdata_vector.begin();
		for(; iter != ccdata_vector.end(); ++iter) {
	
			if(last_data.size() != 0 && last_data.size() == iter->data.size()) {
				if(last_data == iter->data) {
					//LOG_INFO << "Detected duplicate data: " << ccData::byteBufferToString(last_data.begin(), last_data.end()) << std::endl;
					continue;
				}
			} else {
				last_data.resize(iter->data.size());
			}

			std::copy_n(iter->data.begin(), iter->data.size(), last_data.begin());

			// set start index for benchmarking
			iter->start_index = extracted_data.size();
			
			extracted_data_bits_size = merge_byte_vector_helper(
				extracted_data, extracted_data_bits_size,
				iter->data, iter->data_bits_size);

			// insert positions accordingly

			// set end index for benchmarking
			iter->end_index = extracted_data.size();
		}

		/*printf("[%s] extracted data: ", __func__);
		for(std::vector<uint8_t>::iterator viter = extracted_data.begin(); viter != extracted_data.end(); ++viter) {
			printf("%.02x", *viter);
		}
		printf("\n");*/

		// TODO: add levels in the ui
		load_keys_from_byte_vector(extracted_data, current_list); 
	}
}

CCKEX_API void reset_ccdata() {
    ccdata_lists[CCKEX_LEVEL_CLEAR].clear();
}
