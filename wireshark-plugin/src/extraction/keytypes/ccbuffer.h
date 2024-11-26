
#pragma once

#include <iterator>
#include <sstream>
#include <cstdint>
#include <iomanip>
#include <vector>
#include <string>

namespace ccData {

template<class Iterator>
std::string byteBufferToString(Iterator begin, Iterator end) {
	std::stringstream sstr;

	sstr << std::hex;
	for(Iterator it = begin; it != end; ++it) {
		sstr << std::setw(2) << std::setfill('0') << (int)*it;
	}

	return sstr.str();
}

template<class Iterator>
uint32_t byteBufferToId(Iterator begin, Iterator end) {
	Iterator it = begin;
	uint32_t ret = 0;

	for(size_t i = 0; i < 4 && it != end; i++, ++it) {
		ret <<= 8;
		ret |= (uint32_t)*it;
	}

	return ret;
}

class CCBuffer : public std::vector<uint8_t> {
 public:

	CCBuffer() {}
	CCBuffer(std::vector<uint8_t> &vec) { this->insert(this->end(), vec.begin(), vec.end()); }

	virtual ~CCBuffer() {}

	virtual bool dataValid() { return this->size() > 0; }
	virtual uint32_t getKeyId() { return byteBufferToId(this->begin(), this->end()); }

	static size_t	expectedSize() { return 0; }
	static uint16_t getCCStreamDelimiter() { return 0xffff; }

	virtual std::string toString() { return byteBufferToString(this->begin(), this->end()); }

 protected:

};

}	// namespace ccData
