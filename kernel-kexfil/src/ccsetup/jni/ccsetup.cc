// https://stackoverflow.com/questions/4893403/cant-include-c-headers-like-vector-in-android-ndk
#include <iostream>	
#include <sstream>
#include <fstream>
#include <ostream>
#include <cstdint>
#include <vector>
#include <map>

#include <sys/ioctl.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "json.hpp"
#include "argh.h"
#include "../../custom_kernel_module/cc/cc_common.h"
static void die(std::string msg) {
	perror(msg.c_str());
	exit(-1);
}

using json = nlohmann::json;

namespace CcSetup {

int ccKexChardevFd;

int init(std::string lkmChardevPath) {
	
	if((ccKexChardevFd = open(lkmChardevPath.c_str(), O_RDWR)) < 0) {
		die("failed to open " + lkmChardevPath);	
	}

	return 0;
}

void fini() {
	close(ccKexChardevFd);
}

std::map<std::string, unsigned> ccMethods2Index {
	{ "iphdr_full_ttl", CC_METHOD_IPHDR_FULL_TTL }, 
	{ "iphdr_tos"     , CC_METHOD_IPHDR_TOS },
	{ "iphdr_ipflags" , CC_METHOD_IPHDR_IPFLAGS },
	{ "iphdr_ipid"	  , CC_METHOD_IPHDR_IPID },
	{ "iphdr_ipfrag"  , CC_METHOD_IPHDR_IPFRAGMENT },
	{ "tcphdr_urgent" , CC_METHOD_TCPHDR_URGENT },
	{ "timing_ber" 	  , CC_METHOD_TIMING_BER },
	{ "msg_inj"		  , CC_METHOD_MSG_INJ }
};

bool resetLKM() {
	return ioctl(ccKexChardevFd, IOCTL_CMD_RESET, nullptr);
}

bool setupCc(cckex_ioctl_cc_mode_t mode) {
	return ioctl(ccKexChardevFd, IOCTL_CMD_CHNG_CC_MODE, &mode) == 0;
}

bool ccMethodExists(std::string method) {
	if(ccMethods2Index.contains(method)) {
		return true;
	} else {
		std::cout << "[fail] unknown cc method: " << method << std::endl;
		return false;
	}
}

void enableCC(std::string method) {
	if(!ccMethodExists(method)) return;

	if(setupCc({ CCKEX_CC_MODE_ACTION_ADD, ccMethods2Index[method] })) {
		std::cout << "[info] enabled cc method: " << method << std::endl;
	} else {
		std::cout << "[fail] unable to enable cc method: " << method << std::endl;
	}
}

void disableCC(std::string method) {
	if(!ccMethodExists(method)) return;

	if(setupCc({ CCKEX_CC_MODE_ACTION_REMOVE, ccMethods2Index[method] })) {
		std::cout << "[info] enabled cc method: " << method << std::endl;
	} else {
		std::cout << "[fail] unable to enable cc method: " << method << std::endl;
	}
}

void writeMasterSecret(std::string filepath) {
	std::ifstream msfile(filepath, std::ios::binary | std::ios::ate | std::ios::in);

	if(!msfile.is_open()) {
		std::cout << "[fail] unable to open " << filepath << std::endl;
		return;
	}

	std::ofstream lkmfile("/dev/cc_kex", std::ios::binary | std::ios::out);

	if(!lkmfile.is_open()) {
		std::cout << "[fail] unable to open lkm" << std::endl;
		return;
	}

	char data[82];
	int size = msfile.tellg();
	msfile.seekg(0, std::ios::beg);
		
	while(size >= 82) {
		size -= 82;
		std::cout << "remaining size: " << size << std::endl;
		msfile.read(data, 82);
		lkmfile.write(data, 82);
		lkmfile.flush();
	}
}

void writeHexString(std::string hexStr) {

	if(hexStr.size() % 2 == 1) {
		std::cout << "[fail] hex string '" << hexStr << "' malformed." << std::endl;
		return;
	}

	size_t byteArrSize = hexStr.size() / 2;
	uint8_t byteArr[byteArrSize];
	int num;

	std::stringstream sstream;
	for(size_t i = 0; i < hexStr.size(); i += 2) {
		sstream << std::hex << hexStr.substr(i, 2);
		sstream >> num;
		sstream.clear();
		byteArr[i / 2] = (uint8_t)num;
		//std::cout << "converted " << hexStr.substr(i, 2) << " to " << num << ", " << byteArr[i/2] << std::endl;
	}

	std::ofstream lkmfile("/dev/cc_kex", std::ios::binary | std::ios::out);

	if(!lkmfile.is_open()) {
		std::cout << "[fail] unable to open lkm" << std::endl;
		return;
	}

	lkmfile.write((char*)byteArr, byteArrSize);
	lkmfile.flush();
}

void enableEncryption() {
	cckex_ioctl_cipher_mode_t mode = { CCKEX_CIPHER_OUT_ENCRYPTION_ENABLE };
	if(ioctl(ccKexChardevFd, IOCTL_CMD_CHNG_CIPHER, &mode) == 0) {
		std::cout << "[info] outgoing encryption enabled" << std::endl;
	} else {
		std::cout << "[fail] failed to enable outgoing encryption" << std::endl;
	}
}

void printHelp() {
	std::cout 	<< "/// CC-SETUP ///" << std::endl 
				<< "" << std::endl
				<< "usage: ccsetup [OPTION].. [CCLKM-CHARDEV]" << std::	endl 
				<< "Change cc methods, ciphers and other options in the the cc kex lkm." << std::endl
				<< "" << std::endl 
				<< "OPTIONS:" << std::endl 
				<< " -h\t--help \t\t\t Show this help." << std::endl
				<< " -r\t--reset\t\t\t Reset the LKM." << std::endl
				<< " -ecc\t--enable-cc <method> \t Enable specific cc method." << std::endl 
				<< " -dcc\t--disable-cc <method> \t Disable specific cc method." << std::endl 
				<< " -enc\t--enable-encryption \t Enables encryption of the outgoing cc traffic." << std::endl
				<< " -c\t--config <file> \t JSON Configuration file to automatically configure the lkm." << std::endl
				<< " -ms\t--master-secret <file> \t Write raw master secrets from file to cc_kex lkm. " << std::endl
				<< " -w\t--write <data> \t\t Write hex string as raw data tot the cc_kex lkm." << std::endl
				<< "" << std::endl 
				<< "AVAILABLE <method>s:" << std::endl;
	bool firstFlag = true;
	for(auto const& methods : ccMethods2Index) {
	std::cout 	<< (firstFlag ? "" : ", ") << methods.first;
		firstFlag = false;
	}
	std::cout 	<< std::endl << std::endl;
}

void parseConfigAndSetup(std::string filepath) {

	// open config and parse as json
	std::ifstream file(filepath);

	if(!file.is_open()) return;

	// throw exception
	json config = json::parse(file);

	// iterate through methods and enable all methods in config
	for(auto elem : config["cc"]["methods"]) {
		if(!elem["id"].is_number()) {
			std::cout << "[warn][" << __func__ << "] possibly malformed cc method conf entry: \"" << elem << "\"" << std::endl;
			continue;
		}
		// TODO: log output
		setupCc({ CCKEX_CC_MODE_ACTION_ADD, elem["id"] });
	}
}

}; 	// namespace CcSetup

int main(int argc, char** argv) {
	(void) argc;


	argh::parser cmdl(argc, argv, argh::parser::PREFER_PARAM_FOR_UNREG_OPTION);

	if(cmdl[{"--help", "-h"}]) {
		CcSetup::printHelp();
		return 0;
	}

	if(cmdl[1] == "") {
		CcSetup::init("/dev/cc_kex");
	} else {
		CcSetup::init(cmdl[1]);
	}

	// TODO: only accept one config file or parameters
	// TODO: implement this properly 
	for(auto const& param : cmdl.params("ecc")) 				CcSetup::enableCC(param.second);
	for(auto const& param : cmdl.params("enable-cc")) 			CcSetup::enableCC(param.second);
	for(auto const& param : cmdl.params("dcc")) 				CcSetup::disableCC(param.second);
	for(auto const& param : cmdl.params("disable-cc")) 			CcSetup::disableCC(param.second);
	for(auto const& param : cmdl.params("c"))					CcSetup::parseConfigAndSetup(param.second);
	for(auto const& param : cmdl.params("config"))				CcSetup::parseConfigAndSetup(param.second);
	for(auto const& param : cmdl.params("ms"))					CcSetup::writeMasterSecret(param.second);
	for(auto const& param : cmdl.params("master-secret"))		CcSetup::writeMasterSecret(param.second);
	for(auto const& param : cmdl.params("enc"))					CcSetup::enableEncryption();
	for(auto const& param : cmdl.params("enable-encryption"))	CcSetup::enableEncryption();
	for(auto const& param : cmdl.params("w"))					CcSetup::writeHexString(param.second);
	for(auto const& param : cmdl.params("write"))				CcSetup::writeHexString(param.second);
	for(auto const& param : cmdl.params("r"))					CcSetup::resetLKM();
	for(auto const& param : cmdl.params("reset"))				CcSetup::resetLKM();

	CcSetup::fini();

	return 0;
}
