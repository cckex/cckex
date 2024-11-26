#include "common.h"

#include <exception>
#include <fstream>
#include <sstream>
#include <string>

#include <epan/prefs.h>

json config;

CCKEX_API int init_config(const char* path) {

    if(std::string(path) == "") return -1;

    std::ifstream file(path);

    if(!file.is_open()) return -1;

    try{
		config = json::parse(file);
    } catch(std::exception &e) {
		LOG_ERROR << "failed to parse json: "  << e.what() << std::endl;
		return -1;
    }

    return 0;
}

json get_config() {
    return config;
}

uint32_t get_ip_from_string(std::string ip_str) {

    std::string tok;
    std::stringstream sstream(ip_str);

    uint32_t ip_num = 0;

    for(int i = 0; i < 4; i++) {
	if(!std::getline(sstream, tok, '.')) {
	    LOG_WARN << "possibly malformed ip: \"" << ip_str << "\"" << std::endl;
	    break;
	}

	try {
	   ip_num |= (uint32_t)std::stoi(tok) << i * 8;
	} catch(std::exception &e) {
	    LOG_ERROR << "failed to parse ip: \"" << ip_str << "\"" << std::endl;
	    return 0;
	}
    }

    return ip_num;
}

CCKEX_API void set_tls_keylog_file(const char* path) {

	module_t *tls_mod = prefs_find_module("tls");

	if(tls_mod) {

		pref_t *keylog_file_pref = prefs_find_preference(tls_mod, "keylog_file");

		if(keylog_file_pref) {

			char *val = prefs_pref_to_str(keylog_file_pref, pref_current);

			if(val) {
				LOG_INFO << "previous value: " << val << std::endl;
				g_free(val);	// must be free, see documentation
			} else {
				LOG_ERROR << "unable to retrieve previous value" << std::endl;
			}

			char *errmsg = NULL;
			prefs_set_pref_e ret;

			std::string option = "tls.keylog_file:" + std::string(path);

			LOG_INFO << option << std::endl;

			if(PREFS_SET_OK == (ret = prefs_set_pref((char*)option.c_str(), &errmsg))) {
				LOG_INFO << "new value: " << path << std::endl;

				prefs_apply(tls_mod);

			} else {
				LOG_ERROR << "prefs_set_pref (" << path << "): ";
				switch(ret) {
					case PREFS_SET_SYNTAX_ERR:
						LOG_ERROR << "syntax error" << std::endl;
						break;

					case PREFS_SET_NO_SUCH_PREF:
						LOG_ERROR << "no such pref" << std::endl;
						break;

					case PREFS_SET_OBSOLETE:
						LOG_ERROR << "option obsolete" << std::endl;
						break;

					default:
						LOG_ERROR << "unknown error" << std::endl;
						break;
				}
			}

			if(errmsg) {
				LOG_ERROR << errmsg << std::endl;
				g_free(errmsg);
			}


		} else {
			LOG_ERROR << "failed to retrieve keylog_file_pref" << std::endl;
		}

	} else {
		LOG_ERROR << "failed to retrieve tls_mod" << std::endl;
	}

}

CCKEX_API const char* config_get_tls_keylog_file(void) {

	std::string entry_name = "tls_keylog_file";

	if(!config.contains("ws")) {
		LOG_ERROR << "unable to access ws." << entry_name << ": does not contain ws" << std::endl;
		return "";
	}

	if(!config["ws"].contains(entry_name) || !config["ws"][entry_name].is_string()) {
		LOG_ERROR << "unable to access ws." << entry_name << ": entry missing or not a string" << std::endl;
		return "";
	}

	// TODO: memory leak
	return strdup(std::string(config["ws"][entry_name]).c_str());
}

CCKEX_API const char* config_get_signal_key_file(void) {

	std::string entry_name = "signal_key_file";

	if(!config.contains("ws")) {
		LOG_ERROR << "unable to access ws." << entry_name << ": does not contain ws" << std::endl;
		return "";
	}

	if(!config["ws"].contains(entry_name) || !config["ws"][entry_name].is_string()) {
		LOG_ERROR << "unable to access ws." << entry_name << ": entry missing or not a string" << std::endl;
		return "";
	}

	// TODO: memory leak
	return strdup(std::string(config["ws"][entry_name]).c_str());
}

CCKEX_API const char* config_get_stats_file(void) {
	std::string entry_name = "stats_file";

	if(!config.contains("ws")) {
		LOG_ERROR << "unable to access ws." << entry_name << ": does not contain ws" << std::endl;
		return "stats_dump.csv";
	}

	if(!config["ws"].contains(entry_name) || !config["ws"][entry_name].is_string()) {
		LOG_ERROR << "unable to access ws." << entry_name << ": entry missing or not a string" << std::endl;
		return "stats_dump.csv";
	}

	// TODO: memory leak
	return strdup(std::string(config["ws"][entry_name]).c_str());

}
