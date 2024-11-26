#pragma once

#include <stdint.h>
#include <stdio.h>

#define CLOG_ERROR(...) fprintf(stderr, "[error][%s] ", __func__); fprintf(stderr, __VA_ARGS__);
#define CLOG_WARN(...) fprintf(stderr, "[warning][%s] ", __func__); fprintf(stderr, __VA_ARGS__);
#define CLOG_INFO(...) fprintf(stderr, "[info][%s] ", __func__); fprintf(stderr, __VA_ARGS__);

#define CLOG_PKG_ERROR(...) CLOG_ERROR("<pkg:%u> ", pinfo->num); fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n");
#define CLOG_PKG_WARN(...) CLOG_WARN("<pkg:%u> ", pinfo->num); fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n");
#define CLOG_PKG_INFO(...) CLOG_INFO("<pkg:%u> ", pinfo->num); fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n");

#if __cplusplus

// TODO: namespace

#include <iostream>
#include <array>

#include <QString>

#define CCKEX_API extern "C"

#define LOG_ERROR std::cerr << "[error][" << __func__ << "] "
#define LOG_WARN std::cerr << "[warning][" << __func__ << "] "
#define LOG_INFO std::cerr << "[info][" << __func__ << "] "

#define LOG_PKG_ERROR std::cerr << "[error][" << __func__ << "] <" << pinfo->num << "> "
#define LOG_PKG_WARN std::cerr << "[warning][" << __func__ << "] <" << pinfo->num << "> "
#define LOG_PKG_INFO std::cerr << "[info][" << __func__ << "] <" << pinfo->num << "> "

#include "json.hpp"

using json = nlohmann::json;

/*
 */
nlohmann::json get_config();

/*  -- get_ip_from_string --
 *
 *  Function takes a ip string and returns it as 4 bytes in network byte order
 *
 *  @param ip: String which should be converted
 *  @param return: The ip in network byte order or 0
 *
 */
uint32_t get_ip_from_string(std::string ip);

template<size_t N>
QString byteArrayToQString(std::array<uint8_t, N> byteArray)
{
	QByteArray arr;

	for(uint8_t i : byteArray) arr.append(i);

	return QString(arr.toHex());
}

#else

#define CCKEX_API

#endif

/*  -- init_config --
 *
 *  Load json config from file.
 *
 *  @param path: Path to the config file.
 *  @return: 0 on success, -1 if the load failed
 */
CCKEX_API int init_config(const char* path);

/*  -- set_tls_keylog_file --
 *
 *  Set the keylog file option of the tls dissector
 *
 *  @param path: Path to the new keylog file
 *
 */
CCKEX_API void set_tls_keylog_file(const char* path);

/*  -- config_get_tls_keylog_file/signal_key_file --
 *
 *  Make these json config values available to the C part of the CCKex Plugin
 *
 *  @return: path string to the corresponding file
 */
CCKEX_API const char* config_get_tls_keylog_file(void);
CCKEX_API const char* config_get_signal_key_file(void);
CCKEX_API const char* config_get_stats_file(void);
