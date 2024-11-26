# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Modifications for the CCKex plugin
# By Sven Gebhard <sven.gebhard@fau.de>
# Copyright 2024 Sven Gebhard
#

cmake_minimum_required(VERSION 3.20)
cmake_policy(SET CMP0048 NEW)

project(CCKexPlugin VERSION 0.9.0 DESCRIPTION "Covert Channel Key Exfiltration Framework Wireshark Plugin" LANGUAGES C)

find_package(Wireshark CONFIG REQUIRED)

if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
	set(CMAKE_INSTALL_PREFIX "${Wireshark_INSTALL_PREFIX}"
		CACHE PATH "Installation prefix" FORCE
	)
endif()

if(NOT Wireshark_PLUGINS_ENABLED)
	message(WARNING "Wireshark was compiled without support for plugins")
endif()

# External plugins must define HAVE_SSIZE_T for the plugin toolchain.
include(CheckTypeSize)
check_type_size("ssize_t" SSIZE_T)

set(CMAKE_C_VISIBILITY_PRESET hidden)
if(CMAKE_COMPILER_IS_GNUCC)
    set(CMAKE_C_FLAGS  "-Wall -Wextra ${CMAKE_C_FLAGS}")
endif()

add_compile_definitions(
	VERSION=\"${PROJECT_VERSION}\"
	$<$<BOOL:${HAVE_SSIZE_T}>:HAVE_SSIZE_T>
)

# Include wireshark sources to successfully compile plugin
include_directories(wireshark)

add_library(cckex MODULE)
set_target_properties(cckex PROPERTIES PREFIX "" DEFINE_SYMBOL "")
target_link_libraries(cckex epan)

# Set include paths to source to avoid relative include paths in source files
include_directories(src)
# Search for source in the subdirectories
add_subdirectory(src cckex)

# This is the normal installation target to CMAKE_INSTALL_PREFIX. It is relocatable
# using DESTDIR or cmake --install. By default CMAKE_INSTALL_PREFIX should be configured
# correctly for Wireshark's system installation prefix.
install(TARGETS cckex
	LIBRARY DESTINATION "${Wireshark_PLUGIN_LIBDIR}/epan" NAMELINK_SKIP
)

# This custom target installs the plugin to the plugin dir in WiresharkConfig.cmake.
# It does not use CMAKE_INSTALL_PREFIX.
add_custom_target(copy_plugin
	COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:cckex> "${Wireshark_PLUGIN_INSTALL_DIR}/epan"
	COMMENT "Installing plugin to: ${Wireshark_PLUGIN_INSTALL_DIR}/epan"
)

string(TOLOWER "${PROJECT_NAME}-${PROJECT_VERSION}" _pkgname)

add_custom_target(package_prep
	COMMAND ${CMAKE_COMMAND} -E make_directory  ${CMAKE_BINARY_DIR}/${_pkgname}
	COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_SOURCE_DIR}/README $<TARGET_FILE:cckex> ${CMAKE_BINARY_DIR}/${_pkgname}
)

add_custom_target(package
	COMMAND ${CMAKE_COMMAND} -E tar czf ${CMAKE_BINARY_DIR}/${_pkgname}.tar.gz --format=gnutar -- ${CMAKE_BINARY_DIR}/${_pkgname}
)
add_dependencies(package package_prep)

add_custom_target(package_zip
	COMMAND ${CMAKE_COMMAND} -E tar cf ${CMAKE_BINARY_DIR}/${_pkgname}.zip --format=zip -- ${CMAKE_BINARY_DIR}/${_pkgname}
)
add_dependencies(package_zip package_prep)
