# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

include(WiresharkPlugin)

# Plugin name and version info (major minor micro extra)
set_module_info(ccKex 0 9 0 0)

SET(CMAKE_AUTOMOC ON)
SET(CMAKE_AUTOUIC ON)

if(USE_qt6)
	set(qtver "6")
else()
	set(qtver "5")
endif()

find_package(Qt${qtver}Core)
find_package(Qt${qtver}PrintSupport)
find_package(Qt${qtver}Widgets)

set(DISSECTOR_SRC
	packet-ccKex.c
	common.cc
	dissectors/exfil_dissector.cc
	dissectors/signal_websocket_dissector.c
	dissectors/signal_sealed_sender_dissector.c
	dissectors/signal_message_dissector.c
	message_dissection/signalmessagecrypto.cc
	message_dissection/signalmessagedissectors.c
	extraction/ccdatamanager.cc
	extraction/keytypes/signal_message_key.cc
	extraction/keytypes/signal_sealed_sender_key.cc
	extraction/keytypes/tls_client_traffic_secret.cc
	extraction/keytypes/tls_server_traffic_secret.cc
	stats/cckex_stats.cc
	ui/uihandler.h 
	ui/uihandler.cc
	ui/mainpluginui.h 
	ui/mainpluginui.cc
	ui/cctab.h 
	ui/cctab.cc
	ui/keytablewidget.h 
	ui/keytablewidget.cc
	ui/keysfiletab.h 
	ui/keysfiletab.cc
	ui/maintab.h 
	ui/maintab.cc
	ui/keyhighlighter.h 
	ui/keyhighlighter.cc
	ui/messagetab.h 
	ui/messagetab.cc
	ui/configtab.h 
	ui/configtab.cc
	${UI_SRC}
)

set(PLUGIN_FILES
	plugin.c
	${DISSECTOR_SRC}
)

set_source_files_properties(
	plugin.c
	PROPERTIES
	SKIP_AUTOGEN ON
)


set_source_files_properties(
	${PLUGIN_FILES}
	PROPERTIES
	COMPILE_FLAGS "${WERROR_COMMON_FLAGS}"
)

register_plugin_files(plugin.c
	plugin
	${DISSECTOR_SRC}
)

add_wireshark_plugin_library(ccKex epan)

target_link_libraries(ccKex epan Qt${qtver}::Core Qt${qtver}::Widgets Qt${qtver}::PrintSupport)

install_plugin(ccKex epan)

file(GLOB DISSECTOR_HEADERS RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" "*.h")
CHECKAPI(
	NAME
	  ccKex
	SWITCHES
	  --group dissectors-prohibited
	  --group dissectors-restricted
	SOURCES
	  ${DISSECTOR_SRC}
	  ${DISSECTOR_HEADERS}
)

#
# Editor modelines  -  https://www.wireshark.org/tools/modelines.html
#
# Local variables:
# c-basic-offset: 8
# tab-width: 8
# indent-tabs-mode: t
# End:
#
# vi: set shiftwidth=8 tabstop=8 noexpandtab:
# :indentSize=8:tabSize=8:noTabs=false:
#
