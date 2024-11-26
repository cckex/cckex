/* packet-ccKex.c
 * Routines for ccKex Signal Messenger dissection
 * Copyright 2023-2024, Sven Gebhard <sven.gebhard@fau.de>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: MIT
 */

/*
 * (A short description of the protocol including links to specifications,
 *  detailed documentation, etc.)
 */

#define WS_BUILD_DLL
//#include "config.h"
#include <stdint.h>
/* Define the name for the logging domain (try to avoid collisions with existing domains) */
#define WS_LOG_DOMAIN "ccKex"

#ifndef CCKEX_PLUGIN_VERSION
#define CCKEX_PLUGIN_VERSION "0.9.0"
#endif

/* Global header providing a minimum base set of required macros and APIs */
#include <wireshark.h>
//#include <wsutil/plugins.h>

#include <string.h>
#include <stdio.h>

#include <epan/tvbuff.h>
#include <epan/prefs.h>
#include <epan/packet.h>
#include <epan/etypes.h>

#include "message_dissection/signalmessagedissectors.h"
#include "message_dissection/signalmessagecrypto.h"
#include "extraction/ccdataextraction.h"
#include "extraction/ccdatamanager.h"
#include "ui/uihandler.h"
#include "common.h"

#include "dissectors/exfil_dissector.h"
#include "dissectors/signal_message_dissector.h"
#include "dissectors/signal_websocket_dissector.h"
#include "dissectors/signal_sealed_sender_dissector.h"

/* Prototypes */
/* (Required to prevent [-Wmissing-prototypes] warnings */
void proto_reg_handoff_ccKex(void);
void proto_register_ccKex(void);

/* Initialize the protocol and registered fields */
static int proto_ccKex_message = -1;
static int proto_ccKex_key = -1;

static dissector_handle_t ccKex_message_handle;
//static dissector_handle_t ccKex_key_handle;

int hf_websocket_json_text = -1;
int hf_websocket_dst_guid = -1;
int hf_websocket_online = -1;
int hf_websocket_timestamp = -1;
int hf_websocket_urgent = -1;

int hf_sealedsender_cert = -1;
int hf_sealedsender_cert_e164_length = -1;
int hf_sealedsender_cert_e164 = -1;
int hf_sealedsender_cert_uuid_length = -1;
int hf_sealedsender_cert_uuid = -1;
int hf_sealedsender_message_ciphertext = -1;
int hf_sealedsender_content_hint = -1;

int hf_message_type = -1;
int hf_message_text_length = -1;
int hf_message_text = -1;
int hf_message_injected_data_length = -1;
int hf_message_injected_data = -1;

int hf_exfil_iphdr_full_ttl = -1;
int hf_exfil_iphdr_iptos = -1;
int hf_exfil_iphdr_ipflags = -1;
int hf_exfil_iphdr_ipid = -1;
int hf_exfil_iphdr_ipfragment = -1;

/* Initialize the subtree pointers */
int ett_ccKex_websocket = -1;
int ett_ccKex_sealed_sender = -1;
int ett_ccKex_sealed_sender_certificate = -1;
int ett_ccKex_message = -1;
int ett_ccKex_exfil = -1;
//static int ett_cckex_base_message = -1;

const char* signal_message_fingerprint = "\x08\x01\x12\x81\x09\x0a\x03PUT\x12=/v1/messages/";

///////////////
// Preferences
///////////////

static const char *pref_cckex_signal_keyfile_path = "";
static const char *pref_cckex_config_path = "";


/* Code to actually dissect the packets */
static int
dissect_ccKex_signal_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_)
{
    (void) tree;
    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti_websocket, *ti_sealed_sender, *ti_message;
    proto_tree *ccKex_websocket_tree, *ccKex_sealed_sender_tree, *ccKex_message_tree;
    /* Other misc. local variables. */
    unsigned offset = ccKex_SKIP_BEFORE_HEURISTICS;
    unsigned rlen   = tvb_reported_length(tvb);

    /*** CCKEX ***/

    //ws_ip4 *iph = NULL;
    //printf("ccKex <pkg:%i> [info]: cc ttl=%.02x\n", pinfo->num, iph->ip_ttl);

    /*** HEURISTICS ***/

    //printf("ccKex <pkg:%i> [info]: length=%i current_layer_num=%i\n", pinfo->num, tvb_reported_length(tvb), pinfo->curr_layer_num);

    // check packet lengths
    if (rlen < ccKex_MIN_LENGTH)
        return 0;
    if (rlen < ccKex_MIN_LENGTH_FOR_HEURISTICS)
        return 0;

    // check for signal message
    for(unsigned i = ccKex_SKIP_BEFORE_HEURISTICS; i < strlen(signal_message_fingerprint); i++) {
        if(tvb_get_uint8(tvb, offset) != (guint8)signal_message_fingerprint[i]) return 0;
        offset++;
    }

    //printf("ccKex <pkg:%i> [info]: found signal message (len=%i) !!!\n", pinfo->num, tvb_reported_length(tvb));

    /*** COLUMN DATA ***/

    /* Set the Protocol column to the constant string of ccKex */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ccKex SigMsg");

    /*** PROTOCOL TREE ***/

    // find start of json data and dissect top layer / get ciphertext
    uint8_t tmp;
    while(offset < rlen && '{' != (tmp=(char)tvb_get_uint8(tvb, offset))) offset++;

    //printf("ccKex <pkg:%i> [info]: found json at offset=%i\n", pinfo->num, offset);

    // create display subtree for the protocol
    ti_websocket = proto_tree_add_item(tree, proto_ccKex_message, tvb, 0, -1, ENC_NA);
    ccKex_websocket_tree = proto_item_add_subtree(ti_websocket, ett_ccKex_websocket);
    proto_item_set_text(ccKex_websocket_tree, "CCKEX Websocket Layer");

    // check if we are at the end of the buffer / didnt find the start of the json data
    if(offset == rlen) return 0;

    tvbuff_t* sealed_sender_data = NULL;
    dissect_websocket_layer(tvb, pinfo, ccKex_websocket_tree, offset, &sealed_sender_data);

    tvbuff_t* message_data = NULL;
    if(sealed_sender_data) {
        ti_sealed_sender = proto_tree_add_item(tree, proto_ccKex_message, sealed_sender_data, 0, -1, ENC_NA);
        ccKex_sealed_sender_tree = proto_item_add_subtree(ti_sealed_sender, ett_ccKex_sealed_sender);
        proto_item_set_text(ccKex_sealed_sender_tree, "CCKEX Sealed Sender Layer");
        add_new_data_source(pinfo, sealed_sender_data, "Sealed Sender Layer");

        dissect_sealed_sender_layer(sealed_sender_data, pinfo, ccKex_sealed_sender_tree, &message_data);
    } else {
        printf("%s: sealed_sender_data == NULL\n", __func__);
    }

    if(message_data) {
        ti_message = proto_tree_add_item(tree, proto_ccKex_message, message_data, 0, -1, ENC_NA);
        ccKex_message_tree = proto_item_add_subtree(ti_message, ett_ccKex_message);
        proto_item_set_text(ccKex_message_tree, "CCKEX Internal Message");
        add_new_data_source(pinfo, message_data, "Internal Message Layer");

        dissect_message_layer(message_data, pinfo, ccKex_message_tree);
    } else {
        printf("%s: message_data == NULL\n", __func__);
    }

    return tvb_captured_length(tvb);
}

/* Register the protocol with Wireshark.
 *
 * This format is required because a script is used to build the C function that
 * calls all the protocol registration.
 */
void
proto_register_ccKex(void)
{
    module_t *ccKex_module;

    /* Setup list of header fields  See Section 1.5 of README.dissector for
     * details. */
    static hf_register_info hf[] = {
        { &hf_websocket_json_text,
          { "Json Data", "CCKEX_WEBSOCKET_JSONDATA",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "NULL", HFILL }
        },
        { &hf_websocket_dst_guid,
          { "Destination GUID", "CCKEX_WEBSOCKET_DSTGUID",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "NULL", HFILL }
        },
        { &hf_websocket_online,
          { "Online-Flag", "CCKEX_WEBSOCKET_ONLINE",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "NULL", HFILL }
        },
        { &hf_websocket_timestamp,
          { "Timestamp", "CCKEX_WEBSOCKET_TIMESTAMP",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
            "NULL", HFILL }
        },
        { &hf_websocket_urgent,
          { "Urgent-Flag", "CCKEX_WEBSOCKET_URGENT",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "NULL", HFILL }
        },

        { &hf_sealedsender_cert_e164_length,
          { "Phone Number Str Length", "CCKEX_SEALEDSENDER_PHONE_NUMBER_LENGTH",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "NULL", HFILL }
        },
        { &hf_sealedsender_cert_e164,
          { "Sender Phone Number (E164)", "CCKEX_SEALEDSENDER_PHONE_NUMBER",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "NULL", HFILL }
        },
        { &hf_sealedsender_message_ciphertext,
          { "Message Ciphertext", "CCKEX_SEALEDSENDER_MESSAGE_CIPHERTEXT",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "NULL", HFILL }
        },
        { &hf_sealedsender_cert_uuid_length,
          { "UUID String Length", "CCKEX_SEALEDSENDER_CERT_UUID",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "NULL", HFILL }
        },
        { &hf_sealedsender_cert_uuid,
          { "UUID", "CCKEX_SEALEDSENDER_CERT_UUID",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "NULL", HFILL }
        },
        { &hf_sealedsender_content_hint,
          { "Content Hint", "CCKEX_SEALEDSENDER_CONTENT_HINT",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            "NULL", HFILL }
        },
        { &hf_sealedsender_cert,
          { "Sender Certificate", "CCKEX_SEALEDSENDER_CERT",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_message_type,
          { "Type", "CCKEX_MESSAGE_TYPE",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "NULL", HFILL }
        },
        { &hf_message_text_length,
          { "Text Length", "CCKEX_MESSAGE_TEXT_LENGTH",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "NULL", HFILL }
        },
        { &hf_message_text,
          { "Text", "CCKEX_MESSAGE_TEXT",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "NULL", HFILL }
        },
        { &hf_message_injected_data,
          { "Injected Data Length", "CCKEX_MESSAGE_INJECTED_DATA",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "NULL", HFILL }
        },
        { &hf_message_injected_data_length,
          { "Injected Data", "CCKEX_MESSAGE_INJECTED_DATA_LENGTH",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "NULL", HFILL }
        },

		{ &hf_exfil_iphdr_full_ttl,
		  { "TTL", "CCKEX_EXFIL_IPHDR_FULL_TTL",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			"NULL", HFILL }
		},
		{ &hf_exfil_iphdr_iptos,
		  { "TOS", "CCKEX_EXFIL_IPHDR_IPTOS",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			"NULL", HFILL }
		},
		{ &hf_exfil_iphdr_ipflags,
		  { "IPFLAGS", "CCKEX_EXFIL_IPHDR_IPFLAGS",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			"NULL", HFILL }
		},
		{ &hf_exfil_iphdr_ipid,
		  { "IPID", "CCKEX_EXFIL_IPHDR_IPID",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			"NULL", HFILL }
		},
		{ &hf_exfil_iphdr_ipfragment,
		  { "IPFRAG", "CCKEX_EXFIL_IPHDR_IPFRAG",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			"NULL", HFILL }
		}
    };

    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_ccKex_websocket,
        &ett_ccKex_sealed_sender,
        &ett_ccKex_sealed_sender_certificate,
        &ett_ccKex_message,
		&ett_ccKex_exfil
    };

    /* Register the protocol name and description */
    proto_ccKex_message = proto_register_protocol("ccKex Signal Messenger",
            "CCKEX", "cckex.message");
    proto_ccKex_key = proto_register_protocol("ccKex Key Exfiltration", "CCKEX KEY", "cckex.key");

	// register menu entry
	setup_cckex_wireshark_toolbar(proto_ccKex_message);

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_ccKex_message, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

	// after proto handler and subtree are registered -> init exfil dissector
	//init_ccKex_extraction_dissector(proto_ccKex_key, ett_ccKex_exfil);

    /* Use register_dissector() here so that the dissector can be
     * found by name by other protocols, by Lua, by Export PDU,
     * by custom User DLT dissection, etc. Some protocols may require
     * multiple uniquely named dissectors that behave differently
     * depending on the caller, e.g. over TCP directly vs over TLS.
     */
    ccKex_message_handle = register_dissector("ccKex", dissect_ccKex_signal_message,
            proto_ccKex_message);

    //ccKex_key_handle = create_dissector_handle(dissect_ccKex_key, proto_ccKex_key);

    /* Register a preferences module (see section 2.6 of README.dissector
     * for more details). Registration of a prefs callback is not required
     * if there are no preferences that affect protocol registration (an example
     * of a preference that would affect registration is a port preference).
     * If the prefs callback is not needed, use NULL instead of
     * proto_reg_handoff_ccKex in the following.
     */
    ccKex_module = prefs_register_protocol(proto_ccKex_message,
            proto_reg_handoff_ccKex);

    /* Register a preferences module under the preferences subtree.
     * Only use this function instead of prefs_register_protocol (above) if you
     * want to group preferences of several protocols under one preferences
     * subtree.
     *
     * Argument subtree identifies grouping tree node name, several subnodes can
     * be specified using slash '/' (e.g. "OSI/X.500" - protocol preferences
     * will be accessible under Protocols->OSI->X.500-><CCKEX>
     * preferences node.
     */
    ccKex_module = prefs_register_protocol_subtree("",
            proto_ccKex_message, proto_reg_handoff_ccKex);

    prefs_register_filename_preference(ccKex_module, "conffilepath",
            "Configuration File",
            "File containing configuration for cc filter, data extraction and encryption.",
            &pref_cckex_config_path, false);


	cckex_register_exfil_dissector(ccKex_module);
	cckex_register_signal_websocket_dissector(ccKex_module);
	cckex_register_signal_sealed_sender_dissector(ccKex_module);
	cckex_register_signal_message_dissector(ccKex_module);
}

/* If this dissector uses sub-dissector registration add a registration routine.
 * This exact format is required because a script is used to find these
 * routines and create the code that calls these routines.
 *
 * If this function is registered as a prefs callback (see
 * prefs_register_protocol above) this function is also called by Wireshark's
 * preferences manager whenever "Apply" or "OK" are pressed. In that case, it
 * should accommodate being called more than once by use of the static
 * 'initialized' variable included below.
 *
 * This form of the reg_handoff function is used if you perform registration
 * functions which are dependent upon prefs. See below this function for a
 * simpler form which can be used if there are no prefs-dependent registration
 * functions.
 */
void
proto_reg_handoff_ccKex(void)
{
    static bool initialized = false;

    if (!initialized) {
        //dissector_add_uint("ws.port", 443, ccKex_message_handle);
        //register_postdissector(ccKex_key_handle);

        initialized = true;
    } else {

    }

	cckex_handoff_exfil_dissector();
	cckex_handoff_signal_websocket_dissector();
	cckex_handoff_signal_sealed_sender_dissector();
	cckex_handoff_signal_message_dissector();

    // reset data
    reset_ccdata();
    reset_keys();

    // load config from file
    init_config(pref_cckex_config_path);

	pref_cckex_signal_keyfile_path = config_get_signal_key_file();
	set_tls_keylog_file(config_get_tls_keylog_file());

    // load signal message keys, ids, ivs from file
    load_keys_from_file(pref_cckex_signal_keyfile_path);

    // check for new keys
    check_for_new_keys();
}

/*static void
cckex_plugin_register(void)
{
	static proto_plugin plug;

	plug.register_protoinfo = proto_register_ccKex;
	plug.register_handoff = proto_reg_handoff_ccKex;
	proto_register_plugin(&plug);
}

static struct ws_module cckex_module = {
	.flags = WS_PLUGIN_DESC_DISSECTOR,
	.version = CCKEX_PLUGIN_VERSION,
	.spdx_id = "GPL-2.0-or-later",
	.home_url = "Your-URL-here",
	.blurb = "CCKex Covert Channel Key Exfiltration Framework WS Plugin",
	.register_cb = &cckex_plugin_register,
};

WIRESHARK_PLUGIN_REGISTER_EPAN(&cckex_module, 0)*/
