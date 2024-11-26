.PHONY: clean all decrypt pcap_to_json logcat_to_keylist

VERBOSE ?= @

# Programs
PKGDECRYPTOR = pkg_decrypt/pcapdecrypt.py
LOGCATSCRIPT = ./parse_logcat_output.sh
PKGKEXSCRIPT = pkg_decrypt/cckeydump.py
TSHARK = tshark

# Files
PCAP_PKG_FILE = _cap.pcap
JSON_PKG_FILE = cap.json
TLS_KEYFILE = cap.key
LOGCAT_DUMP = cap.logcat
MSG_KEYFILE = cap.keylist

.DEFAULT_GOAL = decrypt

all: pcap_to_json pcap_to_keylist decrypt

decrypt:
	@echo "DECRYPT 		$(JSON_PKG_FILE) $(MSG_KEYFILE)"
	$(VERBOSE) $(PKGDECRYPTOR) $(JSON_PKG_FILE) -kf $(MSG_KEYFILE) -ds -du -de -dd

pcap_to_keylist:
	@echo "EXTRACT 		PCAP -> KEYLIST"
	-$(VERBOSE) $(PKGKEXSCRIPT) $(PCAP_PKG_FILE) -rfttl -fsrc "10.0.2.16" > $(MSG_KEYFILE)

pcap_to_json:
	@echo "TSHARK 		PCAP -> JSON"
	-$(VERBOSE) $(TSHARK) -r $(PCAP_PKG_FILE) -o tls.keylog_file:$(TLS_KEYFILE) -T json -Y tls > $(JSON_PKG_FILE)

logcat_to_keylist:
	@echo "CONVERT 		LOGCAT-OUTPUT -> KEYLIST"
	$(VERBOSE) $(LOGCATSCRIPT) $(LOGCAT_DUMP) > $(MSG_KEYFILE)

clean:
	@echo "RM 			messages"
	-$(VERBOSE) rm -rf message*raw
	@echo "RM 			caps"
	-$(VERBOSE) rm -rf *cap.*
