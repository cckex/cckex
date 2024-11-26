#!/bin/bash

set -e

adb shell su -c /data/local/tmp/ccsetup -r

#adb shell su -c /data/local/tmp/ccsetup -ecc iphdr_full_ttl
#adb shell su -c /data/local/tmp/ccsetup -ecc iphdr_full_ttl -ecc msg_inj
#adb shell su -c /data/local/tmp/ccsetup -ecc iphdr_ipflags
#adb shell su -c /data/local/tmp/ccsetup -ecc iphdr_tos
#adb shell su -c /data/local/tmp/ccsetup -ecc iphdr_ipid
#adb shell su -c /data/local/tmp/ccsetup -ecc iphdr_ipfrag
adb shell su -c /data/local/tmp/ccsetup -ecc tcphdr_urgent

# Start to dump TLS MS
#./dump_tls_mastersecrets.sh 2>&1 /dev/null & 
adb shell su -c dmesg -w > cap.dmesg &
#tcpdump -U -w tcpdump_cap.pcap 2> /dev/null &
adb shell su -c /data/local/tmp/tcpdump -i wlan0 -U -w /data/local/tmp/cap.pcap &

# Disable SELinux to allow the modified libsignal to write to /dev/cckex
adb shell su -c setenforce 0

python3 ../friTap/friTap.py -m -do -k cap.key --spawn org.thoughtcrime.securesms &
adb wait-for-device shell 'while [[ $(ps -A | grep sms) -ne 0 ]]; do sleep 1; done;'
frida -U -p $(adb shell su -c ps -A | grep sms | cut -d' ' -f8) -l ../scripts/signal_injector/signal_injector.js || true

# Reenable SELinux
adb shell su -c setenforce 1

adb pull /data/local/tmp/cap.pcap _cap.pcap

# Kill all background tasks of this script
kill -9 $(jobs -p) || true 

./cleanup.sh
