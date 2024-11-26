#!/bin/bash

set -e

adb shell /data/local/tmp/ccsetup -ecc iphdr_full_ttl
#adb shell /data/local/tmp/ccsetup -ecc iphdr_full_ttl -ecc msg_inj
#adb shell /data/local/tmp/ccsetup -ecc iphdr_ipflags
#adb shell /data/local/tmp/ccsetup -ecc iphdr_tos
#adb shell /data/local/tmp/ccsetup -ecc iphdr_ipid
#adb shell /data/local/tmp/ccsetup -ecc iphdr_ipfrag

tshark -F pcap -w tshark_cap.pcap &> /dev/null &
tcpdump -U -w tcpdump_cap.pcap 2> /dev/null &

# Start to dump TLS MS
#./dump_tls_mastersecrets.sh 2>&1 /dev/null & 
adb shell dmesg -w > cap.dmesg &

# Start appium for automated tests -> WIP
appium &> appium.log &

# Disable SELinux to allow the modified libsignal to write to /dev/cckex
adb shell setenforce 0
# Start the Signal application via friTap -> dump the TLS MS in cap.key and the network traffic into cap.pcap
python3 ../friTap/friTap.py -m org.thoughtcrime.securesms -do -k cap.key --spawn -f -p cap.pcap
# Reenable SELinux
adb shell setenforce 1

# Get the android log as a backup and to debug errors
adb logcat -d | grep ciphertext > cap.logcat

# Kill all background tasks of this script
kill $(jobs -p)

./cleanup.sh
