#!/bin/bash

set -e

adb shell /data/local/tmp/ccsetup -r

#adb shell /data/local/tmp/ccsetup -ecc iphdr_full_ttl
#adb shell /data/local/tmp/ccsetup -ecc iphdr_full_ttl -ecc msg_inj
#adb shell /data/local/tmp/ccsetup -ecc iphdr_ipflags
#adb shell /data/local/tmp/ccsetup -ecc iphdr_tos
#adb shell /data/local/tmp/ccsetup -ecc iphdr_ipid
#adb shell /data/local/tmp/ccsetup -ecc iphdr_ipfrag
adb shell /data/local/tmp/ccsetup -ecc tcphdr_urgent

# Start to dump TLS MS
#./dump_tls_mastersecrets.sh 2>&1 /dev/null & 
adb shell dmesg -w > cap.dmesg &
#tcpdump -U -w tcpdump_cap.pcap 2> /dev/null &
adb shell /data/local/tmp/tcpdump_x86_64_android -U -w /data/local/tmp/cap.pcap &

# Start appium for automated tests -> WIP
appium driver install uiautomator2 || true
appium &> appium.log &

# Disable SELinux to allow the modified libsignal to write to /dev/cckex
adb shell setenforce 0

python3 ../friTap/friTap.py -m -do -k cap.key --spawn org.thoughtcrime.securesms &
sleep 3
frida -U -p $(adb shell ps -A | grep sms | cut -d' ' -f8) -l ../scripts/signal_injector/signal_injector.js || true &
sleep 5
python ../../appium/fixedchard.py
#python ../../appium/randomchar.py

# Reenable SELinux
adb shell setenforce 1

adb pull /data/local/tmp/cap.pcap _cap.pcap

# Kill all background tasks of this script
kill -9 $(jobs -p) || true 

./cleanup.sh
