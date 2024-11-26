#!/bin/bash

set -e

# wait for Emulator to boot
adb wait-for-device shell 'while [[ -z $(getprop sys.boot_completed) ]]; do sleep 1; done;'

# Elevate adb commands to root
adb root
sleep 2

# Remove additional network interface in android device that does not transmit traffic
adb shell ifconfig eth0 down

# Make the CCKex LKM accessible
adb shell chmod 777 /dev/cc_kex

# Start friTap server to enable TLS MS dumping
adb shell /data/local/tmp/frida* &

