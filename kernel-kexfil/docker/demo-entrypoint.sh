#!/usr/bin/env bash

set -e

# start Android Emulator and VNC server
echo "CALLING create_and_run_emulator.sh"
/src/create_and_run_emulator.sh > /dev/null 2>&1 &

# wait for Emulator to boot
adb wait-for-device shell 'while [[ -z $(getprop sys.boot_completed) ]]; do sleep 1; done;'

# copy initramfs.img and bzImage to rootAVD
cp /src/kernel/out/android12-5.10/dist/bzImage /opt/rootAVD/
cp /src/kernel/out/android12-5.10/dist/initramfs.img /opt/rootAVD/

# inject into ramdisk.img using rootAVD
cd /opt/rootAVD/ && ./rootAVD.sh /opt/android-sdk/system-images/android-31/google_apis/x86_64/ramdisk.img InstallKernelModules

# rootAVD should shut down the emulator - wait some time
sleep 3

# start Android Emulator and VNC server
/src/create_and_run_emulator.sh > /dev/null 2>&1 &

/setup-demo-env.sh

read -n1 -s -p "Press any key to start the test.."

cd /capture/frida/captures/
./new_manual_capture.sh
