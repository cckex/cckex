#!/usr/bin/env bash

# download Android kernel
git config --global user.email "you@example.com"
git config --global user.name "Your Name"
mkdir -p /src/kernel && cd /src/kernel && \
yes y | repo init --depth=1 -u https://android.googlesource.com/kernel/manifest -b common-android12-5.10
yes y | repo sync --force-sync --no-clone-bundle --no-tags -j$(nproc)

# compile Android kernel if not already done
if [ ! -f "/src/kernel/out/android12-5.10/dist/bzImage" ]; then
    # make sure that repo is clean
    cd /src/kernel/ && repo forall -vc "git reset --hard"
    
    # make symbolic link to custom module src to build it together with kernel
    # make sure to add build commands in Kbuild -> this is done by build_custom_kernel.py
    ln -sf /src/custom_kernel_module/ /src/kernel/common-modules/virtual-device/
    
    # compile kernel
    cd /src/ && python build_custom_kernel.py /src/kernel/
fi

# start Android Emulator and VNC server
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

# wait for Emulator to boot
adb wait-for-device shell 'while [[ -z $(getprop sys.boot_completed) ]]; do sleep 1; done;'

# Elevate adb commands to root
adb root
sleep 2

adb push /share/ccsetup /data/local/tmp
adb push /share/tcpdump /data/local/tmp
adb push /share/frida-server* /data/local/tmp
adb shell chmod 777 /data/local/tmp/*
adb install /share/Signal*.apk

cd /src

/bin/bash


