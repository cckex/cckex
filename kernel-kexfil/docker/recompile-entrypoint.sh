#!/usr/bin/env bash

set -e

#rm /src/kernel/out/android12-5.10/dist/bzImage
# make symbolic link to custom module src to build it together with kernel
# make sure to add build commands in Kbuild -> this is done by build_custom_kernel.py
ln -sf /src/custom_kernel_module/ /src/kernel/common-modules/virtual-device/

# recompile kernel
#cd /src/kernel/ && BUILD_CONFIG=common-modules/virtual-device/build.config.virtual_device.aarch64 SKIP_MRPROPER=0 build/build.sh -j$(nproc)
cd /src/kernel/ && BUILD_CONFIG=common-modules/virtual-device/build.config.virtual_device.x86_64 SKIP_MRPROPER=1 build/build.sh -j$(nproc)

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

cd /src

/bin/bash


