#!/usr/bin/env bash

set -e

# download Android kernel
git config --global user.email "you@example.com"
git config --global user.name "Your Name"
mkdir -p /src/pixel_kernel && cd /src/pixel_kernel && \

yes y | repo init --depth 1 -u https://android.googlesource.com/kernel/manifest -b android-gs-bluejay-5.10-android12L-d2
yes y | repo sync --force-sync --no-clone-bundle --no-tags -j$(nproc)

# make sure that repo is clean
cd /src/pixel_kernel/ && repo forall -c "git reset --hard ; git clean -fdx"  

# make symbolic link to custom module src to build it together with kernel
# make sure to add build commands in Kbuild -> this is done by build_custom_kernel.py
ln -sf /src/custom_kernel_module/ /src/pixel_kernel/common-modules/virtual-device/
#printf "\nobj-m += custom_kernel_module/\n" >> /src/pixel_kernel/common-modules/virtual-device/Kbuild

# compile kernel
cd /src/pixel_kernel

BUILD_KERNEL=1 SKIP_MRPROPER=1 ./build_slider.sh || true

/bin/bash
