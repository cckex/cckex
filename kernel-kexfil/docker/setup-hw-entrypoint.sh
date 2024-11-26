#!/bin/bash

set -e

# download Android kernel
git config --global user.email "you@example.com"
git config --global user.name "Your Name"
mkdir -p /src/pixel_kernel

git config --global --add safe.directory /src/pixel_kernel/.repo/repo || true
git config --global --add safe.directory /src/pixel_kernel/.repo/manifests || true
cd /src/pixel_kernel

yes y | repo init --depth=1 -u https://android.googlesource.com/kernel/manifest -b android-gs-raviole-5.10-android14-qpr3
yes y | repo sync --force-sync --no-clone-bundle --no-tags -j$(nproc)

# check if cc_key is already added to the kernel
if grep -q "cc_kex" aosp/drivers/Makefile; then
	echo "===> CCKEX ALREADY ADDED TO THE KERNEL"
else

	# add cc_kex LKM to drivers Makefile
	printf "obj-m\t\t\t\t+= cc_kex/" >> aosp/drivers/Makefile
	# add cc_kex LKM to drivers Kconfig
	sed -i "/endmenu/s/^/source \"drivers\/cc_kex\/Kconfig\"\n\n/" aosp/drivers/Kconfig
	# add cc_kex LKM to modules_out
	sed -i "/module_outs/a \"cc_kex.ko\"," private/gs-google/BUILD.bazel
	# update module order list
	echo "drivers/cc_kex/cc_kex.ko" >> aosp/android/gki_aarch64_modules
	# link cc_kex to drivers
	ln -s /src/custom_kernel_module aosp/drivers/cc_kex

	echo "===> ADDED CCKEX TO KERNEL"

fi

echo "===> BUILD KERNEL FOR THE FIRST TIME"
BUILD_AOSP_KERNEL=1 ./build_slider.sh


