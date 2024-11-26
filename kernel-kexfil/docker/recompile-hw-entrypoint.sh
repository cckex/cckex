#!/bin/bash

set -e

cd /src/pixel_kernel

BUILD_AOSP_KERNEL=1 SKIP_MRPROPER=1 ./build_slider.sh
