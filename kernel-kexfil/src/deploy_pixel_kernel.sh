#!/bin/bash

set -e 

echo "Reboot to bootloader.."
adb reboot bootloader

cd pixel_kernel/out/mixed/dist

echo "Press any key to start the flash!"
read -s -n 1

echo "Starting flash.."
fastboot flash boot boot.img
fastboot flash dtbo dtbo.img
fastboot flash vendor_boot vendor_boot.img
fastboot reboot fastboot
fastboot flash vendor_dlkm vendor_dlkm.img

echo "Restart the device now"

