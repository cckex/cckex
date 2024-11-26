#!/usr/bin/env bash
EMULATOR_NAME=kernel-kex-demo
ANDROID_API_LEVEL=${1:-31}

avdmanager list avd | grep $EMULATOR_NAME

if [ $? == 1 ]; then
    echo "Creating new AVD device..."
    avdmanager create avd --package "system-images;android-$ANDROID_API_LEVEL;google_apis;x86_64" --device "pixel_5" --name "$EMULATOR_NAME" || exit 1
fi

cd "${ANDROID_SDK_HOME}/.android/avd/${EMULATOR_NAME}.avd" || exit 1
sed -i "s/hw\.keyboard\=no/hw\.keyboard\=yes/" config.ini

# start VNC server and emulator - do not need this if using X forwarding
vncserver :2 -SecurityTypes None -localhost no --I-KNOW-THIS-IS-INSECURE
export DISPLAY=:2
emulator -avd $EMULATOR_NAME -show-kernel -qemu -s #-S #-gpu swiftshader_indirect
