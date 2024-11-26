#!/bin/bash

set -e

frida -U -p $(adb shell ps -A | grep sms | cut -d' ' -f8) -l signal_injector.js
