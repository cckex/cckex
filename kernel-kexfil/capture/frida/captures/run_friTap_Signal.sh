#!/bin/bash

set -e

python3 ../friTap/friTap.py -m org.thoughtcrime.securesms -do -k cap.key --spawn
