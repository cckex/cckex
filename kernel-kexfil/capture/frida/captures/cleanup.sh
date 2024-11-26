#!/bin/bash

set -e 

# Prepare variables
DUMP_DIR=./eval/$(date +%y%m%d-%H%M%S)-dump
CUR_DIR=./eval/current

# Prepare dump directories in eval dir
mkdir -p $DUMP_DIR
mkdir -p $CUR_DIR

# Extract the dumped keys from the android log as a backup
# make logcat_to_keylist

# Move all dump files to the dump and current directory
mv cap.key backup_cap.key || true
mv *cap.* $DUMP_DIR
mv appium.log $DUMP_DIR || true
cp $DUMP_DIR/* $CUR_DIR

# Make all files readable by my host linux user (is executed inside the docker container, thus the uid/guid must be used)
chown -R 1000:1000 *
