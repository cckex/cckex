#!/usr/bin/env bash

set -e

if [[ -z $1 ]]; then
	echo "$0 <logcat file>"
	exit 0
fi;

cat $1 | sed -E 's/(^.*ciphertext|=|,|\[|\]|\ |^.*&message_encrypt.*$)//g' | sed -E 's/mac_key.*$//g' | sed -E 's/(cipher_key|key|iv)/\ /g'
