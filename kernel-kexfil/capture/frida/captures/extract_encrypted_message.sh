#!/usr/bin/env bash

set -e 

if [[ -z $1 ]]; then
	echo "usage: $0 <wire shark raw pkg files>"
	exit 0
fi

for file in $@; do
	cat $file | grep -o --text -E '"messages":\[{"content":.*==","' | sed -E 's/(.*content":"|",")//g' | base64 -d | dd of=$file.ex skip=84 ibs=1
done
