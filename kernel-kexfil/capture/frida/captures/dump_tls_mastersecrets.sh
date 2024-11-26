#!/bin/bash

set -e

touch _cap.key

while true; do

#	while IFS= read -r line; do
#		data="fff8$(echo $line | cut -d' ' -f2)$(echo $line | cut -d' ' -f3)"
#		echo "dumping $data.."
#		echo $data | xxd -r -p >> cap.key.raw
#	done <<< "$(cat cap.key | grep CLIENT_RANDOM)"

	if [ -f cap.key ]
	then

		FILE_DATA=$(cat cap.key _cap.key | sort | uniq -u)

		if echo "$FILE_DATA" | grep CLIENT_TRAFFIC_SECRET 
		then
		
			if [ -f cap.key.raw ]
			then
				rm cap.key.raw
			fi

			while IFS= read -r line; do
				data="fff7$(echo $line | cut -d' ' -f2)$(echo $line | cut -d' ' -f3)"
				echo "dumping $data.."
				echo $data | xxd -r -p >> cap.key.raw
			done <<< "$(echo "$FILE_DATA" | grep CLIENT_TRAFFIC_SECRET)"

			# TODO: Race condition - keys might be added after the while loop but before the old keys are moved to the backup file

			cat cap.key > _cap.key

			adb push cap.key.raw /data/local/tmp
			adb shell "/data/local/tmp/ccsetup -ms /data/local/tmp/cap.key.raw"

		else
			echo "no new keys to dump.."
		fi

	else
		echo "no new keys to dump.."
	fi

sleep 5

done
