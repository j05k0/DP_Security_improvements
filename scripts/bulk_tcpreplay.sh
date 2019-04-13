#!/bin/bash

# Script for replaying many pcaps one after other
# Input must be path to directory with pcaps and number of first and last pcap

files=("$1"*.pcap)

for ((i=$2; i<$3+1; i++)); do
	pcap=${files[$i]}
	cachefile=${pcap%\.*}
	cachefile=${cachefile##*/}
	cachefile="$1"cachefiles/"$cachefile"_cachefile
	echo "$pcap"
	echo "$cachefile"
	sudo tcpreplay -K --maxsleep=10 -i s1-eth1 -I s3-eth1 -c "$cachefile" "$pcap"
done
