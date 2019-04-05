#!/bin/bash

# Script for rewriting source and destination MAC addresses of many pcaps at once
# Input must be path to directory with pcaps

for f in "$1"*.pcap
do
	c=${f%\.*}
	c=${c##*/}
	o=$c
	c="$1"cachefiles/"$c"_cachefile
	o="$1"out/"$o".pcap
	tcprewrite -c "$c" --enet-dmac=00:00:00:00:00:02,00:00:00:00:00:01 --enet-smac=00:00:00:00:00:01,00:00:00:00:00:02 -i "$f" -o "$o"
done

