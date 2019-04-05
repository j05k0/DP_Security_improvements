#!/bin/bash

# Script for creating cachefiles of many pcaps at once
# Input must be path to directory with pcaps

for f in "$1"*.pcap
do
	c=${f%\.*}
	c=${c##*/}	
	tcpprep -a bridge -i "$f" -o "$1"cachefiles/"$c"_cachefile
done

