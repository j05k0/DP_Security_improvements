#!/bin/bash

# Script for merging parts of pcaps to one big file
# Input must be path to directory with pcaps

files=("$1"*.pcap)

part1=(${files[0]})
for ((i=1; i<1000; i++)); do
    part1+=(${files[$i]})
done

mergecap -w ~/pcaps/22-01-2015_1_part1.pcap "${part1[@]}"

part2=(${files[1000]})
for ((i=1001; i<${#files[@]}; i++)); do
    part2+=(${files[$i]})
done

mergecap -w ~/pcaps/22-01-2015_1_part2.pcap "${part2[@]}"

