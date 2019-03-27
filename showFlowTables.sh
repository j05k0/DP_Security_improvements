#!/bin/bash

# Script for showing flow tables of forwarders

for arg 
do 
	echo '***' $arg '------------------------------------------------------------------------'
	sudo ovs-ofctl dump-flows $arg -O OpenFlow14
done

