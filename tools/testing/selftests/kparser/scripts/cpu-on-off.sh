#!/usr/bin/bash
NUMCPUS=$1  # num of cpus to perform this task
ONOFF=$2  # 0 for off and 1 for on
for (( i=1; i<=${NUMCPUS}; i++ ))
do
        echo ${ONOFF} > /sys/devices/system/cpu/cpu$i/online
done

