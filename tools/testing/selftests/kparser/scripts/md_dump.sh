#!/bin/bash

MAPID=`/home/testusr/wspace/linux-net-next/tools/bpf/bpftool/bpftool map show | grep ctx | cut -d':' -f1 `
#MAPID=4

for ((i=1;i<=100000;i++)); 
do 
	MAPID=`/home/testusr/wspace/linux-net-next/tools/bpf/bpftool/bpftool map show | grep ctx | cut -d':' -f1 `
	echo "CTX - $MAPID "

	/home/testusr/wspace/linux-net-next/tools/bpf/bpftool/bpftool map dump id ${MAPID}
	sleep 3
	      
done
