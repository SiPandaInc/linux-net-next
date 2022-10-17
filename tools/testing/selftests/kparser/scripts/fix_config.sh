#!/usr/bin/bash

REFCONFIG=$1
FIXCONFIG=$2
for elem in `cat ${REFCONFIG}` ; do 
    elem0=`echo $elem | cut -d'=' -f1`
    #echo "ELEMENT $elem0  $elem "
    sed -i -e "s/.*${elem0} .*/${elem}/" $FIXCONFIG
    sed -i -z "/${elem0}/!s/$/${elem}\n/" $FIXCONFIG 
done

