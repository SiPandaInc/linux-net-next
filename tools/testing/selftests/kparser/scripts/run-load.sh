#!/usr/bin/bash
export RNDSTR0=`env date --date 'now ' +'%Y-%m-%d_%H%M%S'`
XDP_IP=192.168.1.224
CLN_IP=192.168.1.222

xdp_check() 
{

sshpass -p root ssh -o StrictHostKeyChecking=no root@192.168.1.222 "bash -s" < ./xdp-check.sh  >> ${PWD}/logs/xdp_check_${RNDSTR0}.log
sshpass -p root ssh -o StrictHostKeyChecking=no root@192.168.1.222 "bash -s" < ./xdp-check.sh  >> ${PWD}/logs/xdp_check_${RNDSTR0}.log
}

export RNDSTR0=`env date --date 'now ' +'%Y-%m-%d_%H%M%S'`
XDPMODS="xdp_kparser_drop_kern xdp_kparser_flowd_kern xdp_kparser_kern"
#XDPMODS="xdp_kparser_drop_kern"
for (( i=1; i<=5; i++ ))
do
for xmod in $XDPMODS
do
        XDPCMD="sshpass -p root ssh -o StrictHostKeyChecking=no root@${XDP_IP}  \"/root/wspace/xdp-test/xdp-load.sh $xmod \" "
        #XDPCMD="screen -dmSL srv_${RNDSTR0} bash -c 'sshpass -p root ssh -o StrictHostKeyChecking=no root@192.168.1.222 "bash -s" < cargs.sh ab 123 ' "
        echo $XDPCMD
        #screen -Logfile ${PWD}/logs/runload_srv_${RNDSTR0}.log -dmSL runload_srv bash -c 'ssh root@192.168.1.226 "/root/wspace/xdp-test/xdp-load.sh xdp_kparser_flowd_kern " '
        screen -Logfile ${PWD}/logs/runload_srv_${RNDSTR0}.log -dmSL runload_srv bash -c "$XDPCMD"

        if [[ "$xmod" == "xdp_kparser_kern" ]]; then
                sleep 1
                #sshpass -p root ssh -o StrictHostKeyChecking=no root@${XDP_IP} "/root/wspace/xdp-test/ftuple_with_md.sh "
                sshpass -p root ssh -o StrictHostKeyChecking=no root@${XDP_IP} "/root/wspace/xdp-test/ftuple_with_md_v3.sh "
        fi

        #screen -Logfile ${PWD}/logs/runload_cln_${RNDSTR0}.log -dmSL runload_cln  bash -c 'ssh root@192.168.101.167 "/home/testusr/wspace/dpdk-stable-21.11.2/run-testpmd.sh " '
        #sshpass -p root  ssh -o StrictHostKeyChecking=no root@192.168.1.222   "screen -dmS runload_cln  bash -c 'ssh root@192.168.101.167 \"/home/testusr/wspace/dpdk-stable-21.11.2/run-testpmd.sh \" ' " /dev/null
        #sshpass -p root  ssh -o StrictHostKeyChecking=no root@${CLN_IP}  "screen -dmS runload_cln  '/home/testusr/wspace/run-testpmd.sh '  " /dev/null
        #echo sshpass -p root  ssh -o StrictHostKeyChecking=no root@${CLN_IP}  "screen -dmS runload_cln  '/home/testusr/wspace/run-testpmd.sh '  " /dev/null 
	sshpass -p root ssh -o StrictHostKeyChecking=no root@192.168.1.222  "screen -dmS runload_cln  '/home/testusr/wspace/run-testpmd.sh'  " /dev/null

        sleep 129

        #ssh root@192.168.101.167 "kill -SIGINT \`pidof dpdk-testpmd\` "
        sshpass -p root  ssh -o StrictHostKeyChecking=no root@${CLN_IP}   "kill -SIGINT \`pidof dpdk-testpmd\` "
        sshpass -p root ssh -o StrictHostKeyChecking=no root@${XDP_IP} "kill -SIGINT \`pidof xdp_kparser_load \` "
        sleep 30
done
done
