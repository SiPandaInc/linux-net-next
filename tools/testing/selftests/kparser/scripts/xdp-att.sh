#EDEV=enp0s8
EDEV=tap102
ip link set dev $EDEV xdp off
ip link ls dev $EDEV
#ip netns exec ns2 ip link set dev veth1 xdp off
export PKD_CONFIG_PATH=${LINUX_NET_NEXT}/tools/lib/bpf
rmmod kparser.ko
cd ${LINUX_NET_NEXT}
#make M=net/kparser clean
#make M=net/kparser 

insmod ${LINUX_NET_NEXT}/net/kparser/kparser.ko
${IPROUTE2_PATH}/ip/ip -V
cd ${LINUX_NET_NEXT}/samples/bpf
#make clean 
#make MDATA==2
#ip link set dev enp0s8 xdp obj xdp_kparser_kern.o verbose
ip link set dev $EDEV xdp obj xdp_kparser_kern.o verbose
ip link ls dev $EDEV
exit 0
#ip netns exec ns11  ip link set dev veth1 xdp obj xdp_kparser_kern.o verbose
#ip link set dev $EDEV xdp obj xdp_kparser_flowd_kern.o verbose
sleep 2
#ip link ls dev enp0s8
ip link ls dev $EDEV
ip netns exec ns11 ${LINUX_NET_NEXT}/samples/bpf/xdp_kparser_load 	\
	-M ${LINUX_NET_NEXT}/samples/bpf/xdp_kparser_kern 		\
	-S nveth11

sleep 2


#ip link set dev enp0s8 xdp off

#${LINUX_NET_NEXT}/tools/bpf/bpftool/bpftool map show
#${LINUX_NET_NEXT}/tools/bpf/bpftool/bpftool map dump id < from above ctx_map id >
#${LINUX_NET_NEXT}/tools/bpf/bpftool/bpftool prog trace


