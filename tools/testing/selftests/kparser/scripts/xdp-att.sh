#EDEV=enp0s8
EDEV=tap10
ip link set dev $EDEV xdp off
ip link ls dev $EDEV
#ip netns exec ns2 ip link set dev veth1 xdp off
export PKD_CONFIG_PATH=/home/testusr/wspace/linux-net-next/tools/lib/bpf
rmmod kparser.ko
cd /home/testusr/wspace/linux-net-next/
#make M=net/kparser clean
#make M=net/kparser 

insmod /home/testusr/wspace/linux-net-next/net/kparser/kparser.ko
/home/testusr/wspace/iproute2/ip/ip -V
cd /home/testusr/wspace/linux-net-next/samples/bpf
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
ip netns exec ns11 /home/testusr/wspace/linux-net-next/samples/bpf/xdp_kparser_load 	\
	-M /home/testusr/wspace/linux-net-next/samples/bpf/xdp_kparser_kern 		\
	-S nveth11

sleep 2

#cd /home/testusr/wspace/iproute2/
#./kparser_3.sh
#/home/testusr/wspace/iproute2/kParser_CLI_5tuple_demo_v0.sh

#ip link set dev enp0s8 xdp off

#/home/testusr/wspace/linux-net-next/tools/bpf/bpftool/bpftool map show
#/home/testusr/wspace/linux-net-next/tools/bpf/bpftool/bpftool map dump id < from above ctx_map id >
#/home/testusr/wspace/linux-net-next/tools/bpf/bpftool/bpftool prog trace


