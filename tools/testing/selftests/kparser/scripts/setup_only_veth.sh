
function perform_step() 
{
	echo " Performing $1 in $PWD "

	$@

	retval=$?
	if [[ $retval -eq 0 ]]; then
		  echo " COMMAND : $@ -> Ok "
	else
		    echo " COMMAND : $@ -> Failure "
		    exit $retval
	fi

}

VNUM=1
IP1=172.18${VNUM}.1.3
IP2=172.18${VNUM}.1.4
VETH0=veth0${VNUM}
VETH1=veth1${VNUM}

setup_veth() 
{
perform_step ip link add $VETH0 type veth peer name $VETH1
perform_step ip link set dev $VETH0 up
perform_step ip link set dev $VETH1 up
perform_step ip addr add $IP1 dev $VETH0
perform_step ip addr add $IP2 dev $VETH1
}

setup_iptable() 
{
#perform_step iptables -t mangle -s $IP1/32 -A OUTPUT -j MARK --set-mark 1
perform_step iptables -t mangle -s $IP1/32 -A OUTPUT -j CONNMARK  --set-mark 1
#perform_step iptables -t mangle -s $IP2/32 -A OUTPUT -j MARK --set-mark 1
perform_step iptables -t mangle -s $IP2/32 -A OUTPUT -j CONNMARK  --set-mark 1
}

setup_priority()
{
perform_step ip rule del from all pref 0 lookup local
perform_step ip rule add from all pref 100 lookup local
}

setup_route()
{
perform_step ip route add $IP2/32 via $IP1 dev $VETH0 table 100
perform_step ip route add $IP1/32 via $IP2 dev $VETH1 table 100
}


setup_finish()
{
perform_step ip rule add fwmark 1 pref 10 lookup 100

echo "   ..... "
echo 1 > /proc/sys/net/ipv4/conf/$VETH0/accept_local
echo 1 > /proc/sys/net/ipv4/conf/$VETH1/accept_local
echo 2 > /proc/sys/net/ipv4/conf/$VETH0/rp_filter
echo 2 > /proc/sys/net/ipv4/conf/$VETH1/rp_filter;
}

setup_nns()
{
perform_step ip netns add ns1
perform_step ip netns add ns2
perform_step ip link set $VETH0 netns ns1
perform_step ip link set $VETH1 netns ns2

# Assign IPs to both vethDemo0 vethDemo1 and enable
perform_step ip netns exec ns1 ip addr add $IP1/24 dev $VETH0
perform_step ip netns exec ns1 ip link set $VETH0 up

perform_step ip netns exec ns2 ip addr add $IP2/24 dev $VETH1
perform_step ip netns exec ns2 ip link set $VETH1 up
}

setup_veth
setup_iptable
setup_priority
setup_route
setup_finish
#setup_nns
