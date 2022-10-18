VNUM=1
NSNAME0=ns${VNUM}0
NSNAME1=ns${VNUM}1

VETH0=nveth${VNUM}0
VETH1=nveth${VNUM}1

IP1=172.2${VNUM}1.1.3
IP2=172.2${VNUM}1.1.4

echo " ns0 ${NSNAME0} ns1 ${NSNAME1}"
echo " nveth0 ${VETH0} nveth1 ${VETH1} "
echo " ip1 $IP1  ip2 $IP2 "

#exit 0
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

IP1=172.2${VNUM}1.1.3
IP2=172.2${VNUM}1.1.4
setup_veth() 
{
perform_step ip link add ${VETH0} type veth peer name ${VETH1}
perform_step ip link set dev ${VETH0} up
perform_step ip link set dev ${VETH1} up
perform_step ip addr add $IP1 dev ${VETH0}
perform_step ip addr add $IP2 dev ${VETH1}
}

setup_iptable() 
{
perform_step iptables -t mangle -s $IP1/32 -A OUTPUT -j MARK --set-mark 1
perform_step iptables -t mangle -s $IP2/32 -A OUTPUT -j MARK --set-mark 1
}

setup_priority()
{
 ip rule del from all pref 0 lookup local
 ip rule add from all pref 100 lookup local
}

setup_route()
{
perform_step ip route add $IP2/32 via $IP1 dev ${VETH0} table 100
perform_step ip route add $IP1/32 via $IP2 dev ${VETH1} table 100
}


setup_finish()
{
 ip rule add fwmark 1 pref 10 lookup 100

 echo 1 > /proc/sys/net/ipv4/conf/${VETH0}/accept_local
 echo 1 > /proc/sys/net/ipv4/conf/${VETH1}/accept_local
 echo 2 > /proc/sys/net/ipv4/conf/${VETH0}/rp_filter
 echo 2 > /proc/sys/net/ipv4/conf/${VETH1}/rp_filter;
}

setup_nns()
{
perform_step ip netns add ${NSNAME0}
perform_step ip netns add ${NSNAME1}
perform_step ip link set ${VETH0} netns ${NSNAME0}
perform_step ip link set ${VETH1} netns ${NSNAME1}

# Assign IPs to both vethDemo0 vethDemo1 and enable
perform_step ip netns exec ${NSNAME0} ip addr add $IP1/24 dev ${VETH0}
perform_step ip netns exec ${NSNAME0} ip link set ${VETH0} up

perform_step ip netns exec ${NSNAME1} ip addr add $IP2/24 dev ${VETH1}
perform_step ip netns exec ${NSNAME1} ip link set ${VETH1} up
}

setup_veth
setup_iptable
setup_priority
setup_route
setup_finish
setup_nns
