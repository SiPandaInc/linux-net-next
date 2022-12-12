import pytest
import netns
import time
import subprocess
import json
import re
import os
from deepdiff import DeepDiff
from scapy.all import *
from pyroute2 import NetNS
from pyroute2 import IPRoute
from pyroute2 import IPDB
import pyroute2

def compile_xdp(mdata=None, lnn=None):
    md_str = ""
    if mdata is not None:
        md_str = 'TEST_FLAGS="-DMDATA=' + str(mdata) + '"'  
    if lnn == None:
    	return run_cmd(" cd ${LINUX_NET_NEXT}/samples/bpf ; make clean; make " + md_str)
    else:
    	return run_cmd(" cd " + lnn + "/samples/bpf ; make clean; make -j16" + md_str)


def _kparser_cmd_(args, json=True):
    _args = [os.getenv("IPROUTE2_PATH") + "/ip/ip"]
    if json:
        _args.append("-j")

    _args.append(args)
    returnObj = {}
    try:
        test_cmd = " ".join(_args)
        print("CMD : ", test_cmd)
        result = subprocess.run(test_cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,  shell=True)
        returnObj['returncode'] = result.returncode
        returnObj['stdout'] = str(result.stdout)
        returnObj['stderr'] = str(result.stderr)
        return returnObj

    except Exception as exception:
        print(" Failed to execute command ", exception)
        return None


def delete_kparser_obj(obj, obj_name, obj_id=None):

    del_cmd_str = " parser delete " + obj
    if (obj_name is not None):
        del_cmd_str = del_cmd_str + " name " + obj_name
    if (obj_id is not None):
        del_cmd_str = del_cmd_str + " id " + obj_id

    ret = _kparser_cmd_(del_cmd_str)
    print(" Delete : ", del_cmd_str, ret)
    return ret


def gen_kparser_cmd(obj, del_obj_exists=False):

    cmd_str = " {} {} ".format(obj['operation'],   obj['object'])
    if 'id' in obj.keys():
        cmd_str = cmd_str + " id " + obj['id']
    if 'name' in obj.keys():
        cmd_str = cmd_str + " name " + obj['name']

    for key in obj.keys():
        if (key == 'operation' or key == 'object' or key == 'name'
                or key == 'id'):
            continue
        cmd_str = cmd_str + " {} {} ".format(key, obj[key])

    ret = _kparser_cmd_(cmd_str)
    if (ret['returncode'] != 0):
        print(" KPARSER CMD FAILED : ", cmd_str)
        print(" STDOUT ", ret['stdout'])
        print(" STDERR ", ret['stderr'])
        return False
    else:
        return True
    return ret


def run_cmd(args):
    returnObj = {}
    try:
        test_cmd = args
        print("CMD : ", test_cmd)
        result = subprocess.run(test_cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,  shell=True)

        returnObj['returncode'] = result.returncode
        returnObj['stdout'] = result.stdout.decode()
        returnObj['stderr'] = str(result.stderr)
        return returnObj

    except Exception as exception:
        print(" Failed to execute command ", exception)
        return None


def load_kparser_module(filename):
    remove_kparser_module()
    return run_cmd(" insmod " + filename)


def remove_kparser_module():
    return run_cmd(" rmmod kparser.ko ")


def attach_xdp_module(file_module, veth, ntsname=None):
    nts_cmd = ""
    if ntsname is not None:
        nts_cmd = " ip netns exec " + ntsname
    return run_cmd(" {} ip link set dev {} xdp obj {}  verbose".format(
            nts_cmd, veth, file_module))


def detach_xdp_module(veth, ntsname=None):
    nts_cmd = ""
    if ntsname is not None:
        nts_cmd = " ip netns exec " + ntsname
    return run_cmd("{} ip link set dev {} xdp off ".format(
                nts_cmd, veth))


def check_xdp(veth, ntsname=None):
    nts_cmd = ""
    if ntsname is not None:
        nts_cmd = " ip netns exec " + ntsname
    result = run_cmd(" {} ip link ls dev {} | grep xdp  ".format(nts_cmd,
                     veth))
    print(" Check XDP Result : ", result)
    if (result['returncode'] == 0):
        return True
    else:
        return False


def get_ctx_id():
    cmd_str = "{}/tools/bpf/bpftool/bpftool map show | grep ctx | \
                cut -d' ' -f1 ".format(os.getenv("LINUX_NET_NEXT"))
    result = run_cmd(cmd_str)
    if (result['returncode'] == 0):
        print(" Got MD ID ", result)
        ctx_id = result['stdout'].split(':')
        return ctx_id[0]
    else:
        return -1


def get_metadata_dump(ctx_id):
    cmd_str = "{}/tools/bpf/bpftool/bpftool map dump id {} ".format(
                os.getenv("LINUX_NET_NEXT"), ctx_id)
    result = run_cmd(cmd_str)
    if (result['returncode'] == 0):
        print(" Metadata ", result['stdout'])
        return result['stdout']
    else:
        print(" Error Metadata stdout: ", result['stdout'])
        print(" Error Metadata stderr: ", result['stderr'])
        print(" Result: ", result)
        return None


def diff_data(d1, d2):
    result = DeepDiff(d1[0], d2[0])

    if (len(result.keys()) == 0) and 'value' in d1[0].keys():
        if 'value' in d2[0].keys():
            result_len = 0
            for key in d1[0]['value']:
                if key in d2[0]['value'].keys():
                    result1 = DeepDiff(d1[0]['value'][key], d2[0]['value'][key])
                    result_len = result_len + len(result1.keys())
            if result_len == 0:
                return True

    print(" Comparing data: ")
    print(" --- Actual : \n ", d1)
    print(" --- Expected : \n", d2)
    print(" --- Diff  : \n", len(result.keys()), result)
    return False


def check_output(exp_str_list, result_str, negativeTest=False):
       for expected_str in exp_str_list:
             if (len(re.findall(expected_str, str(result_str))) > 0):
                   continue
             else:
                print(" Expected String {} not found in result : {} ".format(expected_str, result_str))
                return False
       return True


def setup_kparser(kparser_module=None, xdp_module=None, veth=None, ntsname=None):
    retval1 = load_kparser_module(kparser_module)
    print(" Loading result ", retval1)
    if retval1['returncode'] != 0:
        return False

    retval2 = detach_xdp_module(veth, ntsname)
    print(" Detach Xdp  result ", retval2)
    if retval2['returncode'] != 0:
        return False

    retval3 = attach_xdp_module(xdp_module, veth, ntsname)
    print(" Xdp Loading result ", retval3)
    if retval3['returncode'] != 0:
        return False
    retval4 = check_xdp(veth, ntsname)
    return retval4

def get_test_dict(test_str):
    tkns = test_str.split(' ')
    test_dict = {}
    flag = False
    i = 0
    while i < len(tkns):
        if len(tkns[i]) < 1:
            i = i + 1
            continue
        test_dict[tkns[i]] = tkns[i + 1]
        i = i + 2
    
    if 'length' not in test_dict.keys():
        test_dict['length'] = 2
    return test_dict

def gen_test_flow(kparser_obj={}, src_veth=None, dst_veth=None, packets=None, expect_mdata_json=None, src_netns=None, dst_netns=None, del_kparser_cmd=True):
    if os.getenv("LINUX_NET_NEXT") is None:
        print(" SET LINUX_NET_NEXT Environment variable ")
        return

    load_kparser_config(kparser_obj, del_kparser_cmd)
    test_tx_rx_packet(src_veth=src_veth, dst_veth=dst_veth, packets=packets, src_netns=src_netns, dst_netns=dst_netns)
    ctx_id = get_ctx_id()
    act_mdata_json = json.loads(get_metadata_dump(ctx_id))
    return diff_data(expect_mdata_json, act_mdata_json)


def load_kparser_config(kparser_obj, del_kparser_cmd=True):
    if isinstance(kparser_obj, str):
        if (re.match("^ipcmd\s+\w", kparser_obj)):
            retcode = _kparser_cmd_(kparser_obj.replace("ipcmd", ""))
            if retcode['returncode'] == 0:
                print(" Success  ", retcode)
                return True
            else:
                print(" ERROR  ", retcode)
                return False
        infile = open(kparser_obj, "r")

        for line in infile:
            if (not re.match("^ipcmd\s+\w", line)):
                continue
            tmp_kobj = re.findall(
                                "create\s+([\w_-]+)\s+name\s+([\w._-]+)",
                                    line)
            #print(" DELETE ", tmp_kobj, len(tmp_kobj), del_kparser_cmd)
            if del_kparser_cmd and len(tmp_kobj) == 1 and len(tmp_kobj[0]) == 2:
                #print(" DELETE ", tmp_kobj, len(tmp_kobj[0]), del_kparser_cmd)
                obj_name = tmp_kobj[0][1]
                if not delete_kparser_obj(tmp_kobj[0][0], tmp_kobj[0][1]):
                    return False
            retcode = _kparser_cmd_(line.replace("ipcmd", ""))
            if retcode['returncode'] == 0:
                print(" Success  ", retcode)
            else:
                print(" ERROR  ", retcode)
                return False
    else:
        #TO DO handle kparser json object
        pass
    return True


def create_veth_setup(src_veth="veth0", dst_veth="veth1",
        src_netns="ns0", dst_netns="ns1", src_ip="10.10.200.10",
            dst_ip="10.10.200.20"):
    ipdb_main = IPDB()
    ipdb_src = IPDB(nl=NetNS(src_netns))
    ipdb_dst = IPDB(nl=NetNS(dst_netns))

    ipdb_main.create(ifname=src_veth, kind='veth', peer=dst_veth).commit()

    with ipdb_main.interfaces[src_veth] as veth:
        veth.net_ns_fd = src_netns
    with ipdb_main.interfaces[dst_veth] as veth:
        veth.net_ns_fd = dst_netns

    with ipdb_src.interfaces[src_veth] as veth:
        veth.add_ip(src_ip + "/24")
        veth.up()

    ipdb_src.routes.add({'dst': 'default',
                 'gateway': src_ip}).commit()

    with ipdb_dst.interfaces[dst_veth] as veth:
        veth.add_ip(dst_ip + "/24")
        veth.up()

    ipdb_dst.routes.add({'dst': 'default',
                 'gateway' : dst_ip}).commit()

def create_tap_setup(tapname="tap100", ip="192.168.100.10",  mtu=1500):
    
    result_0 = run_cmd("sudo ip tuntap add name {}  mode tap".format(
                    tapname))
    result_1 = run_cmd("sudo ip link set dev {} mtu {}".format(
                    tapname, mtu))
    result_2 = run_cmd("sudo ip link set {} up".format(
                    tapname))
    result_3 = run_cmd("sudo ip link set {} promisc on".format(
                    tapname))
    result_4 = run_cmd("sudo ip addr add {}/24 dev {}".format(
                    ip, tapname))

    return result_0 and result_1 and result_2 and result_3 and result_4


def cleanup_netns(src_netns="ns0", dst_netns="ns1"):
    ns1 = pyroute2.NetNS(src_netns)
    ns1.close()
    ns1.remove()
    ns2 = pyroute2.NetNS(dst_netns)
    ns2.close()
    ns2.remove()


#if __name__ == '__main__':
def test1() :
    rs = run_cmd("./scripts/mdr_types/gen_md.sh -t hdrdata -l 0 -s 0 -m 0 ")
    print("RESULT ", rs)
    exit(0)
    ip1 = "172.200.1.10"
    ip2 = "172.200.2.10"
    src_veth = "veth1"
    dst_veth = "veth2"
    src_netns = "nsA1"
    dst_netns = "nsA2"

    create_veth_setup(src_veth=src_veth, dst_veth=dst_veth, src_netns=src_netns, dst_netns=dst_netns, src_ip=ip1, dst_ip=ip2)
    pkt0 = [Ether()/IP(src=ip1, dst=ip2)/TCP(flags="S", sport=RandShort(), dport=80)]
    result2 = test_tx_rx_packet(src_veth=src_veth, dst_veth=dst_veth, src_netns=src_netns, dst_netns=dst_netns, packets=pkt0)
    print(" Send packet result ", result2)
    cleanup_netns(src_netns=src_netns, dst_netns=dst_netns)
    result2 = test_tx_rx_packet(src_veth=src_veth, dst_veth=dst_veth, src_netns=src_netns, dst_netns=dst_netns, packets=pkt0)
    print(" Send packet result ", result2)
    exit(0)
    #result1 = setup_kparser(kparser_module="/home/testusr/wspace/linux-net-next/net/kparser/kparser.ko", \
    #           xdp_module= "/home/testusr/wspace/linux-net-next/samples/bpf/xdp_kparser_kern.o", \
    #           veth= "veth11")
    #print(" Step 1 result ", result1)
    #exit(0)
    for i in range(1):
            pkt0 = [Ether()/IP(src="173.211.1.3", dst="172.211.1.4")/TCP(flags="S", sport=RandShort(), dport=80)]
            src_veth = "nveth10"
            result2 = test_tx_rx_packet(src_veth=src_veth, dst_veth="nveth11", packets=pkt0, src_netns="ns10", dst_netns="ns11")
            exit(0)
            ejson = json.loads('[{ "key": 1, "value": { "frame":' +
                    '{ "src_eth": [255,255,255,255,255,255 ],' + 
                    '"dst_eth": [255,255,255,255,255,255 ],' + 
                    '"ip_ver": 65535, "ip_proto": 255, "src_ip_addr":'+
                    ' 4294967295, "dst_ip_addr": 4294967295,' + 
                    '"src_tcp_port": 65535, "dst_tcp_port": 65535,' +
                    ' "src_udp_port": 65535, "dst_udp_port": 65535,' +
                    '"mss": 65535, "tcp_ts": 4294967295,' +
                    '"sack_left_edge": 65535, "sack_right_edge":' +
                    '65535, "gre_flags": 65535, "gre_seqno":' +
                    '4294967295, "vlan_cntr": 65535, "vlantcis":' +
                    ' [65535, 65535]}}}]')
            md_scr = "all_md_def_ln2.sh"
            ipcmdfile = "/home/testusr/wspace/kparser/data/" + md_scr
"""
            #gen_test_flow(kparser_json=test_0, src_veth="nveth0",
            dst_veth="nveth1", packets=pkt0, expect_mdata_json=ejson,
            src_netns="ns1", dst_netns="ns2", del_kparser_cmd=True)
            #gen_test_flow(kparser_obj=ipcmdfile, src_veth="veth01",
            dst_veth="veth11", packets=pkt0, expect_mdata_json=ejson,
            src_netns=None, dst_netns=None, del_kparser_cmd=True)
            #load_kparser_config(ipcmdfile)
"""

def test2():
    pkt0 = Ether()/IP(src="173.211.1.3", dst="172.211.1.4")/GRE(proto=0x0800)/IP(src="173.211.1.3", dst="172.211.1.4")/GRE(proto=0x0800)/IP(src="173.211.1.3", dst="172.211.1.4")/GRE(proto=0x0800)/IP(src="173.211.1.3", dst="172.211.1.4")/TCP(flags="S", sport=1234, dport=80)
    pkt1 = Ether()/IP(src="173.211.1.3", dst="172.211.1.4")
    #for x in range(3) :
    #    pkt1 = pkt1/GRE(proto=0x0800)/IP(src="173.211.1.3", dst="172.211.1.4")
    #pkt1 = pkt1/TCP(flags="S", sport=1234, dport=80)
    pkt1 = pkt1/TCP(flags="S", options=[("MSS",'2'), ( "WScale",'3'),
                    ("SAckOK",'4'), ("SAck", '5'), ("Timestamp", '8') ],
                    sport=1234, dport=80)
    
    print(" COmpare packet " , compare_packet(pkt0, pkt1))
    y0 = (bytes(pkt0).hex(",").replace("," , ",0x")).split(",")
    y1 = (bytes(pkt1).hex(",").replace("," , ",0x")).split(",")
    for i in range(len(y0)):
        if ( y0[i] != y1[i] ) :
            print(" Location {} yo : {} y1 {} ", i, y0[i], y1[i])

if __name__ == '__main__':
    create_tap_setup(tapname="tap102", ip="10.168.100.10",  mtu=1500)
    lnn = os.getenv("LINUX_NET_NEXT")

    time.sleep(2)
    setup_kparser(kparser_module=lnn + "/net/kparser/kparser.ko", 
            xdp_module= lnn + "/samples/bpf/xdp_kparser_kern.o", veth="tap102", ntsname=None)
    
    time.sleep(2)
    #load_kparser_config("./scripts/kparser_config/scenarios/upstream_patch_demo.sh", del_kparser_cmd=False)
    run_cmd("./scripts/kparser_config/scenarios/upstream_patch_demo.sh")
    import packet_util
    pkt = packet_util.get_packet(159)
    pkt1 = Ether()/IP(dst="8.8.8.8")/TCP()
    packet_util.test_tap_tx("tap102", pkt1)
    #ctx_id = get_ctx_id()
    #print(" CTX ", ctx_id )
    #act_mdata_json = json.loads(get_metadata_dump(ctx_id))
    #print(" Metadata ", act_mdata_json)

