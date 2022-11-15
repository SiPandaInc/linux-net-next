import pytest
import codecs
import numpy as np
import json
import kparser_util
import os
from scapy.all import *
import allure
import proto

parent_testsuite=os.getenv("PARENT_TESTSUITE")
suite_name=os.getenv("TESTSUITE_NAME")
subsuite_name=os.getenv("SUB_TESTSUITE_NAME")

def pytest_generate_tests(metafunc):
    
    print(" Reading data ")
    test_ids = []
    test_data = []
    try :
        ifile = open(metafunc.config.option.testfile)
        for line in ifile:
            tokens = line.split("|")
            test_ids.append(tokens[0] )
            test_data.append([tokens[1],tokens[2],tokens[3]] )
    except Exception as exception:
        print(" Exception reading testfile :  ", exception)


    if 'testdata' in metafunc.fixturenames:
        metafunc.parametrize(
            'testdata', test_data , ids=test_ids
        )


@pytest.fixture()
def testdata(request):
    return request.param


@allure.parent_suite(parent_testsuite)
@allure.suite(suite_name)

class TestkParserMD():

    @classmethod
    def setup_class(cls):
        cls.lnn_path = ""
        cls.lnn_path = ""
        if os.getenv("LINUX_NET_NEXT") is None:
            print(" LINUX_NET_NEXT not set ")
            #assert False
            exit(1)
        else:
            cls.lnn_path = os.getenv("LINUX_NET_NEXT")

        #cls.veth0      = request.config.option.veth0
        #cls.veth1      = request.config.option.veth2
        cls.tap = "tap100"

        cls.src_eth = "ff:ff:ff:ff:ff:ff"
        cls.dst_eth = "ff:ff:ff:ff:ff:ff"
        cls.src_ip = "10.10.1.10"
        cls.dst_ip = "10.10.2.11"
        cls.src_port = 8080
        cls.dst_port = 8090


        result_0 = kparser_util.run_cmd("sudo ip tuntap add name {}  mode tap".format(cls.tap))
        result_0 = kparser_util.run_cmd("sudo ip link set dev {} mtu {}".format(cls.tap,8500))
        result_0 = kparser_util.run_cmd("sudo ip link set {} up".format(cls.tap))
        result_0 = kparser_util.run_cmd("sudo ip link set {} promisc on".format(cls.tap))
        result_0 = kparser_util.run_cmd("sudo ip addr add {}/24 dev {}".format(cls.src_ip, cls.tap))
        ip_parts = cls.src_ip.split('.')
        cls.src_ipnum = (int(ip_parts[3]) << 24) + (int(ip_parts[2]) << 16) + (int(ip_parts[1]) << 8) + int(ip_parts[0])
        ip_parts = cls.dst_ip.split('.')
        cls.dst_ipnum = (int(ip_parts[3]) << 24) + (int(ip_parts[2]) << 16) + (int(ip_parts[1]) << 8) + int(ip_parts[0])

        cls.pkts = [[Ether()/IP(src=cls.src_ip, dst=cls.dst_ip)/TCP(flags="S", sport=RandShort(), dport=80)],
                   [Ether()/IP(src=cls.src_ip, dst=cls.dst_ip)/TCP(flags="S", sport=cls.src_port, dport=cls.dst_port),
                   Ether()/IP(src=cls.src_ip, dst=cls.dst_ip)/TCP(flags="S", sport=cls.src_port, dport=cls.dst_port)
                   ]]

        #tmp = [ x for x in range(200,0,-1)]
        cls.pkt = Ether(src="FF:FF:FF:FF:FF:FF",dst="ff:ff:ff:ff:ff:ff")/IP(src=cls.src_ip, dst=cls.dst_ip)/TCP(flags="S", sport=cls.src_port, dport=cls.dst_port)
        #cls.pkt = proto.TestProto2(data='x'*65533)/IP(src=cls.src_ip, dst=cls.dst_ip)/TCP(flags="S", sport=cls.src_port, dport=cls.dst_port)
        #str1 = b'0123456789abcdef'
        str0 = ''.join(format(hex(255),"02") for i in range(128))
        #str0 = ''.join(format(255,") for i in range(128))
        tmp_str = "f"*128
        tmp_str1 = bytes(tmp_str, encoding='utf-8')
        str0 = codecs.decode(tmp_str1, "hex")
        str1 = ''.join(chr(i) for i in range(128))
        x1 = str0 + bytes(str1*510,'utf-8') + str0
        ###cls.pkt = proto.TestProto2(data=x1)/IP(src=cls.src_ip, dst=cls.dst_ip)/TCP(flags="S", sport=cls.src_port, dport=cls.dst_port)
        #cls.pkt = TestProto2(data='A'*65533)/IP(src="10.10.11.2", dst="10.10.11.3")/TCP(flags="S", sport=1234, dport=2345)
        #cls.pkt = Ether(dst=cls.dst_eth, src=cls.src_eth)/IP(dst=cls.dst_ip, src=cls.src_ip)/GRE(proto=0x0800)/IP(dst=cls.src_ip, src=cls.dst_ip, proto=6)/TCP(sport=cls.src_port,dport=cls.dst_port)/("X"*480)
        #cls.pkt = Ether(dst=cls.dst_eth, src=cls.src_eth)/IP(dst=cls.dst_ip, src=cls.src_ip)/GRE(proto=0x0800)/IP(dst=cls.dst_ip, src=cls.src_ip)/GRE(proto=0x0800)/IP(dst=cls.src_ip, src=cls.dst_ip, proto=6)/TCP(sport=cls.src_port,dport=cls.dst_port)/("X"*480)
        ##cls.pkt = Ether(dst=cls.dst_eth, src=cls.src_eth)/IP(dst=cls.dst_ip, src=cls.src_ip)/GRE(proto=0x0800)/IP(dst=cls.dst_ip, src=cls.src_ip)/GRE(proto=0x0800)/IP(dst=cls.dst_ip, src=cls.src_ip)/GRE(proto=0x0800)/IP(dst=cls.dst_ip, src=cls.src_ip)/TCP(sport=cls.src_port,dport=cls.dst_port)/("X"*480)
        cls.pkt1 = Ether(dst=cls.dst_eth, src=cls.src_eth)/IP(dst=cls.dst_ip, src=cls.src_ip)/GRE(proto=0x0800)/IP(dst=cls.dst_ip, src=cls.src_ip)/GRE(proto=0x0800)/IP(dst=cls.dst_ip, src=cls.src_ip)/GRE(proto=0x0800)/IP(dst=cls.dst_ip, src=cls.src_ip)/GRE(proto=0x0800)/IP(dst=cls.dst_ip, src=cls.src_ip)/GRE(proto=0x0800)/IP(dst=cls.dst_ip, src=cls.src_ip)/TCP(sport=cls.src_port,dport=cls.dst_port)/("X"*4)
        cls.pkt = Ether(dst=cls.dst_eth, src=cls.src_eth)/IP(dst=cls.dst_ip, src=cls.src_ip) #/GRE(proto=0x0800)/IP(dst=cls.src_ip, src=cls.dst_ip, proto=6)/TCP(sport=cls.src_port,dport=cls.dst_port)/("X"*480)
        #enlayer = IP(dst=cls.src_ip, src=cls.dst_ip, proto=6)/TCP(sport=cls.src_port,dport=cls.dst_port)/("X"*480)
        #for e in range(2):
        #    cls.pkt = cls.pkt/GRE(proto=0x0800)/IP(dst=cls.src_ip, src=cls.dst_ip, proto=6)  #/TCP(sport=cls.src_port,dport=cls.dst_port)/("X"*480)
        #cls.pkt = cls.pkt/TCP(sport=cls.src_port,dport=cls.dst_port)/("X"*4)
        #cls.pkt = Ether(src="FF:FF:FF:FF:FF:FF",dst="ff:ff:ff:ff:ff:ff")/IP(src=cls.src_ip, dst=cls.dst_ip)/TCP(flags="S", sport=cls.src_port, dport=cls.dst_port)
        cls.pkt1 = Ether()/IP(src="173.211.1.3", dst="172.211.1.4")/GRE(proto=0x0800)/IP(src="173.211.1.3", dst="172.211.1.4")/GRE(proto=0x0800)/IP(src="173.211.1.3", dst="172.211.1.4")/GRE(proto=0x0800)/IP(src="173.211.1.3", dst="172.211.1.4")/TCP(flags="S", sport=1234, dport=80)
        cls.pkt = Ether()/Dot1Q(vlan=0x9,type=0x0800)/IP(src="173.211.1.3", dst="172.211.1.4")
        for x in range(1):
            cls.pkt = cls.pkt/GRE()/Dot1Q(vlan=0x7,type=0x0800)/IP(src="173.211.1.3", dst="172.211.1.4")
        cls.pkt = cls.pkt/TCP(flags="S", options=[("MSS", 2), ( "WScale", 3)],
                             #("SAckOK", '4'), ("SAck", '5'), ("Timestamp", '8') ],
                             sport=1234, dport=80)


    @classmethod
    def teardown_class(cls):
        result = kparser_util.remove_kparser_module()
        result = kparser_util.detach_xdp_module(cls.tap)
        result = kparser_util.run_cmd("sudo ip tuntap del name {}  mode tap".format(cls.tap))
        

    @classmethod
    def print_pkts(cls):
        print(" XYZ : ", bytes(cls.pkt))
        harr0 = ('0x' +  bytes(cls.pkt).hex(",").replace("," , ",0x")).split(",") 
        iarr0 = [ int(x, base=16)  for x in harr0]
        print(" PacketHEX : {} \n PacketINT : {} \n".format(harr0, iarr0 ))
        print(" XYZ1 : ", bytes(cls.pkt1))
        harr1 = ('0x' +  bytes(cls.pkt1).hex(",").replace("," , ",0x")).split(",") 
        iarr1 = [ int(x, base=16)  for x in harr1]
        print(" PacketHEX : {} \n PacketINT : {} \n".format(harr1, iarr1 ))

        if iarr1 == iarr0 :
            print(" Packets are equal ") 
        else :
            print(" Length " , len(iarr0), len(iarr1))
            print(" Packets are Not equal ") 
            for i in range(len(iarr0)):
                if ( iarr0[i] != iarr1[i] ):
                    print(" location " , i) 
                    print(" iarr0 ", iarr0[0:i+1] )
                    print(" iarr1 ", iarr1[0:i+1] )
                    break 
            


    @allure.sub_suite(subsuite_name)
    def test_attach_xdp(self):
        result = kparser_util.setup_kparser(self.lnn_path + "/net/kparser/kparser.ko",
            self.lnn_path + "/samples/bpf/xdp_kparser_kern.o",
            #self.src_veth, self.src_netns)
            self.tap)
        assert result

    @allure.sub_suite(subsuite_name)
    def test_metadata(self,testdata):
        #expect_mdata_json = json.dumps([{"key":1,"value":{"frames":{"ip_offset":14,"l4_offset":34,"ipv4_addrs":[self.src_ipnum,self.dst_ipnum],"ports":[self.dst_port,self.src_port]}}}])
        expect_mdata_json = json.loads(testdata[2])
        kparser_util.load_kparser_module(self.lnn_path + "/net/kparser/kparser.ko")
        #result_0 = kparser_util.run_cmd("./scripts/kparser_config/gen_mdrule.sh " + testdata[0] )
        #result_0 = kparser_util.run_cmd("./scripts/kparser_config/gen_node2.sh " + testdata[0] )
        #result_0 = kparser_util.run_cmd("./scripts/kparser_config/gen_node3.sh " + testdata[0] )
        #result_0 = kparser_util.run_cmd("./scripts/kparser_config/gen_demo.sh " + testdata[0] )
        result_0 = kparser_util.run_cmd("./scripts/kparser_config/gen_tlvnodes.sh " + testdata[0] )
        #result_0 = kparser_util.run_cmd("./scripts/patch_demo.sh ")
        ret_kparser_script = True
        print("KPARSER SCRIPT OUT :",result_0['stdout'])
        print("KPARSER SCRIPT ERR :",result_0['stderr'])
        if (result_0['returncode'] != 0): 
            print(" kParser Config load failed ", result_0 )
            ret_kparser_script = False

        time.sleep(1)
        ret_tx_rx_pkt  = kparser_util.test_tap_tx(self.tap,
              self.pkt)
        ctx_id = kparser_util.get_ctx_id()
        md_str = kparser_util.get_metadata_dump(ctx_id)
        act_mdata_json = json.loads(md_str)
        ret_md_cmp = kparser_util.diff_data(expect_mdata_json, act_mdata_json)
        print(ret_kparser_script, ret_tx_rx_pkt, ret_md_cmp)
        self.print_pkts()
        assert ret_kparser_script and ret_tx_rx_pkt and ret_md_cmp
