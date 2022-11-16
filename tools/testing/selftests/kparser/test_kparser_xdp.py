import pytest
import json
import kparser_util
import packet_util
import os
from scapy.all import *
import allure

parent_testsuite=os.getenv("PARENT_TESTSUITE")
suite_name=os.getenv("TESTSUITE_NAME")
subsuite_name=os.getenv("SUB_TESTSUITE_NAME")


def pytest_generate_tests(metafunc):

    test_ids = []
    test_data = []
    try:
        ifile = open(metafunc.config.option.testfile)
        for line in ifile:
            tokens = line.split("|")
            test_ids.append(tokens[0])
            test_data.append([tokens[1], tokens[2], tokens[3]])
    except Exception as exception:
        print(" Exception reading testfile :  ", exception)

    if 'testdata' in metafunc.fixturenames:
        metafunc.parametrize(
            'testdata', test_data, ids=test_ids
        )


@pytest.fixture()
def testdata(request):
    return request.param


def kparser_cmd(args, json=True):
    _args = ["/home/testusr/wspace/iproute2/ip/ip"]
    if json:
        _args.append("-j")

    _args.append("parser")
    _args.append(args)
    returnObj = {}
    try:
        test_cmd = " ".join(_args)
        print("CMD : ", " ".join(_args))
        result = subprocess.run(test_cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, shell=True)

        returnObj['returncode'] = result.returncode
        returnObj['stdout'] = str(result.stdout)
        returnObj['stderr'] = str(result.stderr)
        return returnObj

    except Exception as exception:
        print(" Failed to execute command ", exception)
        return None



@allure.parent_suite(parent_testsuite)
@allure.suite(suite_name)
class TestKparserXDP():

    @classmethod
    def setup_class(cls):
        cls.lnn_path = ""
        if os.getenv("LINUX_NET_NEXT") is None:
            print(" LINUX_NET_NEXT not set ")
            #assert False
            exit(1)
        else:
            cls.lnn_path = os.getenv("LINUX_NET_NEXT")

        cls.tap = "tap101"
        #cls.veth0      = request.config.option.veth0
        #cls.veth1      = request.config.option.veth2
        cls.src_veth = "veth1"
        cls.dst_veth = "veth2"
        cls.src_netns = "nsT1"
        cls.dst_netns = "nsT2"

        cls.src_ip = packet_util.src_ip4
        cls.dst_ip = packet_util.dst_ip4
        cls.src_port = packet_util.src_port
        cls.dst_port = packet_util.dst_port

        #kparser_util.create_veth_setup(src_veth=cls.src_veth,
        #    dst_veth=cls.dst_veth, src_netns=cls.src_netns,
        #    dst_netns=cls.dst_netns, src_ip=cls.src_ip,
        #    dst_ip=cls.dst_ip)

        kparser_util.create_tap_setup(tapname=cls.tap, 
                    ip=cls.src_ip, mtu=8500) 

        ip_parts = cls.src_ip.split('.')
        cls.src_ipnum = (int(ip_parts[3]) << 24) + (int(ip_parts[2]) << 16) + (int(ip_parts[1]) << 8) + int(ip_parts[0])
        ip_parts = cls.dst_ip.split('.')
        cls.dst_ipnum = (int(ip_parts[3]) << 24) + (int(ip_parts[2]) << 16) + (int(ip_parts[1]) << 8) + int(ip_parts[0])

        #cls.pkt = Ether(src=cls.src_eth)/IP(src=cls.src_ip, dst=cls.dst_ip)/TCP(flags="S", sport=RandShort(), dport=80)
        cls.pkt = packet_util.get_packet(159)
        print("PACKET ", cls.pkt)

    @classmethod
    def teardown_class(cls):
        result0 = kparser_util.remove_kparser_module()
        #result0 = kparser_util.detach_xdp_module(cls.dst_veth, ntsname=cls.dst_netns)
        result = kparser_util.detach_xdp_module(cls.tap)
        #kparser_util.cleanup_netns(src_netns=cls.src_netns, dst_netns=cls.dst_netns)
        result = kparser_util.run_cmd(
                    "sudo ip tuntap del name {}  mode tap".\
                            format(cls.tap))

    @allure.sub_suite(subsuite_name)
    def test_attach_xdp(self):
        result = kparser_util.setup_kparser(self.lnn_path + "/net/kparser/kparser.ko",
            self.lnn_path + "/samples/bpf/xdp_kparser_kern.o",
            self.tap)
            #self.dst_veth, self.dst_netns)
        assert result

    @allure.sub_suite(subsuite_name)
    def test_metadata_without_kparser_config(self):
        expect_mdata_json = json.loads('[{"key":1,"value":{"frames":{"ip_offset":65535,"l4_offset":65535,"ipv4_addrs":[4294967295,4294967295],"ports":[65535,65535]}}}]')

        result0  = packet_util.test_tap_tx(self.tap,
              self.pkt)
        #result0 = packet_util.test_tx_rx_packet(src_veth=self.src_veth, dst_veth=self.dst_veth, packets=self.pkts[0], src_netns=self.src_netns, dst_netns=self.dst_netns)
        ctx_id = kparser_util.get_ctx_id()
        act_mdata_json = json.loads(kparser_util.get_metadata_dump(ctx_id))
        print(" Metadata ", act_mdata_json)
        result1 = kparser_util.diff_data(act_mdata_json, expect_mdata_json)
        assert result0 and result1


    @allure.sub_suite(subsuite_name)
    def test_metadata_with_kparser_config(self):
        #expect_mdata_json = json.dumps([{"key":1,"value":{"frames":{"ip_offset":14,"l4_offset":34,"ipv4_addrs":[self.src_ipnum,self.dst_ipnum],"ports":[self.dst_port,self.src_port]}}}])
        expect_mdata_json = json.loads('[{"key":1,"value":{"frames":{"ip_offset":14,"l4_offset":34,"ipv4_addrs":[' + str(self.src_ipnum) +
                    ',' + str(self.dst_ipnum) + '],"ports":[' + str(self.dst_port) +  ','  + str(self.src_port) + ']}}}]' )

        result0 = kparser_util.load_kparser_config("./scripts/kparser_config/scenarios/upstream_patch_demo.sh", del_kparser_cmd=False)
        time.sleep(1)
        result1  = packet_util.test_tap_tx(self.tap,
              self.pkt)
        result1  = packet_util.test_tap_tx(self.tap,
              self.pkt)
        time.sleep(1)
        ctx_id = kparser_util.get_ctx_id()
        act_mdata_json = json.loads(kparser_util.get_metadata_dump(ctx_id))
        print(" Metadata ", act_mdata_json)
   
        result2 = kparser_util.diff_data(act_mdata_json, expect_mdata_json)
        print(result0, result1, result2)
        assert result0 and result1 and result2

    @allure.sub_suite(subsuite_name)
    def xtest_rmmod_kparser(self):
        expect_md = json.loads('[{"key":1,"value":{"frames":{"ip_offset":65535,"l4_offset":65535,"ipv4_addrs":[4294967295,4294967295],"ports":[65535,65535]}}}]')
        result0 = kparser_util.remove_kparser_module()
        result01 = kparser_util.load_kparser_config(
            "ipcmd parser create md-rule name md.iphdr_offset type offset md-off 0")
        result1 = kparser_util.setup_kparser(
                            self.lnn_path + "/net/kparser/kparser.ko",
                            self.lnn_path + "/samples/bpf/xdp_kparser_kern.o",
                            self.tap)
        result2  = packet_util.test_tap_tx(self.tap,
              self.pkt)
        ctx_id = kparser_util.get_ctx_id()
        act_md = json.loads(kparser_util.get_metadata_dump(ctx_id))
        print(" Metadata ", act_md)
   
        result3 = kparser_util.diff_data(expect_md, act_md)
        assert result0 and not result01 and result1 and result2 and result3
       
    @allure.sub_suite(subsuite_name)
    def xtest_detach_xdp(self):
        #result0 = kparser_util.detach_xdp_module(self.dst_veth, ntsname=self.dst_netns)
        result0 = kparser_util.detach_xdp_module(self.tap)
        result1 = kparser_util.check_xdp(self.tap)
        assert result0 and not result1
