import pytest
import random
import codecs
import json
import kparser_util
import packet_util
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
        cls.tap = "tap" + str(random.randint(100,1000))

        cls.src_eth = "ff:ff:ff:ff:ff:ff"
        cls.dst_eth = "ff:ff:ff:ff:ff:ff"
        cls.src_ip = "10.10.1.10"
        cls.dst_ip = "10.10.2.11"
        cls.src_port = 8080
        cls.dst_port = 8090

        kparser_util.create_tap_setup(tapname=cls.tap, 
                    ip=cls.src_ip, mtu=8500) 

        ip_parts = cls.src_ip.split('.')
        cls.src_ipnum = (int(ip_parts[3]) << 24) + (int(ip_parts[2]) << 16) + (int(ip_parts[1]) << 8) + int(ip_parts[0])
        ip_parts = cls.dst_ip.split('.')
        cls.dst_ipnum = (int(ip_parts[3]) << 24) + (int(ip_parts[2]) << 16) + (int(ip_parts[1]) << 8) + int(ip_parts[0])
        
        #cls.pkt = packet_util.get_encap_pkt(numencaps=1, type=0) 
        #cls.pkt = packet_util.get_custom_packet(length=400)
        cls.pkt = packet_util.get_packet(156)

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


    @classmethod
    def get_expect_metadata(cls,teststr, expect_mdata_json):
        tdict = kparser_util.get_test_dict(teststr)
        pkt_len = len(bytes(cls.pkt) )
        print("Test Dict", tdict, expect_mdata_json)
        print("Sending packet of length: {} ..".format( pkt_len))
        tlen1 = len(expect_mdata_json[0]['value']['frame']['data'])
        if ('isframe' in tdict.keys() and  tdict['isframe'] == 'true') or \
            (int(tdict['length']) >= pkt_len) or (int(tdict['length']) == 0):
            print(" All default values ")
        elif 'type' not in tdict.keys() or tdict['type'] == 'hdrdata':
            exp_data = packet_util.get_data(cls.pkt, int(tdict['hdr-src-off']), int(tdict['length']))
            print("Pcket data ", exp_data)
            #tlen = int(tdict['md-off']) + int(tdict['length'])
            tlen = len(exp_data)
            #tlen1 = len(act_mdata_json[0]['value']['frame']['data'])
            print(" tlen {} tlen1 {} ".format( tlen, tlen1))
            for i in range(tlen):
                if 'isendianneeded' in tdict.keys() and tdict['isendianneeded'] == 'true':
                    indx1 = tlen -i -1
                else:
                    indx1 = i
                indx0 = int(tdict['md-off']) + i
                if indx0 < tlen1:
                    expect_mdata_json[0]['value']['frame']['data'][indx0] = exp_data[indx1]
                else:
                    break

        elif tdict['type'] == 'constant_byte':
            indx0 = int(tdict['md-off'])
            cvalue = 0
            basevalue = 0
            if 'constantvalue' in tdict.keys():
                if 'x' in tdict['constantvalue']:
                    cvalue = int(tdict['constantvalue'], 16)
                else:
                    cvalue = int(tdict['constantvalue'], 10)
    
            if indx0 < tlen1:
                expect_mdata_json[0]['value']['frame']['data'][indx0] = cvalue
            
        else:
            print("Invalid Metadata Types ")
            
            
        print(" Exp data ", expect_mdata_json)

    @allure.sub_suite(subsuite_name)
    def test_attach_xdp(self):
        result = kparser_util.setup_kparser(self.lnn_path + "/net/kparser/kparser.ko",
            self.lnn_path + "/samples/bpf/xdp_kparser_kern.o",
            #self.src_veth, self.src_netns)
            self.tap)
        assert result

    @allure.sub_suite(subsuite_name)
    def test_metadata(self,testdata,request):
        self.testscript = request.config.option.kparserconfig
        #expect_mdata_json = json.dumps([{"key":1,"value":{"frames":{"ip_offset":14,"l4_offset":34,"ipv4_addrs":[self.src_ipnum,self.dst_ipnum],"ports":[self.dst_port,self.src_port]}}}])
        expect_mdata_json = json.loads(testdata[2])
        print("Loading config..")
        kparser_util.load_kparser_module(self.lnn_path + "/net/kparser/kparser.ko")
        #result_0 = kparser_util.run_cmd(
        #            "./scripts/kparser_config/gen_tlvnodes.sh " +
        #            testdata[0])
        result_0 = kparser_util.run_cmd(" {} \"{}\" ".format(
                            self.testscript, testdata[0]))
        ret_kparser_script = True
        if (result_0['returncode'] != 0): 
            print(" kParser Config load failed ", result_0 )
            print("KPARSER SCRIPT OUT :",result_0['stdout'])
            print("KPARSER SCRIPT ERR :",result_0['stderr'])
            ret_kparser_script = False

        time.sleep(1)
       
        ret_tx_rx_pkt  = packet_util.test_tap_tx(self.tap,
              self.pkt)
    
        # get actual meta-data 
        ctx_id = kparser_util.get_ctx_id()
        md_str = kparser_util.get_metadata_dump(ctx_id)
        act_mdata_json = json.loads(md_str)
    
        # prepare expected metadata 
        self.get_expect_metadata(testdata[0], expect_mdata_json)

        # compare actual vs expected meta-data
        ret_md_cmp = kparser_util.diff_data(act_mdata_json, expect_mdata_json)
        print(ret_kparser_script, ret_tx_rx_pkt, ret_md_cmp)

        #self.print_pkts()
        print("---------------------------------------------------------------")
        assert ret_kparser_script and ret_tx_rx_pkt and ret_md_cmp
