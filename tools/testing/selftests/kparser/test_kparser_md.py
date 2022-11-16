import pytest
import json
import kparser_util
import os
from scapy.all import *


""" 
@pytest.fixture(scope='class', autouse=True)
def setup_xdp(self ) :
    lnn_path = ""
    if  os.getenv("LINUX_NET_NEXT") is None :
        print(" LINUX_NET_NEXT not set ")
        assert False 
    else :
        lnn_path = os.getenv("LINUX_NET_NEXT")

    #self.veth0 = request.config.option.veth0
    #self.veth1 = request.config.option.veth2
    self.veth0 = "veth0"
    self.veth1 = "veth1"

    kparser_util.setup_kparser(lnn_path + "/net/kparser/kparser.ko",
            lnn_path + "/samples/bpf/xdp_kparser_kern.o",
            self.veth1 )
""" 

#@pytest.mark.usefixtures('setup_xdp') 
class TestKparserMD():
    @classmethod
    def setup_class(cls ) :
        lnn_path = ""
        if  os.getenv("LINUX_NET_NEXT") is None :
            print(" LINUX_NET_NEXT not set ")
            assert False 
        else :
            lnn_path = os.getenv("LINUX_NET_NEXT")

        #cls.veth0 = request.config.option.veth0
        #cls.veth1 = request.config.option.veth2
        cls.veth0 = "nveth0"
        cls.veth1 = "nveth1"
        cls.netns0 = "ns1"
        cls.netns1 = "ns2"
        cls.pkts = [Ether()/IP(src="172.200.1.3",dst="172.200.1.4")/TCP(flags="S", sport=RandShort(), dport=80) ]

        cls.ejson = json.loads('[{ "key": 1, "value": { "frame": { "src_eth": [255,255,255,255,255,255 ], "dst_eth": [255,255,255,255,255,255 ], "ip_ver": 65535, "ip_proto": 255, "src_ip_addr": 4294967295, "dst_ip_addr": 4294967295, "src_tcp_port": 65535, "dst_tcp_port": 65535, "src_udp_port": 65535, "dst_udp_port": 65535, "mss": 65535, "tcp_ts": 4294967295, "sack_left_edge": 65535, "sack_right_edge": 65535, "gre_flags": 65530, "gre_seqno": 4294967295, "vlan_cntr": 65535, "vlantcis": [65535,65535 ] } } } ] ')
        kparser_util.setup_kparser(lnn_path + "/net/kparser/kparser.ko",
            lnn_path + "/samples/bpf/xdp_kparser_kern.o",
            cls.veth1, cls.netns1 )

#@pytest.mark.usefixtures('setup_xdp') 

    def test_table00(self) :
        
        result = kparser_util.gen_test_flow( kparser_json=test_0, src_veth=self.veth0, dst_veth=self.veth1, packets=self.pkts[0], expect_mdata_json=self.ejson, src_netns="ns1", dst_netns="ns2",del_kparser_cmd=True) 
       
        assert result

    def xtest_table01(self) :
        

        test_0 = [
        {'operation':'create', 'object':'table', 'name':'table.ether' },  
#        { 'operation':'create', 'object':'metadata-rule', 'name':'md.numnodes', 'type':'numnodes' , 'md-off': 8 },
       # { 'operation':'create', 'object':'metadata-rule', 'name':'md.numencaps', 'type':'numencaps' , 'md-off': 4 },
#        { 'operation':'create', 'object':'metadata-rule', 'name':'md.returncode', 'type':'return_code' , 'md-off': 0 },
        #{ 'operation':'create', 'object':'metadata-rule', 'name':'md.timest', 'type':'timestamp' , 'md-off': 12 },
        { 'operation':'create', 'object':'metadata-rule', 'name':'md.eth.type', 'type':'offset' , 'md-off': 0 , 'addoff' : 20 },
#        { 'operation':'create', 'object':'metadata-rule', 'name':'md.boffset1', 'type':'bit_offset' , 'md-off': 16 , 'addoff' : 8 },
#        { 'operation':'create', 'object':'metadata-rule', 'name':'md.nibb1', 'type':'nibbs_hdrdata' , 'md-off': 18 , 'addoff' : 10 },
#        { 'operation':'create', 'object':'metadata-rule', 'name':'md.hdrlen', 'type':'hdrlen' , 'md-off': 19 , 'addoff' : 12 },
#        { 'operation':'create', 'object':'metadata-rule', 'name':'md.const1', 'type':'constant_byte' , 'md-off': 20 , 'constantvalue':'0x80' },
#        { 'operation':'create', 'object':'metadata-rule', 'name':'md.consthb1', 'type':'constant_halfword' , 'md-off': 21 , 'constantvalue':'0x80' },
#        { 'operation':'create', 'object':'metadata-ruleset', 'name':'mdl.ether', 'md.rule':'md.returncode', 'md.rule':'md.numnodes', 'md.rule':'md.numencaps', 'md.rule':'md.timest' , 'md.rule':'md.offset1' , 'md.rule' : 'md.nibb1' , 'md.rule':'md.hdrlen', 'md.rule':'const1', 'md.rule':'md.conshb1', 'md.rule':'md.boffset1' },
#        { 'operation':'create', 'object':'metadata-ruleset', 'name':'mdl.ether', 'md.rule':'md.returncode', 'md.rule':'md.numnodes' },
        { 'operation':'create', 'object':'metadata-ruleset', 'name':'mdl.ether', 'md.rule':'md.eth.type', 'md.rule':'md.numnodes' },
        {'operation':'create', 'object':'node', 'name':'node.ether', 'min-hdr-length':14 , 'nxt.field-off':12, 'nxt.field-len':2, 'nxt.table': 'table.ether', 'md.ruleset': 'mdl.ether' },
        {'operation':'create', 'object':'parser', 'name':'test_parser', 'metametasize':24, 'rootnode':'node.ether'}
        ]
        result = kparser_util.gen_test_flow( kparser_json=test_0, src_veth=self.veth0, dst_veth=self.veth1, packets=self.pkts[0], expect_mdata_json=self.ejson, src_netns="ns1", dst_netns="ns2",del_kparser_cmd=True) 
       
        assert result

    # HDR-SRC-OFF = 100000
    def xtest_hdr_src_off_outside(self) :
        
        
        test_0 = [{'operation':'create', 'object':'table', 'name':'table.ether' },  
            { 'operation':'create', 'object':'metadata-rule', 'name':'md.eth.src', 'hdr-src-off' : 4294967295   , 'length': 6 , 'md-off':0} , 
            { 'operation':'create', 'object':'metadata-rule', 'name':'md.eth.dst', 'hdr-src-off' : 6 , 'length': 6 , 'md-off':6} , 
            { 'operation':'create', 'object':'metadata-ruleset', 'name':'mdl.ether', 'md.rule':'md.eth.src', 'md.rule':'md.eth.dst' },
            {'operation':'create', 'object':'node', 'name':'node.ether', 'min-hdr-length':14 , 'nxt.field-off':12, 'nxt.field-len':2, 'nxt.table': 'table.ether', 'md.ruleset': 'mdl.ether' },
            {'operation':'create', 'object':'parser', 'name':'test_parser', 'metametasize':18, 'rootnode':'node.ether'}
        ]
        kparser_util.gen_test_flow( test_0, self.veth0, self.veth1, self.pkts[0], self.ejson, True) 
        
    #MD-OFF = 100000
    def xtest_md_off_outside(self) :
        
        
        test_0 = [{'operation':'create', 'object':'table', 'name':'table.ether' },  
            { 'operation':'create', 'object':'metadata-rule', 'name':'md.eth.src', 'hdr-src-off' : 6   , 'length': 4294967294 , 'md-off':0} , 
            { 'operation':'create', 'object':'metadata-rule', 'name':'md.eth.dst', 'hdr-src-off' : 6 , 'length': 6 , 'md-off':4294967295} , 
            { 'operation':'create', 'object':'metadata-ruleset', 'name':'mdl.ether', 'md.rule':'md.eth.src', 'md.rule':'md.eth.dst' },
            {'operation':'create', 'object':'node', 'name':'node.ether', 'min-hdr-length':14 , 'nxt.field-off':12, 'nxt.field-len':2, 'nxt.table': 'table.ether', 'md.ruleset': 'mdl.ether' },
            {'operation':'create', 'object':'parser', 'name':'test_parser', 'metametasize':18, 'rootnode':'node.ether'}
        ]
        retval = kparser_util.gen_test_flow( test_0, self.veth0, self.veth1, self.pkts[0], self.ejson, True) 
        assert not retval

    #length = 100000
    def xtest_length_offlimit(self) :
        
        
        test_0 = [{'operation':'create', 'object':'table', 'name':'table.ether' },  
            { 'operation':'create', 'object':'metadata-rule', 'name':'md.eth.src', 'hdr-src-off' : 6   , 'length': 6 , 'md-off':0} , 
            { 'operation':'create', 'object':'metadata-rule', 'name':'md.eth.dst', 'hdr-src-off' : 6 , 'length': 4294967293 , 'md-off':6} , 
            { 'operation':'create', 'object':'metadata-ruleset', 'name':'mdl.ether', 'md.rule':'md.eth.src', 'md.rule':'md.eth.dst' },
            {'operation':'create', 'object':'node', 'name':'node.ether', 'min-hdr-length':14 , 'nxt.field-off':12, 'nxt.field-len':2, 'nxt.table': 'table.ether', 'md.ruleset': 'mdl.ether' },
            {'operation':'create', 'object':'parser', 'name':'test_parser', 'metametasize':18, 'rootnode':'node.ether'}
        ]
        retval = kparser_util.gen_test_flow( test_0, self.veth0, self.veth1, self.pkts[0], self.ejson, True) 

    #mddata = 100000
    def xtest_length_md_offlimit(self) :
        
        
        test_0 = [{'operation':'create', 'object':'table', 'name':'table.ether' },  
            { 'operation':'create', 'object':'metadata-rule', 'name':'md.eth.src', 'hdr-src-off' : 6   , 'length': 6 , 'md-off':0} , 
            { 'operation':'create', 'object':'metadata-rule', 'name':'md.eth.dst', 'hdr-src-off' : 6 , 'length': 120 , 'md-off':6} , 
            { 'operation':'create', 'object':'metadata-ruleset', 'name':'mdl.ether', 'md.rule':'md.eth.src', 'md.rule':'md.eth.dst' },
            {'operation':'create', 'object':'node', 'name':'node.ether', 'min-hdr-length':14 , 'nxt.field-off':12, 'nxt.field-len':2, 'nxt.table': 'table.ether', 'md.ruleset': 'mdl.ether' },
            {'operation':'create', 'object':'parser', 'name':'test_parser', 'metametasize':320, 'rootnode':'node.ether'}
        ]
        retval = kparser_util.gen_test_flow( test_0, self.veth0, self.veth1, self.pkts[0], self.ejson, True) 

    #addoff = 100000
    def xtest_addoff_offlimit(self) :
        
        
        test_0 = [{'operation':'create', 'object':'table', 'name':'table.ether' },  
            { 'operation':'create', 'object':'metadata-rule', 'name':'md.eth.src', 'hdr-src-off' : 0   , 'length': 6 , 'md-off':0} , 
            { 'operation':'create', 'object':'metadata-rule', 'name':'md.eth.dst', 'addoff' : 16777215 , 'length': 6 , 'md-off':6} , 
            { 'operation':'create', 'object':'metadata-ruleset', 'name':'mdl.ether', 'md.rule':'md.eth.src', 'md.rule':'md.eth.dst' },
            {'operation':'create', 'object':'node', 'name':'node.ether', 'min-hdr-length':14 , 'nxt.field-off':12, 'nxt.field-len':2, 'nxt.table': 'table.ether', 'md.ruleset': 'mdl.ether' },
            {'operation':'create', 'object':'parser', 'name':'test_parser', 'metametasize':18, 'rootnode':'node.ether'}
        ]
        retval = kparser_util.gen_test_flow( test_0, self.veth0, self.veth1, self.pkts[0], self.ejson, True) 

    #isframe = true without userframe
    def xtest_isframe_wo(self) :
        
        
        test_0 = [{'operation':'create', 'object':'table', 'name':'table.ether' },  
            { 'operation':'create', 'object':'metadata-rule', 'name':'md.eth.src', 'hdr-src-off' : 0   , 'length': 6 , 'md-off':0} , 
            { 'operation':'create', 'object':'metadata-rule', 'name':'md.eth.dst', 'addoff' : 16777215 , 'length': 6 , 'md-off':6 , 'isframe':'true'} , 
            { 'operation':'create', 'object':'metadata-ruleset', 'name':'mdl.ether', 'md.rule':'md.eth.src', 'md.rule':'md.eth.dst' },
            {'operation':'create', 'object':'node', 'name':'node.ether', 'min-hdr-length':14 , 'nxt.field-off':12, 'nxt.field-len':2, 'nxt.table': 'table.ether', 'md.ruleset': 'mdl.ether' },
            {'operation':'create', 'object':'parser', 'name':'test_parser', 'metametasize':18, 'rootnode':'node.ether'}
        ]
        retval = kparser_util.gen_test_flow( test_0, self.veth0, self.veth1, self.pkts[0], self.ejson, True) 
        assert not retval


    #min hdr length > 65530
    def xtest_min_hdr_len(self) :
        
        
        test_0 = [{'operation':'create', 'object':'table', 'name':'table.ether' },  
            { 'operation':'create', 'object':'metadata-rule', 'name':'md.eth.src', 'hdr-src-off' : 0   , 'length': 6 , 'md-off':0} , 
            { 'operation':'create', 'object':'metadata-rule', 'name':'md.eth.dst', 'hdr-src-off' : 6 , 'length': 6 , 'md-off':6  } , 
            { 'operation':'create', 'object':'metadata-ruleset', 'name':'mdl.ether', 'md.rule':'md.eth.src', 'md.rule':'md.eth.dst' },
            {'operation':'create', 'object':'node', 'name':'node.ether', 'min-hdr-length':4504 , 'nxt.field-off':12, 'nxt.field-len':2, 'nxt.table': 'table.ether', 'md.ruleset': 'mdl.ether' },
            {'operation':'create', 'object':'parser', 'name':'test_parser', 'metametasize':18, 'rootnode':'node.ether'}
        ]
        retval = kparser_util.gen_test_flow( test_0, self.veth0, self.veth1, self.pkts[0], self.ejson, True) 
        assert not retval


    #nxt field off > 65530
    def xtest_nxt_hdr_off(self) :
        
        
        test_0 = [{'operation':'create', 'object':'table', 'name':'table.ether' },  
            { 'operation':'create', 'object':'metadata-rule', 'name':'md.eth.src', 'hdr-src-off' : 0   , 'length': 6 , 'md-off':0} , 
            { 'operation':'create', 'object':'metadata-rule', 'name':'md.eth.dst', 'hdr-src-off' : 6 , 'length': 6 , 'md-off':6  } , 
            { 'operation':'create', 'object':'metadata-ruleset', 'name':'mdl.ether', 'md.rule':'md.eth.src', 'md.rule':'md.eth.dst' },
            {'operation':'create', 'object':'node', 'name':'node.ether', 'min-hdr-length':14 , 'nxt.field-off':65534, 'nxt.field-len':2, 'nxt.table': 'table.ether', 'md.ruleset': 'mdl.ether' },
            {'operation':'create', 'object':'parser', 'name':'test_parser', 'metametasize':18, 'rootnode':'node.ether'}
        ]
        retval = kparser_util.gen_test_flow( test_0, self.veth0, self.veth1, self.pkts[0], self.ejson, True) 


    #nxt field len > 65530
    def xtest_nxt_field_len(self) :
        
        
        test_0 = [{'operation':'create', 'object':'table', 'name':'table.ether' },  
            { 'operation':'create', 'object':'metadata-rule', 'name':'md.eth.src', 'hdr-src-off' : 0   , 'length': 6 , 'md-off':0} , 
            { 'operation':'create', 'object':'metadata-rule', 'name':'md.eth.dst', 'hdr-src-off' : 6 , 'length': 6 , 'md-off':6  } , 
            { 'operation':'create', 'object':'metadata-ruleset', 'name':'mdl.ether', 'md.rule':'md.eth.src', 'md.rule':'md.eth.dst' },
            {'operation':'create', 'object':'node', 'name':'node.ether', 'min-hdr-length':14 , 'nxt.field-off':12, 'nxt.field-len':255, 'nxt.table': 'table.ether', 'md.ruleset': 'mdl.ether' },
            {'operation':'create', 'object':'parser', 'name':'test_parser', 'metametasize':18, 'rootnode':'node.ether'}
        ]
        retval = kparser_util.gen_test_flow( test_0, self.veth0, self.veth1, self.pkts[0], self.ejson, True) 


    #nxt field len > 65530
    def xtest_nxt_field_multiplier(self) :
        
        
        test_0 = [
            {'operation':'create', 'object':'table', 'name':'table.ether' },  
            {'operation':'create', 'object':'table', 'name':'table.ipv4' },  
            { 'operation':'create', 'object':'metadata-rule', 'name':'md.eth.src', 'hdr-src-off' : 0   , 'length': 6 , 'md-off':0} , 
            { 'operation':'create', 'object':'metadata-rule', 'name':'md.eth.dst', 'hdr-src-off' : 6 , 'length': 6 , 'md-off':6  } , 
            { 'operation':'create', 'object':'metadata-rule', 'name':'md.ipv4.ipproto_offset', 'type':'bit_offset', 'addoff' : 72 , 'md-off':12  } , 
            { 'operation':'create', 'object':'metadata-ruleset', 'name':'mdl.ether', 'md.rule':'md.eth.src', 'md.rule':'md.eth.dst' },
            {'operation':'create', 'object':'node', 'name':'node.ether', 'min-hdr-length':14 , 'nxt.field-off':12, 'nxt.field-len':2, 'nxt.table': 'table.ether', 'md.ruleset': 'mdl.ether' },
            {'operation':'create', 'object':'node', 'name':'node.ipv4', 'min-hdr-length':20,
              'hdr.len.field-off':0, 'hdr.len.mask': 0x0f, 'hdr.len.multiplier':4 , 
               'nxt.field-off':9 , 'nxt.field-len':1 ,  'md.rule':'md.ipv4.ipproto_offset', 'nxt.table' :'table.ipv4'   },
            { 'operation':'create', 'object':'table/table.ether' , 'key':'0x800', 'node':'node.ipv4'},
            { 'operation':'create', 'object':'table/table.ipv4' , 'key':'0x800', 'node':'node.ether'},
            {'operation':'create', 'object':'parser', 'name':'test_parser', 'metametasize':18, 'rootnode':'node.ether'}
        ]
        retval = kparser_util.gen_test_flow( test_0, self.veth0, self.veth1, self.pkts[0], self.ejson, True) 

    #nxt field len > 65530
    def xtest_nxt_field_multiplier(self) :
        
        
        test_0 = [
            {'operation':'create', 'object':'table', 'name':'table.ether' },  
            {'operation':'create', 'object':'table', 'name':'table.ipv4' },  
            { 'operation':'create', 'object':'metadata-rule', 'name':'md.eth.src', 'hdr-src-off' : 0   , 'length': 6 , 'md-off':0} , 
            { 'operation':'create', 'object':'metadata-rule', 'name':'md.eth.dst', 'hdr-src-off' : 6 , 'length': 6 , 'md-off':6  } , 
            { 'operation':'create', 'object':'metadata-rule', 'name':'md.ipv4.ipproto_offset', 'type':'bit_offset', 'addoff' : 72 , 'md-off':12  } , 
            { 'operation':'create', 'object':'metadata-ruleset', 'name':'mdl.ether', 'md.rule':'md.eth.src', 'md.rule':'md.eth.dst' },
            {'operation':'create', 'object':'node', 'name':'node.ether', 'min-hdr-length':14 , 'nxt.field-off':12, 'nxt.field-len':2, 'nxt.table': 'table.ether', 'md.ruleset': 'mdl.ether' },
            {'operation':'create', 'object':'node', 'name':'node.ipv4', 'min-hdr-length':20,
              'hdr.len.field-off':0, 'hdr.len.mask': 0x0f, 'hdr.len.multiplier':5 , 
               'nxt.field-off':9 , 'nxt.field-len':1 ,  'md.rule':'md.ipv4.ipproto_offset', 'nxt.table' :'table.ipv4'   },
            { 'operation':'create', 'object':'table/table.ether' , 'key':'0x800', 'node':'node.ipv4'},
            { 'operation':'create', 'object':'table/table.ipv4' , 'key':'0x6', 'node':'node.ether'},
            {'operation':'create', 'object':'parser', 'name':'test_parser', 'metametasize':18, 'rootnode':'node.ether'}
        ]
        retval = kparser_util.gen_test_flow( test_0, self.veth0, self.veth1, self.pkts[0], self.ejson, True) 


    # populate mini mdatada
    def xtest_001(self) :
        
        
        test_0 = [
            {'operation':'create', 'object':'table', 'name':'table.ether' },  
            {'operation':'create', 'object':'table', 'name':'table.ipv4' },  
            { 'operation':'create', 'object':'metadata-rule', 'name':'md.eth.src', 'hdr-src-off' : 10   , 'length': 2 , 'md-off':0} , 
            { 'operation':'create', 'object':'metadata-rule', 'name':'md.eth.dst', 'hdr-src-off' : 12 , 'length': 4 , 'md-off':2  } , 
            #{ 'operation':'create', 'object':'metadata-rule', 'name':'md.ipv4.ipproto_offset', 'type':'bit_offset', 'addoff' : 72 , 'md-off':12  } , 
            { 'operation':'create', 'object':'metadata-rule', 'name':'md.ipv4.src_ip_off', 'type':'bit_offset', 'addoff' : 90 , 'md-off':6  } , 
            { 'operation':'create', 'object':'metadata-rule', 'name':'md.ipv4.dst_ip_off', 'type':'bit_offset', 'addoff' : 128 , 'md-off':8  } , 
            { 'operation':'create', 'object':'metadata-ruleset', 'name':'mdl.ether', 'md.rule':'md.eth.src', 'md.rule':'md.eth.dst' },
            {'operation':'create', 'object':'node', 'name':'node.ether', 'min-hdr-length':14 , 'nxt.field-off':12, 'nxt.field-len':2, 'nxt.table': 'table.ether', 'md.ruleset': 'mdl.ether' },
            {'operation':'create', 'object':'node', 'name':'node.ipv4', 'min-hdr-length':20,
              'hdr.len.field-off':0, 'hdr.len.mask': 0x0f, 'hdr.len.multiplier':4 , 
               'nxt.field-off':9 , 'nxt.field-len':1 ,  'md.rule':'md.ipv4.src_ip_off', 'md.rule':'md.ipv4.dst_ip_off', 'nxt.table' :'table.ipv4'   },
            { 'operation':'create', 'object':'table/table.ether' , 'key':'0x800', 'node':'node.ipv4'},
            { 'operation':'create', 'object':'table/table.ipv4' , 'key':'0x6', 'node':'node.ether'},
            {'operation':'create', 'object':'parser', 'name':'test_parser', 'metametasize':18, 'rootnode':'node.ether'}
        ]

        result = kparser_util.gen_test_flow( kparser_json=test_0, src_veth=self.veth0, dst_veth=self.veth1, packets=self.pkts[0], expect_mdata_json=self.ejson, src_netns="ns1", dst_netns="ns2",del_kparser_cmd=True) 
       
        assert result

