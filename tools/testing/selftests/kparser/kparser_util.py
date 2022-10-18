import pytest
import netns
import time
import subprocess
import json
import re
from deepdiff import DeepDiff
from scapy.all import *


def _kparser_cmd_(args, json=True):
    _args = ["/home/testusr/wspace/iproute2/ip/ip"]
    if json:
        _args.append("-j")

    #_args.append("parser")
    _args.append(args)
    returnObj = {}
    try :
     
        #test_cmd = _args
        test_cmd = " ".join(_args)
        print("CMD : " , test_cmd )
       
        result = subprocess.run( test_cmd , stdout = subprocess.PIPE, stderr = subprocess.PIPE,  shell=True )

        returnObj['returncode'] = result.returncode
        returnObj['stdout'] = str(result.stdout)
        returnObj['stderr'] = str(result.stderr)
        return returnObj

    except Exception as exception :
      print(" Failed to execute command ", exception )
      return None

def delete_kparser_obj( obj, obj_name, obj_id=None ) :
    
    del_cmd_str = " parser delete " +  obj
    if ( obj_name is not None ) :
        del_cmd_str = del_cmd_str + " name " + obj_name 

    if ( obj_id is not None ) :
        del_cmd_str = del_cmd_str + " id " + obj_id 

    ret = _kparser_cmd_(del_cmd_str )
    print(" Delete : " , del_cmd_str, ret )
    return ret



def gen_kparser_cmd( obj , del_obj_exists=False) :

    cmd_str = " {} {} ".format( obj['operation'],   obj['object'])
    if 'id' in obj.keys() :
        cmd_str = cmd_str + " id " + obj['id'] 
    if 'name' in obj.keys() :
        cmd_str = cmd_str + " name " + obj['name'] 

    for key in obj.keys() :
        if ( key == 'operation' or key == 'object' or key == 'name' or key == 'id'  ) :
            continue
        cmd_str = cmd_str + " {} {} ".format(key , obj[key] )

    ret = _kparser_cmd_(cmd_str )
    if ( ret['returncode'] != 0 ) :
        print(" STDOUT " , ret['stdout'] )
        print(" STDERR " , ret['stderr'] )
        return False
    else :
        return True
    return ret

def run_cmd(args ):
    returnObj = {}
    try :
        test_cmd = args  #" ".join(args)
        #print("CMD : " , " ".join(args) )
        print("CMD : " , test_cmd )
        result = subprocess.run( test_cmd , stdout = subprocess.PIPE, stderr = subprocess.PIPE,  shell=True )

        returnObj['returncode'] = result.returncode
        returnObj['stdout'] = result.stdout.decode()
        returnObj['stderr'] = str(result.stderr)
        return returnObj

    except Exception as exception :
      print(" Failed to execute command ", exception )
      return None

def load_kparser_module(filename ) :
    remove_kparser_module()
    return run_cmd(" insmod " + filename )

def remove_kparser_module() :
    return run_cmd(" rmmod kparser.ko ")

def attach_xdp_module( file_module , veth,  ntsname = None) :
    nts_cmd = ""
    if ntsname is not  None :
        nts_cmd = " ip netns exec " + ntsname
    return run_cmd(" {} ip link set dev {} xdp obj {}  verbose".format(nts_cmd, veth, file_module ))

def detach_xdp_module( veth, ntsname = None ) :
    nts_cmd = ""
    if ntsname != None :
        nts_cmd = " ip netns exec " + ntsname
    return run_cmd("{} ip link set dev {} xdp off ".format( nts_cmd,  veth ))

def check_xdp( veth, ntsname = None ) :
    nts_cmd = ""
    if ntsname != None :
        nts_cmd = " ip netns exec " + ntsname
    result =  run_cmd(" {} ip link ls dev {} | grep xdp  ".format(nts_cmd, veth ))
    print(" Result " , result )
    if ( result['returncode']  == 0 ) :
       return True 
    else : 
       return False

def get_ctx_id():
    cmd_str = "{}/tools/bpf/bpftool/bpftool map show | grep ctx | cut -d' ' -f1 ".format(os.getenv("LINUX_NET_NEXT"))
    result = run_cmd(cmd_str ) 
    if ( result['returncode'] == 0 ) :
       return result['stdout'].strip().replace(':','')
    else :
       return -1 

def get_metadata_dump( ctx_id ) :
    cmd_str = "{}/tools/bpf/bpftool/bpftool map dump id {} ".format(os.getenv("LINUX_NET_NEXT"), ctx_id)
    result = run_cmd(cmd_str ) 
    if ( result['returncode'] == 0 ) :
        print(" Metadata ", result['stdout'])
        return result['stdout'] 
    else :
        print(" Error Metadata out ", result['stdout'])
        print(" Error Metadata err ", result['stderr'])
        return None

   
def test_tx_rx_packet(src_veth="veth0",dst_veth="veth0",packets=None,src_netns=None, dst_netns=None) :

    print("Initialize sniff ")
    if dst_netns is not None :
        with netns.NetNS(nsname=dst_netns): 
            sniff_hndl = AsyncSniffer(iface=dst_veth)
            sniff_hndl.start()
    else :
        sniff_hndl = AsyncSniffer(iface=dst_veth)
        sniff_hndl.start()
    
        
    
    if src_netns is not None :
        with netns.NetNS(nsname=src_netns): 
            sendp(packets,iface=src_veth)
    else :
        sendp(packets,iface=src_veth)
        
    time.sleep(2)

    if dst_netns is not None :
        with netns.NetNS(nsname=dst_netns): 
            recv_pkts = sniff_hndl.stop()
    else :
        recv_pkts = sniff_hndl.stop()
    
    print(" RECED ", recv_pkts, sniff_hndl.results )
    rcount = len(recv_pkts)
    scount = len( packets ) 
    if  rcount < scount : 
         print(" Number of packets received {} is less then sent {} ".format( rcount , scount))
         return False
    else :
         return compare_packets( packets, recv_pkts )



def compare_packets( exp_pkts, act_pkts ) :
    
    for pkt0 in exp_pkts :
        i=0
        for pkt1 in exp_pkts :
            if compare_packet(pkt0, pkt1) :
                act_pkts.pop(i) 
                found = True 
                break
            else :
                i = i + 1	

        if not found :
           print(" Packet not found ", pkt0 ) 
           return False
    return True
 
def compare_packet(exp_pkt, act_pkt ) :
   
    return_val = True  
     
    exp_payload =  exp_pkt.payload
    act_payload =  act_pkt.payload
    while True : 
      len1 = len(exp_payload) 
      len2 = len(act_payload) 
 
      if len1 == len2  :
         if ( len1 == 0 ) :
            break
         else :
            if exp_payload.fields == act_payload.fields :
               exp_payload = exp_payload.payload
               act_payload = act_payload.payload
               continue
            else :
               print(" Payload mismatch " , exp_payload.fields, act_payload.fields ) 
               return_val = False
               break
      else :
         print(" Payload len mismatch " , exp_payload.fields, act_payload.fields ) 
         return_val = False 
         break

    return return_val
         

def diff_data(d1 , d2   ) :
    result = DeepDiff(d1[0],d2[0])

    if (len(result.keys()) ==  0)  and ('value' in d1[0].keys() and 'frame' in d1[0]['value']  ) :
        if 'value' in d2[0].keys() and 'frame' in d2[0]['value']  :
            result1 = DeepDiff(d1[0]['value']['frame'], d2[0]['value']['frame'])
            if len(result.keys()) == 0 :
                return True
            
    print(" Comparing data : ")
    print(" --- Actual : \n " , d1 )
    print(" --- Expected : \n" , d2 )
    print(" --- Diff  : \n" , result )
    return False

    
def check_output( exp_str_list, result_str, negativeTest=False): 
       
       for expected_str in exp_str_list :
             if ( len( re.findall( expected_str , str(result_str) )) > 0 ) :
                   continue
             else :
                print(" Expected String {} not found in result : {} ".format(expected_str , result_str ))
                return False
       return True

def setup_kparser(kparser_module=None, xdp_module=None , veth=None, ntsname=None ) :
    retval1 = load_kparser_module(kparser_module ) 
    print(" Loading result " , retval1 )
    if  retval1['returncode'] != 0 :
        return False 

    retval2 =  detach_xdp_module( veth, ntsname ) 
    print(" Detaich Xdp  result " , retval2 )
    if  retval2['returncode'] != 0 :
        return False 

    retval3 =  attach_xdp_module( xdp_module, veth, ntsname ) 
    print(" Xdp Loading result " , retval3 )
    if  retval3['returncode'] != 0 :
        return False 
    retval4 =  check_xdp( veth, ntsname ) 
    
    return retval4

def gen_test_flow( kparser_obj={}, src_veth=None, dst_veth=None, packets=None, expect_mdata_json=None, src_netns=None, dst_netns=None, del_kparser_cmd=True) :
    if os.getenv("LINUX_NET_NEXT") is None :
        print(" SET LINUX_NET_NEXT Environment variable ")
        return 
   
    load_kparser_config(kparser_obj,del_kparser_cmd)
    test_tx_rx_packet(src_veth=src_veth,dst_veth=dst_veth,packets=packets,src_netns=src_netns, dst_netns=dst_netns) 
    ctx_id = get_ctx_id()
    act_mdata_json = json.loads(get_metadata_dump( ctx_id ))
    #print(" Metadata " , act_mdata_json)
    
    return diff_data(expect_mdata_json , act_mdata_json  ) 

def load_kparser_config( kparser_obj , del_kparser_cmd=True) : 
    if ( type(kparser_obj) == type("str")) :  
        infile = open(kparser_obj , "r") 
        
        for line in infile :
            if ( not re.match("^ipcmd\s+\w" , line ) ) :
                continue
            tmp_kobj  = re.findall("create\s+([\w_-]+)\s+name\s+([\w._-]+)",line)
            #print(" DELETE " , tmp_kobj , len(tmp_kobj) , del_kparser_cmd) 
            if del_kparser_cmd and len(tmp_kobj) == 1 and len(tmp_kobj[0]) == 2 :
                #print(" DELETE " , tmp_kobj , len(tmp_kobj[0]) , del_kparser_cmd) 
                obj_name = tmp_kobj[0][1]
                if not delete_kparser_obj(tmp_kobj[0][0] , tmp_kobj[0][1] ) :
                    return Falase
                
    
#        obj_id = None
#        if ( 'id' in kparser_json[i].keys() ):
#            obj_id = kparser_json[i]['id']
#        obj_name = None
#        if del_kparser_cmd and ( 'name' in kparser_json[i].keys() ):
#            obj_name = kparser_json[i]['name']
#            delete_kparser_obj( kparser_json[i]['object'], obj_name, obj_id ) 
#        if gen_kparser_cmd(kparser_json[i])  :
            retcode =  _kparser_cmd_( line.replace("ipcmd", "")  )
            if retcode['returncode'] == 0 :
                print(" Success  ", retcode )
            else :
                print(" ERROR  ", retcode )
                return False
    else :
        #handle kparser json object 
        pass
    return True

if __name__ == '__main__':
    #result1 = setup_kparser( kparser_module="/home/testusr/wspace/linux-net-next/net/kparser/kparser.ko", \
    #           xdp_module= "/home/testusr/wspace/linux-net-next/samples/bpf/xdp_kparser_kern.o", \
    #           veth= "veth11")
    #print(" Step 1 result " , result1 )

    for i in range(1):
            pkt0 = [Ether()/IP(src="172.180.1.3",dst="172.180.1.4")/TCP(flags="S", sport=RandShort(), dport=80) ]
            #result2 = test_tx_rx_packet("veth0","veth1", pkt0 )
            #exit(0) 
            #print(" COMP " , result2 )    
            #result2 = test_tx_rx_packet("nveth0","nveth1", pkt0 ,"ns1","ns2")
            src_veth="veth01"
            result2 = test_tx_rx_packet(src_veth=src_veth,dst_veth="veth11", packets=pkt0 )
            continue
            
            ipcmdfile = "/home/testusr/wspace/test/data/all_md_types_len2.sh"
            #ipcmdfile = "/home/testusr/wspace/test/data/all_md_def_len2.sh"
            #gen_test_flow( kparser_json=test_0, src_veth="nveth0", dst_veth="nveth1", packets=pkt0, expect_mdata_json=ejson, src_netns="ns1",dst_netns="ns2", del_kparser_cmd=True) 
            gen_test_flow( kparser_obj=ipcmdfile, src_veth="veth01", dst_veth="veth11", packets=pkt0, expect_mdata_json=ejson, src_netns=None,dst_netns=None, del_kparser_cmd=True) 
            
