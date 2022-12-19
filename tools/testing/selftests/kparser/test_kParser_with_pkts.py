import json
import kparser_util
import packet_util
import os
from scapy.all import *
from argparse import ArgumentParser
import shutil
import time

global backup_md_file
global tap
 
def check_and_assert(result):
	if isinstance(result, bool):
		if result != True:
			assert result
			exit (-1)
		return

	if result == None or result['returncode'] != 0:
		print ("err: {}".format(result))
		assert result
		exit (-1)

def construct_path(path_conf, lnn_path):
	if path_conf == None:
		return None
	if 'path-inside-lnn' not in path_conf:
		return None
	if 'file' not in path_conf:
		return None
	file = None
	if path_conf['path-inside-lnn'] == "yes":
		file = lnn_path
	file = file + path_conf['file']
	return file

def setup_xdp(xdp_conf, lnn_path):
	global backup_md_file
	if xdp_conf['recompile-samples-prog'] != "yes":
		return True

	target_md_hdr_file = construct_path(xdp_conf['target-md-hdr-file-path'], lnn_path)
	if os.path.isfile(target_md_hdr_file) == False:
		print ("{} is missing" . format(target_md_hdr_file))
		return False

	src_md_hdr_file = construct_path(xdp_conf['src-md-hdr-file-path'], lnn_path)
	if os.path.isfile(src_md_hdr_file) == False:
		print ("{} is missing" . format(src_md_hdr_file))
		return False

	if os.path.isfile(target_md_hdr_file):

		if os.path.isfile(src_md_hdr_file):
			backup_md_file = target_md_hdr_file + '.' + str(time.time())
			shutil.copyfile(target_md_hdr_file, backup_md_file)
			shutil.copyfile(src_md_hdr_file, target_md_hdr_file)
			print ("current md hdr file {} is backed up at {} and"
				" replaced by {}".
				format(target_md_hdr_file, backup_md_file,
					src_md_hdr_file))
			result = kparser_util.compile_xdp(lnn = lnn_path)
			check_and_assert(result)
			return True

		if xdp_conf['C-md-structure'] != "":
			backup_md_file = target_md_hdr_file + '.' + str(time.time())
			shutil.copyfile(target_md_hdr_file, backup_md_file)
			print ("current md hdr file {} is backed up at {}" .
				format(target_md_hdr_file, backup_md_file))
			with open(target_md_hdr_file, 'w') as md_file:
				for line in xdp_conf['C-md-structure']:
					md_file.write(line)
					md_file.write("\n")
			result = kparser_util.compile_xdp(lnn = lnn_path)
			check_and_assert(result)

	return True

def execute_test(test):
	global tap
	print ("INFO: Starting test: {}, desc: \"{}\"" .
		format(test['test-name'], test['description']))
	lnn_path = ""
	if 'lnn-path' not in test:
		if os.getenv("LINUX_NET_NEXT") is None:
			print("LINUX_NET_NEXT not set ")
			exit(-1)
		else:
			lnn_path = os.getenv("LINUX_NET_NEXT")
	else:
		lnn_path = test['lnn-path']

	iproute2_path = ""
	if 'iproute2-path' not in test:
		if os.getenv("IPROUTE2_PATH") is None:
			print("IPROUTE2_PATH not set ")
			exit(-1)
		else:
			iproute2_path = os.getenv("IPROUTE2_PATH")
	else:
		iproute2_path = test['iproute2-path']

	log_dir = construct_path(test['log-dir-path'], lnn_path)
	print ("complete log dir: {}" . format(log_dir))

	cmd = "mkdir -p " + log_dir
	result = kparser_util.run_cmd(cmd)
	check_and_assert(result)

	if 'kParser' in test:
		if test['kParser']['recompile-kmod'] == "yes":
			cmd = "cd " + lnn_path + " && make M=net/kparser clean && make M=net/kparser -j$(nproc)"
			result = kparser_util.run_cmd(cmd)
			check_and_assert(result)
		if test['kParser']['recompile-cli'] == "yes":
			cmd = "cd " + iproute2_path + " && make clean && make -j$(nproc)"
			result = kparser_util.run_cmd(cmd)
			check_and_assert(result)

	if 'xdp-md' in test:
		result = setup_xdp(test['xdp-md'], lnn_path)
		check_and_assert(result)

	# tap = "tap" + str(random.randint(100,1000))
	tap = "tap201"
	src_eth = "ff:ff:ff:ff:ff:ff"
	dst_eth = "ff:ff:ff:ff:ff:ff"
	src_ip = "10.10.1.10"
	dst_ip = "10.10.2.11"
	src_port = 8080
	dst_port = 8090

	result = kparser_util.remove_kparser_module()
	# check_and_assert(result)
	result = kparser_util.detach_xdp_module(tap)
	# check_and_assert(result)
	result = kparser_util.run_cmd("sudo ip tuntap del name {}  mode tap".format(tap))
	# check_and_assert(result)

	kparser_module = lnn_path + "net/kparser/kparser.ko"
	xdp_module = lnn_path + "samples/bpf/xdp_kparser_kern.o"
	result = kparser_util.create_tap_setup(tapname=tap, ip=src_ip, mtu=8500)
	check_and_assert(result)
	result = kparser_util.setup_kparser(lnn_path + "/net/kparser/kparser.ko",
			lnn_path + "/samples/bpf/xdp_kparser_kern.o", tap)
	check_and_assert(result)

	cli_config = construct_path(test['kParser']['cli-setup-config-file-path'],
			lnn_path)

	result = kparser_util.run_cmd("dmesg -c")
	check_and_assert(result)

	result = kparser_util.run_cmd(" {} {}".format(cli_config, iproute2_path))
	print (result)
	check_and_assert(result)

	# print("now setup tcpdump...")
	# time.sleep(1)

	print("Sending packet..")
	pcap_file = construct_path(test['test-pcap-file-path'], lnn_path)
	pkt = packet_util.read_pcap_file(pcap_file, int(test['pkt-index-in-pcap']))
	print ("dumping raw packet bytes: ...")
	original_scappy_pkt = pkt
	print (bytes_hex((pkt)))
	pkt = bytes(pkt)
	print (pkt)
	ret_tx_rx_pkt  = packet_util.test_tap_tx(tap, pkt)
	# print (ret_tx_rx_pkt)
	ctx_id = kparser_util.get_ctx_id(lnn_path)
	md_str = kparser_util.get_metadata_dump(ctx_id, lnn_path)
	act_mdata_json = json.loads(md_str)
	# print (act_mdata_json)
	time.sleep(1)
	cmd = "dmesg > " + log_dir + "/dmesg.out"
	result = kparser_util.run_cmd(cmd)
	check_and_assert(result)
	# return
	cmd = "grep kParserdump:len: " + log_dir + "/dmesg.out"
	result = kparser_util.run_cmd(cmd)
	out = result['stdout']
	pkt_len = out.split(':')
	# print ("pkt len: {}" . format(pkt_len[2]))
	cmd = "grep kParserdump:rcvd_pkt: " + log_dir + "/dmesg.out"
	result = kparser_util.run_cmd(cmd)
	out = result['stdout'].splitlines(True)
	buf = ""
	for line in out:
		data = line.split(':')
		buf = buf + data[3]
		buf = buf.split(".")[0]
		buf = buf.replace(" ", "")
	raw_pkt_frm_dmsg = bytes.fromhex(buf)
	if pkt != raw_pkt_frm_dmsg:
		print ("i/o packets didn't match. Rerun this test.\n"
			"input:{}\noutput:{}".
			# format(bytes(pkt), raw_pkt_frm_dmsg))
			format(bytes_hex(pkt), buf))
	#print (type(pkt))
	#print (type(raw_pkt_frm_dmsg))
	#pkt_array = bytearray(pkt)
	#print (bytes(pkt_array[13]))
	#print ((pkt[12:1]))
	for obj in act_mdata_json:
		if obj == test['expected-md-values']:
			print ("bpf md matched")
			print ("Test Passed: {}". format(test['test-name']))
		else:
			print ("bpf md didn't match")
			print ("Test Failed: {}". format(test['test-name']))
			# print (obj)
			# print (test['expected-md-values'])

parser = ArgumentParser()
parser.add_argument("-f", "--config-file", dest="filename",
	help="test config JSON FILE", metavar="FILE")
args = parser.parse_args()

with open(args.filename) as f:
	conf = json.load(f)

for test in conf['tests']:
	global tap
	execute_test(test)
	result = kparser_util.remove_kparser_module()
	result = kparser_util.detach_xdp_module(tap)
	result = kparser_util.run_cmd(
		"sudo ip tuntap del name {}  mode tap".format(tap))

