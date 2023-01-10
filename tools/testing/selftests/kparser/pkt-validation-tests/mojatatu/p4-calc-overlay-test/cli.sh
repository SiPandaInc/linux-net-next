#!/bin/bash -x
#Execute until failure flag
set -e

# This is a sample demo script which creates a kParser instance named
# "test_parser" for parsing bit offsets for five tuples of TCP-IP header,
# i.e. ipproto, ipv4 source address, ipv4 destination address, tcp source port,
# tcp destination port.

die()
{
	echo "error:$1"
	exit -1
}

IP="$1/ip/ip"
ipcmd() {
# -j -p enables formatted json print in stdout
	echo "Executing \`$IP -j -p $@\`" | fold -w 80
	$IP -j -p "$@" || die "command \`$@\` failed."
	echo "---------------------------------------------------------------"
}

#Extraction definition per header. Values (addoff local offsets)
ipcmd parser create metadata-rule name md.calc.dstAddr	\
		type bit-offset						    		\
		md-off 0							        	\
		addoff 0

ipcmd parser create metadata-rule name md.calc.srcAddr	\
		type bit-offset			    	            	\
		md-off 2				                    	\
		addoff 48

ipcmd parser create metadata-rule name md.calc.etherType\
		type bit-offset			    	            	\
		md-off 4				                    	\
		addoff 96

ipcmd parser create metadata-rule name md.calc.p	\
		type bit-offset						    	\
		md-off 6							        \
		addoff 0

ipcmd parser create metadata-rule name md.calc.four	\
		type bit-offset			    	            \
		md-off 8				                    \
		addoff 8

ipcmd parser create metadata-rule name md.calc.ver	\
		type bit-offset						        \
		md-off 10						            \
		addoff 16

ipcmd parser create metadata-rule name md.calc.op	\
		type bit-offset						        \
		md-off 12						            \
		addoff 24

ipcmd parser create metadata-rule name md.calc.operand_a    \
		type bit-offset						                \
		md-off 14						                    \
		addoff 32

ipcmd parser create metadata-rule name md.calc.operand_b    \
		type bit-offset						                \
		md-off 16						                    \
		addoff 64

ipcmd parser create metadata-rule name md.calc.res		\
	type bit-offset						\
	md-off 18						\
	addoff 96

ipcmd parser create metadata-rule name md.calc.isValid		\
	type constant-halfword					\
	md-off 20						\
	constantvalue 1

ipcmd parser create node name node.calc \
		min-hdr-length 16 	\
		md.rule md.calc.p                   \
		md.rule md.calc.four                \
		md.rule md.calc.ver                 \
		md.rule md.calc.op                  \
		md.rule md.calc.operand_a           \
		md.rule md.calc.operand_b           \
		md.rule md.calc.res  \
		md.rule md.calc.isValid

ipcmd parser create node name node.calc.check.ver \
		min-hdr-length 16 \
		nxt.field-off 2	\
		nxt.field-len 1 \
		overlay true	\
		nxt.table-ent 0x01:node.calc

ipcmd parser create node name node.calc.check.four \
		min-hdr-length 16 \
		nxt.field-off 1	\
		nxt.field-len 1 \
		overlay true	\
		nxt.table-ent 0x34:node.calc.check.ver

ipcmd parser create node name node.calc.check.P \
		min-hdr-length 16 \
		nxt.field-off 0	\
		nxt.field-len 1 \
		overlay true	\
		nxt.table-ent 0x50:node.calc.check.four

# Creates a parse nodes. Contains header size and how to calculate next header
ipcmd parser create node name node.ether	\
		min-hdr-length 14					\
		nxt.field-off 12					\
		nxt.field-len 2						\
		md.rule md.calc.dstAddr					\
		md.rule md.calc.srcAddr					\
		md.rule md.calc.etherType				\
		nxt.table-ent 0x1234:node.calc.check.P

# Creates a parser object and specifies starting node
ipcmd parser create parser name calc_parser id 1			\
		metametasize 21						\
		rootnode node.ether flags enable-all-debug-logs
