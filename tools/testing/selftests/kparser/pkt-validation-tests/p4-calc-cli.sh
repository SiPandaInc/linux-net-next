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

#IP="/home/ehalep/Workspace/iproute2-p4tc/ip/ip"
IP="$1/ip/ip"
ipcmd() {
# -j -p enables formatted json print in stdout
	echo "Executing \`./ip/ip -j -p $@\`" | fold -w 80
	$IP -j -p "$@" || die "command \`$@\` failed."
	echo "---------------------------------------------------------------"
}

#Lookup table creation for checking next nodes
ipcmd parser create table name table.ether

#Extraction definition per header. Values (addoff local offsets)
ipcmd parser create metadata-rule name md.calc.dstAddr	\
		type bit-offset						    		\
		md-off 0							        	\
		addoff 0

ipcmd parser create metadata-rule name md.calc.srcAddr	\
		type bit-offset			    	            	\
		md-off 2				                    	\
		addoff 48

ipcmd parser create metadata-rule name md.calc.p	\
		type bit-offset						    	\
		md-off 4							        \
		addoff 0

ipcmd parser create metadata-rule name md.calc.four	\
		type bit-offset			    	            \
		md-off 6				                    \
		addoff 8

ipcmd parser create metadata-rule name md.calc.ver	\
		type bit-offset						        \
		md-off 8						            \
		addoff 16

ipcmd parser create metadata-rule name md.calc.op	\
		type bit-offset						        \
		md-off 10						            \
		addoff 24

ipcmd parser create metadata-rule name md.calc.operand_a    \
		type bit-offset						                \
		md-off 12						                    \
		addoff 32

ipcmd parser create metadata-rule name md.calc.operand_b    \
		type bit-offset						                \
		md-off 14						                    \
		addoff 64

ipcmd parser create metadata-rule name md.calc.res  \
		type bit-offset						        \
		md-off 16						            \
		addoff 96

# Creates a metalist object to be associated with a parse node. 
ipcmd parser create metalist name mdl.calceth	\
		md.rule md.calc.dstAddr					\
		md.rule md.calc.srcAddr

ipcmd parser create metalist name mdl.calc  \
		md.rule md.calc.p                   \
		md.rule md.calc.four                \
		md.rule md.calc.ver                 \
		md.rule md.calc.op                  \
        md.rule md.calc.operand_a           \
        md.rule md.calc.operand_b           \
        md.rule md.calc.res  

# Creates a parse nodes. Contains header size and how to calculate next header
ipcmd parser create node name node.ether	\
		min-hdr-length 14					\
		nxt.field-off 12					\
		nxt.field-len 2						\
		metalist mdl.calceth				\
		nxt.table table.ether

#The command condexprstable condtable.calc attaches the conditional table to this node.
#Conditionals run prior to node processing.
ipcmd parser create node name node.calc 	\
		min-hdr-length 16 					\
		condexprstable condtable.calc	\
		metalist mdl.calc

#Create a conditional expression
ipcmd parser create condexprs name cond.check_calc_all_values	\
                type equal                                  	\
                src.field-off 0                             	\
                src.field-len 3	                            	\
                value 0x503401

#Create a conditional list with the type and (all must be true)
ipcmd parser create condexprslist name condlist.calc	\
                type and                                \
                defaultfail stop-fail-compare

#Populate the conditional list with the conditional expression
ipcmd parser create condexprslist/condlist.calc	\
                condexprs cond.check_calc_all_values

#Create an conditional table
ipcmd parser create condexprstable name condtable.calc

#Populate the conditional table with the condional list
ipcmd parser create condexprstable/condtable.calc	\
                condexprslist condlist.calc

# Populate lookup tables.
ipcmd parser create table/table.ether	\
		key 0x1234						\
		node node.calc

# Creates a parser object and specifies starting node
ipcmd parser create parser name calc_parser id 1	\
		metametasize 18								\
		rootnode node.ether
