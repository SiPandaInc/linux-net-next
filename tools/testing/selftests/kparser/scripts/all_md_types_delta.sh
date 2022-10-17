# Create metadata instances and list
IPPATH="/home/testusr/wspace/iproute2/"

die()
{
    echo "error:$1"
    exit -1
}

ipcmd() {
# -j -p enables formatted json print in stdout
    echo "Executing \`./ip/ip -j -p $@\`" | fold -w 80
    $IPPATH/ip/ip -j -p "$@" || die "command \`$@\` failed."
    echo "---------------------------------------------------------------"
}

 
#IPCMD="/home/testusr/wspace/iproute2/ip/ip -j -p" 
#ipcmd parser create metadata-rule name p0.ipv4_node.md.hdr type hdrdata hdr-src-off 12 md-off 3 length 1
#ipcmd parser create metadata-rule name p0.ipv4_node.md.nhdr type nibbs_hdrdata hdr-src-off 16 md-off 4 length 1
#ipcmd parser create metadata-rule name p0.ipv4_node.md.hdrlen type hdrlen hdr-src-off 9 md-off 5 length 1
#ipcmd parser create metadata-rule name p0.ipv4_node.md.cbyte type constant_byte constantvalue 99 md-off 6 length 1
#ipcmd parser create metadata-rule name p0.ipv4_node.md.hwcbyte type constant_halfword constantvalue 245 md-off 9 length 1

ipcmd parser create metadata-rule name p0.md.boffset type bit_offset addoff 40  md-off 8 length 1
ipcmd parser create metadata-rule name p0.md.offset type offset addoff 65  md-off 7 length 1
ipcmd parser create metadata-rule name p0.md.tstamp type timestamp md-off 10 length 1

#ipcmd parser create metadata-ruleset name p0.ipv4_node.metadata md.rule p0.ipv4_node.md.hdr md.rule p0.ipv4_node.md.nhdr md.rule p0.ipv4_node.md.hdrlen md.rule p0.ipv4_node.md.cbyte md.rule p0.ipv4_node.md.hwcbyte md.rule p0.md.tstamp

ipcmd parser create metadata-ruleset name p0.mdset.offset md.rule  p0.md.boffset md.rule p0.md.offset 

#ipcmd parser create metadata-rule name p0.md.num_nodes type numnodes md-off 0 length 1
#ipcmd parser create metadata-rule name p0.md.num_encaps type numencaps md-off 1 length 1
#ipcmd parser create metadata-rule name p0.md.return_code type return_code md-off 2 length 1

#ipcmd parser create metadata-ruleset name p0.mdset.mdd  md.rule p0.md.num_nodes md.rule p0.md.num_encaps md.rule p0.md.return_code 

# Create protocol tables
#ipcmd parser create table name p0.ether_table
#ipcmd parser create table name p0.ip_table

# Create parse nodes
#ipcmd parser create node name p0.ether_node min-hdr-length 14 nxt.field-off 12 nxt.field-len 2  nxt.table p0.ether_table md.ruleset p0.mdset.offset
#ipcmd parser create node name p0.ipv4_node min-hdr-length 20 hdr.len.field-off 0 hdr.len.field-len 1 hdr.len.mask 0xf hdr.len.multiplier 4 nxt.field-off 9 nxt.field-len 1 md.ruleset p0.ipv4_node.metadata nxt.table p0.ip_table

#ipcmd parser create node name p0.node.exit0 md.ruleset p0.mdset.mdd
#ipcmd parser create node name p0.node.exit256 md.ruleset p0.mdset.mdd

# Create proto table entries
#ipcmd parser create table/p0.ether_table name p0.ether_table.tabent.ipv4_node key 0x8 node p0.ipv4_node

# Create parsers
#ipcmd parser create parser name test_parser0 rootnode p0.ether_node oknode p0.node.exit0 failnode p0.node.exit256  metametasize 11
