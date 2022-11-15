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
ipcmd parser create metadata-rule name ipv4_node.md.hdr type hdrdata hdr-src-off 8 md-off 6 
ipcmd parser create metadata-rule name ipv4_node.md.nhdr type nibbs_hdrdata hdr-src-off 10 md-off 8 
ipcmd parser create metadata-rule name ipv4_node.md.hdrlen type hdrlen hdr-src-off 9 md-off 10 
ipcmd parser create metadata-rule name ipv4_node.md.cbyte type constant_byte constantvalue 89 md-off 12 
ipcmd parser create metadata-rule name ipv4_node.md.hwcbyte type constant_halfword constantvalue 145 md-off 14 

ipcmd parser create metadata-rule name md.boffset type bit_offset addoff 30  md-off 16 
ipcmd parser create metadata-rule name md.offset type offset addoff 55  md-off 18 
ipcmd parser create metadata-rule name md.tstamp type timestamp md-off 20 

ipcmd parser create metadata-ruleset name ipv4_node.metadata md.rule ipv4_node.md.hdr md.rule ipv4_node.md.nhdr md.rule ipv4_node.md.hdrlen md.rule ipv4_node.md.cbyte md.rule ipv4_node.md.hwcbyte md.rule md.tstamp

ipcmd parser create metadata-ruleset name mdset.offset md.rule  md.boffset md.rule md.offset 
ipcmd parser create metadata-rule name md.num_nodes type numnodes md-off 0 
ipcmd parser create metadata-rule name md.num_encaps type numencaps md-off 2 
ipcmd parser create metadata-rule name md.return_code type return_code md-off 4 

ipcmd parser create metadata-ruleset name mdset.mdd  md.rule md.num_nodes md.rule md.num_encaps md.rule md.return_code 

# Create protocol tables
ipcmd parser create table name ether_table
ipcmd parser create table name ip_table

# Create parse nodes
ipcmd parser create node name ether_node min-hdr-length 14 nxt.field-off 12 nxt.field-len 2  nxt.table ether_table md.ruleset mdset.offset
ipcmd parser create node name ipv4_node min-hdr-length 20 hdr.len.field-off 0 hdr.len.field-len 1 hdr.len.mask 0xf hdr.len.multiplier 4 nxt.field-off 9 nxt.field-len 1 md.ruleset ipv4_node.metadata nxt.table ip_table

ipcmd parser create node name node.exit0 md.ruleset mdset.mdd
ipcmd parser create node name node.exit256 md.ruleset mdset.mdd

# Create proto table entries
ipcmd parser create table/ether_table name ether_table.tabent.ipv4_node key 0x8 node ipv4_node

# Create parsers
ipcmd parser create parser name test_parser116 rootnode ether_node oknode node.exit0 failnode node.exit256  metametasize 22
