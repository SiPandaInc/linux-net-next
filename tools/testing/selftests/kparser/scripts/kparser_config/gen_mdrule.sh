#!/usr/bin/bash
# Create metadata instances and list
IPPATH="/home/testusr/wspace/iproute2/"
IN_ARGS=$1

if [ ! -z $2 ]; then
    MD_DELETE=$2
fi 

die()
{
    echo "error:$1"
    exit -1
}

ipcmd() {
# -j -p enables formatted json print in stdout
    #echo "Executing \`./ip/ip -j -p $@\`" | fold -w 80
    echo "Executing \`./ip/ip -j -p $@"  | fold -w 80
    if [ ! -z "$MD_DELETE" ] ; then
        echo "Check delete .. "
        if [[ "$2" == "create" ]] && [[ ! "$3" == "metadata-rule"  ]] && [[ ! "$3" == "table/"* ]] ; then
        
            del_cmd=${@/create/delete}
            echo "DELETE CMD $del_cmd" 
            $IPPATH/ip/ip -j -p $1 delete $3 $4 $5 || echo "command $1 delete $3 $4 $5   failed."
        fi
    fi
    
    $IPPATH/ip/ip -j -p "$@" || die "command \`$@\` failed."
    echo "---------------------------------------------------------------"
}


#ipcmd parser delete  metadata-ruleset name ipv4_node.metadata 
#ipcmd parser create  metadata-ruleset name ipv4_node.metadata 

#ipcmd parser delete metadata-rule name ipv4_node.md
echo "CMDSTR ipcmd parser create metadata-rule name ipv4_node.md $IN_ARGS"
ipcmd parser create metadata-rule name node.md $IN_ARGS

ipcmd parser create metadata-ruleset name node.metadata md-rule node.md

#ipcmd parser create metadata-ruleset name ipv4_node.metadata md-ruleipv4_node.md.hdr md-ruleipv4_node.md.nhdr md-ruleipv4_node.md.hdrlen md-ruleipv4_node.md.cbyte md-ruleipv4_node.md.hwcbyte md-rulemd.tstamp

#ipcmd parser create metadata-ruleset name mdset.offset md-rule  md.boffset md-rule md.offset 
#ipcmd parser create metadata-rule name md.num_nodes type numnodes md-off 0 
#ipcmd parser create metadata-rule name md.num_encaps type numencaps md-off 2 
#ipcmd parser create metadata-rule name md.return_code type return_code md-off 4 

#ipcmd parser create metadata-ruleset name mdset.mdd  md-rule md.num_nodes md-rule md.num_encaps md-rule md.return_code 

# Create protocol tables
#ipcmd parser create table name ether_table
#ipcmd parser create table name ip_table

# Create parse nodes
#ipcmd parser create node name ether_node min-hdr-length 14 nxt.field-off 12 nxt.field-len 2  nxt.table ether_table 
#ipcmd parser create node name node.ether hdr.minlen 14 nxt.offset 12 nxt.length 2  nxt.table-ent 0x8:ipv4_node
ipcmd parser create node name node.ether md-ruleset node.metadata


#ipcmd parser create node name ipv4_node min-hdr-length 20 hdr.len-field-off 0 hdr.len-field-len 1 hdr.len-field-mask  0xf hdr.len-field-multiplier 4 nxt.field-off 9 nxt.field-len 1 md-ruleset ipv4_node.metadata nxt.table ip_table

#ipcmd parser create node name node.exit0 md-ruleset mdset.mdd
#ipcmd parser create node name node.exit256 md-ruleset mdset.mdd

# Create proto table entries
#ipcmd parser create table/ether_table name ether_table.tabent.ipv4_node key 0x8 node ipv4_node

# Create parsers

mmlen=${MDMDLEN:-16}

ipcmd parser create parser name test_parser100 id 16 rootnode node.ether metametasize $mmlen
