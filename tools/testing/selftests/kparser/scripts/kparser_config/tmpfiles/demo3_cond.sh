
IPPATH=/home/testusr/wspace/iproute2/
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

#ipcmd parser create condexprs name ftv3.ipv4.cond type equal src.field-off 0 src.field-len 1 mask 0x00 value 0x14
ipcmd parser create condexprs name ftv3.ipv4.cond1 type equal src.field-off 0 src.field-len 1 mask 0xf0 value 4
ipcmd parser create condexprs name ftv3.ipv4.cond2 type equal src.field-off 9 src.field-len 1 mask 0xff value 17


#ipcmd parser create condexprslist name ftv3.ipv4.clist defaultfail RET_OKAY condexprs  ftv3.ipv4.cond
ipcmd parser create condexprslist name ftv3.ipv4.clist defaultfail STOP_FAIL condexprs  ftv3.ipv4.cond1  condexprs ftv3.ipv4.cond2

ipcmd parser create condexprstable name ftv3.ipv4.ctable

ipcmd parser create condexprstable/ftv3.ipv4.ctable condexprslist  ftv3.ipv4.clist

#ipcmd parser create node name ftv3.node.ipv4 min-hdr-length 20 hdr.len.field-off 0 hdr.len.mask 0x0f hdr.len.multiplier 4 nxt.field-off 9 nxt.field-len 1 nxt.tableent 0x06:ftv3.node.tcp nxt.tableent 0x11:ftv3.node.udp md-rule ftv3.md.ipv4.dst_address md-rule ftv3.md.ipv4.src_address md-rule ftv3.md.ipv4.ipproto condexprstable name ftv3.ipv4.ctable


ipcmd parser create md-rule name md.iphdr_offset type offset md-off 0

ipcmd parser create md-rule name md.ipaddrs src-hdr-off 12 length 8 md-off 4

ipcmd parser create md-rule name md.l4_hdr.offset type offset md-off 2

ipcmd parser create md-rule name md.ports src-hdr-off 0 length 4 md-off 12 isendianneeded true

ipcmd parser create node name node.ports hdr.minlen 4 md-rule md.l4_hdr.offset md-rule md.ports

ipcmd parser create node name node.ipv4 hdr.minlen 20 hdr.len-field-off 0 hdr.len-field-len 1 \
hdr.len-field-mask 0x0f hdr.len-field-multiplier 4 nxt.field-off 9 nxt.field-len 1 \
nxt.table-ent 6:node.ports nxt.table-ent 17:node.ports md-rule md.iphdr_offset \
md-rule md.ipaddrs 								\
condexprstable ftv3.ipv4.ctable

ipcmd parser create node name node.ether hdr.minlen 14 nxt.offset 12 nxt.length 2 \
nxt.table-ent 0x800:node.ipv4

ipcmd parser create parser name test_parser rootnode node.ether base-metametadata-size 14
