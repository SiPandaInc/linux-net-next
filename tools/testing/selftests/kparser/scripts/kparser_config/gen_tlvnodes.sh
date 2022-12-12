rmmod kparser; insmod $LINUX_NET_NEXT/net/kparser/kparser.ko
die()
{
        echo "error:$1"
        exit -1
}

ipcmd() {
# -j -p enables formatted json print in stdout
        echo "Executing \`./ip/ip -j -p $@\`" | fold -w 80
        ${IPROUTE2_PATH}/ip/ip -j -p "$@" || die "command \`$@\` failed."
        echo "---------------------------------------------------------------"
}

ipcmd parser create table name table.ether
ipcmd parser create table name table.ip

ipcmd parser create md-rule name md.gre hdr-src-off 2 length 2 md-off 2 isframe true

ipcmd parser create md-rule name md.eth hdr-src-off 6 isframe true  length 8 md-off 0

ipcmd parser create md-rule name md.ip hdr-src-off 12 isframe true length 8 md-off 2

ipcmd parser create md-rule name md.ports hdr-src-off 2 isframe true length 2 md-off 6 isendianneeded true

ipcmd parser create condexprs name cond.ipv6.vercheck			\
		type greaterthan				\
		src.field-off 0						\
		src.field-len 8							\
		mask  0xf						\
		value 0x2

ipcmd parser create condexprs name cond.ipv4.vercheck			\
		type greaterthan				\
		src.field-off 0						\
		src.field-len 8							\
		mask  0xf						\
		value 0x1

ipcmd parser create condexprs name cond.ipv4.vercheck1			\
		type greaterthanequal				\
		src.field-off 0						\
		src.field-len 4							\
		mask 0xf0ff						\
		value 0xFFff

ipcmd parser create condexprstable name condtable.ipv4

ipcmd parser create condexprslist name condlist.ipv4			\
		type or defaultfail stop-fail-compare       		\
        #table table.ipkj
		#defaultfail STOP_FAIL_CMP

ipcmd parser create condexprslist name condlist.ipv6			\
		type or defaultfail  stop-fail-compare

ipcmd parser create condexprslist/condlist.ipv4				\
		condexprs cond.ipv4.vercheck            \
		condexprs cond.ipv4.vercheck1

ipcmd parser create condexprslist/condlist.ipv6				\
		condexprs cond.ipv6.vercheck            \
#ipcmd parser create condexprstable name condtable.ipv4

ipcmd parser create condexprstable/condtable.ipv4			\
		condexprslist condlist.ipv4

ipcmd parser create condexprstable/condtable.ipv4			\
		condexprslist condlist.ipv6

#ipcmd parser create table/table.ether                   \
#        key 0x8100                      \
#        node node.vlan

#ipcmd parser create table/table.ether                   \
#        key 0x86dd                      \
#        node node.ipv6

ipcmd parser create metadata-rule name md.tcp.tlv.mss			\
		type hdrdata						\
		hdr-src-off 2						\
		md-off 14							\
		isframe true
ipcmd parser create metadata-rule name md.tcp.tlv.ts				\
		type hdrdata						\
		hdr-src-off 2							\
		md-off 16							\
		length 4						\
		isframe true

ipcmd parser create metadata-ruleset name ml.tcp.tlv.mss			\
		md-rule md.tcp.tlv.mss
ipcmd parser create metadata-ruleset name ml.tcp.tlv.ts				\
		md-rule md.tcp.tlv.ts

ipcmd parser create tlvnode name node.tlv.tcp.mss			\
		min-hdr-length 4						\
		md-ruleset ml.tcp.tlv.mss
ipcmd parser create tlvnode name node.tlv.tcp.ts			\
		min-hdr-length 10						\
		md-ruleset ml.tcp.tlv.ts
ipcmd parser create tlvtable name table.tlv.tcp
ipcmd parser create tlvtable/table.tlv.tcp				\
		tlvtype 8						\
		tlvnode node.tlv.tcp.ts
ipcmd parser create tlvtable/table.tlv.tcp				\
		tlvtype 2						\
		tlvnode node.tlv.tcp.mss

#ipcmd parser create node name node.ports hdr.minlen 4 md-rule md.ports \
ipcmd parser create node name node.ports hdr.minlen 4 md-rule md.ports \
		tlvs.table table.tlv.tcp        \
        minlen 20                       \
        hdrlenoff 12                        \
        hdrlenlen 1                     \
        hdrlenmask 0xf0                     \
        hdrlenmultiplier 4                  \
        tlvspad1 1                      \
        tlvseol 0                       \
		tlvs.table table.tlv.tcp
        #tlvstable.name table.tlv.tcp
        #tlvs.startoff.constantoff          20\

ipcmd parser create table/table.ip                   \
        key 0x11                       \
        node node.ports

ipcmd parser create table/table.ip                   \
        key 0x06                       \
        node node.ports

ipcmd parser create node name node.ipv4 hdr.minlen 20 hdr.len-field-off 0 hdr.len-field-len 1 hdr.len-field-mask 0x0f hdr.len-field-multiplier 4 nxt.field-off 9 nxt.field-len 1  md-rule md.ip  nxt.table table.ip condexprstable condtable.ipv4

ipcmd parser create table/table.ether                   \
        key 0x800                       \
        node node.ipv4

ipcmd parser create node name node.gre                  \
        md-rule md.gre                          \
        nxt.encap true                      \
        hdr.minlen 4                        \
        nxt.field-off 2                     \
        nxt.table table.ether              \
        nxt.field-len 2      

        #nxt.encap true                      \
ipcmd parser create table/table.ip                   \
        key 0x2F                       \
        node node.gre

ipcmd parser create counter name cntr.vlan.1 id 1				\
		maxvalue 2						\
		arraylimit 2						\
		arrayelementsize 2

#define the vlan tci metadata extraction rule
ipcmd parser create metadata-rule name md.cntr.vlanci			\
		hdr-src-off 0							\
		md-off 34							\
		length 2						\
		counteridx cntr.vlan.1						\
        isendianneeded true                   \
		isframe true

#                type counter                                       \

ipcmd parser create metadata-rule name md.cntr.inc				\
		type counter-mode counteridx cntr.vlan.1			\
		counterop incr isframe true

# define where to store the counter value in user metadata
ipcmd parser create metadata-rule name md.cntr.store				\
		type counter-mode length 2 md-off 32 counteridx cntr.vlan.1	\
		counterop noop isframe true

ipcmd parser create metadata-ruleset name mdl.vlan				\
		md-rule md.cntr.vlanci				\
		md-rule md.cntr.inc				\
		md-rule md.cntr.store

ipcmd parser create node name node.vlan					\
		md-ruleset mdl.vlan				\
		min-hdr-length 4 						\
		nxt.field-off 2						\
		nxt.field-len 2						\
		nxt.table table.ether

ipcmd parser create table/table.ether					\
		key 0x8100						\
		node node.vlan
#ipcmd parser create node name node.ether hdr.minlen 14 nxt.offset 12 nxt.length 2 nxt.table-ent 0x800:node.ipv4 md-rule md.eth
#ipcmd parser create node name node.ether hdr.minlen 203 nxt.offset 203 nxt.length 4 nxt.table-ent 0x800:node.ipv4 md-rule md.eth
#ipcmd parser create node name node.ether  hdr.len-field-off 10 hdr.len-field-len 4  hdr.len-field-multiplier 1 hdr.len.mask 0x0 hdr.len-field-addvalue 0 hdr.len.endian true hdr.len.rightshift 254 nxt.offset 65534 nxt.length 2 nxt.mask 0xFF nxt.rightshift 2  nxt.table-ent 0x800:node.ipv4 md-rule md.eth


#ipcmd parser create node name node.ether  hdr.len-field-off 65535 hdr.len-field-addvalue 254 hdr.len-field-len 4 hdr.len-field-multiplier 240 hdr.len.mask 0x0  nxt.offset 9 nxt.length 2 nxt.mask 0xFF nxt.rightshift 2  nxt.table table.ether  md-rule md.eth
ipcmd parser create node name node.ether hdr.minlen 14 nxt.offset 12 nxt.length 2 nxt.table table.ether  md-rule md.eth

ipcmd parser create metadata-rule name md.num_nodes             \
        type numnodes                           \
        isendianneeded false                   \
        isframe false                   \
        md-off 0 
ipcmd parser create metadata-rule name md.num_encaps                \
        type numencaps                      \
        isendianneeded false                   \
        isframe false                   \
        md-off 2
ipcmd parser create metadata-rule name md.return_code           \
        type return-code                    \
        md-off 4
ipcmd parser create metadata-ruleset name mdl.final_status          \
        md-rule md.num_nodes                \
        md-rule md.num_encaps               \
        md-rule md.return_code
ipcmd parser create node name node.parser_exit_ok           \
        md-ruleset mdl.final_status
ipcmd parser create node name node.parser_exit_fail         \
        md-ruleset mdl.final_status


ipcmd parser create parser name tuple_parser id 512 rootnode node.ether \
        oknode node.parser_exit_ok              \
        metametasize 26                     \
        maxencaps   5  \
        maxnodes    11\
        framesize 44                        \
        failnode node.parser_exit_fail          
#        base-metametadata-size 14


