#!/bin/bash
IPPATH=/home/testusr/wspace/iproute2

<< ////
/* SPDX-License-Identifier: BSD-2-Clause-FreeBSD */
/* Copyright (c) 2022, SiPanda Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * Author:     Pratyush Kumar Khan <pratyush@sipanda.io>
 */
////
# This is a sample demo script which creates a kParser instance named
# "test_parser" for parsing bit offsets for five tuples of TCP-IP header,
# i.e. ipproto, ipv4 source address, ipv4 destination address, tcp source port,
# tcp destination port. UDP ports were added later.

die()
{
  echo "error:$1"
  exit -1
}

ipcmd() {
# -j -p enables formatted json print in stdout
  echo "Executing \`./ip/ip -j -p $@\`" 
    $IPPATH/ip/ip -j -p "$@" || die "command \`$@\` failed."  echo "---------------------------------------------------------------"
}

# Explicit Lookup table creation for checking next nodes
# This is for protocol ether
ipcmd parser create table name ftv3.table.ether

#Extraction definition per header. Values (addoff local offsets)
#ipcmd parser create metadata-rule name ftv3.md.ipv4.ttl type hdrdata  md-off 0 isendianneeded true isframe true hdr-src-off 8 length 1

ipcmd parser create metadata-rule name ftv3.md.ipv4.ipproto type hdrdata   md-off 0  hdr-src-off 9 length 1

ipcmd parser create metadata-rule name ftv3.md.ipv4.src_address type hdrdata hdr-src-off 12  md-off 1 length 4

ipcmd parser create metadata-rule name ftv3.md.ipv4.dst_address type hdrdata  hdr-src-off 16  md-off 5 length 4

ipcmd parser create metadata-rule name ftv3.md.tcp.src_port type hdrdata hdr-src-off 0  isendianneeded true    md-off 9 length 2

ipcmd parser create metadata-rule name ftv3.md.tcp.dst_port type hdrdata hdr-src-off 2 isendianneeded true  md-off 11 length 2

ipcmd parser create metadata-rule name ftv3.md.udp.src_port type hdrdata hdr-src-off 0 isendianneeded true  md-off 13 length 2

ipcmd parser create metadata-rule name ftv3.md.udp.dst_port type hdrdata hdr-src-off 2 isendianneeded true  md-off 15 length 2

# Explicitly define a metalist (i.e. metadata-ruleset) for UDP
ipcmd parser create metadata-ruleset name ftv3.mdl.udp md.rule ftv3.md.udp.src_port md.rule ftv3.md.udp.dst_port

# Define udp parse node and explicitly attach it with metadata-ruleset for UDP
ipcmd parser create node name ftv3.node.udp min-hdr-length 8 md.ruleset ftv3.mdl.udp

# Creates parse nodes. Contains header size and how to calculate next header
# Here md.rule are linked inline.
# We are not validating TCP length
ipcmd parser create node name ftv3.node.tcp min-hdr-length 20 md.rule ftv3.md.tcp.src_port md.rule ftv3.md.tcp.dst_port

# Define IPv4 common proto parse node configs in a reusable shell variable
# for later reuse
IPv4protonode=$(cat <<-END            
    min-hdr-length 20          
    hdr.len.field-off 0          
    hdr.len.mask 0x0f          
    hdr.len.multiplier 4
    nxt.field-off 9
    nxt.field-len 1
END
)

#min-hdr-length 20 hdr.len.field-off 0 hdr.len.mask 0x0f hdr.len.multiplier 4 nxt.field-off 9 nxt.field-len 1
# Lookup table entries for IPv4 are also populated inline.
# Notice: ftv3.node.udp and ftv3.node.tcp must be defined before this linking.
#ipcmd parser create node name ftv3.node.ipv4 min-hdr-length 20 hdr.len.field-off 0 hdr.len.mask 0x0f hdr.len.multiplier 4 nxt.field-off 9 nxt.field-len 1 nxt.tableent 0x06:ftv3.node.tcp nxt.tableent 0x11:ftv3.node.udp md.rule ftv3.md.ipv4.dst_address md.rule ftv3.md.ipv4.src_address md.rule ftv3.md.ipv4.ttl md.rule ftv3.md.ipv4.ipproto
ipcmd parser create node name ftv3.node.ipv4 min-hdr-length 20 hdr.len.field-off 0 hdr.len.mask 0x0f hdr.len.multiplier 4 nxt.field-off 9 nxt.field-len 1 nxt.tableent 0x06:ftv3.node.tcp nxt.tableent 0x11:ftv3.node.udp md.rule ftv3.md.ipv4.dst_address md.rule ftv3.md.ipv4.src_address md.rule ftv3.md.ipv4.ipproto

ipcmd parser create node name ftv3.node.ipv6
# Explicitly populate lookup table for ethernet for checking next nodes
ipcmd parser create table/ftv3.table.ether key 0x800 node ftv3.node.ipv4
ipcmd parser create table/ftv3.table.ether key 0x800 node ftv3.node.ipv6

ipcmd parser create node name ftv3.node.ether min-hdr-length 14  nxt.field-off 12 nxt.field-len 2  nxt.table ftv3.table.ether


#ipcmd parser create metadata-rule name ftv3.md.num_nodes type numnodes md-off 0
#ipcmd parser create metadata-rule name ftv3.md.num_encaps type numencaps md-off 4
#ipcmd parser create metadata-rule name ftv3.md.return_code type return_code md-off 8
#ipcmd parser create metadata-ruleset name ftv3.mdl.final_status md.rule ftv3.md.num_nodes md.rule ftv3.md.num_encaps md.rule ftv3.md.return_code
#ipcmd parser create node name ftv3.node.parser_exit_ok md.ruleset ftv3.mdl.final_status
#ipcmd parser create node name ftv3.node.parser_exit_fail md.ruleset ftv3.mdl.final_status

# Creates a parser object and specifies starting node
#ipcmd parser create parser name ftv3.test_parser        #    metametasize 16            #    rootnode node.ether

#ipcmd parser create parser name test_parser maxnodes 12 maxencaps 3 maxframes 3 metametasize 18 framesize 20 rootnode ftv3.node.ether oknode ftv3.node.parser_exit_ok failnode ftv3.node.parser_exit_fail
ipcmd parser create parser name test_parser maxnodes 12 maxencaps 3 maxframes 3  metametasize 17 rootnode ftv3.node.ether #oknode ftv3.node.parser_exit_ok failnode ftv3.node.parser_exit_fail

ipcmd parser read parser name test_parser
