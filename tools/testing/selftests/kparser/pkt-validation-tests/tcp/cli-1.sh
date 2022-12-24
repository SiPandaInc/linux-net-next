#!/bin/bash

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
 * Author:     Sumon Singh <sumon@sipanda.io>
 */
////

# tcp destination port.

die()
{
        echo "error: $@"
        exit -1
}

IP="$1/ip/ip"
ipcmd() {
# -j -p enables formatted json print in stdout
	echo "Executing \`./ip/ip -j -p $@\`" | fold -w 80
	$IP -j -p "$@" || die "command \`$@\` failed."
	echo "---------------------------------------------------------------"
}


ipcmd parser create metadata-rule name okay_node.metadata.numencaps type numencaps md-off 0
ipcmd parser create metadata-rule name okay_node.metadata.numnodes type numnodes md-off 2 
ipcmd parser create metadata-ruleset name okay_node.metadata md.rule okay_node.metadata.numencaps md.rule okay_node.metadata.numnodes

ipcmd parser create metadata-rule name fail_node.metadata.numencaps type numencaps md-off 4
ipcmd parser create metadata-rule name fail_node.metadata.numnodes type numnodes md-off 8
ipcmd parser create metadata-ruleset name fail_node.metadata md.rule fail_node.metadata.numencaps md.rule fail_node.metadata.numnodes

ipcmd parser create node name okay_node md-ruleset okay_node.metadata

ipcmd parser create node name fail_node md-ruleset fail_node.metadata

# Create metadata instances and list
ipcmd parser create metadata-rule name ether_node.metadata.mac-addrs type hdrdata hdr-src-off 0 isframe true length 12 md-off 0
ipcmd parser create metadata-rule name ether_node.metadata.ethtype type hdrdata hdr-src-off 12 isframe true length 2 md-off 12
ipcmd parser create metadata-ruleset name ether_node.metadata md.rule ether_node.metadata.mac-addrs md.rule ether_node.metadata.ethtype

ipcmd parser create metadata-rule name ipv4_node.metadata.src-addrs type hdrdata hdr-src-off 12 isframe true length 4 md-off 14 host-order-conversion true
ipcmd parser create metadata-rule name ipv4_node.metadata.dst-addrs type hdrdata hdr-src-off 16 isframe true length 4 md-off 18 host-order-conversion true
ipcmd parser create metadata-rule name ipv4_node.metadata.protocol type hdrdata hdr-src-off 9 isframe true length 1 md-off 22
ipcmd parser create metadata-ruleset name ipv4_node.metadata md.rule ipv4_node.metadata.src-addrs md.rule ipv4_node.metadata.dst-addrs md.rule ipv4_node.metadata.protocol

ipcmd parser create metadata-rule name tcp_node.metadata.src-ports type hdrdata hdr-src-off 0 isframe true length 2 md-off 23 host-order-conversion true
ipcmd parser create metadata-rule name tcp_node.metadata.dst-ports type hdrdata hdr-src-off 2 isframe true length 2 md-off 25 host-order-conversion true
ipcmd parser create metadata-ruleset name tcp_node.metadata md.rule tcp_node.metadata.src-ports md.rule tcp_node.metadata.dst-ports

# Create protocol tables
ipcmd parser create table name ether_table
ipcmd parser create table name ip_table
ipcmd parser create table name ipv4_table

# Create parse nodes
ipcmd parser create node name ether_node min-hdr-length 14 nxt.field-off 12 nxt.field-len 2 nxt.table ether_table md-ruleset ether_node.metadata

ipcmd parser create node name ipv4_node min-hdr-length 20 hdr.len.field-off 0 hdr.len.field-len 2 hdr.len.mask 0xf hdr.len.multiplier 4 nxt.field-off 9 nxt.field-len 1 nxt.table ipv4_table md-ruleset ipv4_node.metadata

ipcmd parser create node name ports_node min-hdr-length 4 md-ruleset ports_node.metadata

ipcmd parser create node name tcp_node min-hdr-length 2 hdr.len.field-off 12 hdr.len.field-len 1 hdr.len.mask 0xf0 hdr.len.multiplier 4 tlvs.table tcp_node.tlv_table tlvs.startoff.constantoff 20 tlvs.type.field-off 0 tlvs.type.field-len 1 tlvs.len.field-off 1 tlvs.len.field-len 1 tlvs.len.addvalue 2 tlvs.pad1 1 tlvs.eol 0 tlvs.maxloop 255 tlvs.maxnon 255 tlvs.maxplen 255 tlvs.maxcpad 255 tlvs.exceedloopcntiserr false md-ruleset tcp_node.metadata
# ipcmd parser create node name tcp_node min-hdr-length 2 hdr.len.field-off 12 hdr.len.field-len 1 hdr.len.mask 0xf0 hdr.len.multiplier 4 tlvs.startoff.constantoff 20 tlvs.type.field-off 0 tlvs.type.field-len 1 tlvs.len.field-off 1 tlvs.len.field-len 1 tlvs.len.addvalue 2 tlvs.pad1 1 tlvs.eol 0 tlvs.maxloop 255 tlvs.maxnon 255 tlvs.maxplen 255 tlvs.maxcpad 255 tlvs.exceedloopcntiserr false md-ruleset tcp_node.metadata


# Create proto table entries
ipcmd parser create table/ether_table key 0x800 node ipv4_node
ipcmd parser create table/ipv4_table key 0x6 node tcp_node

# Create parsers
ipcmd parser create parser name ipv4-tcp-opts-parser id 1 rootnode ether_node oknode okay_node failnode fail_node maxnodes 255 metametasize 8 framesize 27 flags enable-all-debug-logs
