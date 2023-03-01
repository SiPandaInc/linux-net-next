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

# Create counters

# Create metadata instances and list
ipcmd parser create metadata-rule name ipv4_node.metadata.addrs.v4_addrs.src type hdrdata hdr-src-off 12 length 4 md-off 8 
ipcmd parser create metadata-rule name ipv4_node.metadata.addrs.v4_addrs.dst type hdrdata hdr-src-off 16 length 8 md-off 8 
ipcmd parser create metadata-rule name ipv4_node.metadata.ip_proto type hdrdata hdr-src-off 9 length 1 md-off 1 
ipcmd parser create metadata-rule name ipv4_node.metadata.addr_type type constant-byte constantvalue 1 length 1 md-off 0 
ipcmd parser create metadata-ruleset name ipv4_node.metadata md.rule ipv4_node.metadata.addrs.v4_addrs.src md.rule ipv4_node.metadata.addrs.v4_addrs.dst md.rule ipv4_node.metadata.ip_proto md.rule ipv4_node.metadata.addr_type

ipcmd parser create metadata-rule name ipv6_node.metadata.addrs.v6_addrs type hdrdata hdr-src-off 8 length 4 md-off 8 
ipcmd parser create metadata-rule name ipv6_node.metadata.addr_type type constant-byte constantvalue 2 length 1 md-off 0 
ipcmd parser create metadata-rule name ipv6_node.metadata.ip_proto type hdrdata hdr-src-off 6 length 1 md-off 1 
ipcmd parser create metadata-ruleset name ipv6_node.metadata md.rule ipv6_node.metadata.addrs.v6_addrs md.rule ipv6_node.metadata.addr_type md.rule ipv6_node.metadata.ip_proto

ipcmd parser create metadata-rule name ports_node.metadata.ports type hdrdata hdr-src-off 0 length 4 md-off 4 
ipcmd parser create metadata-ruleset name ports_node.metadata md.rule ports_node.metadata.ports

# Create protocol tables
ipcmd parser create table name ether_table
ipcmd parser create table name ip_table

# Create parse nodes
ipcmd parser create node name ether_node min-hdr-length 14 nxt.field-off 12 nxt.field-len 2 nxt.table ether_table
ipcmd parser create node name ipv4_node min-hdr-length 20 hdr.len.field-off 0 hdr.len.field-len 1 hdr.len.mask 0xf hdr.len.multiplier 4 nxt.field-off 9 nxt.field-len 1 nxt.table ip_table md-ruleset ipv4_node.metadata
ipcmd parser create node name ipv6_node min-hdr-length 40 nxt.field-off 6 nxt.field-len 1 nxt.table ip_table md-ruleset ipv6_node.metadata
ipcmd parser create node name ports_node min-hdr-length 4 md-ruleset ports_node.metadata

# Create proto table entries
ipcmd parser create table/ether_table key 0x8 node ipv4_node
ipcmd parser create table/ether_table key 0xdd86 node ipv6_node
ipcmd parser create table/ip_table key 0x6 node ports_node
ipcmd parser create table/ip_table key 0x11 node ports_node

# Create parsers
ipcmd parser create parser name sdpu_parser rootnode ether_node

