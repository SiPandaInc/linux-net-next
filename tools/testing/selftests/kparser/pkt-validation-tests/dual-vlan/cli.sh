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

# sample metadata structure for this test:
# the pcap must have two vlans after ethernet:
# struct user_frame {
#	unsigned short vlan_cnt;
#	unsigned short vlan_type_offsets[MAX_VLAN];
# } __packed;
# struct user_metadata {
#        struct user_frame frames;
# } __packed;

# define a counter which represents max vlan hdr count, size of array elements
# vlan_type_offsets and element count of vlan_type_offsets
ipcmd parser create counter name vlan_cntr maxvalue 2 arraylimit 2 arrayelementsize 2

# link that counter to a metadata object, this also defines the rule to extract offset of the
# vlan type field from vlan header and stores it into vlan_type_offsets
ipcmd parser create metadata-rule name md.cntr.field	\
	type offset addoff 2 doff 2 length 2 counteridx vlan_cntr

# create another metadata object to increment the vlan counter
# notice `counterop incr`
ipcmd parser create metadata-rule name md.cntr.inc	\
	type counter-mode doff 0 counteridx vlan_cntr	\
	counterdata vlan_cntr counterop incr

# create another metadata object to store the vlan counter
# at vlan_cnt
ipcmd parser create metadata-rule name md.cntr.store	\
	type counter-mode doff 0 counteridx vlan_cntr	\
	counterdata vlan_cntr counterop noop

# rest are same as previous examples
ipcmd parser create metadata-ruleset name vlan.metadata	\
	md.rule md.cntr.field	\
	md.rule md.cntr.inc	\
	md.rule md.cntr.store

# Create protocol tables
ipcmd parser create table name ether_table
ipcmd parser create table name vlan_table

# Create parse nodes
ipcmd parser create node name ether_node min-hdr-length 14	\
	nxt.field-off 12 nxt.field-len 2 nxt.table ether_table

ipcmd parser create node name vlan_node min-hdr-length 4	\
	nxt.field-off 2 nxt.field-len 2 \
	nxt.table vlan_table md-ruleset vlan.metadata

# Create proto table entries
ipcmd parser create table/ether_table key 0x8100 node vlan_node
ipcmd parser create table/vlan_table key 0x8100 node vlan_node

# Create parsers
ipcmd parser create parser name dual-vlan-parser id 1 rootnode ether_node	\
	maxnodes 255 metametasize 6 flags enable-all-debug-logs
