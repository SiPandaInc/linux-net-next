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
	echo "Executing \`./ip/ip -j -p $@\`" | fold -w 80
	${IPROUTE2_PATH}/ip/ip -j -p "$@" || die "command \`$@\` failed."
	echo "---------------------------------------------------------------"
}

# Explicit Lookup table creation for checking next nodes
# This is for protocol ether
ipcmd parser create table name table.ether
ipcmd parser create table name table.ipv4

#Extraction definition per header. Values (addoff local offsets)
ipcmd parser create metadata-rule name md.ipv4.ttl			\
		type bit_offset						\
		md-off 0						\
		isframe true						\
		addoff 64

ipcmd parser create metadata-rule name md.ipv4.ipproto_offset		\
		type bit_offset						\
		isframe true						\
		md-off 2						\
		addoff 72

ipcmd parser create metadata-rule name md.ipv4.src_address_offset	\
		type bit_offset						\
		addoff 96						\
		isframe true						\
		md-off 4

ipcmd parser create metadata-rule name md.ipv4.dst_address_offset	\
		type bit_offset						\
		addoff 128						\
		isframe true						\
		md-off 6

ipcmd parser create metadata-rule name md.tcp.src_port			\
		type bit_offset						\
		addoff 0						\
		isframe true						\
		md-off 8

ipcmd parser create metadata-rule name md.tcp.dst_port			\
		type bit_offset						\
		addoff 16						\
		isframe true						\
		md-off 10



# Creates parse nodes. Contains header size and how to calculate next header
# Here md.rule are linked inline.
# We are not validating TCP length
ipcmd parser create node name node.tcp					\
		min-hdr-length 20					\
		md.rule md.tcp.src_port					\
		md.rule md.tcp.dst_port

ipcmd parser create table/table.ipv4                                      \
                key 0x6                                                 \
                node node.tcp

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

# Lookup table entries for IPv4 are also populated inline.
# Notice: node.udp and node.tcp must be defined before this linking.
ipcmd parser create node name node.ipv4					\
		$IPv4protonode						\
		md.rule md.ipv4.dst_address_offset			\
		md.rule md.ipv4.src_address_offset 			\
		md.rule md.ipv4.ttl              			\
		md.rule md.ipv4.ipproto_offset				\
		nxt.table table.ipv4

# Explicitly populate lookup table for ethernet for checking next nodes
ipcmd parser create table/table.ether					\
		key 0x800						\
		node node.ipv4


ipcmd parser create node name node.ether				\
		min-hdr-length 14					\
		nxt.field-off 12					\
		nxt.field-len 2						\
		nxt.table table.ether


ipcmd parser create metadata-rule name md.num_nodes				\
			type numnodes						\
					md-off 0
ipcmd parser create metadata-rule name md.num_encaps				\
			type numencaps						\
					md-off 4
ipcmd parser create metadata-rule name md.return_code			\
			type return_code					\
					md-off 8
ipcmd parser create metadata-ruleset name mdl.final_status			\
			md.rule md.num_nodes				\
					md.rule md.num_encaps				\
							md.rule md.return_code
ipcmd parser create node name node.parser_exit_ok			\
			md.ruleset mdl.final_status
ipcmd parser create node name node.parser_exit_fail			\
			md.ruleset mdl.final_status

# Creates a parser object and specifies starting node
#ipcmd parser create parser name test_parser				\
#		metametasize 16						\
#		rootnode node.ether

ipcmd parser create parser name test_parser				\
		maxnodes 12						\
		maxencaps 3						\
		maxframes 3						\
		metametasize 18						\
		framesize 16						\
		rootnode node.ether				\
		oknode node.parser_exit_ok				\
		failnode node.parser_exit_fail

ipcmd parser read parser name test_parser
