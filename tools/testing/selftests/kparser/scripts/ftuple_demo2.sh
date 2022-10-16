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
	echo "Executing \`./ip/ip -j -p $@\`" | fold -w 80
	$IPPATH/ip/ip -j -p "$@" || die "command \`$@\` failed."
	echo "---------------------------------------------------------------"
}


ipcmd parser create metadata-rule name md.udp.src_port			\
		type bit_offset						\
		addoff 0						\
		isframe true						\
		md-off 12

ipcmd parser create metadata-rule name md.udp.dst_port			\
		type bit_offset						\
		addoff 16						\
		isframe true						\
		md-off 14

# Explicitly define a metalist (i.e. metadata-ruleset) for UDP
ipcmd parser create metadata-ruleset name mdl.udp			\
		md.rule md.udp.src_port					\
		md.rule md.udp.dst_port

# Define udp parse node and explicitly attach it with metadata-ruleset for UDP
ipcmd parser create node name node.udp					\
		min-hdr-length 8					\
		md.ruleset mdl.udp

#ipcmd parser unlock node name table.ip
#ipcmd  parser unlock table name table.ipv4
#ipcmd  parser lock table name table.ipv4
#parser lock table name tab
ipcmd parser create table/table.ipv4                                     \
                        key 0x11                                                \
                        node node.udp
#ipcmd  parser unlock table name table.ipv4
