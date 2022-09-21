# SPDX-License-Identifier: GPL-2.0-only
#
# Makefile for KPARSER module
#

ccflags-y := -DDEBUG -DKERNEL_MOD

obj-$(CONFIG_KPARSER) += kparser.o

kparser-objs := kparser_main.o kparser_cmds.o kparser_cmds_ops.o kparser_cmds_dump_ops.o kparser_datapath.o
