/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (c) 2022, SiPanda Inc.
 *
 * kparser.h - kParser global net header file
 *
 * Authors:     Pratyush Kumar Khan <pratyush@sipanda.io>
 */

#ifndef _NET_KPARSER_H
#define _NET_KPARSER_H

#include <linux/kparser.h>
#include <linux/skbuff.h>

/* The kParser data path API can consume max 512 bytes */
#define KPARSER_MAX_SKB_PACKET_LEN	512

/* kParser datapath API 1: Function to parse a skb using a parser instance key.
 *
 * skb: input packet skb
 * kparser_key: key of the associated kParser parser object which must be
 *              already created via CLI.
 * _metadata: User provided metadata buffer. It must be same as configured
 *            metadata objects in CLI.
 * metadata_len: Total length of the user provided metadata buffer.
 * return: kParser error code as defined in include/uapi/linux/kparser.h
 */
extern int kparser_parse(struct sk_buff *skb,
			 const struct kparser_hkey *kparser_key,
			 void *_metadata, size_t metadata_len);

/* kParser datapath API 2: Function to parse a void * packet buffer using a parser instance key.
 *
 * parser: Non NULL kparser_get_parser() returned and cached opaque pointer
 * referencing a valid parser instance.
 * _hdr: input packet buffer
 * parse_len: length of input packet buffer
 * _metadata: User provided metadata buffer. It must be same as configured
 * metadata objects in CLI.
 * metadata_len: Total length of the user provided metadata buffer.
 * return: kParser error code as defined in include/uapi/linux/kparser.h
 */
extern int __kparser_parse(const void *parser, void *_hdr,
			   size_t parse_len, void *_metadata, size_t metadata_len);

/* kParser datapath API 3: Function to get/freeze a parser instance using a key.
 *
 * kparser_key: key of the associated kParser parser object which must be
 * already created via CLI.
 * return: NULL if key not found, else an opaque parser instance pointer which
 * can be used in the following APIs 3 and 4.
 *
 * NOTE: This call makes the whole parser tree immutable. If caller calls this
 * more than once, later caller will need to release the same parser exactly that
 * many times using the API kparser_put_parser().
 */
extern const void *kparser_get_parser(const struct kparser_hkey *kparser_key);

/* kParser datapath API 4: Function to put/un-freeze a parser instance using a previously
 * obtained opaque parser pointer via API kparser_get_parser().
 *
 * parser: void *, Non NULL opaque pointer which was previously returned by kparser_get_parser().
 * Caller can use cached opaque pointer as long as system does not restart and kparser.ko is not
 * reloaded.
 * return: boolean, true if put operation is success, else false.
 *
 * NOTE: This call makes the whole parser tree deletable for the very last call.
 */
extern bool kparser_put_parser(const void *parser);

/* net/core/filter.c's callback hook structure to use kParser APIs if kParser enabled */
struct get_kparser_funchooks {
	const void * (*kparser_get_parser_hook)(const struct kparser_hkey *kparser_key);
	int (*__kparser_parse_hook)(const void *parser, void *_hdr,
				    size_t parse_len, void *_metadata, size_t metadata_len);
	bool (*kparser_put_parser_hook)(const void *prsr);
};

extern struct get_kparser_funchooks kparser_funchooks;

#endif /* _NET_KPARSER_H */
