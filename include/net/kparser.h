/* SPDX-License-Identifier: BSD-2-Clause-FreeBSD */
/* Copyright (c) 2022, SiPanda Inc.
 *
 * kparser.h - kParser net header file
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
 * Authors:     Pratyush Kumar Khan <pratyush@sipanda.io>
 */

#ifndef _NET_KPARSER_H
#define _NET_KPARSER_H

#include <linux/kparser.h>

/* kParser datapath API 1: parse a skb using a parser instance key.
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

/* kParser datapath API 2: get/freeze a parser instance using a key.
 * kparser_key: key of the associated kParser parser object which must be
 * already created via CLI.
 * return: NULL if key not found, else an opaque parser instance pointer which
 *         can be used in the following APIs 3 and 4.
 * NOTE: This call makes the whole parser tree immutable. If caller calls this
 * more than once, later caller will need to release the same parser exactly that
 * many times using the API kparser_put_parser().
 */
extern const void * kparser_get_parser(const struct kparser_hkey *kparser_key);

/* kParser datapath API 3: parse a void * packet buffer using a parser instance
			   key.
 * parser: Non NULL kparser_get_parser() returned and cached opaque pointer
 *         referencing a valid parser instance.
 * _hdr: input packet buffer
 * parse_len: length of input packet buffer
 * _metadata: User provided metadata buffer. It must be same as configured
 *            metadata objects in CLI.
 * metadata_len: Total length of the user provided metadata buffer.
 * return: kParser error code as defined in include/uapi/linux/kparser.h
 */
extern int __kparser_parse(const struct kparser_parser *parser, void *_hdr,
		size_t parse_len, void *_metadata, size_t metadata_len);

/* kParser datapath API 4: put/un-freeze a parser instance using a previously
 * obtained opaque parser pointer via API kparser_get_parser().
 * parser: Non NULL kparser_get_parser() returned and cached opaque pointer
 *         referencing a valid parser instance.
 * return: true if put operation is success, else false.
 * NOTE: This call makes the whole parser tree deletable for the very last call.
 */
extern bool kparser_put_parser(const void *prsr);

#endif /* _NET_KPARSER_H */
