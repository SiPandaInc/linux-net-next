/* SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2020,2021 SiPanda Inc.
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
 */

#ifndef __KPARSER_METAEXTRACT_H__
#define __KPARSER_METAEXTRACT_H__

#include "kparser.h"

#define PANDA_PARSER_METADATA_CTRL_OFFSET	0
#define PANDA_PARSER_METADATA_CTRL_LENGTH	1

#define __PANDA_PARSER_METADATA_MAKE_BYTE_EXTRACT(SRC_OFF, DST_OFF,	\
						  LEN, E_BIT) {		\
	.byte.code = PANDA_PARSER_METADATA_BYTE_EXTRACT,		\
	.byte.src_off = SRC_OFF,					\
	.byte.dst_off = DST_OFF,					\
	.byte.length = LEN,						\
	.byte.e_bit = E_BIT,						\
}

#define PANDA_PARSER_METADATA_MAKE_BYTE_EXTRACT(NAME, SRC_OFF, DST_OFF,	\
						LEN, E_BIT)		\
	const struct kparser_md_xtrct_cnf NAME =			\
		__PANDA_PARSER_METADATA_MAKE_BYTE_EXTRACT(SRC_OFF,	\
							  DST_OFF,	\
							  LEN, E_BIT);

static inline struct kparser_md_xtrct_cnf
		panda_parser_metadata_make_byte_extract(size_t src_off,
							size_t dst_off,
							size_t len, bool e_bit)
{
	struct kparser_md_xtrct_cnf mde =
			__PANDA_PARSER_METADATA_MAKE_BYTE_EXTRACT(src_off,
								  dst_off,
								  len, e_bit);

	return mde;
}

#define __PANDA_PARSER_METADATA_MAKE_NIBB_EXTRACT(SRC_OFF, DST_OFF,	\
						  LEN, E_BIT, N_BIT) {	\
	.nibb.code = PANDA_PARSER_METADATA_NIBB_EXTRACT,		\
	.nibb.src_off = SRC_OFF,					\
	.nibb.dst_off = DST_OFF,					\
	.nibb.length = LEN,						\
	.nibb.e_bit = E_BIT,						\
	.nibb.n_bit = N_BIT,						\
}

#define PANDA_PARSER_METADATA_MAKE_NIBB_EXTRACT(NAME, SRC_OFF, DST_OFF,	\
						LEN, E_BIT, N_BIT)	\
	struct kparser_md_xtrct_cnf NAME =				\
		__PANDA_PARSER_METADATA_MAKE_NIBB_EXTRACT(SRC_OFF,	\
							  DST_OFF,	\
							  LEN, E_BIT,	\
							  N_BIT);

static inline struct kparser_md_xtrct_cnf
		panda_parser_make_make_nibb_extract(size_t src_off,
						    size_t dst_off,
						    size_t len, bool e_bit,
						    bool n_bit)
{
// TODO: Expand kparser_md_xtrct_cnf to kparser_md_extrct_conf
	struct kparser_md_xtrct_cnf mde =
			__PANDA_PARSER_METADATA_MAKE_NIBB_EXTRACT(src_off,
								  dst_off,
								  len, e_bit,
								  n_bit);

	return mde;
}

#define __PANDA_PARSER_METADATA_MAKE_SET_CONST_BYTE(DST_OFF, DATA) {	\
	.const_set.code = PANDA_PARSER_METADATA_CONSTANT_SET,		\
	.const_set.dst_off = DST_OFF,					\
	.const_set.data_low = DATA,					\
}

#define PANDA_PARSER_METADATA_MAKE_SET_CONST_BYTE(NAME, DST_OFF, DATA)	\
	const struct kparser_md_xtrct_cnf NAME =			\
		__PANDA_PARSER_METADATA_MAKE_SET_CONST_BYTE(DST_OFF,	\
							    DATA)

#define __PANDA_PARSER_METADATA_MAKE_SET_CONST_HALFWORD(DST_OFF, DATA) {\
	.const_set.code = PANDA_PARSER_METADATA_BYTE_EXTRACT,		\
	.const_set.dst_off = DST_OFF,					\
	.const_set.data_low = (DATA) & 0xff,				\
	.const_set.data_high = (DATA) >> 8,				\
	.const_set.l_bit = 1,						\
}

#define PANDA_PARSER_METADATA_MAKE_SET_CONST_HALFWORD(DST_OFF, DATA)	\
	struct kparser_md_xtrct_cnf NAME =				\
		__PANDA_PARSER_METADATA_MAKE_SET_CONST_HALFWORD(	\
							DST_OFF, DATA)

#define PANDA_PARSER_METADATA_MAKE_OR_CONST_BYTE(DST_OFF, DATA) {	\
	.const_set.code = PANDA_PARSER_METADATA_CONSTANT_SET,		\
	.const_set.dst_off = DST_OFF,					\
	.const_set.data_low = DATA,					\
	.const_set.o_bit = 1,						\
}

#define PANDA_PARSER_METADATA_MAKE_OR_CONST_HALFWORD(DST_OFF, DATA) {	\
	.const_set.code = PANDA_PARSER_METADATA_BYTE_EXTRACT,		\
	.const_set.dst_off = DST_OFF,					\
	.const_set.data_low = (DATA) & 0xff,				\
	.const_set.data_high = (DATA) >> 8,				\
	.const_set.l_bit = 1,						\
	.const_set.o_bit = 1,						\
}

static inline struct kparser_md_xtrct_cnf 
	panda_parser_metadata_set_const_byte_ins(size_t dst_off, __u8 data)
{
	struct kparser_md_xtrct_cnf mde =
		__PANDA_PARSER_METADATA_MAKE_SET_CONST_BYTE(dst_off, data);

	return mde;
}

static inline struct kparser_md_xtrct_cnf 
	panda_parser_metadata_set_set_const_halfword_ins(size_t dst_off,
							 __u16 data)
{
	struct kparser_md_xtrct_cnf mde =
			__PANDA_PARSER_METADATA_MAKE_SET_CONST_HALFWORD(
								dst_off, data);

	return mde;
}

static inline struct kparser_md_xtrct_cnf 
	panda_parser_metadata_set_or_const_byte_ins(size_t dst_off, __u8 data)
{
	struct kparser_md_xtrct_cnf mde =
			PANDA_PARSER_METADATA_MAKE_OR_CONST_BYTE(dst_off, data);

	return mde;
}

static inline struct kparser_md_xtrct_cnf 
	panda_parser_metadata_set_or_const_halfword_ins(size_t dst_off,
							__u16 data)
{
	struct  kparser_md_xtrct_cnf mde =
			PANDA_PARSER_METADATA_MAKE_OR_CONST_HALFWORD(
								dst_off, data);

	return mde;
}

#define PANDA_PARSER_METADATA_SET_CONTROL_OFFSET_INS(DST_OFF) {		\
	.control.code = PANDA_PARSER_METADATA_CONTROL_SET,		\
	.control.data_select = PANDA_PARSER_METADATA_CTRL_OFFSET,	\
}

#define PANDA_PARSER_METADATA_SET_CONTROL_LENGTH_INS(DST_OFF) {		\
	.control.code = PANDA_PARSER_METADATA_CONTROL_SET,		\
	.control.data_select = PANDA_PARSER_METADATA_CTRL_LENGTH,	\
}

static inline struct kparser_md_xtrct_cnf 
	panda_parser_metadata_set_control_offset_ins(size_t dst_off)
{
	struct  kparser_md_xtrct_cnf mde =
			PANDA_PARSER_METADATA_SET_CONTROL_OFFSET_INS(dst_off);

	return mde;
}

static inline struct kparser_md_xtrct_cnf 
	panda_parser_metadata_set_control_length_ins(size_t dst_off)
{
	struct  kparser_md_xtrct_cnf mde =
			PANDA_PARSER_METADATA_SET_CONTROL_LENGTH_INS(dst_off);

	return mde;
}

static inline void __panda_parser_metadata_byte_extract(const __u8 *sptr,
							__u8 *dptr,
							size_t length,
							bool e_bit)
{
	__u16 v16;
	__u32 v32;
	__u64 v64;

	switch (length) {
	case sizeof(__u8):
		*dptr = *sptr;
		break;
	case sizeof(__u16):
		v16 = *(__u16 *)sptr;
		*((__u16 *)dptr) = e_bit ? ntohs(v16) : v16;
		break;
	case sizeof(__u32):
		v32 = *(__u32 *)sptr;
		*((__u32 *)dptr) = e_bit ? ntohl(v32) : v32;
		break;
	case sizeof(__u64):
		v64 = *(__u64 *)sptr;
		// TODO: ntohll() NA in kernel
		// *((__u64 *)dptr) = e_bit ? ntohll(v64) : v64;
		break;
	default:
		if (e_bit) {
			int i;

			for (i = 0; i < length; i++)
				dptr[i] = sptr[length - 1 - i];
		} else {
			memcpy(dptr, sptr, length);
		}
	}
}

static inline void panda_parser_metadata_byte_extract(
				struct  kparser_md_xtrct_cnf mde,
				const void *hdr, void *mdata)
{
	__u8 *sptr = &((__u8 *)hdr)[mde.byte.src_off];
	__u8 *dptr = &((__u8 *)mdata)[mde.byte.dst_off];

	__panda_parser_metadata_byte_extract(sptr, dptr, mde.byte.length,
					     mde.byte.e_bit);
}

static inline void panda_parser_metadata_nibb_extract(
				struct  kparser_md_xtrct_cnf mde,
				const void *hdr, void *mdata)
{
	const __u8 *sptr = &((__u8 *)hdr)[mde.nibb.src_off];
	__u8 *dptr = &((__u8 *)mdata)[mde.nibb.dst_off];
	__u8 data;
	int i;


	if (mde.nibb.length == 0)
		return;

	if (!mde.nibb.n_bit && !(mde.nibb.length % 2)) {
		/* This is effectively a byte transfer case */

		__panda_parser_metadata_byte_extract(sptr, dptr,
						     mde.nibb.length / 2,
						     mde.nibb.e_bit);
		return;
	}

	if (mde.nibb.e_bit) {
		/* Endianness bit is set. dlen is the number of bytes
		 * set for output
		 */

		size_t dlen = (mde.nibb.length + 1) / 2;

		if (mde.nibb.n_bit) {
			if (mde.nibb.length % 2) {
				/* Odd length and n-bit is set. Set the reverse
				 * of all the bytes after the first nibble, and
				 * construct the last byte from the low order
				 * nibble of the first input byte
				 */
				for (i = 0; i < dlen - 1; i++)
					dptr[i] = sptr[dlen - 1 - i];
				dptr[i] = sptr[0] & 0xf;
			} else {
				/* Even length and n-bit is set. Logically
				 * shift all the nibbles in the string left and
				 * then set the reversed bytes.
				 */

				/* High order nibble of last byte becomes
				 * low order nibble of first output byte
				 */
				data = sptr[dlen] >> 4;

				for (i = 0; i < dlen - 1; i++) {
					/* Construct intermediate bytes. data
					 * contains the input high order nibble
					 * of the next input byte shifted right.
					 * That value is or'ed with the shifted
					 * left low order nibble of the current
					 * byte. The result is set in the
					 * reversed position in the output
					 */
					dptr[i] = data |
						sptr[dlen - 1 - i] << 4;

					/* Get the next data value */
					data = sptr[dlen - 1 - i] >> 4;
				}
				/* Set the last byte as the or of the last
				 * data value and the low order nibble of the
				 * zeroth byte of the input shifted left
				 */
				dptr[i] = data | sptr[0] << 4;
			}
		} else {
			/* Odd length (per check above) and n-bit is not
			 * set. Logically shift all the nibbles in the
			 * string right and then set the reversed bytes
			 */

			/* High order nibble of last byte becomes
			 * low order nibble of first output byte
			 */
			data = sptr[dlen - 1] >> 4;

			for (i = 0; i < dlen - 1; i++) {
				/* Construct intermediate bytes. data contains
				 * the input high order nibble of the next
				 * input byte shifted right. That value is
				 * or'ed with the shifted left low order nibble
				 * of the current byte. The result is set in the
				 * reversed position in the output
				 */
				dptr[i] = data | sptr[dlen - 2 - i] << 4;

				/* Get next data value */
				data = sptr[dlen - 2 - i] >> 4;
			}

			/* Last output byte is set to high oder nibble of first
			 * input byte shifted right
			 */
			dptr[i] = data;
		}
	} else {
		/* No e-bit (no endiannes) */

		size_t byte_len, len = mde.nibb.length;
		int ind = 0;


		if (mde.nibb.n_bit) {
			/* n-bit is set. Set first output byte to masked
			 * low order nibble of first input byte
			 */
			dptr[0] = sptr[0] & 0xf;
			ind = 1;
			len = mde.nibb.length - 1;
		}

		/* Copy all the whole intermediate bytes */
		byte_len = len / 2;
		memcpy(&dptr[ind], &sptr[ind], byte_len);

		if (len % 2) {
			/* Have an odd nibble at the endian. Set the last
			 * output byte to the mask high order nibble of the
			 * last input byte
			 */
			dptr[ind + byte_len] = sptr[ind + byte_len] & 0xf0;
		}
	}
}

static inline void panda_parser_metadata_const_set(
				struct kparser_md_xtrct_cnf mde,
				void *mdata)
{
	__u8 *dptr = &((__u8 *)mdata)[mde.const_set.dst_off];

	if (mde.const_set.o_bit) {
		dptr[0] |= mde.const_set.data_low;
		if (mde.const_set.l_bit)
			dptr[1] |= mde.const_set.data_high;
	} else {
		dptr[0] = mde.const_set.data_low;
		if (mde.const_set.l_bit)
			dptr[1] = mde.const_set.data_high;
	}
}

static inline void panda_parser_metadata_control_set(
				struct  kparser_md_xtrct_cnf mde,
				void *mdata, size_t hdr_len, size_t hdr_offset)
{
	__u8 *dptr = &((__u8 *)mdata)[mde.const_set.dst_off];

	switch (mde.control.code) {
	case PANDA_PARSER_METADATA_CTRL_OFFSET: {
		__u16 add = mde.const_set.data_low;

		if (mde.const_set.l_bit)
			add += mde.const_set.data_high << 8;
		*((__u16 *)dptr) = hdr_offset + add;
		break;
	}
	case PANDA_PARSER_METADATA_CTRL_LENGTH:
		*((__u16 *)dptr) = hdr_len;
		break;
	default:
		pr_debug("%s:Unknown extract:%u\n",
				__FUNCTION__, mde.control.code);
		break;
	}
}

static inline __s32 kparser_metadata_extract(
				const struct  kparser_md_xtrct_cnf mde,
				const void *hdr, size_t hdr_len,
				void *mdata, void *metadata_base,
				size_t hdr_offset)
{
	switch (mde.gen.code) {
	case PANDA_PARSER_METADATA_BYTE_EXTRACT:
		panda_parser_metadata_byte_extract(mde, hdr, mdata);
		break;
	case PANDA_PARSER_METADATA_NIBB_EXTRACT:
		panda_parser_metadata_nibb_extract(mde, hdr, mdata);
		break;
	case PANDA_PARSER_METADATA_CONSTANT_SET:
		panda_parser_metadata_const_set(mde, mdata);
		break;
	case PANDA_PARSER_METADATA_CONTROL_SET:
		panda_parser_metadata_control_set(mde, mdata, hdr_len,
						  hdr_offset);
		break;
	default:
		pr_debug("%s:Unknown extract:%u\n",
				__FUNCTION__, mde.gen.code);
		return -EINVAL;
	}

	return 0;
}

#endif /* __KPARSER_METAEXTRACT_H__ */
