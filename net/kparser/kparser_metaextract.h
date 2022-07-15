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

/* Metadata extraction parameterizations */

#include "kparser_types.h"

#include "linux/byteorder/little_endian.h"
#define __BYTE_ORDER __LITTLE_ENDIAN

#define __BIG_ENDIAN 0

#if __BYTE_ORDER == __BIG_ENDIAN
#define kparser_htonll(x) (x)
#elif __BYTE_ORDER == __LITTLE_ENDIAN
#define kparser_htonll(x)						\
	(((__u64)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
#else
#error "Cannot determine endianness"
#endif

#if __BYTE_ORDER == __BIG_ENDIAN
#define kparser_ntohll(x) (x)
#elif __BYTE_ORDER == __LITTLE_ENDIAN
#define kparser_ntohll(x)						\
	(((__u64)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))
#else
#error "Cannot determine endianness"
#endif

#ifdef KPARSER_NEED_ENDIAN_FUNCS

#define htonl __htonl
#define ntohl __ntohl
#define htons __htons
#define ntohs __ntohs

#endif

#define KPARSER_SWAP(a, b) do {					\
	typeof(a) __tmp = (a); (a) = (b); (b) = __tmp;		\
} while (0)

#define __KPARSER_COMBINE1(X, Y, Z) X##Y##Z
#define __KPARSER_COMBINE(X, Y, Z) __KPARSER_COMBINE1(X, Y, Z)

#ifdef __COUNTER__
#define KPARSER_UNIQUE_NAME(PREFIX, SUFFIX)				\
			__KPARSER_COMBINE(PREFIX, __COUNTER__, SUFFIX)
#else
#define KPARSER_UNIQUE_NAME(PREFIX, SUFFIX)				\
			__KPARSER_COMBINE(PREFIX, __LINE__, SUFFIX)
#endif

#define KPARSER_METADATA_BYTE_EXTRACT		0
#define KPARSER_METADATA_NIBB_EXTRACT		1
#define KPARSER_METADATA_CONSTANT_SET		2
#define KPARSER_METADATA_CONTROL_SET		3

#define KPARSER_METADATA_CTRL_OFFSET		0
#define KPARSER_METADATA_CTRL_LENGTH		1
#define KPARSER_METADATA_CTRL_NUM_NODES		2
#define KPARSER_METADATA_CTRL_NUM_ENCAPS	3

/* Metadata extraction pseudo instructions */
struct kparser_metadata_extract {
	union {
		struct {
			__u32 code: 4;	// One of KPARSER_METADATA_* ops
			__u32 frame: 1;	// Write to frame (true) else to meta
			__u32 rsvd: 3;
			__u32 dst_off: 9;	// Target offset in frame or meta
			__u32 src_off: 9;	// Src offset in header
			__u32 length;	// Byte length to read/write
		} gen;
		struct {
			__u32 code: 4;	// One of KPARSER_METADATA_* ops
			__u32 frame: 1;	// Write to frame (true) else to meta
			__u32 e_bit: 1;	// Swap endianness (true)
			__u32 rsvd: 2;
			__u32 dst_off: 9;	// Target offset in frame or meta
			__u32 src_off: 9;	// Src offset in header
			__u32 length;	// Byte length to read/write
		} byte;
		struct {
			__u32 code: 4;	// One of KPARSER_METADATA_* ops
			__u32 frame: 1;	// Write to frame (true) else to meta
			__u32 e_bit: 1;	// Swap endianness (true)
			__u32 n_bit: 1;	// Low order nibb (true) else high one
			__u32 rsvd: 1;
			__u32 dst_off: 9;	// Target offset in frame or meta
			__u32 src_off: 9;	// Src offset in header
			__u32 length;	// Byte length to read/write
		} nibb;
		struct {
			__u32 code: 4;	// One of KPARSER_METADATA_* ops
			__u32 frame: 1;	// Write to frame (true) else to meta
			__u32 l_bit: 1;	// Set eight bits only (true)
			__u32 rsvd: 2;
			__u32 dst_off;	// Target offset in frame or meta
			__u32 data_low;	// Low order bits of constant
			__u32 data_high;	// High order bits of constant
		} const_set;
		struct {
			__u32 code: 4;	// One of KPARSER_METADATA_* ops
			__u32 frame: 1;	// Write to frame (true) else to meta
			__u32 rsvd1: 3;
			__u32 dst_off;	// Target offset in frame or meta
			__u32 data_select; // One of KPARSER_METADATA_CTRL_*
			__u32 rsvd2;
		} control;
		__u32 val;
	};
};

/* Helper macros to make various pseudo instructions */

#define __KPARSER_METADATA_MAKE_BYTE_EXTRACT(FRAME, SRC_OFF,		\
						  DST_OFF, LEN, E_BIT)	\
{									\
	.byte.code = KPARSER_METADATA_BYTE_EXTRACT,			\
	.byte.frame = FRAME,						\
	.byte.src_off = SRC_OFF,					\
	.byte.dst_off = DST_OFF,					\
	.byte.length = LEN,						\
	.byte.e_bit = E_BIT,						\
}

#define __KPARSER_METADATA_MAKE_BYTE_EXTRACT_META(SRC_OFF,		\
						       DST_OFF, LEN,	\
						       E_BIT)		\
	__KPARSER_METADATA_MAKE_BYTE_EXTRACT(false, SRC_OFF,		\
						  DST_OFF, LEN, E_BIT)

#define KPARSER_METADATA_MAKE_BYTE_EXTRACT_META(NAME, SRC_OFF,		\
						     DST_OFF, LEN,	\
						     E_BIT)		\
const struct kparser_metadata_extract NAME = {				\
	__KPARSER_METADATA_MAKE_BYTE_EXTRACT_META(SRC_OFF,		\
						       DST_OFF, LEN,	\
						       E_BIT)		\
}

#define __KPARSER_METADATA_MAKE_BYTE_EXTRACT_FRAME(SRC_OFF,		\
							DST_OFF, LEN,	\
							E_BIT)		\
	__KPARSER_METADATA_MAKE_BYTE_EXTRACT(true, SRC_OFF,		\
						  DST_OFF, LEN, E_BIT)


#define KPARSER_METADATA_MAKE_BYTE_EXTRACT_FRAME(NAME, SRC_OFF,		\
						      DST_OFF, LEN,	\
						      E_BIT)		\
const struct kparser_metadata_extract NAME = {				\
	__KPARSER_METADATA_MAKE_BYTE_EXTRACT_FRAME(SRC_OFF,		\
							DST_OFF, LEN,	\
							E_BIT)		\
}

static inline struct kparser_metadata_extract
	__kparser_metadata_make_byte_extract(bool frame, size_t src_off,
						  size_t dst_off, size_t len,
						  bool e_bit)
{
	const struct kparser_metadata_extract mde =
		__KPARSER_METADATA_MAKE_BYTE_EXTRACT(frame, src_off,
							  dst_off, len, e_bit)
	;

	return mde;
}

static inline struct kparser_metadata_extract
	kparser_metadata_make_byte_extract_meta(size_t src_off,
						     size_t dst_off,
						     size_t len, bool e_bit)
{
	return __kparser_metadata_make_byte_extract(false, src_off,
							 dst_off, len, e_bit);
}

static inline struct kparser_metadata_extract
	kparser_metadata_make_byte_extract_frame(size_t src_off,
						      size_t dst_off,
						      size_t len, bool e_bit)
{
	return __kparser_metadata_make_byte_extract(true, src_off,
							 dst_off, len, e_bit);
}

#define __KPARSER_METADATA_MAKE_NIBB_EXTRACT(FRAME, SRC_OFF,		\
						  DST_OFF, LEN, E_BIT,	\
						  N_BIT)		\
{									\
	.nibb.code = KPARSER_METADATA_NIBB_EXTRACT,			\
	.nibb.frame = FRAME,						\
	.nibb.src_off = SRC_OFF,					\
	.nibb.dst_off = DST_OFF,					\
	.nibb.length = LEN,						\
	.nibb.e_bit = E_BIT,						\
	.nibb.n_bit = N_BIT,						\
}

#define __KPARSER_METADATA_MAKE_NIBB_EXTRACT_META(SRC_OFF,		\
						       DST_OFF, LEN,	\
						       E_BIT, N_BIT)	\
	__KPARSER_METADATA_MAKE_NIBB_EXTRACT(false, SRC_OFF,		\
						  DST_OFF, LEN, E_BIT,	\
						  N_BIT)

#define KPARSER_METADATA_MAKE_NIBB_EXTRACT_META(NAME, SRC_OFF,		\
						     DST_OFF, LEN,	\
						     E_BIT, N_BIT)	\
const struct kparser_metadata_extract NAME =				\
	__KPARSER_METADATA_MAKE_NIBB_EXTRACT_META(SRC_OFF,		\
						       DST_OFF, LEN,	\
						       E_BIT, N_BIT)


#define __KPARSER_METADATA_MAKE_NIBB_EXTRACT_FRAME(SRC_OFF,		\
							DST_OFF, LEN,	\
							E_BIT, N_BIT)	\
	__KPARSER_METADATA_MAKE_NIBB_EXTRACT(true, SRC_OFF,		\
						  DST_OFF, LEN, E_BIT,	\
						  N_BIT)

#define KPARSER_METADATA_MAKE_NIBB_EXTRACT_FRAME(NAME, SRC_OFF,		\
						      DST_OFF, LEN,	\
						      E_BIT, N_BIT)	\
const struct kparser_metadata_extract NAME =				\
	__KPARSER_METADATA_MAKE_NIBB_EXTRACT_FRAME(NAME, true,		\
							SRC_OFF,	\
							DST_OFF, LEN,	\
							E_BIT, N_BIT)

static inline struct kparser_metadata_extract
	__kparser_make_make_nibb_extract(bool frame, size_t src_off,
					      size_t dst_off, size_t len,
					      bool e_bit, bool n_bit)
{
	const struct kparser_metadata_extract mde =
		__KPARSER_METADATA_MAKE_NIBB_EXTRACT(frame, src_off,
							  dst_off, len, e_bit,
							  n_bit)
	;

	return mde;
}

static inline struct kparser_metadata_extract
	kparser_make_make_nibb_extract_meta(size_t src_off, size_t dst_off,
						 size_t len, bool e_bit,
						 bool n_bit)
{
	return __kparser_make_make_nibb_extract(false, src_off, dst_off,
						     len, e_bit, n_bit);
}

static inline struct kparser_metadata_extract
	kparser_make_make_nibb_extract_frame(size_t src_off,
						  size_t dst_off, size_t len,
						  bool e_bit, bool n_bit)
{
	return __kparser_make_make_nibb_extract(true, src_off, dst_off,
						     len, e_bit, n_bit);
}

#define __KPARSER_METADATA_MAKE_SET_CONST_BYTE(FRAME, DST_OFF,		\
						    DATA)		\
{									\
	.const_set.code = KPARSER_METADATA_CONSTANT_SET,		\
	.const_set.frame = FRAME,					\
	.const_set.dst_off = DST_OFF,					\
	.const_set.data_low = DATA,					\
}

#define __KPARSER_METADATA_MAKE_SET_CONST_BYTE_META(DST_OFF, DATA)	\
	__KPARSER_METADATA_MAKE_SET_CONST_BYTE(false, DST_OFF, DATA)

#define KPARSER_METADATA_MAKE_SET_CONST_BYTE_META(NAME, DST_OFF,	\
						       DATA)		\
const struct kparser_metadata_extract NAME = {				\
	__KPARSER_METADATA_MAKE_SET_CONST_BYTE(false, DST_OFF,		\
						    DATA)		\
}

#define __KPARSER_METADATA_MAKE_SET_CONST_BYTE_FRAME(DST_OFF,		\
							  DATA)		\
	__KPARSER_METADATA_MAKE_SET_CONST_BYTE(true, DST_OFF, DATA)

#define KPARSER_METADATA_MAKE_SET_CONST_BYTE_FRAME(NAME, DST_OFF,	\
							DATA)		\
const struct kparser_metadata_extract NAME =				\
	__KPARSER_METADATA_MAKE_SET_CONST_BYTE(true, DST_OFF, DATA)

static inline struct kparser_metadata_extract
	__kparser_metadata_set_const_byte(bool frame, size_t dst_off,
					       __u8 data)
{
	const struct kparser_metadata_extract mde =
		__KPARSER_METADATA_MAKE_SET_CONST_BYTE(frame, dst_off,
							    data)
	;

	return mde;
}

static inline struct kparser_metadata_extract
	kparser_make_set_const_byte_meta(size_t dst_off, __u8 data)
{
	return __kparser_metadata_set_const_byte(false, dst_off, data);
}

static inline struct kparser_metadata_extract
	kparser_make_set_const_byte_frame(size_t dst_off, __u8 data)
{
	return __kparser_metadata_set_const_byte(true, dst_off, data);
}

#define __KPARSER_METADATA_MAKE_SET_CONST_HALFWORD(FRAME, DST_OFF,	\
							DATA)		\
{									\
	.const_set.code = KPARSER_METADATA_BYTE_EXTRACT,		\
	.const_set.frame = FRAME,					\
	.const_set.dst_off = DST_OFF,					\
	.const_set.data_low = (DATA) & 0xff,				\
	.const_set.data_high = (DATA) >> 8,				\
	.const_set.l_bit = 1,						\
}

#define __KPARSER_METADATA_MAKE_SET_CONST_HALFWORD_META(DST_OFF,	\
							     DATA)	\
	__KPARSER_METADATA_MAKE_SET_CONST_HALFWORD(false, DST_OFF,	\
							DATA)		\

#define KPARSER_METADATA_MAKE_SET_CONST_HALFWORD_META(NAME,		\
							  DST_OFF, DATA)\
const struct kparser_metadata_extract NAME = {				\
	__KPARSER_METADATA_MAKE_SET_CONST_HALFWORD(false, DST_OFF, 	\
							DATA)		\
}

#define __KPARSER_METADATA_MAKE_SET_CONST_HALFWORD_FRAME(DST_OFF,	\
							      DATA)	\
	__KPARSER_METADATA_MAKE_SET_CONST_HALFWORD(true, DST_OFF, DATA)

#define KPARSER_METADATA_MAKE_SET_CONST_HALFWORD_FRAME(NAME,		\
							   DST_OFF,	\
							   DATA)	\
const struct kparser_metadata_extract NAME = {				\
	__KPARSER_METADATA_MAKE_SET_CONST_HALFWORD(true, DST_OFF,	\
							DATA)		\
}

static inline struct kparser_metadata_extract
	__kparser_metadata_set_const_halfword(bool frame, size_t dst_off,
						   __u16 data)
{
	const struct kparser_metadata_extract mde =
		__KPARSER_METADATA_MAKE_SET_CONST_HALFWORD(frame, dst_off,
								data)
	;

	return mde;
}

static inline struct kparser_metadata_extract
	kparser_make_set_const_halfword_meta(size_t dst_off, __u16 data)
{
	return __kparser_metadata_set_const_halfword(false, dst_off, data);
}

static inline struct kparser_metadata_extract
	kparser_make_set_const_halfword_frame(size_t dst_off, __u16 data)
{
	return __kparser_metadata_set_const_halfword(true, dst_off, data);
}

#define __KPARSER_METADATA_MAKE_SET_CONTROL(FRAME, TYPE, DST_OFF)	\
{									\
	.control.code = KPARSER_METADATA_CONTROL_SET,			\
	.control.frame = FRAME,						\
	.control.dst_off = DST_OFF,					\
	.control.data_select = TYPE,					\
}

#define __KPARSER_METADATA_MAKE_SET_CONTROL_META(TYPE, DST_OFF)		\
	__KPARSER_METADATA_MAKE_SET_CONTROL(false, TYPE, DST_OFF)

#define KPARSER_METADATA_MAKE_SET_CONTROL_META(NAME, TYPE, DST_OFF)	\
const struct kparser_metadata_extract NAME = {				\
	__KPARSER_METADATA_MAKE_SET_CONTROL(false, TYPE, DST_OFF)	\
}

#define __KPARSER_METADATA_MAKE_SET_CONTROL_FRAME(TYPE, DST_OFF)	\
	__KPARSER_METADATA_MAKE_SET_CONTROL(true, TYPE, DST_OFF)

#define KPARSER_METADATA_MAKE_SET_CONTROL_FRAME(NAME, TYPE,		\
						     DST_OFF)		\
const struct kparser_metadata_extract NAME = {				\
	__KPARSER_METADATA_MAKE_SET_CONTROL(NAME, true, TYPE,		\
						 DST_OFF)		\
}

static inline struct kparser_metadata_extract
	__kparser_metadata_set_control(bool frame, unsigned int type,
					    size_t dst_off)
{
	const struct kparser_metadata_extract mde =
		__KPARSER_METADATA_MAKE_SET_CONTROL(frame, type, dst_off);
	;

	return mde;
}

static inline struct kparser_metadata_extract
	kparser_metadata_set_control_offset_meta(size_t dst_off)
{
	return __kparser_metadata_set_control(
			false, KPARSER_METADATA_CTRL_OFFSET, dst_off);
}

static inline struct kparser_metadata_extract
	kparser_metadata_set_control_offset_frame(size_t dst_off)
{
	return __kparser_metadata_set_control(
			true, KPARSER_METADATA_CTRL_OFFSET, dst_off);
}

static inline struct kparser_metadata_extract
	kparser_metadata_set_control_length_meta(size_t dst_off)
{
	return __kparser_metadata_set_control(
			false, KPARSER_METADATA_CTRL_LENGTH, dst_off);
}

static inline struct kparser_metadata_extract
	kparser_metadata_set_control_length_frame(size_t dst_off)
{
	return __kparser_metadata_set_control(
			true, KPARSER_METADATA_CTRL_LENGTH, dst_off);
}

static inline struct kparser_metadata_extract
	kparser_metadata_set_control_num_nodes_meta(size_t dst_off)
{
	return __kparser_metadata_set_control(
			false, KPARSER_METADATA_CTRL_NUM_NODES, dst_off);
}

static inline struct kparser_metadata_extract
	kparser_metadata_set_control_num_nodes_frame(size_t dst_off)
{
	return __kparser_metadata_set_control(
			true, KPARSER_METADATA_CTRL_NUM_NODES, dst_off);
}

static inline struct kparser_metadata_extract
	kparser_metadata_set_control_num_encaps_meta(size_t dst_off)
{
	return __kparser_metadata_set_control(
			false, KPARSER_METADATA_CTRL_NUM_ENCAPS, dst_off);
}

static inline struct kparser_metadata_extract
	kparser_metadata_set_control_num_encaps_frame(size_t dst_off)
{
	return __kparser_metadata_set_control(
			true, KPARSER_METADATA_CTRL_NUM_ENCAPS, dst_off);
}

struct kparser_metadata_table {
	int num_ents;
	struct kparser_metadata_extract __rcu *entries;
};

/* Helper to create a parser table */
#define KPARSER_MAKE_METADATA_TABLE(NAME, ...)				\
	static const struct kparser_metadata_extract __##NAME[] =	\
						{ __VA_ARGS__ };	\
	static const struct kparser_metadata_table NAME =	{	\
		.num_ents = sizeof(__##NAME) /				\
			sizeof(struct kparser_metadata_extract),	\
		.entries = __##NAME,					\
	}


/* Extract functions */

static inline void __kparser_metadata_byte_extract(const __u8 *sptr,
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
		*((__u64 *)dptr) = e_bit ? kparser_ntohll(v64) : v64;
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

static inline void kparser_metadata_byte_extract(
				struct kparser_metadata_extract mde,
				const void *hdr, void *mdata)
{
	__u8 *sptr = &((__u8 *)hdr)[mde.byte.src_off];
	__u8 *dptr = &((__u8 *)mdata)[mde.byte.dst_off];

	__kparser_metadata_byte_extract(sptr, dptr, mde.byte.length,
					     mde.byte.e_bit);
}

static inline void kparser_metadata_nibb_extract(
				struct kparser_metadata_extract mde,
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

		__kparser_metadata_byte_extract(sptr, dptr,
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

static inline void kparser_metadata_const_set(
				struct kparser_metadata_extract mde,
				void *mdata)
{
	__u8 *dptr = &((__u8 *)mdata)[mde.const_set.dst_off];

	dptr[0] = mde.const_set.data_low;
	if (mde.const_set.l_bit)
		dptr[1] = mde.const_set.data_high;
}

static inline void kparser_metadata_control_set(
				struct kparser_metadata_extract mde,
				void *mdata, size_t hdr_len, size_t hdr_offset,
				const struct kparser_ctrl_data *ctrl)

{
	__u8 *dptr = &((__u8 *)mdata)[mde.control.dst_off];

	switch (mde.control.data_select) {
	case KPARSER_METADATA_CTRL_OFFSET: {
		__u16 add = mde.const_set.data_low;

		if (mde.const_set.l_bit)
			add += mde.const_set.data_high << 8;
		*((__u16 *)dptr) = hdr_offset + add;
		break;
	}
	case KPARSER_METADATA_CTRL_LENGTH:
		*((__u16 *)dptr) = hdr_len;
		break;
	case KPARSER_METADATA_CTRL_NUM_NODES:
		*((__u16 *)dptr) = ctrl->node_cnt;
		break;
	case KPARSER_METADATA_CTRL_NUM_ENCAPS:
		*((__u16 *)dptr) = ctrl->encap_levels;
		break;
	default:
		pr_debug("Unknown extract\n");
		break;
	}
}

/* Front end functions to process one metadata extraction pseudo instruction
 * in the context of parsing a packet
 */
static inline void kparser_metadata_extract(
				const struct kparser_metadata_extract mde,
				const void *_hdr, size_t hdr_len,
				size_t hdr_offset, void *_metadata,
				void *_frame,
				const struct kparser_ctrl_data *ctrl)
{
	void *mdata = mde.gen.frame ? _frame : _metadata;

	switch (mde.gen.code) {
	case KPARSER_METADATA_BYTE_EXTRACT:
		kparser_metadata_byte_extract(mde, _hdr, mdata);
		break;
	case KPARSER_METADATA_NIBB_EXTRACT:
		kparser_metadata_nibb_extract(mde, _hdr, mdata);
		break;
	case KPARSER_METADATA_CONSTANT_SET:
		kparser_metadata_const_set(mde, mdata);
		break;
	case KPARSER_METADATA_CONTROL_SET:
		kparser_metadata_control_set(mde, mdata, hdr_len,
						  hdr_offset, ctrl);
		break;
	default:
		pr_debug("Unknown extract\n");
		break;
	}
}

static inline bool kparser_md_convert(const struct kparser_conf_metadata *conf,
		struct kparser_metadata_extract *mde)
{
	__u32 encoding_type;

	switch(conf->type) {
	case KPARSER_MD_HDRDATA:
		*mde = __kparser_metadata_make_byte_extract(conf->frame,
				conf->soff, conf->doff, conf->len, conf->e_bit);
		return true;

	case KPARSER_MD_HDRLEN:
		encoding_type = KPARSER_METADATA_CTRL_LENGTH;
		break;

	case KPARSER_MD_OFFSET:
		// TODO: soff is needed
		encoding_type = KPARSER_METADATA_CTRL_OFFSET;
		break;

	case KPARSER_MD_NUMENCAPS:
		encoding_type = KPARSER_METADATA_CTRL_NUM_ENCAPS;
		break;

	case KPARSER_MD_NUMNODES:
		encoding_type = KPARSER_METADATA_CTRL_NUM_NODES;
		break;

	case KPARSER_MD_TIMESTAMP:
	default:
		return false; // TODO
	}

	*mde = __kparser_metadata_set_control(conf->frame,
		encoding_type, conf->doff);

	return true;
}
#endif /* __KPARSER_METAEXTRACT_H__ */
