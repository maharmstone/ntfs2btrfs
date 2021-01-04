/*
 * xpress_decompress.c
 *
 * A decompressor for the XPRESS compression format (Huffman variant).
 */

/*
 *
 * Copyright (C) 2012-2016 Eric Biggers
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 2 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */


/*
 * The XPRESS compression format is an LZ77 and Huffman-code based algorithm.
 * That means it is fairly similar to LZX compression, but XPRESS is simpler, so
 * it is a little faster to compress and decompress.
 *
 * The XPRESS compression format is mostly documented in a file called "[MS-XCA]
 * Xpress Compression Algorithm".  In the MSDN library, it can currently be
 * found under Open Specifications => Protocols => Windows Protocols => Windows
 * Server Protocols => [MS-XCA] Xpress Compression Algorithm".  The format in
 * WIMs is specifically the algorithm labeled as the "LZ77+Huffman Algorithm"
 * (there apparently are some other versions of XPRESS as well).
 *
 * If you are already familiar with the LZ77 algorithm and Huffman coding, the
 * XPRESS format is fairly simple.  The compressed data begins with 256 bytes
 * that contain 512 4-bit integers that are the lengths of the symbols in the
 * Huffman code used for match/literal headers.  In contrast with more
 * complicated formats such as DEFLATE and LZX, this is the only Huffman code
 * that is used for the entirety of the XPRESS compressed data, and the codeword
 * lengths are not encoded with a pretree.
 *
 * The rest of the compressed data is Huffman-encoded symbols.  Values 0 through
 * 255 represent the corresponding literal bytes.  Values 256 through 511
 * represent matches and may require extra bits or bytes to be read to get the
 * match offset and match length.
 *
 * The trickiest part is probably the way in which literal bytes for match
 * lengths are interleaved in the bitstream.
 *
 * Also, a caveat--- according to Microsoft's documentation for XPRESS,
 *
 *	"Some implementation of the decompression algorithm expect an extra
 *	symbol to mark the end of the data.  Specifically, some implementations
 *	fail during decompression if the Huffman symbol 256 is not found after
 *	the actual data."
 *
 * This is the case with Microsoft's implementation in WIMGAPI, for example.  So
 * although our implementation doesn't currently check for this extra symbol,
 * compressors would be wise to add it.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "decompress_common.h"
#include "system_compression.h"
#include "xpress_constants.h"

/* This value is chosen for fast decompression.  */
#define XPRESS_TABLEBITS 11

struct xpress_decompressor {
	union {
		DECODE_TABLE(decode_table, XPRESS_NUM_SYMBOLS,
			     XPRESS_TABLEBITS, XPRESS_MAX_CODEWORD_LEN);
		u8 lens[XPRESS_NUM_SYMBOLS];
	};
	DECODE_TABLE_WORKING_SPACE(working_space, XPRESS_NUM_SYMBOLS,
				   XPRESS_MAX_CODEWORD_LEN);
} _aligned_attribute(DECODE_TABLE_ALIGNMENT);

int
xpress_decompress(struct xpress_decompressor *restrict d,
		  const void *restrict compressed_data, size_t compressed_size,
		  void *restrict uncompressed_data, size_t uncompressed_size)
{
	const u8 * const in_begin = compressed_data;
	u8 * const out_begin = uncompressed_data;
	u8 *out_next = out_begin;
	u8 * const out_end = out_begin + uncompressed_size;
	struct input_bitstream is;

	/* Read the Huffman codeword lengths.  */
	if (compressed_size < XPRESS_NUM_SYMBOLS / 2)
		return -1;
	for (int i = 0; i < XPRESS_NUM_SYMBOLS / 2; i++) {
		d->lens[2 * i + 0] = in_begin[i] & 0xf;
		d->lens[2 * i + 1] = in_begin[i] >> 4;
	}

	/* Build a decoding table for the Huffman code.  */
	if (make_huffman_decode_table(d->decode_table, XPRESS_NUM_SYMBOLS,
				      XPRESS_TABLEBITS, d->lens,
				      XPRESS_MAX_CODEWORD_LEN,
				      d->working_space))
		return -1;

	/* Decode the matches and literals.  */

	init_input_bitstream(&is, in_begin + XPRESS_NUM_SYMBOLS / 2,
			     compressed_size - XPRESS_NUM_SYMBOLS / 2);

	while (out_next != out_end) {
		unsigned sym;
		unsigned log2_offset;
		u32 length;
		u32 offset;

		sym = read_huffsym(&is, d->decode_table,
				   XPRESS_TABLEBITS, XPRESS_MAX_CODEWORD_LEN);
		if (sym < XPRESS_NUM_CHARS) {
			/* Literal  */
			*out_next++ = sym;
		} else {
			/* Match  */
			length = sym & 0xf;
			log2_offset = (sym >> 4) & 0xf;

			bitstream_ensure_bits(&is, 16);

			offset = ((u32)1 << log2_offset) |
				 bitstream_pop_bits(&is, log2_offset);

			if (length == 0xf) {
				length += bitstream_read_byte(&is);
				if (length == 0xf + 0xff)
					length = bitstream_read_u16(&is);
			}
			length += XPRESS_MIN_MATCH_LEN;

			if (unlikely(lz_copy(length, offset,
					     out_begin, out_next, out_end,
					     XPRESS_MIN_MATCH_LEN)))
				return -1;

			out_next += length;
		}
	}
	return 0;
}

struct xpress_decompressor *
xpress_allocate_decompressor(void)
{
	return aligned_malloc(sizeof(struct xpress_decompressor),
			      DECODE_TABLE_ALIGNMENT);
}

void
xpress_free_decompressor(struct xpress_decompressor *d)
{
	aligned_free(d);
}
