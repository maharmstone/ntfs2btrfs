/* Copyright (c) Mark Harmstone 2021
 *
 * This file is part of ntfs2btrfs.
 *
 * Ntfs2btrfs is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public Licence as published by
 * the Free Software Foundation, either version 2 of the Licence, or
 * (at your option) any later version.
 *
 * Ntfs2btrfs is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public Licence for more details.
 *
 * You should have received a copy of the GNU General Public Licence
 * along with Ntfs2btrfs. If not, see <https://www.gnu.org/licenses/>. */

#include "ntfs2btrfs.h"

#ifdef WITH_ZLIB
#include <zlib.h>
#endif

#ifdef WITH_LZO
#include <lzo/lzo1x.h>
#endif

#ifdef WITH_ZSTD
#include <zstd.h>
#endif

using namespace std;

#ifdef WITH_ZLIB
optional<string> zlib_compress(const string_view& data, uint32_t cluster_size) {
    z_stream c_stream;
    int ret;
    string out(data.length(), 0);

    c_stream.zalloc = Z_NULL;
    c_stream.zfree = Z_NULL;
    c_stream.opaque = (voidpf)0;

    ret = deflateInit(&c_stream, Z_DEFAULT_COMPRESSION);

    if (ret != Z_OK)
        throw formatted_error("deflateInit returned {}", ret);

    c_stream.next_in = (uint8_t*)data.data();
    c_stream.avail_in = (unsigned int)data.length();

    c_stream.next_out = (uint8_t*)out.data();
    c_stream.avail_out = (unsigned int)out.length();

    do {
        ret = deflate(&c_stream, Z_FINISH);

        if (ret != Z_OK && ret != Z_STREAM_END) {
            deflateEnd(&c_stream);
            throw formatted_error("deflate returned {}", ret);
        }

        if (c_stream.avail_in == 0 || c_stream.avail_out == 0)
            break;
    } while (ret != Z_STREAM_END);

    deflateEnd(&c_stream);

    if (c_stream.avail_in > 0) // compressed version would be longer than uncompressed
        return nullopt;

    if (c_stream.total_out > data.length() - cluster_size) // space saving less than one sector
        return nullopt;

    // round to sector, and zero end
    out.resize((c_stream.total_out + cluster_size - 1) & ~(cluster_size - 1), 0);

    return out;
}
#endif

#ifdef WITH_LZO
static __inline size_t lzo_max_outlen(size_t inlen) {
    return inlen + (inlen / 16) + 64 + 3; // formula comes from LZO.FAQ
}

optional<string> lzo_compress(const string_view& data, uint32_t cluster_size) {
    size_t num_pages;

    num_pages = data.length() / cluster_size;

    // Four-byte overall header
    // Another four-byte header page
    // Each page has a maximum size of lzo_max_outlen(cluster_size)
    // Plus another four bytes for possible padding
    string outbuf(sizeof(uint32_t) + ((lzo_max_outlen(cluster_size) + (2 * sizeof(uint32_t))) * num_pages), 0);
    string wrkmem(LZO1X_MEM_COMPRESS, 0);

    auto out_size = (uint32_t*)outbuf.data();
    *out_size = sizeof(uint32_t);

    auto in = (lzo_bytep)data.data();
    auto out = (lzo_bytep)(outbuf.data() + (2 * sizeof(uint32_t)));

    for (unsigned int i = 0; i < num_pages; i++) {
        auto pagelen = (uint32_t*)(out - sizeof(uint32_t));
        lzo_uint outlen;

        auto ret = lzo1x_1_compress(in, cluster_size, out, &outlen, wrkmem.data());
        if (ret != LZO_E_OK)
            throw formatted_error("lzo1x_1_compress returned {}", ret);

        *pagelen = (uint32_t)outlen;
        *out_size += (uint32_t)(outlen + sizeof(uint32_t));

        in += cluster_size;
        out += outlen + sizeof(uint32_t);

        // new page needs to start at a 32-bit boundary
        if (cluster_size - (*out_size % cluster_size) < sizeof(uint32_t)) {
            memset(out, 0, cluster_size - (*out_size % cluster_size));
            out += cluster_size - (*out_size % cluster_size);
            *out_size += cluster_size - (*out_size % cluster_size);
        }

        if (*out_size >= data.length())
            return nullopt;
    }

    outbuf.resize(*out_size);

    if (outbuf.length() > data.length() - cluster_size)
        return nullopt;

    outbuf.resize((outbuf.length() + cluster_size - 1) & ~(cluster_size - 1), 0);

    return outbuf;
}
#endif

#ifdef WITH_ZSTD
optional<string> zstd_compress(const string_view& data, uint32_t cluster_size) {
    string out(ZSTD_compressBound(data.length()), 0);

    auto ret = ZSTD_compress(out.data(), out.length(), data.data(), data.length(), 1);
    if (ZSTD_isError(ret))
        throw formatted_error("ZSTD_compress returned {}", ret);

    if (ret > data.length() - cluster_size)
        return nullopt;

    out.resize(ret);
    out.resize((out.length() + cluster_size - 1) & ~(cluster_size - 1), 0);

    return out;
}
#endif
