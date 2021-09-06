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
#include "config.h"

#ifdef WITH_ZLIB
#include <zlib.h>
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
