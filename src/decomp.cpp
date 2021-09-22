/* Copyright (c) Mark Harmstone 2020
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
#include "ebiggers/system_compression.h"

#define LZX_CHUNK_SIZE 32768

using namespace std;

static buffer_t lznt1_decompress_chunk(string_view data) {
    buffer_t s;

    while (!data.empty()) {
        auto fg = (uint8_t)data[0];

        data = data.substr(1);

        if (fg == 0) {
            if (data.length() < 8) {
                s.insert(s.end(), data.begin(), data.end());

                return s;
            } else {
                s.insert(s.end(), data.begin(), data.begin() + 8);
                data = data.substr(8);
            }
        } else {
            for (unsigned int i = 0; i < 8; i++) {
                if (data.empty())
                    return s;

                if (!(fg & 1)) {
                    s.insert(s.end(), data.begin(), data.begin() + 1);
                    data = data.substr(1);
                } else {
                    if (data.length() < sizeof(uint16_t))
                        throw formatted_error("Compressed chunk was {} bytes, expected at least 2.", data.length());

                    // See https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/90fc6a28-f627-4ee5-82ce-445a6cf98b22

                    auto v = *(uint16_t*)data.data();

                    data = data.substr(2);

                    // Shamelessly stolen from https://github.com/you0708/lznt1 - thank you!

                    uint64_t u = s.size() - 1;
                    uint64_t lm = 0xfff;
                    uint64_t os = 12;

                    while (u >= 0x10) {
                        lm >>= 1;
                        os--;
                        u >>= 1;
                    }

                    auto l = (v & lm) + 3;
                    auto d = (v >> os) + 1;

                    s.reserve((uint32_t)(s.size() + l));

                    while (l > 0) {
                        s.resize(s.size() + 1);
                        s[s.size() - 1] = s[s.size() - d - 1];
                        l--;
                    }
                }

                fg >>= 1;
            }
        }
    }

    return s;
}

buffer_t lznt1_decompress(string_view compdata, uint32_t size) {
    buffer_t ret(size);
    uint8_t* ptr;

    memset(ret.data(), 0, ret.size());

    ptr = ret.data();

    while (true) {
        if (compdata.length() < sizeof(uint16_t))
            throw formatted_error("compdata was {} bytes, expected at least 2.", compdata.length());

        auto h = *(uint16_t*)compdata.data();

        if (h == 0)
            return ret;

        compdata = compdata.substr(2);

        auto sig = (h & 0x7000) >> 12;

        if (sig != 3)
            throw formatted_error("Compression signature was {}, expected 3.", sig);

        auto len = (uint32_t)(((uint64_t)h & 0xfff) + 1);

        if (compdata.length() < len)
            throw formatted_error("compdata was {} bytes, expected at least {}.", compdata.length(), len);

        auto data = string_view(compdata.data(), len);

        compdata = compdata.substr(len);

        if (h & 0x8000) {
            auto c = lznt1_decompress_chunk(data);

            if (ptr + c.size() >= ret.data() + size) {
                memcpy(ptr, c.data(), size - (ptr - ret.data()));

                return ret;
            } else {
                memcpy(ptr, c.data(), c.size());
                ptr += c.size();
            }
        } else {
            if (ptr + data.length() >= ret.data() + size) {
                memcpy(ptr, data.data(), size - (ptr - ret.data()));

                return ret;
            } else {
                memcpy(ptr, data.data(), data.length());
                ptr += data.length();
            }
        }
    }

    return ret;
}

buffer_t do_lzx_decompress(const string_view& compdata, uint32_t size) {
    auto ctx = lzx_allocate_decompressor(LZX_CHUNK_SIZE);

    if (!ctx)
        throw formatted_error("lzx_allocate_decompressor returned NULL.");

    uint64_t num_chunks = (size + LZX_CHUNK_SIZE - 1) / LZX_CHUNK_SIZE;
    auto offsets = (uint32_t*)compdata.data();

    buffer_t ret(size);

    auto data = string_view(compdata.data() + ((num_chunks - 1) * sizeof(uint32_t)),
                            (uint32_t)(compdata.length() - ((num_chunks - 1) * sizeof(uint32_t))));

    for (uint64_t i = 0; i < num_chunks; i++) {
        uint64_t off = i == 0 ? 0 : offsets[i - 1];
        uint32_t complen;

        if (i == 0)
            complen = num_chunks > 1 ? offsets[0] : (uint32_t)data.length();
        else if (i == num_chunks - 1)
            complen = (uint32_t)data.length() - offsets[i - 1];
        else
            complen = offsets[i] - offsets[i - 1];

        if (complen == (i == num_chunks - 1 ? (ret.size() - (i * LZX_CHUNK_SIZE)) : LZX_CHUNK_SIZE)) {
            // stored uncompressed
            memcpy(ret.data() + (i * LZX_CHUNK_SIZE), data.data() + off, complen);
        } else {
            auto err = lzx_decompress(ctx, data.data() + off, complen, ret.data() + (i * LZX_CHUNK_SIZE),
                                      (uint32_t)(i == num_chunks - 1 ? (ret.size() - (i * LZX_CHUNK_SIZE)) : LZX_CHUNK_SIZE));

            if (err != 0) {
                lzx_free_decompressor(ctx);
                throw formatted_error("lzx_decompress returned {}.", err);
            }
        }
    }

    lzx_free_decompressor(ctx);

    return ret;
}

buffer_t do_xpress_decompress(const string_view& compdata, uint32_t size, uint32_t chunk_size) {
    auto ctx = xpress_allocate_decompressor();

    if (!ctx)
        throw formatted_error("xpress_allocate_decompressor returned NULL.");

    uint64_t num_chunks = (size + chunk_size - 1) / chunk_size;
    auto offsets = (uint32_t*)compdata.data();

    buffer_t ret(size);

    auto data = string_view(compdata.data() + ((num_chunks - 1) * sizeof(uint32_t)),
                            (uint32_t)(compdata.length() - ((num_chunks - 1) * sizeof(uint32_t))));

    for (uint64_t i = 0; i < num_chunks; i++) {
        uint64_t off = i == 0 ? 0 : offsets[i - 1];
        uint32_t complen;

        if (i == 0)
            complen = num_chunks > 1 ? offsets[0] : (uint32_t)data.length();
        else if (i == num_chunks - 1)
            complen = (uint32_t)data.length() - offsets[i - 1];
        else
            complen = offsets[i] - offsets[i - 1];

        if (complen == (i == num_chunks - 1 ? (ret.size() - (i * chunk_size)) : chunk_size)) {
            // stored uncompressed
            memcpy(ret.data() + (i * chunk_size), data.data() + off, complen);
        } else {
            auto err = xpress_decompress(ctx, data.data() + off, complen, ret.data() + (i * chunk_size),
                                         (size_t)(i == num_chunks - 1 ? (ret.size() - (i * chunk_size)) : chunk_size));

            if (err != 0) {
                xpress_free_decompressor(ctx);
                throw formatted_error("xpress_decompress returned {}.", err);
            }
        }
    }

    xpress_free_decompressor(ctx);

    return ret;
}
