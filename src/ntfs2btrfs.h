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

#pragma once

#include "btrfs.h"
#include "config.h"
#include <string.h>
#include <map>
#include <list>
#include <string>
#include <vector>
#include <optional>

#pragma warning(push)
#pragma warning(disable : 26495 26451 26437 26812)
#include <fmt/format.h>
#pragma warning(pop)

#ifdef _MSC_VER

#ifdef _M_IX86
#define __i386__
#elif defined(_M_X64)
#define __x86_64__
#endif

#endif

#ifdef _WIN32
class last_error : public std::exception {
public:
    last_error(const std::string_view& function, int le) {
        std::string nice_msg;

        {
            char* fm;

            if (FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr,
                               le, 0, reinterpret_cast<LPSTR>(&fm), 0, nullptr)) {
                try {
                    std::string_view s = fm;

                    while (!s.empty() && (s[s.length() - 1] == u'\r' || s[s.length() - 1] == u'\n')) {
                        s.remove_suffix(1);
                    }

                    nice_msg = s;
                } catch (...) {
                    LocalFree(fm);
                    throw;
                }

                LocalFree(fm);
            }
        }

        msg = std::string(function) + " failed (error " + std::to_string(le) + (!nice_msg.empty() ? (", " + nice_msg) : "") + ").";
    }

    const char* what() const noexcept {
        return msg.c_str();
    }

private:
    std::string msg;
};

class handle_closer {
public:
    typedef HANDLE pointer;

    void operator()(HANDLE h) {
        if (h == INVALID_HANDLE_VALUE)
            return;

        CloseHandle(h);
    }
};

typedef std::unique_ptr<HANDLE, handle_closer> unique_handle;
#endif

class formatted_error : public std::exception {
public:
    template<typename T, typename... Args>
    formatted_error(const T& s, Args&&... args) {
        msg = fmt::format(s, std::forward<Args>(args)...);
    }

    const char* what() const noexcept {
        return msg.c_str();
    }

private:
    std::string msg;
};

struct space {
    space(uint64_t offset, uint64_t length) : offset(offset), length(length) { }

    uint64_t offset;
    uint64_t length;
};

struct chunk {
    chunk(uint64_t offset, uint64_t length, uint64_t disk_start, uint64_t type) : offset(offset), length(length), disk_start(disk_start), type(type) { }

    uint64_t offset;
    uint64_t length;
    uint64_t disk_start;
    uint64_t type;
    std::list<space> space_list;
    bool added = false;
    uint64_t used = 0;
};

struct data_alloc {
    data_alloc(uint64_t offset, uint64_t length, uint64_t inode = 0, uint64_t file_offset = 0, bool relocated = false, bool not_in_img = false) :
    offset(offset), length(length), inode(inode), file_offset(file_offset), relocated(relocated), not_in_img(not_in_img) { }

    uint64_t offset;
    uint64_t length;
    uint64_t inode;
    uint64_t file_offset;
    bool relocated;
    bool not_in_img;
};

template<typename T, typename A = std::allocator<T>>
class default_init_allocator : public A {
public:
    typedef std::allocator_traits<A> a_t;

    template<typename U>
    struct rebind {
        using other = default_init_allocator<U, typename a_t::template rebind_alloc<U>>;
    };

    using A::A;

    template<typename U>
    void construct(U* ptr) noexcept(std::is_nothrow_default_constructible<U>::value) {
        ::new(static_cast<void*>(ptr)) U;
    }

    template<typename U, typename...Args>
    void construct(U* ptr, Args&&... args) {
        a_t::construct(static_cast<A&>(*this), ptr, std::forward<Args>(args)...);
    }
};

using buffer_t = std::vector<uint8_t, default_init_allocator<uint8_t>>;

static bool inline operator<(const KEY& a, const KEY& b) {
    if (a.obj_id < b.obj_id)
        return true;
    else if (a.obj_id > b.obj_id)
        return false;

    if (a.obj_type < b.obj_type)
        return true;
    else if (a.obj_type > b.obj_type)
        return false;

    if (a.offset < b.offset)
        return true;

    return false;
}

class ntfs;

class root {
public:
    root(uint64_t id) : id(id) { }

    void create_trees(root& extent_root, enum btrfs_csum_type csum_type);
    void write_trees(ntfs& dev);

    uint64_t id;
    std::map<KEY, buffer_t> items;
    std::vector<buffer_t> trees;
    uint64_t tree_addr;
    uint8_t level;
    uint64_t metadata_size = 0;
    std::list<uint64_t> addresses, old_addresses;
    bool allocations_done = false;
    bool readonly = false;
    std::map<uint64_t, uint64_t> dir_seqs;
    std::map<uint64_t, uint64_t> dir_size;
};

// from sys/stat.h
#define __S_IFMT        0170000 /* These bits determine file type.  */
#define __S_IFDIR       0040000 /* Directory.  */
#define __S_IFCHR       0020000 /* Character device.  */
#define __S_IFBLK       0060000 /* Block device.  */
#define __S_IFREG       0100000 /* Regular file.  */
#define __S_IFIFO       0010000 /* FIFO.  */
#define __S_IFLNK       0120000 /* Symbolic link.  */
#define __S_IFSOCK      0140000 /* Socket.  */
#define __S_ISTYPE(mode, mask)  (((mode) & __S_IFMT) == (mask))

#ifndef S_ISDIR
#define S_ISDIR(mode)    __S_ISTYPE((mode), __S_IFDIR)
#endif

#ifndef S_IRUSR
#define S_IRUSR 0000400
#endif

#ifndef S_IWUSR
#define S_IWUSR 0000200
#endif

#ifndef S_IXUSR
#define S_IXUSR 0000100
#endif

#ifndef S_IRGRP
#define S_IRGRP (S_IRUSR >> 3)
#endif

#ifndef S_IWGRP
#define S_IWGRP (S_IWUSR >> 3)
#endif

#ifndef S_IXGRP
#define S_IXGRP (S_IXUSR >> 3)
#endif

#ifndef S_IROTH
#define S_IROTH (S_IRGRP >> 3)
#endif

#ifndef S_IWOTH
#define S_IWOTH (S_IWGRP >> 3)
#endif

#ifndef S_IXOTH
#define S_IXOTH (S_IXGRP >> 3)
#endif

#ifndef S_ISUID
#define S_ISUID 0004000
#endif

#ifndef S_ISGID
#define S_ISGID 0002000
#endif

#ifndef S_ISVTX
#define S_ISVTX 0001000
#endif

#pragma pack(push,1)

typedef struct {
    CHUNK_ITEM chunk_item;
    CHUNK_ITEM_STRIPE stripe;
} chunk_item_one_stripe;

typedef struct {
    EXTENT_ITEM extent_item;
    uint8_t type;
    TREE_BLOCK_REF tbr;
} metadata_item;

typedef struct {
    EXTENT_ITEM extent_item;
    uint8_t type;
    EXTENT_DATA_REF edr;
} data_item;

typedef struct {
    EXTENT_ITEM extent_item;
    uint8_t type1;
    EXTENT_DATA_REF edr1;
    uint8_t type2;
    EXTENT_DATA_REF edr2;
} data_item2;

#pragma pack(pop)

struct relocation {
    relocation(uint64_t old_start, uint64_t length, uint64_t new_start) : old_start(old_start), length(length), new_start(new_start) { }

    uint64_t old_start;
    uint64_t length;
    uint64_t new_start;
};

static inline uint64_t sector_align(uint64_t v, uint64_t s) {
    return ((v + s - 1) / s) * s;
}

static const uint64_t image_subvol_id = 0x100;
static const char image_filename[] = "ntfs.img";

// decomp.cpp
std::string lznt1_decompress(std::string_view compdata, uint32_t size);
std::string do_lzx_decompress(const std::string_view& compdata, uint32_t size);
std::string do_xpress_decompress(const std::string_view& compdata, uint32_t size, uint32_t chunk_size);

// compress.cpp
#ifdef WITH_ZLIB
std::optional<std::string> zlib_compress(const std::string_view& data, uint32_t cluster_size);
#endif
#ifdef WITH_LZO
std::optional<std::string> lzo_compress(const std::string_view& data, uint32_t cluster_size);
#endif
#ifdef WITH_ZSTD
std::optional<std::string> zstd_compress(const std::string_view& data, uint32_t cluster_size);
#endif

// sha256.c
extern "C" void calc_sha256(uint8_t* hash, const void* input, size_t len);

// blake2b-ref.c
extern "C" void blake2b(void *out, size_t outlen, const void* in, size_t inlen);

// rollback.cpp
void rollback(const std::string& fn);
