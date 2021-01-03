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

#define _SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING

#include "ntfs.h"
#include "ntfs2btrfs.h"
#include "crc32c.h"

#if defined(__i386__) || defined(__x86_64__)
#ifndef _MSC_VER
#include <cpuid.h>
#else
#include <intrin.h>
#endif
#endif

#include <iostream>
#include <new>
#include <chrono>
#include <random>
#include <locale>
#include <codecvt>

#ifdef _WIN32
#include <windows.h>
#endif

#include "config.h"

using namespace std;

list<chunk> chunks;
list<root> roots;
uint32_t tree_size = 0x4000; // FIXME
list<space> space_list;
bool chunks_changed;
uint64_t data_size = 0;
BTRFS_UUID fs_uuid, chunk_uuid, dev_uuid, subvol_uuid;
list<relocation> relocs;
uint64_t device_size, orig_device_size;
bool reloc_last_sector = false;

static const uint64_t stripe_length = 0x10000;
static const uint64_t chunk_virt_offset = 0x100000;
static const uint64_t dummy_inode = 0xffffffffffffffff; // protected data
static const uint64_t image_subvol_id = 0x100;

static const uint64_t first_ntfs_inode = 24;

static const uint64_t data_chunk_size = 128 * 1024 * 1024; // FIXME

static const uint64_t inode_offset = 0x101;

static const uint16_t max_inline = 2048;
static const uint64_t max_extent_size = 0x8000000; // 128 MB

#define EA_NTACL "security.NTACL"
#define EA_NTACL_HASH 0x45922146

#define EA_DOSATTRIB "user.DOSATTRIB"
#define EA_DOSATTRIB_HASH 0x914f9939

#define EA_REPARSE "user.reparse"
#define EA_REPARSE_HASH 0xfabad1fe

static void space_list_remove(list<space>& space_list, uint64_t offset, uint64_t length) {
    auto it = space_list.begin();

    while (it != space_list.end()) {
        if (it->offset > offset + length)
            return;

        if (it->offset >= offset && it->offset + it->length <= offset + length) { // remove entry entirely
            auto it2 = it;

            it2++;
            space_list.erase(it);
            it = it2;
            continue;
        } else if (offset + length > it->offset && offset + length < it->offset + it->length) {
            if (offset > it->offset) { // cut out hole
                space_list.insert(it, space(it->offset, offset - it->offset));

                it->length = it->offset + it->length - offset - length;
                it->offset = offset + length;

                return;
            } else { // remove start of entry
                it->length -= offset + length - it->offset;
                it->offset = offset + length;
            }
        } else if (offset > it->offset && offset < it->offset + it->length) // remove end of entry
            it->length = offset - it->offset;

        it++;
    }
}

static void create_data_chunks(ntfs& dev, const string& bmpdata) {
    uint64_t clusters_per_chunk = data_chunk_size / ((uint64_t)dev.boot_sector->BytesPerSector * (uint64_t)dev.boot_sector->SectorsPerCluster);
    uint64_t addr = 0;

    // FIXME - make sure clusters_per_chunk is multiple of 8

    string_view bdsv = bmpdata;

    // FIXME - make sure we stop at disk end - don't create a chunk at end purely because of NTFS overround

    while (bdsv.length() > 0) {
        string_view csv = bdsv.substr(0, clusters_per_chunk / 8);
        size_t len = csv.length();
        bool chunk_used = false;

        // FIXME - do by uint64_t if 64-bit processor?
        while (csv.length() >= sizeof(uint32_t)) {
            auto v = *(uint32_t*)csv.data();

            if (v != 0) {
                chunk_used = true;
                break;
            }

            csv = csv.substr(sizeof(uint32_t));
        }

        if (!chunk_used) {
            while (!csv.empty()) {
                auto v = *(uint8_t*)csv.data();

                if (v != 0) {
                    chunk_used = true;
                    break;
                }

                csv = csv.substr(1);
            }
        }

        if (chunk_used) {
            uint64_t length = min(device_size - addr, data_chunk_size);

            if (length % stripe_length != 0)
                length -= length % stripe_length;

            space_list_remove(space_list, addr, length);
            chunks.emplace_back(addr + chunk_virt_offset, length, addr, BLOCK_FLAG_DATA);
        }

        addr += data_chunk_size;
        bdsv = bdsv.substr(len);
    }
}

static void add_item(root& r, uint64_t obj_id, uint8_t obj_type, uint64_t offset, const void* data, uint16_t len) {
    auto ret = r.items.emplace(KEY{obj_id, obj_type, offset}, tree_item{});

    if (!ret.second)
        throw formatted_error(FMT_STRING("Could not insert entry ({:x}, {:x}, {:x}) into root items list."), obj_id, obj_type, offset);

    auto& it = ret.first->second;

    new (&it) tree_item(data, len);
}

static void add_chunk(root& chunk_root, root& devtree_root, root& extent_root, const chunk& c) {
    chunk_item_one_stripe ci1s;
    DEV_EXTENT de;
    BLOCK_GROUP_ITEM bgi;

    memset(&ci1s, 0, sizeof(chunk_item_one_stripe));

    ci1s.chunk_item.size = c.length;
    ci1s.chunk_item.root_id = BTRFS_ROOT_EXTENT;
    ci1s.chunk_item.stripe_length = 0x10000;
    ci1s.chunk_item.type = c.type;
    ci1s.chunk_item.opt_io_alignment = 0x10000;
    ci1s.chunk_item.opt_io_width = 0x10000;
    ci1s.chunk_item.sector_size = 0x1000; // FIXME - get from superblock
    ci1s.chunk_item.num_stripes = 1;
    ci1s.chunk_item.sub_stripes = 1;
    ci1s.stripe.dev_id = 1;
    ci1s.stripe.offset = c.disk_start;
    ci1s.stripe.dev_uuid = dev_uuid;

    add_item(chunk_root, 0x100, TYPE_CHUNK_ITEM, c.offset, &ci1s, sizeof(ci1s));

    de.chunktree = BTRFS_ROOT_CHUNK;
    de.objid = 0x100;
    de.address = c.offset;
    de.length = c.length;
    de.chunktree_uuid = chunk_uuid;

    add_item(devtree_root, 1, TYPE_DEV_EXTENT, c.disk_start, &de, sizeof(DEV_EXTENT));

    bgi.chunk_tree = 0x100;
    bgi.flags = c.type;
    // bgi.used gets set in update_extent_root

    add_item(extent_root, c.offset, TYPE_BLOCK_GROUP_ITEM, c.length, &bgi, sizeof(BLOCK_GROUP_ITEM));
}

static void remove_superblocks(chunk& c) {
    unsigned int i = 0;

    // FIXME - DUP

    while (superblock_addrs[i] != 0) {
        if (c.disk_start + c.length > superblock_addrs[i] && c.disk_start < superblock_addrs[i] + stripe_length) {
            uint64_t start = max(c.offset, superblock_addrs[i] - c.disk_start + c.offset);
            uint64_t end = min(c.offset + c.length, superblock_addrs[i] + stripe_length - c.disk_start + c.offset);

            space_list_remove(c.space_list, start, end - start);
        }

        i++;
    }
}

static uint64_t allocate_metadata(uint64_t r, root& extent_root, uint8_t level) {
    bool system_chunk = r == BTRFS_ROOT_CHUNK;
    uint64_t chunk_size, disk_offset;
    bool found = false;
    metadata_item mi;

    mi.extent_item.refcount = 1;
    mi.extent_item.generation = 1;
    mi.extent_item.flags = EXTENT_ITEM_TREE_BLOCK;
    mi.type = TYPE_TREE_BLOCK_REF;
    mi.tbr.offset = r;

    for (auto& c : chunks) {
        if ((system_chunk && c.type & BLOCK_FLAG_SYSTEM) || (!system_chunk && c.type & BLOCK_FLAG_METADATA)) {
            for (auto it = c.space_list.begin(); it != c.space_list.end(); it++) {
                if (it->length >= tree_size) {
                    uint64_t addr = it->offset;

                    if (it->length == tree_size)
                        c.space_list.erase(it);
                    else {
                        it->offset += tree_size;
                        it->length -= tree_size;
                    }

                    c.used += tree_size;

                    add_item(extent_root, addr, TYPE_METADATA_ITEM, level, &mi, sizeof(metadata_item));

                    return addr;
                }
            }
        }
    }

    // create new chunk

    chunks_changed = true;

    if (system_chunk)
        chunk_size = 32 * 1024 * 1024;
    else
        chunk_size = 128 * 1024 * 1024; // FIXME

    for (const auto& s : space_list) {
        if (s.length >= chunk_size) {
            disk_offset = s.offset;
            space_list_remove(space_list, disk_offset, chunk_size);
            found = true;
            break;
        }
    }

    if (!found)
        throw formatted_error(FMT_STRING("Could not find enough space to create new chunk."));

    chunks.emplace_back(disk_offset + chunk_virt_offset, chunk_size, disk_offset, system_chunk ? BLOCK_FLAG_SYSTEM : BLOCK_FLAG_METADATA);

    chunk& c = chunks.back();

    c.space_list.emplace_back(c.offset, c.length);

    remove_superblocks(c);

    for (auto it = c.space_list.begin(); it != c.space_list.end(); it++) {
        if (it->length >= tree_size) {
            uint64_t addr = it->offset;

            if (it->length == tree_size)
                c.space_list.erase(it);
            else {
                it->offset += tree_size;
                it->length -= tree_size;
            }

            c.used = tree_size;

            add_item(extent_root, addr, TYPE_METADATA_ITEM, level, &mi, sizeof(metadata_item));

            return addr;
        }
    }

    throw formatted_error(FMT_STRING("Could not allocate metadata address"));
}

static uint64_t allocate_data(uint64_t length) {
    uint64_t disk_offset;
    bool found = false;

    for (auto& c : chunks) {
        if (c.type & BLOCK_FLAG_DATA) {
            for (auto it = c.space_list.begin(); it != c.space_list.end(); it++) {
                if (it->length >= length) {
                    uint64_t addr = it->offset;

                    if (it->length == length)
                        c.space_list.erase(it);
                    else {
                        it->offset += length;
                        it->length -= length;
                    }

                    c.used += length;
                    return addr;
                }
            }
        }
    }

    // create new chunk

    chunks_changed = true;

    for (const auto& s : space_list) {
        if (s.length >= data_chunk_size) {
            disk_offset = s.offset;
            space_list_remove(space_list, disk_offset, data_chunk_size);
            found = true;
            break;
        }
    }

    if (!found)
        throw formatted_error(FMT_STRING("Could not find enough space to create new chunk."));

    chunks.emplace_back(disk_offset + chunk_virt_offset, data_chunk_size, disk_offset, BLOCK_FLAG_DATA);

    chunk& c = chunks.back();

    c.space_list.emplace_back(c.offset, c.length);

    remove_superblocks(c);

    for (auto it = c.space_list.begin(); it != c.space_list.end(); it++) {
        if (it->length >= length) {
            uint64_t addr = it->offset;

            if (it->length == length)
                c.space_list.erase(it);
            else {
                it->offset += length;
                it->length -= length;
            }

            c.used = length;

            return addr;
        }
    }

    throw formatted_error(FMT_STRING("Could not allocate data address"));
}

void root::create_trees(root& extent_root) {
    uint32_t space_left, num_items;
    string buf;
    tree_header* th;

    buf.resize(tree_size);

    memset(buf.data(), 0, tree_size);
    space_left = tree_size - (uint32_t)sizeof(tree_header);
    num_items = 0;

    th = (tree_header*)buf.data();
    th->fs_uuid = fs_uuid;
    th->flags = HEADER_FLAG_MIXED_BACKREF | HEADER_FLAG_WRITTEN;
    th->chunk_tree_uuid = chunk_uuid;
    th->generation = 1;
    th->tree_id = id;
    th->level = 0;

    {
        auto ln = (leaf_node*)((uint8_t*)buf.data() + sizeof(tree_header));
        uint32_t data_off = tree_size - (uint32_t)sizeof(tree_header);

        for (const auto& i : items) {
            if (sizeof(leaf_node) + i.second.len > space_left) { // tree complete, add to list
                if (!old_addresses.empty()) {
                    th->address = old_addresses.front();
                    old_addresses.pop_front();
                } else {
                    th->address = allocate_metadata(id, extent_root, th->level);
                    allocations_done = true;
                }

                addresses.push_back(th->address);
                th->num_items = num_items;

                *(uint32_t*)th->csum = ~calc_crc32c(0xffffffff, (uint8_t*)&th->fs_uuid, tree_size - (uint32_t)sizeof(th->csum));

                trees.push_back(buf);
                metadata_size += tree_size;

                memset(buf.data(), 0, tree_size);

                th->fs_uuid = fs_uuid;
                th->flags = HEADER_FLAG_MIXED_BACKREF | HEADER_FLAG_WRITTEN;
                th->chunk_tree_uuid = chunk_uuid;
                th->generation = 1;
                th->tree_id = id;

                space_left = data_off = tree_size - (uint32_t)sizeof(tree_header);
                num_items = 0;
                ln = (leaf_node*)((uint8_t*)buf.data() + sizeof(tree_header));
            }

            if (sizeof(leaf_node) + i.second.len + sizeof(tree_header) > tree_size)
                throw formatted_error(FMT_STRING("Item too large for tree."));

            ln->key = i.first;
            ln->size = i.second.len;

            if (i.second.len != 0) {
                data_off -= i.second.len;
                memcpy((uint8_t*)buf.data() + sizeof(tree_header) + data_off, i.second.data, i.second.len);
            }

            ln->offset = data_off;

            ln++;

            num_items++;
            space_left -= (uint32_t)sizeof(leaf_node) + i.second.len;
        }
    }

    if (num_items > 0 || items.size() == 0) { // flush remaining tree
        if (!old_addresses.empty()) {
            th->address = old_addresses.front();
            old_addresses.pop_front();
        } else {
            th->address = allocate_metadata(id, extent_root, th->level);
            allocations_done = true;
        }

        addresses.push_back(th->address);
        th->num_items = num_items;

        *(uint32_t*)th->csum = ~calc_crc32c(0xffffffff, (uint8_t*)&th->fs_uuid, tree_size - (uint32_t)sizeof(th->csum));

        trees.push_back(buf);
        metadata_size += tree_size;
    }

    level = 0;

    if (trees.size() == 1) { // no internal trees needed
        tree_addr = ((tree_header*)trees.back().data())->address;
        return;
    }

    // create internal trees if necessary

    do {
        unsigned int trees_added = 0;

        level++;

        memset(buf.data(), 0, tree_size);

        th = (tree_header*)buf.data();
        th->fs_uuid = fs_uuid;
        th->flags = HEADER_FLAG_MIXED_BACKREF | HEADER_FLAG_WRITTEN;
        th->chunk_tree_uuid = chunk_uuid;
        th->generation = 1;
        th->tree_id = id;
        th->level = level;

        num_items = 0;
        space_left = tree_size - (uint32_t)sizeof(tree_header);

        auto in = (internal_node*)((uint8_t*)buf.data() + sizeof(tree_header));

        for (const auto& t : trees) {
            auto th2 = (tree_header*)t.data();

            if (th2->level >= level)
                break;

            if (th2->level < level - 1)
                continue;

            if (sizeof(internal_node) > space_left) { // tree complete, add to list
                if (!old_addresses.empty()) {
                    th->address = old_addresses.front();
                    old_addresses.pop_front();
                } else {
                    th->address = allocate_metadata(id, extent_root, th->level);
                    allocations_done = true;
                }

                addresses.push_back(th->address);
                th->num_items = num_items;

                *(uint32_t*)th->csum = ~calc_crc32c(0xffffffff, (uint8_t*)&th->fs_uuid, tree_size - (uint32_t)sizeof(th->csum));

                trees.push_back(buf);
                metadata_size += tree_size;

                memset(buf.data(), 0, tree_size);

                th->fs_uuid = fs_uuid;
                th->flags = HEADER_FLAG_MIXED_BACKREF | HEADER_FLAG_WRITTEN;
                th->chunk_tree_uuid = chunk_uuid;
                th->generation = 1;
                th->tree_id = id;
                th->level = level;

                space_left = tree_size - (uint32_t)sizeof(tree_header);
                num_items = 0;
                in = (internal_node*)((uint8_t*)buf.data() + sizeof(tree_header));

                trees_added++;
            }

            auto ln = (leaf_node*)((uint8_t*)t.data() + sizeof(tree_header));

            in->key = ln->key;
            in->address = th2->address;
            in->generation = 1;

            in++;

            num_items++;
            space_left -= (uint32_t)sizeof(internal_node);
        }

        if (num_items > 0) { // flush remaining tree
            if (!old_addresses.empty()) {
                th->address = old_addresses.front();
                old_addresses.pop_front();
            } else {
                th->address = allocate_metadata(id, extent_root, th->level);
                allocations_done = true;
            }

            addresses.push_back(th->address);
            th->num_items = num_items;

            *(uint32_t*)th->csum = ~calc_crc32c(0xffffffff, (uint8_t*)&th->fs_uuid, tree_size - (uint32_t)sizeof(th->csum));

            trees.push_back(buf);
            metadata_size += tree_size;

            trees_added++;
        }

        if (trees_added == 1)
            break;
    } while (true);

    tree_addr = ((tree_header*)trees.back().data())->address;

    // FIXME - make sure level of METADATA_ITEMs is correct
}

void root::write_trees(ntfs& dev) {
    for (const auto& t : trees) {
        auto th = (tree_header*)t.data();
        uint64_t addr = th->address;
        bool found = false;

        for (const auto& c : chunks) {
            if (c.offset <= addr && c.offset + c.length >= addr + tree_size) {
                uint64_t physaddr = th->address - c.offset + c.disk_start;

                // FIXME - handle DUP

                dev.seek(physaddr);
                dev.write(t.data(), t.length());

                found = true;
                break;
            }
        }

        if (!found)
            throw formatted_error(FMT_STRING("Could not find chunk containing address.")); // FIXME - include number
    }
}

static void set_volume_label(superblock* sb, ntfs& dev) {
    try {
        ntfs_file vol_file(dev, NTFS_VOLUME_INODE);

        auto vnw = vol_file.read(0, 0, ntfs_attribute::VOLUME_NAME);

        if (vnw.empty())
            return;

        wstring_convert<codecvt_utf8_utf16<char16_t>, char16_t> convert;

        auto vn = convert.to_bytes((char16_t*)vnw.data(), (char16_t*)&vnw[vnw.length()]);

        if (vn.length() > MAX_LABEL_SIZE) {
            vn = vn.substr(0, MAX_LABEL_SIZE);

            // remove whole code point
            while (!vn.empty() && vn[vn.length() - 1] & 0x80) {
                vn.pop_back();
            }

            cerr << "Truncating volume label to \"" << vn << "\"" << endl;
        }

        // FIXME - check label doesn't contain slash or backslash

        if (vn.empty())
            return;

        memcpy(sb->label, vn.data(), vn.length());
    } catch (const exception& e) { // shouldn't be fatal
        cerr << "Error while setting volume label: " << e.what() << endl;
    }
}

static void write_superblocks(ntfs& dev, root& chunk_root, root& root_root) {
    uint32_t sector_size = 0x1000; // FIXME
    string buf;
    superblock* sb;
    unsigned int i;
    uint32_t sys_chunk_size;
    uint64_t total_used;

    buf.resize(sector_align(sizeof(superblock), sector_size));
    sb = (superblock*)buf.data();

    memset(buf.data(), 0, buf.length());

    sys_chunk_size = 0;
    for (const auto& c : chunk_root.items) {
        if (c.first.obj_type == TYPE_CHUNK_ITEM) {
            auto ci = (CHUNK_ITEM*)c.second.data;

            if (ci->type & BLOCK_FLAG_SYSTEM) {
                sys_chunk_size += sizeof(KEY);
                sys_chunk_size += c.second.len;
            }
        }
    }

    if (sys_chunk_size > SYS_CHUNK_ARRAY_SIZE)
        throw formatted_error(FMT_STRING("System chunk list was too long ({} > {}."), sys_chunk_size, SYS_CHUNK_ARRAY_SIZE);

    total_used = data_size;

    for (const auto& r : roots) {
        total_used += r.metadata_size;
    }

    sb->uuid = fs_uuid;
    sb->magic = BTRFS_MAGIC;
    sb->generation = 1;
    sb->root_tree_addr = root_root.tree_addr;
    sb->chunk_tree_addr = chunk_root.tree_addr;
    sb->total_bytes = device_size;
    sb->bytes_used = total_used;
    sb->root_dir_objectid = BTRFS_ROOT_TREEDIR;
    sb->num_devices = 1;
    sb->sector_size = sector_size;
    sb->node_size = tree_size;
    sb->leaf_size = tree_size;
    sb->stripe_size = sector_size;
    sb->n = sys_chunk_size;
    sb->chunk_root_generation = 1;
    sb->incompat_flags = BTRFS_INCOMPAT_FLAGS_MIXED_BACKREF | BTRFS_INCOMPAT_FLAGS_BIG_METADATA | BTRFS_INCOMPAT_FLAGS_EXTENDED_IREF |
                         BTRFS_INCOMPAT_FLAGS_SKINNY_METADATA | BTRFS_INCOMPAT_FLAGS_NO_HOLES;
    sb->root_level = root_root.level;
    sb->chunk_root_level = chunk_root.level;

    set_volume_label(sb, dev);

    for (const auto& c : chunk_root.items) {
        if (c.first.obj_type == TYPE_DEV_ITEM) {
            memcpy(&sb->dev_item, c.second.data, sizeof(DEV_ITEM));
            break;
        }
    }

    sb->uuid_tree_generation = 1;

    {
        uint8_t* ptr = sb->sys_chunk_array;

        for (const auto& c : chunk_root.items) {
            if (c.first.obj_type == TYPE_CHUNK_ITEM) {
                auto ci = (CHUNK_ITEM*)c.second.data;

                if (ci->type & BLOCK_FLAG_SYSTEM) {
                    KEY* key = (KEY*)ptr;

                    *key = c.first;

                    ptr += sizeof(KEY);

                    memcpy(ptr, c.second.data, c.second.len);

                    ptr += c.second.len;
                }
            }
        }
    }

    i = 0;
    while (superblock_addrs[i] != 0) {
        if (superblock_addrs[i] > device_size - buf.length())
            return;

        sb->sb_phys_addr = superblock_addrs[i];

        *(uint32_t*)sb->checksum = ~calc_crc32c(0xffffffff, (uint8_t*)&sb->uuid, sizeof(superblock) - sizeof(sb->checksum));

        dev.seek(superblock_addrs[i]);
        dev.write(buf.data(), buf.length());

        i++;
    }
}

static void add_dev_item(root& chunk_root) {
    DEV_ITEM di;
    uint32_t sector_size = 0x1000; // FIXME - get from superblock

    memset(&di, 0, sizeof(DEV_ITEM));
    di.dev_id = 1;
    di.num_bytes = device_size;
    //uint64_t bytes_used; // FIXME
    di.optimal_io_align = sector_size;
    di.optimal_io_width = sector_size;
    di.minimal_io_size = sector_size;
    di.device_uuid = dev_uuid;
    di.fs_uuid = fs_uuid;

    add_item(chunk_root, 1, TYPE_DEV_ITEM, 1, &di, sizeof(DEV_ITEM));
}

static void add_to_root_root(const root& r, root& root_root) {
    ROOT_ITEM ri;

    memset(&ri, 0, sizeof(ROOT_ITEM));

    ri.inode.generation = 1;
    ri.inode.st_blocks = tree_size;
    ri.inode.st_size = 3;
    ri.inode.st_nlink = 1;
    ri.inode.st_mode = __S_IFDIR | S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;
    ri.generation = 1;
    ri.objid = (r.id == BTRFS_ROOT_FSTREE || r.id >= 0x100) ? SUBVOL_ROOT_INODE : 0;
    ri.flags = r.readonly ? BTRFS_SUBVOL_READONLY : 0;
    ri.num_references = 1;
    ri.generation2 = 1;

    if (r.id == image_subvol_id)
        ri.uuid = subvol_uuid;

    // block_number, bytes_used, and root_level are set in update_root_root

    add_item(root_root, r.id, TYPE_ROOT_ITEM, 0, &ri, sizeof(ROOT_ITEM));
}

static void update_root_root(root& root_root) {
    for (auto& t : root_root.trees) {
        auto th = (tree_header*)t.data();

        if (th->level > 0)
            return;

        auto ln = (leaf_node*)((uint8_t*)t.data() + sizeof(tree_header));
        bool changed = true;

        for (unsigned int i = 0; i < th->num_items; i++) {
            if (ln[i].key.obj_type == TYPE_ROOT_ITEM) {
                auto ri = (ROOT_ITEM*)((uint8_t*)t.data() + sizeof(tree_header) + ln[i].offset);

                for (const auto& r : roots) {
                    if (r.id == ln[i].key.obj_id) {
                        ri->block_number = r.tree_addr;
                        ri->root_level = r.level;
                        ri->bytes_used = r.metadata_size;

                        changed = true;
                    }
                }
            }
        }

        if (changed)
            *(uint32_t*)th->csum = ~calc_crc32c(0xffffffff, (uint8_t*)&th->fs_uuid, tree_size - (uint32_t)sizeof(th->csum));
    }
}

static void add_dev_stats(root& r) {
    uint64_t ds[5];

    memset(ds, 0, sizeof(ds));

    add_item(r, 0, TYPE_DEV_STATS, 1, &ds, sizeof(ds));
}

static BTRFS_UUID generate_uuid(default_random_engine& gen) {
    BTRFS_UUID uuid;
    uniform_int_distribution<unsigned int> dist(0,0xffffffff);

    for (unsigned int i = 0; i < 4; i++) {
        *(uint32_t*)&uuid.uuid[i * sizeof(uint32_t)] = dist(gen);
    }

    return uuid;
}

static void update_extent_root(root& extent_root) {
    for (auto& t : extent_root.trees) {
        auto th = (tree_header*)t.data();

        if (th->level > 0)
            return;

        auto ln = (leaf_node*)((uint8_t*)t.data() + sizeof(tree_header));
        bool changed = true;

        for (unsigned int i = 0; i < th->num_items; i++) {
            if (ln[i].key.obj_type == TYPE_BLOCK_GROUP_ITEM) {
                auto bgi = (BLOCK_GROUP_ITEM*)((uint8_t*)t.data() + sizeof(tree_header) + ln[i].offset);

                for (const auto& c : chunks) {
                    if (c.offset == ln[i].key.obj_id) {
                        bgi->used = c.used;

                        changed = true;
                    }
                }
            }
        }

        if (changed)
            *(uint32_t*)th->csum = ~calc_crc32c(0xffffffff, (uint8_t*)&th->fs_uuid, tree_size - (uint32_t)sizeof(th->csum));
    }
}

static void add_inode_ref(root& r, uint64_t inode, uint64_t parent, uint64_t index, const string_view& name) {
    if (r.items.count(KEY{inode, TYPE_INODE_REF, parent}) != 0) { // collision, append to the end
        auto& old = r.items.at(KEY{inode, TYPE_INODE_REF, parent});

        size_t irlen = offsetof(INODE_REF, name[0]) + name.length() + old.len;

        // FIXME - check if too long for tree, and create INODE_EXTREF instead

        auto buf = malloc(irlen);
        if (!buf)
            throw bad_alloc();

        try {
            memcpy(buf, old.data, old.len);

            auto ir = (INODE_REF*)((uint8_t*)buf + old.len);

            ir->index = index;
            ir->n = (uint16_t)name.length();
            memcpy(ir->name, name.data(), name.length());
        } catch (...) {
            free(buf);
            throw;
        }

        old.data = buf;
        old.len = (uint16_t)irlen;

        return;
    }

    size_t irlen = offsetof(INODE_REF, name[0]) + name.length();

    auto ir = (INODE_REF*)malloc(irlen);
    if (!ir)
        throw bad_alloc();

    try {
        ir->index = index;
        ir->n = (uint16_t)name.length();
        memcpy(ir->name, name.data(), name.length());

        add_item(r, inode, TYPE_INODE_REF, parent, ir, (uint16_t)irlen);
    } catch (...) {
        free(ir);
        throw;
    }

    free(ir);
}

static void populate_fstree(root& r) {
    INODE_ITEM ii;

    memset(&ii, 0, sizeof(INODE_ITEM));

    ii.generation = 1;
    ii.transid = 1;
    ii.st_nlink = 1;
    ii.st_mode = __S_IFDIR | S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;
    ii.sequence = 1;

    add_item(r, SUBVOL_ROOT_INODE, TYPE_INODE_ITEM, 0, &ii, sizeof(INODE_ITEM));

    add_inode_ref(r, SUBVOL_ROOT_INODE, SUBVOL_ROOT_INODE, 0, "..");
}

static void update_chunk_root(root& chunk_root) {
    for (auto& t : chunk_root.trees) {
        auto th = (tree_header*)t.data();

        if (th->level > 0)
            return;

        auto ln = (leaf_node*)((uint8_t*)t.data() + sizeof(tree_header));

        for (unsigned int i = 0; i < th->num_items; i++) {
            if (ln[i].key.obj_id == 1 && ln[i].key.obj_type == TYPE_DEV_ITEM && ln[i].key.offset == 1) {
                auto di = (DEV_ITEM*)((uint8_t*)t.data() + sizeof(tree_header) + ln[i].offset);

                di->bytes_used = 0;

                for (const auto& c : chunks) {
                    di->bytes_used += c.length;
                }

                *(uint32_t*)th->csum = ~calc_crc32c(0xffffffff, (uint8_t*)&th->fs_uuid, tree_size - (uint32_t)sizeof(th->csum));

                return;
            }
        }
    }
}

static root& add_image_subvol(root& root_root, root& fstree_root) {
    static const char subvol_name[] = "image";

    roots.emplace_back(image_subvol_id);
    root& r = roots.back();

    r.readonly = true;

    // add ROOT_REF and ROOT_BACKREF

    {
        size_t rrlen = offsetof(ROOT_REF, name[0]) + sizeof(subvol_name) - 1;
        auto rr = (ROOT_REF*)malloc(rrlen);
        if (!rr)
            throw bad_alloc();

        try {
            rr->dir = SUBVOL_ROOT_INODE;
            rr->index = 2;
            rr->n = sizeof(subvol_name) - 1;
            memcpy(rr->name, subvol_name, sizeof(subvol_name) - 1);

            add_item(root_root, BTRFS_ROOT_FSTREE, TYPE_ROOT_REF, image_subvol_id, rr, (uint16_t)rrlen);
            add_item(root_root, image_subvol_id, TYPE_ROOT_BACKREF, BTRFS_ROOT_FSTREE, rr, (uint16_t)rrlen);
        } catch (...) {
            free(rr);
            throw;
        }

        free(rr);
    }

    // add DIR_ITEM and DIR_INDEX

    {
        size_t dilen = offsetof(DIR_ITEM, name[0]) + sizeof(subvol_name) - 1;
        auto di = (DIR_ITEM*)malloc(dilen);
        if (!di)
            throw bad_alloc();

        try {
            uint32_t hash;

            di->key.obj_id = image_subvol_id;
            di->key.obj_type = TYPE_ROOT_ITEM;
            di->key.offset = 0xffffffffffffffff;
            di->transid = 1;
            di->m = 0;
            di->n = sizeof(subvol_name) - 1;
            di->type = BTRFS_TYPE_DIRECTORY;
            memcpy(di->name, subvol_name, sizeof(subvol_name) - 1);

            hash = calc_crc32c(0xfffffffe, (const uint8_t*)subvol_name, sizeof(subvol_name) - 1);

            add_item(fstree_root, SUBVOL_ROOT_INODE, TYPE_DIR_ITEM, hash, di, (uint16_t)dilen);
            add_item(fstree_root, SUBVOL_ROOT_INODE, TYPE_DIR_INDEX, 2, di, (uint16_t)dilen);
        } catch (...) {
            free(di);
            throw;
        }

        free(di);
    }

    // increase st_size in parent dir
    if (fstree_root.dir_size.count(SUBVOL_ROOT_INODE) == 0)
        fstree_root.dir_size[SUBVOL_ROOT_INODE] = (sizeof(subvol_name) - 1) * 2;
    else
        fstree_root.dir_size.at(SUBVOL_ROOT_INODE) += (sizeof(subvol_name) - 1) * 2;

    populate_fstree(r);

    return r;
}

static void create_image(root& r, ntfs& dev, const list<data_alloc>& runs, uint64_t inode) {
    INODE_ITEM ii;
    uint64_t cluster_size = (uint64_t)dev.boot_sector->BytesPerSector * (uint64_t)dev.boot_sector->SectorsPerCluster;

    static const char filename[] = "ntfs.img";

    // add INODE_ITEM

    memset(&ii, 0, sizeof(INODE_ITEM));

    ii.generation = 1;
    ii.transid = 1;
    ii.st_size = orig_device_size;
    ii.st_nlink = 1;
    ii.st_mode = __S_IFREG | S_IRUSR | S_IWUSR;
    ii.sequence = 1;

    // FIXME - use current time for the following
//     BTRFS_TIME st_atime;
//     BTRFS_TIME st_ctime;
//     BTRFS_TIME st_mtime;
//     BTRFS_TIME otime;

    for (const auto& run : runs) {
        if (!run.relocated && !run.not_in_img)
            ii.st_blocks += run.length * cluster_size;
    }

    add_item(r, inode, TYPE_INODE_ITEM, 0, &ii, sizeof(INODE_ITEM));

    // add DIR_ITEM and DIR_INDEX

    {
        size_t dilen = offsetof(DIR_ITEM, name[0]) + sizeof(filename) - 1;
        auto di = (DIR_ITEM*)malloc(dilen);
        if (!di)
            throw bad_alloc();

        try {
            uint32_t hash;

            di->key.obj_id = inode;
            di->key.obj_type = TYPE_INODE_ITEM;
            di->key.offset = 0;
            di->transid = 1;
            di->m = 0;
            di->n = sizeof(filename) - 1;
            di->type = BTRFS_TYPE_FILE;
            memcpy(di->name, filename, sizeof(filename) - 1);

            hash = calc_crc32c(0xfffffffe, (const uint8_t*)filename, sizeof(filename) - 1);

            add_item(r, SUBVOL_ROOT_INODE, TYPE_DIR_ITEM, hash, di, (uint16_t)dilen);
            add_item(r, SUBVOL_ROOT_INODE, TYPE_DIR_INDEX, 2, di, (uint16_t)dilen);
        } catch (...) {
            free(di);
            throw;
        }

        free(di);
    }

    // add INODE_REF

    add_inode_ref(r, inode, SUBVOL_ROOT_INODE, 2, filename);

    // increase st_size in parent dir

    for (auto& it : r.items) {
        if (it.first.obj_id == SUBVOL_ROOT_INODE && it.first.obj_type == TYPE_INODE_ITEM) {
            auto ii2 = (INODE_ITEM*)it.second.data;

            ii2->st_size += (sizeof(filename) - 1) * 2;
            break;
        }
    }

    // add extents

    {
        size_t extlen = offsetof(EXTENT_DATA, data[0]) + sizeof(EXTENT_DATA2);
        auto ed = (EXTENT_DATA*)malloc(extlen);
        if (!ed)
            throw bad_alloc();

        auto ed2 = (EXTENT_DATA2*)&ed->data;

        ed->generation = 1;
        ed->compression = 0;
        ed->encryption = 0;
        ed->encoding = 0;
        ed->type = EXTENT_TYPE_REGULAR;

        try {
            for (const auto& run : runs) {
                uint64_t addr;

                if (run.relocated || run.not_in_img)
                    continue;

                ed->decoded_size = ed2->size = ed2->num_bytes = run.length * cluster_size;

                addr = run.offset * cluster_size;

                if (run.inode == dummy_inode) {
                    for (const auto& reloc : relocs) {
                        if (reloc.old_start == run.offset) {
                            ed2->address = (reloc.new_start * cluster_size) + chunk_virt_offset;
                            break;
                        }
                    }
                } else
                    ed2->address = addr + chunk_virt_offset;

                ed2->offset = 0;

                add_item(r, inode, TYPE_EXTENT_DATA, addr, ed, (uint16_t)extlen);

                data_size += ed2->size;
            }
        } catch (...) {
            free(ed);
            throw;
        }

        free(ed);
    }
}

template<typename T>
static void parse_bitmap(const string& bmpdata, list<T>& runs) {
    uint64_t run_start = 0, pos = 0;
    bool set = false;
    string_view bdsv = bmpdata;

    // FIXME - by 64-bits if 64-bit processor (use typedef for uint64_t/uint32_t?)

    while (bdsv.size() >= sizeof(uint32_t)) {
        auto v = *(uint32_t*)bdsv.data();

        if ((!set && v == 0) || (set && v == 0xffffffff)) {
            pos += sizeof(uint32_t) * 8;
            bdsv = bdsv.substr(sizeof(uint32_t));
            continue;
        }

        if (!set && v == 0xffffffff) {
            run_start = pos;
            set = true;
            pos += sizeof(uint32_t) * 8;
        } else if (set && v == 0) {
            if (pos != run_start)
                runs.emplace_back(run_start, pos - run_start);

            set = false;
            pos += sizeof(uint32_t) * 8;
        } else {
            for (unsigned int i = 0; i < sizeof(uint32_t) * 8; i++) {
                if (v & 1) {
                    if (!set) {
                        run_start = pos;
                        set = true;
                    }
                } else {
                    if (set) {
                        if (pos != run_start)
                            runs.emplace_back(run_start, pos - run_start);

                        set = false;
                    }
                }

                v >>= 1;
                pos++;
            }
        }

        bdsv = bdsv.substr(sizeof(uint32_t));
    }

    while (!bdsv.empty()) {
        auto v = *(uint8_t*)bdsv.data();

        if ((!set && v == 0) || (set && v == 0xff)) {
            pos++;
            bdsv = bdsv.substr(1);
            continue;
        }

        if (!set && v == 0xff) {
            run_start = pos;
            set = true;
            pos += 8;
        } else if (set && v == 0) {
            if (pos != run_start)
                runs.emplace_back(run_start, pos - run_start);

            set = false;
            pos += 8;
        } else {
            for (unsigned int i = 0; i < 8; i++) {
                if (v & 1) {
                    if (!set) {
                        run_start = pos;
                        set = true;
                    }
                } else {
                    if (set) {
                        if (pos != run_start)
                            runs.emplace_back(run_start, pos - run_start);

                        set = false;
                    }
                }

                v >>= 1;
                pos++;
            }
        }

        bdsv = bdsv.substr(1);
    }

    if (set && run_start != pos)
        runs.emplace_back(run_start, pos - run_start);

    // FIXME - remove any bits after end of volume
}

static BTRFS_TIME win_time_to_unix(int64_t time) {
    uint64_t l = (uint64_t)time - 116444736000000000ULL;
    BTRFS_TIME bt;

    bt.seconds = l / 10000000;
    bt.nanoseconds = (uint32_t)((l % 10000000) * 100);

    return bt;
}

static void link_inode(root& r, uint64_t inode, uint64_t dir, const string_view& name, uint8_t type) {
    uint64_t seq;

    // add DIR_ITEM and DIR_INDEX

    if (r.dir_seqs.count(dir) == 0)
        r.dir_seqs[dir] = 2;

    seq = r.dir_seqs.at(dir);

    {
        size_t dilen = offsetof(DIR_ITEM, name[0]) + name.length();
        auto di = (DIR_ITEM*)malloc(dilen);
        if (!di)
            throw bad_alloc();

        try {
            uint32_t hash;

            di->key.obj_id = inode;
            di->key.obj_type = TYPE_INODE_ITEM;
            di->key.offset = 0;
            di->transid = 1;
            di->m = 0;
            di->n = (uint16_t)name.length();
            di->type = type;
            memcpy(di->name, name.data(), name.length());

            hash = calc_crc32c(0xfffffffe, (const uint8_t*)name.data(), (uint32_t)name.length());

            if (r.items.count(KEY{dir, TYPE_DIR_ITEM, hash}) == 0)
                add_item(r, dir, TYPE_DIR_ITEM, hash, di, (uint16_t)dilen);
            else { // hash collision
                auto& ent = r.items.at(KEY{dir, TYPE_DIR_ITEM, hash});

                if (ent.len != 0) {
                    void* data = malloc(ent.len + dilen);

                    if (!data)
                        throw bad_alloc();

                    memcpy(data, ent.data, ent.len);
                    memcpy((uint8_t*)data + ent.len, di, dilen);

                    free(ent.data);

                    ent.data = data;
                    ent.len += (uint32_t)dilen;
                } else {
                    ent.data = malloc(dilen);
                    if (!ent.data)
                        throw bad_alloc();

                    ent.len = (uint32_t)dilen;
                    memcpy(ent.data, di, dilen);
                }
            }

            add_item(r, dir, TYPE_DIR_INDEX, seq, di, (uint16_t)dilen);
        } catch (...) {
            free(di);
            throw;
        }

        free(di);
    }

    // add INODE_REF

    add_inode_ref(r, inode, dir, seq, name);

    // increase st_size in parent dir

    if (r.dir_size.count(dir) == 0)
        r.dir_size[dir] = name.length() * 2;
    else
        r.dir_size.at(dir) += name.length() * 2;

    r.dir_seqs[dir]++;
}

static bool split_runs(list<data_alloc>& runs, uint64_t offset, uint64_t length, uint64_t inode, uint64_t file_offset) {
    for (auto it = runs.begin(); it != runs.end(); it++) {
        auto& r = *it;

        if (r.offset > offset + length)
            break;

        if (offset + length > r.offset && offset < r.offset + r.length) {
            if (offset >= r.offset && offset + length <= r.offset + r.length) { // cut out middle
                if (offset > r.offset)
                    runs.emplace(it, r.offset, offset - r.offset);

                runs.emplace(it, offset, length, inode, file_offset, r.relocated);

                if (offset + length < r.offset + r.length) {
                    r.length = r.offset + r.length - offset - length;
                    r.offset = offset + length;
                } else
                    runs.erase(it);

                return true;
            }

            throw formatted_error(FMT_STRING("Error assigning space to file. This can occur if the space bitmap has become corrupted. Run chkdsk and try again."));
        }
    }

    return false;
}

static void process_mappings(const ntfs& dev, uint64_t inode, list<mapping>& mappings, list<data_alloc>& runs) {
    uint64_t cluster_size = (uint64_t)dev.boot_sector->BytesPerSector * (uint64_t)dev.boot_sector->SectorsPerCluster;
    uint64_t clusters_per_chunk = data_chunk_size / cluster_size;
    list<mapping> mappings2;

    // avoid chunk boundaries

    for (const auto& m : mappings) {
        if (m.lcn == 0) // sparse
            continue;

        uint64_t chunk_start = m.lcn / clusters_per_chunk;
        uint64_t chunk_end = ((m.lcn + m.length) - 1) / clusters_per_chunk;

        if (chunk_end > chunk_start) {
            uint64_t start = m.lcn, vcn = m.vcn;

            do {
                uint64_t end = min((((start / clusters_per_chunk) + 1) * clusters_per_chunk), m.lcn + m.length);

                if (end == start)
                    break;

                mappings2.emplace_back(start, vcn, end - start);

                vcn += end - start;
                start = end;
            } while (true);
        } else
            mappings2.emplace_back(m.lcn, m.vcn, m.length);
    }

    mappings.clear();
    mappings.splice(mappings.begin(), mappings2);

    // change to avoid superblocks

    for (auto& r : relocs) {
        for (auto it = mappings.begin(); it != mappings.end(); it++) {
            auto& m = *it;

            if (m.lcn + m.length > r.old_start && m.lcn < r.old_start + r.length) {
                if (m.lcn >= r.old_start && m.lcn + m.length <= r.old_start + r.length) { // change whole mapping
                    if (r.old_start < m.lcn) { // reloc starts before mapping
                        for (auto it2 = runs.begin(); it2 != runs.end(); it2++) {
                            auto& r2 = *it2;

                            if (r2.offset == r.old_start) {
                                runs.emplace(it2, r2.offset, m.lcn - r2.offset, dummy_inode);

                                r2.length -= m.lcn - r2.offset;
                                r2.offset = m.lcn;
                            }

                            if (r2.offset == r.new_start) {
                                runs.emplace(it2, r2.offset, m.lcn - r.old_start, 0, 0, true);

                                r2.offset += m.lcn - r.old_start;
                                r2.length -= m.lcn - r.old_start;
                            }
                        }

                        relocs.emplace_back(r.old_start, m.lcn - r.old_start, r.new_start);

                        r.length -= m.lcn - r.old_start;
                        r.new_start += m.lcn - r.old_start;
                        r.old_start = m.lcn;
                    }

                    if (r.old_start + r.length > m.lcn + m.length) { // reloc goes beyond end of mapping
                        relocs.emplace_back(m.lcn + m.length, r.old_start + r.length - m.lcn - m.length,
                                            r.new_start + m.lcn + m.length - r.old_start);

                        r.length = m.lcn + m.length - r.old_start;

                        for (auto it2 = runs.begin(); it2 != runs.end(); it2++) {
                            auto& r2 = *it2;

                            if (r2.offset == r.old_start) {
                                runs.emplace(it2, r.old_start, m.lcn + m.length - r.old_start, dummy_inode);

                                r2.length -= m.lcn + m.length - r2.offset;
                                r2.offset = m.lcn + m.length;
                            }

                            if (r2.offset == r.new_start) {
                                runs.emplace(it2, r2.offset, m.lcn + m.length - r.old_start, 0, 0, true);

                                r2.offset += m.lcn + m.length - r.old_start;
                                r2.length -= m.lcn + m.length - r.old_start;
                            }
                        }
                    }

                    m.lcn -= r.old_start;
                    m.lcn += r.new_start;
                } else if (m.lcn <= r.old_start && m.lcn + m.length >= r.old_start + r.length) { // change middle
                    if (m.lcn < r.old_start) {
                        mappings.emplace(it, m.lcn, m.vcn, r.old_start - m.lcn);
                        m.vcn += r.old_start - m.lcn;
                        m.length -= r.old_start - m.lcn;
                        m.lcn = r.old_start;
                    }

                    if (m.lcn + m.length > r.old_start + r.length) {
                        mappings.emplace(it, r.new_start, m.vcn, r.length);

                        m.lcn = r.old_start + r.length;
                        m.length -= r.length;
                        m.vcn += r.length;
                    } else {
                        m.lcn -= r.old_start;
                        m.lcn += r.new_start;
                    }
                } else if (m.lcn < r.old_start && m.lcn + m.length <= r.old_start + r.length) { // change end
                    mappings.emplace(it, m.lcn, m.vcn, r.old_start - m.lcn);

                    m.vcn += r.old_start - m.lcn;
                    m.length -= r.old_start - m.lcn;
                    m.lcn = r.new_start;

                    if (r.length > m.length) {
                        relocs.emplace_back(r.old_start + m.length, r.length - m.length, r.new_start + m.length);

                        r.length = m.length;

                        for (auto it2 = runs.begin(); it2 != runs.end(); it2++) {
                            auto& r2 = *it2;

                            if (r2.offset == r.old_start) {
                                runs.emplace(it2, r2.offset, m.length, dummy_inode);

                                r2.offset += m.length;
                                r2.length -= m.length;

                                break;
                            }
                        }
                    }
                } else if (m.lcn > r.old_start && m.lcn + m.length > r.old_start + r.length) { // change beginning
                    auto orig_r = r;

                    if (r.old_start < m.lcn) {
                        for (auto it2 = runs.begin(); it2 != runs.end(); it2++) {
                            auto& r2 = *it2;

                            if (r2.offset == r.old_start) {
                                runs.emplace(it2, r2.offset, m.lcn - r2.offset, dummy_inode);

                                r2.length -= m.lcn - r2.offset;
                                r2.offset = m.lcn;
                            }

                            if (r2.offset == r.new_start) {
                                runs.emplace(it2, r2.offset, m.lcn - r.old_start, 0, 0, true);

                                r2.offset += m.lcn - r.old_start;
                                r2.length -= m.lcn - r.old_start;
                            }
                        }

                        relocs.emplace_back(m.lcn, r.old_start + r.length - m.lcn, r.new_start + m.lcn - r.old_start);

                        r.length = m.lcn - r.old_start;
                    }

                    mappings.emplace(it, m.lcn - orig_r.old_start + orig_r.new_start, m.vcn, orig_r.old_start + orig_r.length - m.lcn);

                    m.vcn += orig_r.old_start + orig_r.length - m.lcn;
                    m.length -= orig_r.old_start + orig_r.length - m.lcn;
                    m.lcn = orig_r.old_start + orig_r.length;
                }
            }
        }
    }

    for (const auto& m : mappings) {
        split_runs(runs, m.lcn, m.length, inode, m.vcn);
    }
}

static void set_xattr(root& r, uint64_t inode, const string_view& name, uint32_t hash, const string_view& data) {
    auto di = (DIR_ITEM*)malloc(offsetof(DIR_ITEM, name[0]) + name.size() + data.size());

    if (!di)
        throw bad_alloc();

    try {
        di->key.obj_id = di->key.offset = 0;
        di->key.obj_type = 0;
        di->transid = 1;
        di->m = (uint16_t)data.size();
        di->n = (uint16_t)name.size();
        di->type = BTRFS_TYPE_EA;
        memcpy(di->name, name.data(), name.size());
        memcpy(di->name + name.size(), data.data(), data.size());

        add_item(r, inode, TYPE_XATTR_ITEM, hash, di, (uint16_t)(offsetof(DIR_ITEM, name[0]) + name.size() + data.size()));
    } catch (...) {
        free(di);
        throw;
    }

    free(di);
}

static void clear_line() {
#ifdef _WIN32
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    HANDLE console = GetStdHandle(STD_OUTPUT_HANDLE);

    if (GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi)) {
        DWORD written;

        SetConsoleCursorPosition(console, { 0, csbi.dwCursorPosition.Y });

        string spaces(csbi.dwSize.X, ' ');

        WriteConsole(console, spaces.data(), (DWORD)spaces.length(), &written, nullptr);

        SetConsoleCursorPosition(console, { 0, csbi.dwCursorPosition.Y });
    }
#else
    fmt::print(FMT_STRING("\33[2K"));
    fflush(stdout);
#endif
}

static bool string_eq_ci(const string_view& s1, const string_view& s2) {
    if (s1.length() != s2.length())
        return false;

    auto c1 = &s1[0];
    auto c2 = &s2[0];

    for (size_t i = 0; i < s1.length(); i++) {
        auto c1a = *c1;
        auto c2a = *c2;

        if (c1a >= 'A' && c1a <= 'Z')
            c1a = c1a - 'A' + 'a';

        if (c2a >= 'A' && c2a <= 'Z')
            c2a = c2a - 'A' + 'a';

        if (c1a != c2a)
            return false;

        c1++;
        c2++;
    }

    return true;
}

static void add_inode(root& r, uint64_t inode, uint64_t ntfs_inode, bool& is_dir, list<data_alloc>& runs,
                      ntfs_file& secure, ntfs& dev, const list<uint64_t>& skiplist) {
    INODE_ITEM ii;
    uint64_t file_size = 0;
    list<mapping> mappings;
    wstring_convert<codecvt_utf8_utf16<char16_t>, char16_t> convert;
    vector<tuple<uint64_t, string>> links;
    string standard_info, inline_data, sd, reparse_point, symlink;
    uint32_t atts;
    bool atts_set = false;
    map<string, tuple<uint32_t, string>> xattrs;
    string filename, wof_compressed_data;
    uint32_t cluster_size = dev.boot_sector->BytesPerSector * dev.boot_sector->SectorsPerCluster;
    bool processed_data = false;
    uint16_t compression_unit;
    uint64_t vdl;

    static const uint32_t sector_size = 0x1000; // FIXME

    ntfs_file f(dev, ntfs_inode);

    if (f.file_record->BaseFileRecordSegment.SegmentNumber != 0)
        return;

    is_dir = f.is_directory();

    f.loop_through_atts([&](const ATTRIBUTE_RECORD_HEADER* att, const string_view& res_data, const u16string_view& name) -> bool {
        switch (att->TypeCode) {
            case ntfs_attribute::STANDARD_INFORMATION:
                if (att->FormCode == NTFS_ATTRIBUTE_FORM::NONRESIDENT_FORM)
                    throw formatted_error(FMT_STRING("Error - STANDARD_INFORMATION is non-resident")); // FIXME - can this happen?

                standard_info = res_data;
            break;

            case ntfs_attribute::DATA:
                if (name.empty()) { // main file data
                    if (att->Flags & ATTRIBUTE_FLAG_ENCRYPTED) {
                        clear_line();

                        if (filename.empty())
                            filename = f.get_filename();

                        fmt::print(stderr, FMT_STRING("Skipping encrypted inode {:x} ({})\n"), inode - inode_offset, filename);
                        return true;
                    }

                    if (att->FormCode == NTFS_ATTRIBUTE_FORM::RESIDENT_FORM && !processed_data) {
                        file_size = att->Form.Resident.ValueLength;

                        inline_data = res_data;
                    } else {
                        if (!processed_data) {
                            file_size = att->Form.Nonresident.FileSize;
                            compression_unit = att->Form.Nonresident.CompressionUnit;
                            vdl = att->Form.Nonresident.ValidDataLength;

                            if (!(att->Flags & ATTRIBUTE_FLAG_COMPRESSION_MASK))
                                compression_unit = 0;
                        }

                        if (compression_unit != 0) {
                            list<mapping> comp_mappings;
                            string compdata;
                            uint64_t cus = 1 << compression_unit;

                            read_nonresident_mappings(att, comp_mappings, cluster_size, vdl);

                            compdata.resize(cus * cluster_size);

                            try {
                                uint64_t vcn = att->Form.Nonresident.LowestVcn;

                                while (true) {
                                    uint64_t clusters = 0;

                                    while (clusters < cus) {
                                        if (comp_mappings.empty()) {
                                            memset(compdata.data() + (clusters * cluster_size), 0, (cus - clusters) * cluster_size);
                                            break;
                                        }

                                        auto& m = comp_mappings.front();
                                        auto l = min(m.length, cus - clusters);

                                        if (m.lcn == 0) {
                                            memset(compdata.data() + (clusters * cluster_size), 0, l * cluster_size);

                                            if (l < m.length) {
                                                m.vcn += l;
                                                m.length -= l;
                                            } else
                                                comp_mappings.pop_front();
                                        } else {
                                            dev.seek(m.lcn * cluster_size);
                                            dev.read(compdata.data() + (clusters * cluster_size), l * cluster_size);

                                            if (l < m.length) {
                                                m.lcn += l;
                                                m.vcn += l;
                                                m.length -= l;
                                            } else
                                                comp_mappings.pop_front();
                                        }

                                        clusters += l;
                                    }

                                    inline_data += lznt1_decompress(compdata, compdata.length());

                                    if (inline_data.length() >= file_size) {
                                        inline_data.resize(file_size);
                                        break;
                                    }

                                    vcn += cus;

                                    if (vcn >= att->Form.Nonresident.HighestVcn)
                                        break;
                                }
                            } catch (const exception& e) {
                                if (filename.empty())
                                    filename = f.get_filename();

                                throw formatted_error(FMT_STRING("{}: {}"), filename, e.what());
                            }
                        } else {
                            // FIXME - if ValidDataLength < FileSize, will need to zero end

                            read_nonresident_mappings(att, mappings, cluster_size, vdl);
                        }
                    }

                    processed_data = true;
                } else { // ADS
                    static const char xattr_prefix[] = "user.";

                    auto ads_name = convert.to_bytes(name.data(), name.data() + name.length());
                    auto max_xattr_size = (uint32_t)(tree_size - sizeof(tree_header) - sizeof(leaf_node) - offsetof(DIR_ITEM, name[0]) - ads_name.length() - (sizeof(xattr_prefix) - 1));

                    // FIXME - check xattr_name not reserved

                    if (att->Flags & ATTRIBUTE_FLAG_ENCRYPTED) {
                        clear_line();

                        if (filename.empty())
                            filename = f.get_filename();

                        fmt::print(stderr, FMT_STRING("Skipping encrypted ADS {}:{}\n"), filename, ads_name);

                        break;
                    }

                    if (att->Flags & ATTRIBUTE_FLAG_COMPRESSION_MASK) {
                        clear_line();

                        if (filename.empty())
                            filename = f.get_filename();

                        fmt::print(stderr, FMT_STRING("Skipping compressed ADS {}:{}\n"), filename, ads_name); // FIXME

                        break;
                    }

                    auto name2 = xattr_prefix + ads_name;

                    uint32_t hash = calc_crc32c(0xfffffffe, (const uint8_t*)name2.data(), (uint32_t)name2.length());

                    if (att->FormCode == NTFS_ATTRIBUTE_FORM::RESIDENT_FORM) {
                        if (ads_name == "WofCompressedData")
                            wof_compressed_data = res_data;
                        else {
                            if (att->Form.Resident.ValueLength > max_xattr_size) {
                                clear_line();

                                if (filename.empty())
                                    filename = f.get_filename();

                                fmt::print(stderr, FMT_STRING("Skipping overly large ADS {}:{} ({} > {})\n"), filename.c_str(), ads_name.c_str(), att->Form.Resident.ValueLength, max_xattr_size);

                                break;
                            }

                            xattrs.emplace(name2, make_pair(hash, res_data));
                        }
                    } else {
                        if (att->Form.Nonresident.FileSize > max_xattr_size && ads_name != "WofCompressedData") {
                            clear_line();

                            if (filename.empty())
                                filename = f.get_filename();

                            fmt::print(stderr, FMT_STRING("Skipping overly large ADS {}:{} ({} > {})\n"), filename.c_str(), ads_name.c_str(), att->Form.Nonresident.FileSize, max_xattr_size);

                            break;
                        }

                        list<mapping> ads_mappings;
                        string ads_data;

                        read_nonresident_mappings(att, ads_mappings, cluster_size, att->Form.Nonresident.ValidDataLength);

                        ads_data.resize(sector_align(att->Form.Nonresident.FileSize, cluster_size));
                        memset(ads_data.data(), 0, ads_data.length());

                        for (const auto& m : ads_mappings) {
                            dev.seek(m.lcn * cluster_size);
                            dev.read(ads_data.data() + (m.vcn * cluster_size), m.length * cluster_size);
                        }

                        ads_data.resize(att->Form.Nonresident.FileSize);

                        if (ads_name == "WofCompressedData")
                            wof_compressed_data = ads_data;
                        else
                            xattrs.emplace(name2, make_pair(hash, ads_data));
                    }
                }
            break;

            case ntfs_attribute::FILE_NAME: {
                if (att->FormCode == NTFS_ATTRIBUTE_FORM::NONRESIDENT_FORM)
                    throw formatted_error(FMT_STRING("Error - FILE_NAME is non-resident")); // FIXME - can this happen?

                if (att->Form.Resident.ValueLength < offsetof(FILE_NAME, FileName[0]))
                    throw formatted_error(FMT_STRING("FILE_NAME was truncated"));

                auto fn = reinterpret_cast<const FILE_NAME*>(res_data.data());

                if (fn->Namespace != FILE_NAME_DOS) {
                    if (att->Form.Resident.ValueLength < offsetof(FILE_NAME, FileName[0]) + (fn->FileNameLength * sizeof(char16_t)))
                        throw formatted_error(FMT_STRING("FILE_NAME was truncated"));

                    auto name2 = convert.to_bytes(fn->FileName, fn->FileName + fn->FileNameLength);

                    uint64_t parent = fn->Parent.SegmentNumber;

                    if (!is_dir || links.empty()) {
                        bool skip = false;

                        for (auto n : skiplist) {
                            if (n == parent) {
                                skip = true;
                                break;
                            }
                        }

                        if (!skip) {
                            for (const auto& l : links) {
                                if (get<0>(l) == parent && get<1>(l) == name2) {
                                    skip = true;
                                    break;
                                }
                            }
                        }

                        if (!skip)
                            links.emplace_back(parent, name2);
                    }
                }

                break;
            }

            case ntfs_attribute::SYMBOLIC_LINK:
                if (att->FormCode == NTFS_ATTRIBUTE_FORM::NONRESIDENT_FORM)
                    throw formatted_error(FMT_STRING("Error - SYMBOLIC_LINK is non-resident")); // FIXME - can this happen?

                reparse_point = res_data;
                symlink.clear();

                if (!is_dir && reparse_point.size() > offsetof(REPARSE_DATA_BUFFER, SymbolicLinkReparseBuffer.PathBuffer)) {
                    auto rpb = reinterpret_cast<const REPARSE_DATA_BUFFER*>(reparse_point.data());

                    if ((rpb->ReparseTag == IO_REPARSE_TAG_SYMLINK && rpb->SymbolicLinkReparseBuffer.Flags & SYMLINK_FLAG_RELATIVE) ||
                        rpb->ReparseTag == IO_REPARSE_TAG_LX_SYMLINK) {

                        if (reparse_point.size() < offsetof(REPARSE_DATA_BUFFER, SymbolicLinkReparseBuffer.PathBuffer) +
                                                   rpb->SymbolicLinkReparseBuffer.PrintNameOffset +
                                                   rpb->SymbolicLinkReparseBuffer.PrintNameLength) {
                            clear_line();

                            if (filename.empty())
                                filename = f.get_filename();

                            fmt::print(stderr, FMT_STRING("Reparse point buffer of {} was truncated."), filename);
                        } else {
                            symlink = convert.to_bytes(&rpb->SymbolicLinkReparseBuffer.PathBuffer[rpb->SymbolicLinkReparseBuffer.PrintNameOffset / sizeof(char16_t)],
                                                       &rpb->SymbolicLinkReparseBuffer.PathBuffer[(rpb->SymbolicLinkReparseBuffer.PrintNameOffset + rpb->SymbolicLinkReparseBuffer.PrintNameLength) / sizeof(char16_t)]);

                            for (auto& c : symlink) {
                                if (c == '\\')
                                    c = '/';
                            }

                            reparse_point = "";
                        }
                    }
                }
            break;

            default:
            break;
        }

        return true;
    });

    // skip page files
    if (links.size() == 1 && get<0>(links.front()) == NTFS_ROOT_DIR_INODE) {
        if (string_eq_ci(get<1>(links.front()), "pagefile.sys") || string_eq_ci(get<1>(links.front()), "hiberfil.sys") ||
            string_eq_ci(get<1>(links.front()), "swapfile.sys"))
            return;
    }

    if (links.empty())
        return; // don't create orphaned inodes

    memset(&ii, 0, sizeof(INODE_ITEM));

    if (standard_info.length() >= offsetof(STANDARD_INFORMATION, MaximumVersions)) {
        auto si = reinterpret_cast<const STANDARD_INFORMATION*>(standard_info.data());
        uint32_t defda = 0;

        atts = si->FileAttributes;

        if (links.size() == 1 && get<1>(links[0])[0] == '.')
            defda |= FILE_ATTRIBUTE_HIDDEN;

        if (is_dir) {
            defda |= FILE_ATTRIBUTE_DIRECTORY;
            atts |= FILE_ATTRIBUTE_DIRECTORY;
        } else {
            defda |= FILE_ATTRIBUTE_ARCHIVE;
            atts &= ~FILE_ATTRIBUTE_DIRECTORY;
        }

        if (!reparse_point.empty() || !symlink.empty())
            atts |= FILE_ATTRIBUTE_REPARSE_POINT;
        else
            atts &= ~FILE_ATTRIBUTE_REPARSE_POINT;

        if (atts != defda)
            atts_set = true;
    }

    if (standard_info.length() >= offsetof(STANDARD_INFORMATION, OwnerId)) {
        auto si = reinterpret_cast<const STANDARD_INFORMATION*>(standard_info.data());

        ii.otime = win_time_to_unix(si->CreationTime);
        ii.st_atime = win_time_to_unix(si->LastAccessTime);
        ii.st_mtime = win_time_to_unix(si->LastWriteTime);
        ii.st_ctime = win_time_to_unix(si->ChangeTime);
    }

    if (standard_info.length() >= offsetof(STANDARD_INFORMATION, QuotaCharged)) {
        auto si = reinterpret_cast<const STANDARD_INFORMATION*>(standard_info.data());

        sd = find_sd(si->SecurityId, secure, dev);

        if (sd.empty()) {
            clear_line();

            if (filename.empty())
                filename = f.get_filename();

            fmt::print(stderr, FMT_STRING("Could not find SecurityId {} ({})\n"), si->SecurityId, filename);
        }
    }

    if (reparse_point.length() > sizeof(uint32_t) && *(uint32_t*)reparse_point.data() == IO_REPARSE_TAG_WOF) {
        try {
            if (reparse_point.length() < offsetof(reparse_point_header, DataBuffer)) {
                throw formatted_error(FMT_STRING("IO_REPARSE_TAG_WOF reparse point buffer was {} bytes, expected at least {}."),
                                      reparse_point.length(), offsetof(reparse_point_header, DataBuffer));
            }

            auto rph = (reparse_point_header*)reparse_point.data();

            if (reparse_point.length() < offsetof(reparse_point_header, DataBuffer) + rph->ReparseDataLength) {
                throw formatted_error(FMT_STRING("IO_REPARSE_TAG_WOF reparse point buffer was {} bytes, expected {}."),
                                      reparse_point.length(), offsetof(reparse_point_header, DataBuffer) + rph->ReparseDataLength);
            }

            if (rph->ReparseDataLength < sizeof(WOF_EXTERNAL_INFO)) {
                throw formatted_error(FMT_STRING("rph->ReparseDataLength was {} bytes, expected at least {}."),
                                      rph->ReparseDataLength, sizeof(WOF_EXTERNAL_INFO));
            }

            auto wofei = (WOF_EXTERNAL_INFO*)rph->DataBuffer;

            if (wofei->Version != WOF_CURRENT_VERSION)
                throw formatted_error(FMT_STRING("Unsupported WOF version {}."), wofei->Version);

            if (wofei->Provider == WOF_PROVIDER_WIM)
                throw formatted_error(FMT_STRING("Unsupported WOF provider WOF_PROVIDER_WIM."));
            else if (wofei->Provider != WOF_PROVIDER_FILE)
                throw formatted_error(FMT_STRING("Unsupported WOF provider {}."), wofei->Provider);

            if (rph->ReparseDataLength < sizeof(WOF_EXTERNAL_INFO) + sizeof(FILE_PROVIDER_EXTERNAL_INFO_V0)) {
                throw formatted_error(FMT_STRING("rph->ReparseDataLength was {} bytes, expected {}."),
                                      rph->ReparseDataLength, sizeof(WOF_EXTERNAL_INFO) + sizeof(FILE_PROVIDER_EXTERNAL_INFO_V0));
            }

            auto fpei = *(FILE_PROVIDER_EXTERNAL_INFO_V0*)&wofei[1];

            if (fpei.Version != FILE_PROVIDER_CURRENT_VERSION) {
                throw formatted_error(FMT_STRING("rph->FILE_PROVIDER_EXTERNAL_INFO_V0 Version was {}, expected {}."),
                                      fpei.Version, FILE_PROVIDER_CURRENT_VERSION);
            }

            reparse_point.clear();

            switch (fpei.Algorithm) {
                case FILE_PROVIDER_COMPRESSION_XPRESS4K:
                    throw formatted_error(FMT_STRING("FIXME - FILE_PROVIDER_COMPRESSION_XPRESS4K WofCompressedData"));

                case FILE_PROVIDER_COMPRESSION_LZX:
                    mappings.clear();
                    inline_data = do_lzx_decompress(wof_compressed_data, file_size);
                    break;

                case FILE_PROVIDER_COMPRESSION_XPRESS8K:
                    throw formatted_error(FMT_STRING("FIXME - FILE_PROVIDER_COMPRESSION_XPRESS8K WofCompressedData"));

                case FILE_PROVIDER_COMPRESSION_XPRESS16K:
                    throw formatted_error(FMT_STRING("FIXME - FILE_PROVIDER_COMPRESSION_XPRESS16K WofCompressedData"));

                default:
                    throw formatted_error(FMT_STRING("Unrecognized WOF compression algorithm {}"), fpei.Algorithm);
            }
        } catch (const exception& e) {
            if (filename.empty())
                filename = f.get_filename();

            fmt::print(stderr, FMT_STRING("{}: {}\n"), filename, e.what());
        }
    }

    ii.generation = 1;
    ii.transid = 1;

    if (!is_dir && !reparse_point.empty()) {
        inline_data = reparse_point;
        file_size = reparse_point.size();
    } else if (!symlink.empty()) {
        mappings.clear();
        inline_data = symlink;
        file_size = symlink.size();
    }

    if (!is_dir)
        ii.st_size = file_size;

    ii.st_nlink = (uint32_t)links.size();

    if (is_dir)
        ii.st_mode = __S_IFDIR | S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;
    else
        ii.st_mode = __S_IFREG | S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;

    if (!symlink.empty())
        ii.st_mode |= __S_IFLNK;

    ii.sequence = 1;

    // FIXME - xattrs (EAs, etc.)
    // FIXME - LXSS

    if (!mappings.empty()) {
        size_t extlen = offsetof(EXTENT_DATA, data[0]) + sizeof(EXTENT_DATA2);
        auto ed = (EXTENT_DATA*)malloc(extlen);
        if (!ed)
            throw bad_alloc();

        auto ed2 = (EXTENT_DATA2*)&ed->data;

        ed->generation = 1;
        ed->compression = 0;
        ed->encryption = 0;
        ed->encoding = 0;
        ed->type = EXTENT_TYPE_REGULAR;

        try {
            process_mappings(dev, inode, mappings, runs);

            for (const auto& m : mappings) {
                if (m.lcn != 0) { // not sparse
                    ed->decoded_size = ed2->size = ed2->num_bytes = m.length * dev.boot_sector->BytesPerSector * dev.boot_sector->SectorsPerCluster;
                    ii.st_blocks += ed->decoded_size;

                    ed2->address = (m.lcn * dev.boot_sector->BytesPerSector * dev.boot_sector->SectorsPerCluster) + chunk_virt_offset;
                    ed2->offset = 0;

                    add_item(r, inode, TYPE_EXTENT_DATA, m.vcn * dev.boot_sector->BytesPerSector * dev.boot_sector->SectorsPerCluster, ed, (uint16_t)extlen);
                }
            }
        } catch (...) {
            free(ed);
            throw;
        }

        free(ed);
    } else if (!inline_data.empty()) {
        if (inline_data.length() > max_inline) {
            size_t extlen = offsetof(EXTENT_DATA, data[0]) + sizeof(EXTENT_DATA2);
            auto ed = (EXTENT_DATA*)malloc(extlen);
            if (!ed)
                throw bad_alloc();

            auto ed2 = (EXTENT_DATA2*)&ed->data;

            ed->generation = 1;
            ed->compression = 0; // FIXME - recompress?
            ed->encryption = 0;
            ed->encoding = 0;
            ed->type = EXTENT_TYPE_REGULAR;

            // round to nearest sector, and zero end

            if (inline_data.length() & (sector_size - 1)) {
                auto oldlen = inline_data.length();

                inline_data.resize(sector_align(inline_data.length(), sector_size));
                memset(inline_data.data() + oldlen, 0, inline_data.length() - oldlen);
            }

            try {
                uint64_t pos = 0;

                while (!inline_data.empty()) {
                    uint64_t len, lcn, cl;
                    bool inserted = false;

                    if (inline_data.length() >= max_extent_size)
                        len = max_extent_size;
                    else
                        len = inline_data.length();

                    ed->decoded_size = ed2->size = ed2->num_bytes = len;
                    ii.st_blocks += ed->decoded_size;

                    ed2->address = allocate_data(len);
                    ed2->offset = 0;

                    dev.seek(ed2->address - chunk_virt_offset);
                    dev.write(inline_data.data(), len);

                    add_item(r, inode, TYPE_EXTENT_DATA, pos, ed, (uint16_t)extlen);

                    lcn = (ed2->address - chunk_virt_offset) / cluster_size;
                    cl = len / cluster_size;

                    for (auto it = runs.begin(); it != runs.end(); it++) {
                        auto& r = *it;

                        if (r.offset > lcn + cl) {
                            runs.emplace(it, lcn, cl, inode, pos, false, true);
                            inserted = true;
                            break;
                        }
                    }

                    if (!inserted)
                        runs.emplace_back(lcn, cl, inode, pos, false, true);

                    if (inline_data.length() > len) {
                        pos += len;
                        inline_data = inline_data.substr(len);
                    } else
                        break;
                }
            } catch (...) {
                free(ed);
                throw;
            }

            free(ed);
        } else {
            size_t extlen = offsetof(EXTENT_DATA, data[0]) + inline_data.length();
            auto ed = (EXTENT_DATA*)malloc(extlen);
            if (!ed)
                throw bad_alloc();

            ed->generation = 1;
            ed->decoded_size = inline_data.length();
            ed->compression = 0;
            ed->encryption = 0;
            ed->encoding = 0;
            ed->type = EXTENT_TYPE_INLINE;

            memcpy(ed->data, inline_data.data(), inline_data.length());

            add_item(r, inode, TYPE_EXTENT_DATA, 0, ed, (uint16_t)extlen);

            free(ed);

            ii.st_blocks = inline_data.length();
        }
    }

    add_item(r, inode, TYPE_INODE_ITEM, 0, &ii, sizeof(INODE_ITEM));

    {
        uint8_t type;

        if (is_dir)
            type = BTRFS_TYPE_DIRECTORY;
        else if (!symlink.empty())
            type = BTRFS_TYPE_SYMLINK;
        else
            type = BTRFS_TYPE_FILE;

        for (const auto& l : links) {
            if (get<0>(l) == NTFS_ROOT_DIR_INODE)
                link_inode(r, inode, SUBVOL_ROOT_INODE, get<1>(l), type);
            else
                link_inode(r, inode, get<0>(l) + inode_offset, get<1>(l), type);
        }
    }

    if (!sd.empty()) {
        // FIXME - omit SD if only one hard link and implied from parent?
        xattrs.emplace(EA_NTACL, make_pair(EA_NTACL_HASH, sd));
    }

    if (atts_set) {
        char val[16], *val2;

        val2 = &val[sizeof(val) - 1];

        do {
            uint8_t c = atts % 16;
            *val2 = (char)(c <= 9 ? (c + '0') : (c - 0xa + 'a'));

            val2--;
            atts >>= 4;
        } while (atts != 0);

        *val2 = 'x';
        val2--;
        *val2 = '0';

        xattrs.emplace(EA_DOSATTRIB, make_pair(EA_DOSATTRIB_HASH, string_view(val2, val + sizeof(val) - val2)));
    }

    if (!reparse_point.empty() && is_dir)
        xattrs.emplace(EA_REPARSE, make_pair(EA_REPARSE_HASH, reparse_point));

    for (const auto& xa : xattrs) {
        // FIXME - collisions (make hash key of map?)
        set_xattr(r, inode, xa.first, get<0>(xa.second), get<1>(xa.second));
    }
}

static void create_inodes(root& r, const string& mftbmp, ntfs& dev, list<data_alloc>& runs, ntfs_file& secure) {
    list<space> inodes;
    list<uint64_t> skiplist;
    uint64_t total = 0, num = 0;

    r.dir_seqs[SUBVOL_ROOT_INODE] = 3;

    parse_bitmap(mftbmp, inodes);

    for (const auto& l : inodes) {
        total += l.length;
    }

    while (!inodes.empty()) {
        auto& run = inodes.front();
        uint64_t ntfs_inode = run.offset;
        uint64_t inode = ntfs_inode + inode_offset;
        bool dir;

        try {
            if (ntfs_inode >= first_ntfs_inode)
                add_inode(r, inode, ntfs_inode, dir, runs, secure, dev, skiplist);
            else if (ntfs_inode != NTFS_ROOT_DIR_INODE)
                populate_skip_list(dev, ntfs_inode, skiplist);
        } catch (...) {
            clear_line();
            throw;
        }

        num++;
        fmt::print(FMT_STRING("Processing inode {} / {} ({:1.1f}%)\r"), num, total, (float)num * 100.0f / (float)total);
        fflush(stdout);

        if (run.length == 1)
            inodes.pop_front();
        else {
            run.offset++;
            run.length--;
        }
    }

    fmt::print(FMT_STRING("\n"));
}

static void create_data_extent_items(root& extent_root, const list<data_alloc>& runs, uint32_t cluster_size, uint64_t image_subvol_id,
                                     uint64_t image_inode) {
    for (const auto& r : runs) {
        uint64_t img_addr;

        if (r.inode == dummy_inode)
            continue;

        if (r.relocated) {
            for (const auto& reloc : relocs) {
                if (reloc.new_start == r.offset) {
                    img_addr = reloc.old_start * cluster_size;
                    break;
                }
            }
        } else
            img_addr = r.offset * cluster_size;

        if (r.inode == 0) {
            data_item di;

            di.extent_item.refcount = 1;
            di.extent_item.generation = 1;
            di.extent_item.flags = EXTENT_ITEM_DATA;
            di.type = TYPE_EXTENT_DATA_REF;
            di.edr.root = image_subvol_id;
            di.edr.objid = image_inode;
            di.edr.count = 1;
            di.edr.offset = img_addr;

            add_item(extent_root, (r.offset * cluster_size) + chunk_virt_offset, TYPE_EXTENT_ITEM, r.length * cluster_size,
                     &di, sizeof(data_item));
        } else if (r.not_in_img) {
            data_item di;

            di.extent_item.refcount = 1;
            di.extent_item.generation = 1;
            di.extent_item.flags = EXTENT_ITEM_DATA;
            di.type = TYPE_EXTENT_DATA_REF;
            di.edr.root = BTRFS_ROOT_FSTREE;
            di.edr.objid = r.inode;
            di.edr.count = 1;
            di.edr.offset = r.file_offset * cluster_size;

            add_item(extent_root, (r.offset * cluster_size) + chunk_virt_offset, TYPE_EXTENT_ITEM, r.length * cluster_size,
                     &di, sizeof(data_item));
        } else {
            data_item2 di2;

            di2.extent_item.refcount = 2;
            di2.extent_item.generation = 1;
            di2.extent_item.flags = EXTENT_ITEM_DATA;
            di2.type1 = TYPE_EXTENT_DATA_REF;
            di2.edr1.root = image_subvol_id;
            di2.edr1.objid = image_inode;
            di2.edr1.count = 1;
            di2.edr1.offset = img_addr;
            di2.type2 = TYPE_EXTENT_DATA_REF;
            di2.edr2.root = BTRFS_ROOT_FSTREE;
            di2.edr2.objid = r.inode;
            di2.edr2.count = 1;
            di2.edr2.offset = r.file_offset * cluster_size;

            add_item(extent_root, (r.offset * cluster_size) + chunk_virt_offset, TYPE_EXTENT_ITEM, r.length * cluster_size,
                     &di2, sizeof(data_item2));
        }
    }
}

static void calc_checksums(root& csum_root, list<data_alloc> runs, ntfs& dev) {
    uint32_t sector_size = 0x1000; // FIXME
    uint32_t cluster_size = dev.boot_sector->BytesPerSector * dev.boot_sector->SectorsPerCluster;
    list<space> runs2;
    uint64_t total = 0, num = 0;

    auto max_run = (uint32_t)((tree_size - sizeof(tree_header) - sizeof(leaf_node)) / sizeof(uint32_t));

    // FIXME - these are clusters, when they should be sectors

    // split and merge runs
    // FIXME - do we need to force a break at a chunk boundary?

    while (!runs.empty()) {
        auto& r = runs.front();

        if (r.inode == dummy_inode) {
            runs.pop_front();
            continue;
        }

        if (runs2.empty() || runs2.back().offset + runs2.back().length < r.offset || runs2.back().length == max_run) {
            // create new run

            if (r.length > max_run) {
                runs2.emplace_back(r.offset, max_run);
                r.offset += max_run;
                r.length -= max_run;
            } else {
                runs2.emplace_back(r.offset, r.length);
                runs.pop_front();
            }

            continue;
        }

        // continue existing run

        if (runs2.back().length + r.length <= max_run) {
            runs2.back().length += r.length;
            runs.pop_front();
            continue;
        }

        r.offset += max_run - runs2.back().length;
        r.length -= max_run - runs2.back().length;
        runs2.back().length = max_run;
    }

    for (const auto& r : runs2) {
        total += r.length;
    }

    for (const auto& r : runs2) {
        string data;
        vector<uint32_t> csums;

        if (r.offset * cluster_size >= orig_device_size)
            break;

        data.resize(r.length * cluster_size);
        csums.resize(r.length * cluster_size / sector_size);

        dev.seek(r.offset * cluster_size);
        dev.read(data.data(), data.length());

        string_view sv = data;
        uint32_t* csum = &csums[0];

        while (sv.length() > 0) {
            *csum = ~calc_crc32c(0xffffffff, (const uint8_t*)sv.data(), sector_size);

            csum++;
            sv = sv.substr(sector_size);

            num++;

            if (num % 1000 == 0 || num == total) {
                fmt::print(FMT_STRING("Calculating checksums {} / {} ({:1.1f}%)\r"), num, total, (float)num * 100.0f / (float)total);
                fflush(stdout);
            }
        }

        add_item(csum_root, EXTENT_CSUM_ID, TYPE_EXTENT_CSUM, (r.offset * cluster_size) + chunk_virt_offset, &csums[0], (uint16_t)(r.length * cluster_size * sizeof(uint32_t) / sector_size));
    }

    fmt::print(FMT_STRING("\n"));
}

static void protect_data(ntfs& dev, list<data_alloc>& runs, uint64_t cluster_start, uint64_t cluster_end) {
    if (split_runs(runs, cluster_start, cluster_end - cluster_start, dummy_inode, 0)) {
        string sb;
        uint32_t cluster_size = dev.boot_sector->BytesPerSector * dev.boot_sector->SectorsPerCluster;
        uint64_t addr = allocate_data((cluster_end - cluster_start) * cluster_size) - chunk_virt_offset;

        if (cluster_end * cluster_size > orig_device_size)
            sb.resize(orig_device_size - (cluster_start * cluster_size));
        else
            sb.resize((cluster_end - cluster_start) * cluster_size);

        dev.seek(cluster_start * cluster_size);
        dev.read(sb.data(), sb.length());

        dev.seek(addr);
        dev.write(sb.data(), sb.length());

        relocs.emplace_back(cluster_start, cluster_end - cluster_start, addr / cluster_size);

        for (auto it = runs.begin(); it != runs.end(); it++) {
            if (it->offset > addr / cluster_size) {
                runs.emplace(it, addr / cluster_size, cluster_end - cluster_start, 0, 0, true);
                return;
            }
        }

        runs.emplace_back(addr / cluster_size, cluster_end - cluster_start, 0, 0, true);
    }
}

static void protect_superblocks(ntfs& dev, list<data_alloc>& runs) {
    uint32_t cluster_size = dev.boot_sector->BytesPerSector * dev.boot_sector->SectorsPerCluster;

    unsigned int i = 0;
    while (superblock_addrs[i] != 0) {
        if (superblock_addrs[i] > device_size - sizeof(superblock))
            break;

        uint64_t cluster_start = (superblock_addrs[i] - (superblock_addrs[i] % stripe_length)) / cluster_size;
        uint64_t cluster_end = sector_align(superblock_addrs[i] - (superblock_addrs[i] % stripe_length) + stripe_length, cluster_size) / cluster_size;

        protect_data(dev, runs, cluster_start, cluster_end);

        i++;
    }

    // also relocate first cluster

    protect_data(dev, runs, 0, 1);

    if (reloc_last_sector)
        protect_data(dev, runs, device_size / cluster_size, (device_size / cluster_size) + 1);
}

static void clear_first_cluster(ntfs& dev) {
    uint32_t cluster_size = dev.boot_sector->BytesPerSector * dev.boot_sector->SectorsPerCluster;
    string data;

    data.resize(cluster_size);

    memset(data.data(), 0, cluster_size);

    dev.seek(0);
    dev.write(data.data(), data.length());
}

static void calc_used_space(list<data_alloc>& runs, uint32_t cluster_size) {
    list<data_alloc> runs2;
    uint64_t clusters_per_chunk = data_chunk_size / cluster_size;

    // split runs on chunk boundaries

    for (const auto& r : runs) {
        uint64_t chunk_start = r.offset / clusters_per_chunk;
        uint64_t chunk_end = ((r.offset + r.length) - 1) / clusters_per_chunk;

        if (chunk_end > chunk_start) {
            uint64_t start = r.offset;

            do {
                uint64_t end = min((((start / clusters_per_chunk) + 1) * clusters_per_chunk), r.offset + r.length);

                if (end == start)
                    break;

                runs2.emplace_back(start, end - start, r.inode, r.file_offset + ((start - r.offset) * cluster_size), r.relocated);

                start = end;
            } while (true);
        } else
            runs2.emplace_back(r.offset, r.length, r.inode, r.file_offset, r.relocated);
    }

    runs.clear();
    runs.splice(runs.begin(), runs2);

    chunk* c = nullptr;

    for (const auto& r : runs) {
        if (!c || ((r.offset - (r.offset % clusters_per_chunk)) * cluster_size) + chunk_virt_offset != c->offset) {
            uint64_t off = (r.offset - (r.offset % clusters_per_chunk)) * cluster_size;

            c = nullptr;

            for (auto& c2 : chunks) {
                if (c2.offset == off + chunk_virt_offset) {
                    c = &c2;
                    break;
                }
            }

            if (!c)
                throw formatted_error(FMT_STRING("Could not find chunk.")); // FIXME - include address
        }

        c->used += r.length * cluster_size;
    }
}

static void populate_root_root(root& root_root) {
    INODE_ITEM ii;

    static const char default_subvol[] = "default";
    static const uint32_t default_hash = 0x8dbfc2d2;

    for (const auto& r : roots) {
        if (r.id != BTRFS_ROOT_ROOT && r.id != BTRFS_ROOT_CHUNK)
            add_to_root_root(r, root_root);
    }

    add_inode_ref(root_root, BTRFS_ROOT_FSTREE, BTRFS_ROOT_TREEDIR, 0, "default");

    memset(&ii, 0, sizeof(INODE_ITEM));

    ii.generation = 1;
    ii.transid = 1;
    ii.st_nlink = 1;
    ii.st_mode = __S_IFDIR | S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;

    add_item(root_root, BTRFS_ROOT_TREEDIR, TYPE_INODE_ITEM, 0, &ii, sizeof(INODE_ITEM));

    add_inode_ref(root_root, BTRFS_ROOT_TREEDIR, BTRFS_ROOT_TREEDIR, 0, "..");

    {
        size_t dilen = offsetof(DIR_ITEM, name[0]) + sizeof(default_subvol) - 1;
        auto di = (DIR_ITEM*)malloc(dilen);
        if (!di)
            throw bad_alloc();

        try {
            di->key.obj_id = BTRFS_ROOT_FSTREE;
            di->key.obj_type = TYPE_ROOT_ITEM;
            di->key.offset = 0xffffffffffffffff;
            di->transid = 0;
            di->m = 0;
            di->n = sizeof(default_subvol) - 1;
            di->type = BTRFS_TYPE_DIRECTORY;
            memcpy(di->name, default_subvol, sizeof(default_subvol) - 1);

            add_item(root_root, BTRFS_ROOT_TREEDIR, TYPE_DIR_ITEM, default_hash, di, (uint16_t)dilen);
        } catch (...) {
            free(di);
            throw;
        }

        free(di);
    }
}

static void add_subvol_uuid(root& r) {
    add_item(r, *(uint64_t*)&subvol_uuid, TYPE_SUBVOL_UUID, *(uint64_t*)&subvol_uuid.uuid[sizeof(uint64_t)],
             &image_subvol_id, sizeof(image_subvol_id));
}

static void update_dir_sizes(root& r) {
    for (auto& it : r.items) {
        if (it.first.obj_type == TYPE_INODE_ITEM && r.dir_size.count(it.first.obj_id) != 0) {
            auto ii = (INODE_ITEM*)it.second.data;

            // FIXME - would it speed things up if we removed the entry from dir_size map here?

            ii->st_size = r.dir_size.at(it.first.obj_id);
        }
    }
}

static void convert(ntfs& dev) {
    uint32_t sector_size = 0x1000; // FIXME
    uint64_t cluster_size = (uint64_t)dev.boot_sector->BytesPerSector * (uint64_t)dev.boot_sector->SectorsPerCluster;
    list<data_alloc> runs;

    static const uint64_t image_inode = 0x101;

    // FIXME - die if cluster size not multiple of 4096

    {
        default_random_engine generator;

        generator.seed((unsigned int)chrono::high_resolution_clock::now().time_since_epoch().count());

        fs_uuid = generate_uuid(generator);
        chunk_uuid = generate_uuid(generator);
        dev_uuid = generate_uuid(generator);
        subvol_uuid = generate_uuid(generator);
    }

    device_size = orig_device_size = dev.boot_sector->TotalSectors * dev.boot_sector->BytesPerSector;

    if (device_size % sector_size != 0) {
        device_size -= device_size % sector_size;
        reloc_last_sector = true;
    }

    space_list.emplace_back(0, device_size);

    ntfs_file bitmap(dev, NTFS_BITMAP_INODE);

    auto bmpdata = bitmap.read();

    create_data_chunks(dev, bmpdata);

    roots.emplace_back(BTRFS_ROOT_ROOT);
    root& root_root = roots.back();

    roots.emplace_back(BTRFS_ROOT_EXTENT);
    root& extent_root = roots.back();

    roots.emplace_back(BTRFS_ROOT_CHUNK);
    root& chunk_root = roots.back();

    add_dev_item(chunk_root);

    roots.emplace_back(BTRFS_ROOT_DEVTREE);
    root& devtree_root = roots.back();

    add_dev_stats(devtree_root);

    roots.emplace_back(BTRFS_ROOT_FSTREE);
    root& fstree_root = roots.back();

    populate_fstree(fstree_root);

    roots.emplace_back(BTRFS_ROOT_DATA_RELOC);
    populate_fstree(roots.back());

    roots.emplace_back(BTRFS_ROOT_CHECKSUM);
    root& csum_root = roots.back();

    root& image_subvol = add_image_subvol(root_root, fstree_root);

    parse_bitmap(bmpdata, runs);

    // make sure runs don't go beyond end of device

    while (!runs.empty() && (runs.back().offset * cluster_size) + runs.back().length > device_size) {
        if (runs.back().offset * cluster_size >= orig_device_size)
            runs.pop_back();
        else {
            uint64_t len = orig_device_size - (runs.back().offset * cluster_size);

            if (len % cluster_size)
                runs.back().length = (len / cluster_size) + 1;
            else
                runs.back().length = len / cluster_size;

            break;
        }
    }

    protect_superblocks(dev, runs);

    calc_used_space(runs, dev.boot_sector->BytesPerSector * dev.boot_sector->SectorsPerCluster);

    auto mftbmp = dev.mft->read(0, 0, ntfs_attribute::BITMAP);

    {
        ntfs_file secure(dev, NTFS_SECURE_INODE);

        create_inodes(fstree_root, mftbmp, dev, runs, secure);
    }

    create_image(image_subvol, dev, runs, image_inode);

    roots.emplace_back(BTRFS_ROOT_UUID);
    add_subvol_uuid(roots.back());

    create_data_extent_items(extent_root, runs, dev.boot_sector->BytesPerSector * dev.boot_sector->SectorsPerCluster,
                             image_subvol.id, image_inode);

    fmt::print(FMT_STRING("Updating directory sizes\n"));

    for (auto& r : roots) {
        if (!r.dir_size.empty())
            update_dir_sizes(r);
    }

    calc_checksums(csum_root, runs, dev);

    populate_root_root(root_root);

    for (auto& r : roots) {
        if (r.id != BTRFS_ROOT_EXTENT && r.id != BTRFS_ROOT_CHUNK && r.id != BTRFS_ROOT_DEVTREE)
            r.create_trees(extent_root);
    }

    do {
        bool extents_changed = false;

        chunks_changed = false;

        for (auto& c : chunks) {
            if (!c.added) {
                add_chunk(chunk_root, devtree_root, extent_root, c);
                c.added = true;
            }
        }

        for (auto& r : roots) {
            if (r.id == BTRFS_ROOT_EXTENT || r.id == BTRFS_ROOT_CHUNK || r.id == BTRFS_ROOT_DEVTREE) {
                r.old_addresses = r.addresses;
                r.addresses.clear();

                // FIXME - unallocate metadata and changed used value in chunks
                r.metadata_size -= r.trees.size() * tree_size;
                r.trees.clear();

                r.allocations_done = false;
                r.create_trees(extent_root);

                if (r.allocations_done)
                    extents_changed = true;
            }
        }

        if (!chunks_changed && !extents_changed)
            break;
    } while (true);

    // update tree addresses and levels in-place in root 1
    update_root_root(root_root);

    // update used value in BLOCK_GROUP_ITEMs
    update_extent_root(extent_root);

    // update bytes_used in DEV_ITEM in root 3
    update_chunk_root(chunk_root);

    for (auto& r : roots) {
        r.write_trees(dev);
    }

    write_superblocks(dev, chunk_root, root_root);

    clear_first_cluster(dev);
}

#if defined(__i386__) || defined(__x86_64__)
static void check_cpu() {
#ifndef _MSC_VER
    unsigned int cpuInfo[4];

    __get_cpuid(1, &cpuInfo[0], &cpuInfo[1], &cpuInfo[2], &cpuInfo[3]);

    if (cpuInfo[2] & bit_SSE4_2)
        calc_crc32c = calc_crc32c_hw;
#else
    int cpuInfo[4];

    __cpuid(cpuInfo, 1);

    if (cpuInfo[2] & (1 << 20))
        calc_crc32c = calc_crc32c_hw;
#endif
}
#endif

int main(int argc, char* argv[]) {
#if defined(__i386__) || defined(__x86_64__)
    check_cpu();
#endif

    try {
        if (argc < 2 || (argc == 2 && (!strcmp(argv[1], "--help") || !strcmp(argv[1], "/?")))) {
            fmt::print(FMT_STRING("Usage: ntfs2btrfs device\n"));
            return 1;
        }

        if (argc == 2 && !strcmp(argv[1], "--version")) {
            fmt::print(FMT_STRING("ntfs2btrfs " PROJECT_VER "\n"));
            return 1;
        }

        string fn = argv[1];

        ntfs dev(fn);

        convert(dev);
    } catch (const exception& e) {
        cerr << e.what() << endl;
        return 1;
    }

    return 0;
}
