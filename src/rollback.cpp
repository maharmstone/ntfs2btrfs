#include "ntfs2btrfs.h"
#include <iostream>
#include <functional>

using namespace std;

using chunks_t = map<uint64_t, vector<uint8_t>>;

#define INCOMPAT_SUPPORTED (BTRFS_INCOMPAT_FLAGS_MIXED_BACKREF | BTRFS_INCOMPAT_FLAGS_DEFAULT_SUBVOL | BTRFS_INCOMPAT_FLAGS_MIXED_GROUPS | \
                            BTRFS_INCOMPAT_FLAGS_COMPRESS_LZO | BTRFS_INCOMPAT_FLAGS_BIG_METADATA | BTRFS_INCOMPAT_FLAGS_RAID56 | \
                            BTRFS_INCOMPAT_FLAGS_EXTENDED_IREF | BTRFS_INCOMPAT_FLAGS_SKINNY_METADATA | BTRFS_INCOMPAT_FLAGS_NO_HOLES | \
                            BTRFS_INCOMPAT_FLAGS_COMPRESS_ZSTD | BTRFS_INCOMPAT_FLAGS_METADATA_UUID | BTRFS_INCOMPAT_FLAGS_RAID1C34)

class btrfs {
public:
    btrfs(const string& fn);
    uint64_t find_root_addr(uint64_t root);

private:
    superblock read_superblock();
    void read_chunks();
    vector<uint8_t> read(uint64_t addr, uint32_t len);
    void walk_tree(uint64_t addr, const function<bool(const KEY&, const string_view&)>& func);
    pair<uint64_t, vector<uint8_t>> find_chunk(uint64_t addr);

    fstream f;
    superblock sb;
    chunks_t chunks;
};


btrfs::btrfs(const string& fn) {
    // FIXME - CreateFile on Windows
    f = fstream(fn, ios_base::in | ios_base::out | ios::binary);

    if (!f.good())
        throw formatted_error("Failed to open {}.", fn);

    sb = read_superblock();

    read_chunks();
}

superblock btrfs::read_superblock() {
    optional<superblock> sb;

    // find length of volume
    // FIXME - Windows version
    f.ignore(numeric_limits<streamsize>::max());
    uint64_t device_size = f.gcount();
    f.clear();

    unsigned int i = 0;
    while (superblock_addrs[i] != 0 && superblock_addrs[i] + sizeof(superblock) < device_size) {
        superblock sb2;

        f.seekg(superblock_addrs[i], ios_base::beg);

        f.read((char*)&sb2, sizeof(superblock));

        if (f.fail())
            throw formatted_error("Error reading superblock at {:x}.", superblock_addrs[i]);

        if (sb2.magic != BTRFS_MAGIC) {
            i++;
            continue;
        }

        // FIXME - check checksum

        if (!sb.has_value() || sb2.generation > sb.value().generation)
            sb = sb2;

        i++;
    }

    if (!sb.has_value())
        throw runtime_error("Not a Btrfs volume.");

    if (sb.value().incompat_flags & ~INCOMPAT_SUPPORTED)
        throw formatted_error("Unsupported incompat flags {:x}.", sb.value().incompat_flags & ~INCOMPAT_SUPPORTED);

    return sb.value();
}

pair<uint64_t, vector<uint8_t>> btrfs::find_chunk(uint64_t addr) {
    for (const auto& c : chunks) {
        if (addr < c.first)
            continue;

        const auto& ci = *(CHUNK_ITEM*)c.second.data();

        if (addr < c.first + ci.size)
            return c;
    }

    throw formatted_error("Could not find chunk for virtual address {:x}.", addr);
}

vector<uint8_t> btrfs::read(uint64_t addr, uint32_t len) {
    const auto& cp = find_chunk(addr);
    const auto& c = *(CHUNK_ITEM*)cp.second.data();

    if (c.type & BLOCK_FLAG_RAID0)
        throw runtime_error("FIXME - RAID 0");
    else if (c.type & BLOCK_FLAG_RAID1)
        throw runtime_error("FIXME - RAID 1");
    else if (c.type & BLOCK_FLAG_RAID1)
        throw runtime_error("FIXME - DUPLICATE");
    else if (c.type & BLOCK_FLAG_RAID10)
        throw runtime_error("FIXME - RAID10");
    else if (c.type & BLOCK_FLAG_RAID5)
        throw runtime_error("FIXME - RAID5");
    else if (c.type & BLOCK_FLAG_RAID6)
        throw runtime_error("FIXME - RAID6");
    else if (c.type & BLOCK_FLAG_RAID1C3)
        throw runtime_error("FIXME - RAID1C3");
    else if (c.type & BLOCK_FLAG_RAID1C4)
        throw runtime_error("FIXME - RAID1C4");

    // SINGLE

    if (c.num_stripes == 0)
        throw runtime_error("CHUNK_ITEM had num_stripes == 0");

    auto* cis = (CHUNK_ITEM_STRIPE*)(&c + 1);

    if (cis[0].dev_id != sb.dev_item.dev_id)
        throw runtime_error("Reading from other device not implemented.");

    uint64_t off = addr - cp.first + cis[0].offset;

    // FIXME - ReadFile on Windows

    f.seekg(off);

    if (f.fail())
        throw formatted_error("Error seeking to {:x}.", off);

    vector<uint8_t> ret;
    ret.resize(len);

    f.read((char*)ret.data(), ret.size());

    if (f.fail())
        throw formatted_error("Error reading {:x} bytes at {:x}.", ret.size(), off);

    return ret;
}

void btrfs::walk_tree(uint64_t addr, const function<bool(const KEY&, const string_view&)>& func) {
    auto tree = read(addr, sb.node_size);

    // FIXME - check checksum

    auto& th = *(tree_header*)tree.data();

    // FIXME - if root is not 0, recurse
    if (th.level != 0)
        throw runtime_error("FIXME - th.level != 0");

    auto nodes = (leaf_node*)(&th + 1);

    for (unsigned int i = 0; i < th.num_items; i++) {
        const auto& n = nodes[i];
        bool b;

        if (n.size == 0)
            b = func(n.key, {});
        else
            b = func(n.key, { (char*)&th + sizeof(tree_header) + n.offset, n.size });

        if (!b)
            break;
    }
}

void btrfs::read_chunks() {
    auto ptr = (uint8_t*)&sb.sys_chunk_array;

    do {
        auto& key = *(KEY*)ptr;

        if (key.obj_type != TYPE_CHUNK_ITEM)
            break;

        auto& ci = *(CHUNK_ITEM*)(ptr + sizeof(key));

        basic_string_view<uint8_t> chunk_item{ptr + sizeof(key), sizeof(ci) + (ci.num_stripes * sizeof(CHUNK_ITEM_STRIPE))};

        chunks.emplace(key.offset, vector<uint8_t>{chunk_item.data(), chunk_item.data() + chunk_item.size()});

        ptr += sizeof(key) + chunk_item.size();
    } while (ptr < &sb.sys_chunk_array[SYS_CHUNK_ARRAY_SIZE]);

#if 0
    for (const auto& c : chunks) {
        fmt::print("{:x}\n", c.first);

        const auto& ci = *(CHUNK_ITEM*)c.second.data();

        fmt::print("  size {:x}, root_id {:x}, stripe_length {:x}, type {:x}, opt_io_alignment {:x}, opt_io_width {:x}, sector_size {:x}, num_stripes {:x}, sub_stripes {:x}\n",
                   ci.size, ci.root_id, ci.stripe_length, ci.type, ci.opt_io_alignment, ci.opt_io_width, ci.sector_size, ci.num_stripes, ci.sub_stripes);

        auto* cis = (CHUNK_ITEM_STRIPE*)(&ci + 1);

        for (unsigned int i = 0; i < ci.num_stripes; i++) {
            fmt::print("  dev_id {:x}, offset {:x}\n", cis[i].dev_id, cis[i].offset);
        }
    }
#endif

    chunks_t chunks2;

    walk_tree(sb.chunk_tree_addr, [&](const KEY& key, const string_view& data) {
        if (key.obj_type != TYPE_CHUNK_ITEM)
            return true;

        chunks2.emplace(key.offset, vector<uint8_t>{data.data(), data.data() + data.size()});

        return true;
    });

    chunks.swap(chunks2);
}

uint64_t btrfs::find_root_addr(uint64_t root) {
    optional<uint64_t> ret;

    walk_tree(sb.root_tree_addr, [&](const KEY& key, const string_view& data) {
        if (key.obj_id != root || key.obj_type != TYPE_ROOT_ITEM)
            return true;

        const auto& ri = *(ROOT_ITEM*)data.data();

        ret = ri.block_number;

        return false;
    });

    if (!ret.has_value())
        throw formatted_error("Could not find address for root {:x}.", root);

    return ret.value();
}

void rollback(const string& fn) {
    btrfs b(fn);

    auto img_root_addr = b.find_root_addr(image_subvol_id);

    // FIXME - find file called ntfs.img
    // FIXME - parse extent items
    // FIXME - resolve logical addresses to physical
    // FIXME - remove identity maps
    // FIXME - copy over relocations

    throw runtime_error("FIXME");
}
