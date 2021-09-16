#include "ntfs2btrfs.h"
#include <iostream>

using namespace std;

static superblock read_superblock(fstream& f) {
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

    return sb.value();
}

void rollback(const string& fn) {
    // FIXME - CreateFile on Windows
    fstream f(fn, ios_base::in | ios_base::out | ios::binary);

    if (!f.good())
        throw formatted_error("Failed to open {}.", fn);

    auto sb = read_superblock(f);

    // FIXME - find root of tree 100
    // FIXME - find file called ntfs.img
    // FIXME - parse extent items
    // FIXME - resolve logical addresses to physical
    // FIXME - remove identity maps
    // FIXME - copy over relocations

    throw runtime_error("FIXME");
}
