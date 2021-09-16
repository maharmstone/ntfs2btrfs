#include "ntfs2btrfs.h"

using namespace std;

void rollback(const string& fn) {
    // FIXME - read superblocks
    // FIXME - find root of tree 100
    // FIXME - find file called ntfs.img
    // FIXME - parse extent items
    // FIXME - resolve logical addresses to physical
    // FIXME - remove identity maps
    // FIXME - copy over relocations

    throw runtime_error("FIXME");
}
