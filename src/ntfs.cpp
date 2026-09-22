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

module;

#include <stdint.h>
#include <vector>
#include <string>
#include <list>
#include <functional>
#include <memory>
#include <map>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

export module ntfs;

import buffer_t;

using namespace std;

#pragma pack(push,1)

typedef struct {
    uint8_t Jmp[3];
    uint8_t FsName[8];
    uint16_t BytesPerSector;
    uint8_t SectorsPerCluster;
    uint16_t ReservedSectors;
    uint8_t Unused1[5];
    uint8_t Media;
    uint8_t Unused2[2];
    uint16_t SectorsPerTrack;
    uint16_t Heads;
    uint32_t HiddenSectors;
    uint32_t Unused3;
    uint32_t Unknown;
    uint64_t TotalSectors;
    uint64_t MFT;
    uint64_t MFTMirr;
    int8_t ClustersPerMFTRecord;
    uint8_t Padding1[3];
    int8_t ClustersPerIndexRecord;
    uint8_t Padding2[3];
    uint64_t SerialNumber;
    uint32_t Checksum;
} NTFS_BOOT_SECTOR;

export constexpr char NTFS_FS_NAME[] = "NTFS    ";

// https://docs.microsoft.com/en-us/windows/win32/devnotes/attribute-record-header
export constexpr uint16_t ATTRIBUTE_FLAG_COMPRESSION_MASK = 0x00ff;
export constexpr uint16_t ATTRIBUTE_FLAG_SPARSE = 0x8000;
export constexpr uint16_t ATTRIBUTE_FLAG_ENCRYPTED = 0x4000;

export enum class NTFS_ATTRIBUTE_FORM : uint8_t {
    RESIDENT_FORM = 0,
    NONRESIDENT_FORM = 1
};

export enum class ntfs_attribute : uint32_t {
    STANDARD_INFORMATION = 0x10,
    ATTRIBUTE_LIST = 0x20,
    FILE_NAME = 0x30,
    VOLUME_VERSION = 0x40,
    SECURITY_DESCRIPTOR = 0x50,
    VOLUME_NAME = 0x60,
    VOLUME_INFORMATION = 0x70,
    DATA = 0x80,
    INDEX_ROOT = 0x90,
    INDEX_ALLOCATION = 0xA0,
    BITMAP = 0xB0,
    REPARSE_POINT = 0xC0,
    EA_INFORMATION = 0xD0,
    EA = 0xE0,
    PROPERTY_SET = 0xF0,
    LOGGED_UTILITY_STREAM = 0x100,
};

export struct ATTRIBUTE_RECORD_HEADER {
    enum ntfs_attribute TypeCode;
    uint16_t RecordLength;
    uint16_t Unknown;
    NTFS_ATTRIBUTE_FORM FormCode;
    uint8_t NameLength;
    uint16_t NameOffset;
    uint16_t Flags;
    uint16_t Instance;
    union {
        struct {
            uint32_t ValueLength;
            uint16_t ValueOffset;
            uint8_t Reserved[2];
        } Resident;
        struct {
            uint64_t LowestVcn;
            uint64_t HighestVcn;
            uint16_t MappingPairsOffset;
            uint16_t CompressionUnit;
            uint32_t Padding;
            uint64_t AllocatedLength;
            uint64_t FileSize;
            uint64_t ValidDataLength;
            uint64_t TotalAllocated;
        } Nonresident;
    } Form;
};

// https://docs.microsoft.com/en-us/windows/win32/devnotes/multi-sector-header
typedef struct {
    uint32_t Signature;
    uint16_t UpdateSequenceArrayOffset;
    uint16_t UpdateSequenceArraySize;
} MULTI_SECTOR_HEADER;

// https://docs.microsoft.com/en-us/windows/win32/devnotes/mft-segment-reference
typedef struct {
    uint64_t SegmentNumber : 48;
    uint64_t SequenceNumber : 16;
} MFT_SEGMENT_REFERENCE;

// based on https://docs.microsoft.com/en-us/windows/win32/devnotes/file-record-segment-header and
// http://www.cse.scu.edu/~tschwarz/coen252_07Fall/Lectures/NTFS.html
typedef struct {
    MULTI_SECTOR_HEADER MultiSectorHeader;
    uint64_t LogFileSequenceNumber;
    uint16_t SequenceNumber;
    uint16_t HardLinkCount;
    uint16_t FirstAttributeOffset;
    uint16_t Flags;
    uint32_t EntryUsedSize;
    uint32_t EntryAllocatedSize;
    MFT_SEGMENT_REFERENCE BaseFileRecordSegment;
    uint16_t NextAttributeID;
} FILE_RECORD_SEGMENT_HEADER;

#define FILE_RECORD_SEGMENT_IN_USE      1
#define FILE_RECORD_IS_DIRECTORY        2

export constexpr uint32_t NTFS_FILE_SIGNATURE = 0x454c4946; // "FILE"

export constexpr uint64_t NTFS_VOLUME_INODE = 3;
export constexpr uint64_t NTFS_ROOT_DIR_INODE = 5;
export constexpr uint64_t NTFS_BITMAP_INODE = 6;
export constexpr uint64_t NTFS_SECURE_INODE = 9;

// https://flatcap.org/linux-ntfs/ntfs/attributes/standard_information.html

export struct STANDARD_INFORMATION {
    int64_t CreationTime;
    int64_t LastAccessTime;
    int64_t LastWriteTime;
    int64_t ChangeTime;
    uint32_t FileAttributes;
    uint32_t MaximumVersions;
    uint32_t VersionNumber;
    uint32_t ClassId;
    uint32_t OwnerId;
    uint32_t SecurityId;
    uint64_t QuotaCharged;
    uint64_t USN;
};

#undef FILE_ATTRIBUTE_READONLY
#undef FILE_ATTRIBUTE_HIDDEN
#undef FILE_ATTRIBUTE_SYSTEM
#undef FILE_ATTRIBUTE_DIRECTORY
#undef FILE_ATTRIBUTE_ARCHIVE
#undef FILE_ATTRIBUTE_DEVICE
#undef FILE_ATTRIBUTE_NORMAL
#undef FILE_ATTRIBUTE_TEMPORARY
#undef FILE_ATTRIBUTE_SPARSE_FILE
#undef FILE_ATTRIBUTE_REPARSE_POINT
#undef FILE_ATTRIBUTE_COMPRESSED
#undef FILE_ATTRIBUTE_OFFLINE
#undef FILE_ATTRIBUTE_NOT_CONTENT_INDEXED
#undef FILE_ATTRIBUTE_ENCRYPTED
#undef FILE_ATTRIBUTE_VIRTUAL

export constexpr uint32_t FILE_ATTRIBUTE_READONLY = 0x00000001;
export constexpr uint32_t FILE_ATTRIBUTE_HIDDEN = 0x00000002;
export constexpr uint32_t FILE_ATTRIBUTE_SYSTEM = 0x00000004;
export constexpr uint32_t FILE_ATTRIBUTE_DIRECTORY = 0x00000010;
export constexpr uint32_t FILE_ATTRIBUTE_ARCHIVE = 0x00000020;
export constexpr uint32_t FILE_ATTRIBUTE_DEVICE = 0x00000040;
export constexpr uint32_t FILE_ATTRIBUTE_NORMAL = 0x00000080;
export constexpr uint32_t FILE_ATTRIBUTE_TEMPORARY = 0x00000100;
export constexpr uint32_t FILE_ATTRIBUTE_SPARSE_FILE = 0x00000200;
export constexpr uint32_t FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400;
export constexpr uint32_t FILE_ATTRIBUTE_COMPRESSED = 0x00000800;
export constexpr uint32_t FILE_ATTRIBUTE_OFFLINE = 0x00001000;
export constexpr uint32_t FILE_ATTRIBUTE_NOT_CONTENT_INDEXED = 0x00002000;
export constexpr uint32_t FILE_ATTRIBUTE_ENCRYPTED = 0x00004000;
export constexpr uint32_t FILE_ATTRIBUTE_VIRTUAL = 0x00010000;

export constexpr uint32_t FILE_ATTRIBUTE_DIRECTORY_MFT = 0x10000000;

// https://flatcap.org/linux-ntfs/ntfs/attributes/file_name.html

export enum class file_name_type : uint8_t {
    POSIX = 0,
    WINDOWS = 1,
    DOS = 2,
    WINDOWS_AND_DOS = 3
};

export struct FILE_NAME {
    MFT_SEGMENT_REFERENCE Parent;
    int64_t CreationTime;
    int64_t LastAccessTime;
    int64_t LastWriteTime;
    int64_t ChangeTime;
    uint64_t AllocationSize;
    uint64_t EndOfFile;
    uint32_t FileAttributes;
    uint32_t EaSize;
    uint8_t FileNameLength;
    file_name_type Namespace;
    char16_t FileName[1];
};

// https://flatcap.org/linux-ntfs/ntfs/concepts/node_header.html

typedef struct {
    uint32_t first_entry;
    uint32_t total_size;
    uint32_t allocated_size;
    uint32_t flags;
} index_node_header;

// https://flatcap.org/linux-ntfs/ntfs/concepts/index_entry.html

export constexpr uint32_t INDEX_ENTRY_SUBNODE = 1;
export constexpr uint32_t INDEX_ENTRY_LAST = 2;

typedef struct {
    MFT_SEGMENT_REFERENCE file_reference;
    uint16_t entry_length;
    uint16_t stream_length;
    uint32_t flags;
} index_entry;

// https://flatcap.org/linux-ntfs/ntfs/attributes/index_root.html

typedef struct {
    uint32_t attribute_type;
    uint32_t collation_rule;
    uint32_t bytes_per_index_record;
    uint8_t clusters_per_index_record;
    uint8_t padding[3];
    index_node_header node_header;
    index_entry entries[1];
} index_root;

// https://flatcap.org/linux-ntfs/ntfs/concepts/index_record.html

typedef struct {
    MULTI_SECTOR_HEADER MultiSectorHeader;
    uint64_t sequence_number;
    uint64_t vcn;
    index_node_header header;
    uint16_t update_sequence;
} index_record;

export constexpr uint32_t INDEX_RECORD_MAGIC = 0x58444e49; // "INDX"

// https://flatcap.org/linux-ntfs/ntfs/files/secure.html

typedef struct {
    uint32_t hash;
    uint32_t id;
    uint64_t offset;
    uint32_t length;
} sd_entry;

// https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_reparse_data_buffer

export struct REPARSE_DATA_BUFFER {
    uint32_t ReparseTag;
    uint16_t ReparseDataLength;
    uint16_t Reserved;

    union {
        struct {
            uint16_t SubstituteNameOffset;
            uint16_t SubstituteNameLength;
            uint16_t PrintNameOffset;
            uint16_t PrintNameLength;
            uint32_t Flags;
            char16_t PathBuffer[1];
        } SymbolicLinkReparseBuffer;

        struct {
            uint16_t SubstituteNameOffset;
            uint16_t SubstituteNameLength;
            uint16_t PrintNameOffset;
            uint16_t PrintNameLength;
            char16_t PathBuffer[1];
        } MountPointReparseBuffer;

        struct {
            uint8_t DataBuffer[1];
        } GenericReparseBuffer;

        struct {
            uint32_t unknown;
            char name[1];
        } LxSymlink; // undocumented
    };
};

typedef struct {
    uint32_t unknown;
    char name[1];
} REPARSE_DATA_BUFFER_LX_SYMLINK;

#undef IO_REPARSE_TAG_WOF
#undef IO_REPARSE_TAG_SYMLINK
#undef IO_REPARSE_TAG_LX_SYMLINK

export constexpr uint32_t IO_REPARSE_TAG_WOF = 0x80000017;
export constexpr uint32_t IO_REPARSE_TAG_SYMLINK = 0xa000000c;
export constexpr uint32_t IO_REPARSE_TAG_LX_SYMLINK = 0xa000001d;

#undef SYMLINK_FLAG_RELATIVE

export constexpr uint32_t SYMLINK_FLAG_RELATIVE = 0x00000001;

// https://flatcap.org/linux-ntfs/ntfs/attributes/volume_information.html

typedef struct {
    uint64_t Unknown1;
    uint8_t MajorVersion;
    uint8_t MinorVersion;
    uint16_t Flags;
    uint32_t Unknown2;
} VOLUME_INFORMATION;

export constexpr uint16_t NTFS_VOLUME_DIRTY = 0x0001;
export constexpr uint16_t NTFS_VOLUME_RESIZE_JOURNAL = 0x0002;
export constexpr uint16_t NTFS_VOLUME_UPGRADE_ON_MOUNT = 0x0004;
export constexpr uint16_t NTFS_VOLUME_MOUNTED_ON_NT4 = 0x0008;
export constexpr uint16_t NTFS_VOLUME_DELETE_USN_UNDERWAY = 0x0010;
export constexpr uint16_t NTFS_VOLUME_REPAIR_OBJECT_IDS = 0x0020;
export constexpr uint16_t NTFS_VOLUME_MODIFIED_BY_CHKDSK = 0x8000;

// https://flatcap.org/linux-ntfs/ntfs/attributes/attribute_list.html

typedef struct {
    enum ntfs_attribute type;
    uint16_t record_length;
    uint8_t name_length;
    uint8_t name_offset;
    uint64_t starting_vcn;
    MFT_SEGMENT_REFERENCE file_reference;
    uint16_t instance;
} attribute_list_entry;

#undef WOF_CURRENT_VERSION

export constexpr uint32_t WOF_CURRENT_VERSION = 1;

#undef WOF_PROVIDER_WIM
#undef WOF_PROVIDER_FILE

export constexpr uint32_t WOF_PROVIDER_WIM = 1;
export constexpr uint32_t WOF_PROVIDER_FILE = 2;

export struct reparse_point_header { // edited form of REPARSE_DATA_BUFFER
    uint32_t ReparseTag;
    uint16_t ReparseDataLength;
    uint16_t Reserved;
    uint8_t DataBuffer[1];
};

export struct wof_external_info { // WOF_EXTERNAL_INFO in winioctl.h
    uint32_t Version;
    uint32_t Provider;
};

#undef FILE_PROVIDER_CURRENT_VERSION

export constexpr uint32_t FILE_PROVIDER_CURRENT_VERSION = 1;

#undef FILE_PROVIDER_COMPRESSION_XPRESS4K
#undef FILE_PROVIDER_COMPRESSION_LZX
#undef FILE_PROVIDER_COMPRESSION_XPRESS8K
#undef FILE_PROVIDER_COMPRESSION_XPRESS16K

export constexpr uint32_t FILE_PROVIDER_COMPRESSION_XPRESS4K = 0;
export constexpr uint32_t FILE_PROVIDER_COMPRESSION_LZX = 1;
export constexpr uint32_t FILE_PROVIDER_COMPRESSION_XPRESS8K = 2;
export constexpr uint32_t FILE_PROVIDER_COMPRESSION_XPRESS16K = 3;

export struct file_provider_external_info_v0 { // FILE_PROVIDER_EXTERNAL_INFO_V0 in winioctl.h
    uint32_t Version;
    uint32_t Algorithm;
};

// cf. https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_file_full_ea_information

export struct ea_data {
    uint32_t NextEntryOffset;
    uint8_t Flags;
    uint8_t EaNameLength;
    uint16_t EaValueLength;
    char EaName[1];
};

export struct lxdev {
    uint32_t major;
    uint32_t minor;
};

// https://dfir.ru/2019/01/19/ntfs-today/

export struct lxattrb {
    uint16_t format;
    uint16_t version;
    uint32_t mode;
    uint32_t uid;
    uint32_t gid;
    uint32_t rdev;
    uint32_t atime_ns;
    uint32_t mtime_ns;
    uint32_t ctime_ns;
    uint64_t atime;
    uint64_t mtime;
    uint64_t ctime;
};

#pragma pack(pop)

export class ntfs;

export struct mapping {
    mapping(uint64_t lcn, uint64_t vcn, uint64_t length) : lcn(lcn), vcn(vcn), length(length) { }

    uint64_t lcn;
    uint64_t vcn;
    uint64_t length;
};

export class ntfs_file {
public:
    ntfs_file(ntfs& dev, uint64_t inode);
    buffer_t read(uint64_t offset = 0, uint32_t length = 0, enum ntfs_attribute type = ntfs_attribute::DATA, u16string_view name = u"");
    list<mapping> read_mappings(enum ntfs_attribute type = ntfs_attribute::DATA, u16string_view name = u"");

    bool is_directory() const {
        return file_record->Flags & FILE_RECORD_IS_DIRECTORY;
    }

    void loop_through_atts(const function<bool(const ATTRIBUTE_RECORD_HEADER&, string_view, u16string_view)>& func);
    string get_filename();

    FILE_RECORD_SEGMENT_HEADER* file_record;

private:
    buffer_t read_nonresident_attribute(uint64_t offset, uint32_t length, const ATTRIBUTE_RECORD_HEADER* att);
    buffer_t read_nonresident_data(uint64_t offset, uint32_t length, uint64_t file_size,
                                   const list<mapping>& mappings);

    // Cache of $DATA mappings. Reading any MFT record goes through
    // $MFT:$DATA, so recomputing it every time would be pathological.
    list<mapping> data_mappings_cache;
    bool data_mappings_cached = false;

    buffer_t file_record_buf;
    ntfs& dev;
    uint64_t inode;
};

export class ntfs {
public:
    ntfs(const string& fn);

    ~ntfs() {
#ifdef _WIN32
        CloseHandle(h);
#else
        close(fd);
#endif
    }

    void read(uint64_t offset, uint8_t* buf, size_t length);
    void write(uint64_t offset, const uint8_t* buf, size_t length);
    string_view find_sd(uint32_t id, ntfs_file& secure);

    unique_ptr<ntfs_file> mft;
    buffer_t boot_sector_buf;
    NTFS_BOOT_SECTOR* boot_sector = nullptr;
    uint64_t file_record_size;
    map<uint32_t, buffer_t> sd_list;

#ifdef _WIN32
    HANDLE h;
#else
    int fd;
#endif
};

// ntfs.cpp
export void read_nonresident_mappings(const ATTRIBUTE_RECORD_HEADER& att,
                                      list<mapping>& mappings,
                                      uint32_t cluster_size, uint64_t vdl);
export void populate_skip_list(ntfs& dev, uint64_t inode,
                               list<uint64_t>& skiplist);
