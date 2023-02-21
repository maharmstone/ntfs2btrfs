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

#include "ntfs2btrfs.h"
#include "ntfs.h"
#include <functional>
#include <locale>
#include <codecvt>
#include <algorithm>

#ifndef _WIN32
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#endif

using namespace std;

static void process_fixups(MULTI_SECTOR_HEADER* header, uint64_t length, unsigned int sector_size) {
    uint64_t sectors;
    uint16_t* seq;
    uint8_t* ptr;

    if (length % sector_size != 0)
        throw formatted_error("Length was not a multiple of sector_size.");

    sectors = length / sector_size;

    if (header->UpdateSequenceArraySize < sectors + 1)
        throw formatted_error("UpdateSequenceArraySize was {:x}, expected {:x}", header->UpdateSequenceArraySize, sectors + 1);

    seq = (uint16_t*)((uint8_t*)header + header->UpdateSequenceArrayOffset);

    ptr = (uint8_t*)header + sector_size - sizeof(uint16_t);

    for (unsigned int i = 0; i < sectors; i++) {
        if (*(uint16_t*)ptr != seq[0])
            throw formatted_error("Update sequence mismatch.");

        *(uint16_t*)ptr = seq[i + 1];

        ptr += sector_size;
    }
}

ntfs_file::ntfs_file(ntfs& dev, uint64_t inode) : dev(dev), inode(inode) {
    file_record_buf.resize((size_t)dev.file_record_size);

    if (inode == 0) {
        dev.seek(dev.boot_sector->MFT * dev.boot_sector->BytesPerSector * dev.boot_sector->SectorsPerCluster);
        dev.read(file_record_buf.data(), (uint32_t)dev.file_record_size);
    } else { // read from MFT
        auto str = dev.mft->read(inode * dev.file_record_size, (uint32_t)dev.file_record_size);

        memcpy(file_record_buf.data(), str.data(), (uint32_t)dev.file_record_size); // FIXME - can we avoid copy?
    }

    file_record = reinterpret_cast<FILE_RECORD_SEGMENT_HEADER*>(file_record_buf.data());

    if (file_record->MultiSectorHeader.Signature != NTFS_FILE_SIGNATURE) {
        throw formatted_error("Invalid file signature ({:08x}, expected {:08x}).",
                              file_record->MultiSectorHeader.Signature, NTFS_FILE_SIGNATURE);
    }

    process_fixups(&file_record->MultiSectorHeader, dev.file_record_size, dev.boot_sector->BytesPerSector);
}

void read_nonresident_mappings(const ATTRIBUTE_RECORD_HEADER& att, list<mapping>& mappings,
                               uint32_t cluster_size, uint64_t vdl) {
    uint64_t next_vcn = att.Form.Nonresident.LowestVcn, current_lcn = 0, current_vcn;
    uint8_t* stream = (uint8_t*)&att + att.Form.Nonresident.MappingPairsOffset;
    uint64_t max_cluster = vdl / cluster_size;

    if (vdl & (cluster_size - 1))
        max_cluster++;

    if (max_cluster == 0)
        return;

    while (true) {
        uint64_t v, l;
        int64_t v_val, l_val;

        current_vcn = next_vcn;

        if (*stream == 0)
            break;

        v = *stream & 0xf;
        l = *stream >> 4;

        stream++;

        if (v > 8)
            throw formatted_error("Error: v > 8");

        if (l > 8)
            throw formatted_error("Error: l > 8");

        // FIXME - do we need to make sure that int64_t pointers don't go past end of buffer?

        v_val = *(int64_t*)stream;
        v_val &= (1ull << (v * 8)) - 1;

        if ((uint64_t)v_val & (1ull << ((v * 8) - 1))) // sign-extend if negative
            v_val |= 0xffffffffffffffff & ~((1ull << (v * 8)) - 1);

        stream += v;

        next_vcn += v_val;

        if (l != 0) {
            l_val = *(int64_t*)stream;
            l_val &= (1ull << (l * 8)) - 1;

            if ((uint64_t)l_val & (1ull << ((l * 8) - 1))) // sign-extend if negative
                l_val |= 0xffffffffffffffff & ~((1ull << (l * 8)) - 1);

            stream += l;

            current_lcn += l_val;

            if (next_vcn > max_cluster)
                next_vcn = max_cluster;

            mappings.emplace_back(current_lcn, current_vcn, next_vcn - current_vcn);
        } else
            mappings.emplace_back(0, current_vcn, next_vcn - current_vcn);

        if (next_vcn == max_cluster)
            break;
    }
}

buffer_t ntfs_file::read_nonresident_attribute(uint64_t offset, uint32_t length, const ATTRIBUTE_RECORD_HEADER* att) {
    list<mapping> mappings;
    uint32_t cluster_size = dev.boot_sector->BytesPerSector * dev.boot_sector->SectorsPerCluster;

    read_nonresident_mappings(*att, mappings, cluster_size, att->Form.Nonresident.ValidDataLength);

    // FIXME - do we need to check that mappings is contiguous and in order?

    if (offset >= (uint64_t)att->Form.Nonresident.FileSize)
        return {};

    if (offset + length > (uint64_t)att->Form.Nonresident.FileSize || length == 0)
        length = (uint32_t)(att->Form.Nonresident.FileSize - offset);

    buffer_t ret(length);
    memset(ret.data(), 0, length);

    for (const auto& m : mappings) {
        if (offset + length >= m.vcn * cluster_size && offset < (m.vcn + m.length) * cluster_size) {
            uint32_t buf_start, buf_end;
            uint64_t read_start, read_end;
            unsigned int skip_start, skip_end;

            if (offset < m.vcn * cluster_size)
                buf_start = (uint32_t)((m.vcn * cluster_size) - offset);
            else
                buf_start = 0;

            if (offset + length > (m.vcn + m.length) * cluster_size)
                buf_end = min((uint32_t)((m.vcn + m.length) * cluster_size), length);
            else
                buf_end = length;

            if (buf_end == buf_start)
                continue;

            read_start = m.lcn * cluster_size;

            if (offset > m.vcn * cluster_size)
                read_start += offset - (m.vcn * cluster_size);

            read_end = read_start + buf_end - buf_start;

            if ((read_start % dev.boot_sector->BytesPerSector) != 0) {
                skip_start = (unsigned int)(read_start % dev.boot_sector->BytesPerSector);
                read_start -= skip_start;
            } else
                skip_start = 0;

            if ((read_end % dev.boot_sector->BytesPerSector) != 0) {
                skip_end = (unsigned int)(dev.boot_sector->BytesPerSector - (read_end % dev.boot_sector->BytesPerSector));
                read_end += skip_end;
            } else
                skip_end = 0;

            dev.seek(read_start);

            if (skip_start != 0 || skip_end != 0) {
                buffer_t tmp(read_end - read_start);

                dev.read(tmp.data(), tmp.size());

                memcpy(&ret[buf_start], &tmp[skip_start], buf_end - buf_start);
            } else
                dev.read(&ret[buf_start], buf_end - buf_start);
        }
    }

    // FIXME - zero end if ValidDataLength < FileSize

    return ret;
}

buffer_t ntfs_file::read(uint64_t offset, uint32_t length, enum ntfs_attribute type, u16string_view name) {
    buffer_t ret;
    bool found = false;

    loop_through_atts([&](const ATTRIBUTE_RECORD_HEADER& att, string_view res_data, u16string_view att_name) -> bool {
        if (att.TypeCode != type || name != att_name)
            return true;

        if (att.Flags & ATTRIBUTE_FLAG_ENCRYPTED)
            throw formatted_error("Cannot read encrypted attribute");

        if (att.Flags & ATTRIBUTE_FLAG_COMPRESSION_MASK)
            throw formatted_error("FIXME - handle reading compressed attribute"); // FIXME

        if (att.FormCode == NTFS_ATTRIBUTE_FORM::NONRESIDENT_FORM)
            ret = read_nonresident_attribute(offset, length, &att);
        else {
            if (offset >= res_data.length())
                ret.clear();
            else {
                if (offset + length > res_data.length() || length == 0)
                    length = (uint32_t)(res_data.length() - offset);

                ret.resize(length);

                memcpy(ret.data(), &res_data[(uint32_t)offset], length);
            }
        }

        found = true;

        return false;
    });

    if (!found)
        throw formatted_error("Attribute not found.");

    return ret;
}

list<mapping> ntfs_file::read_mappings(enum ntfs_attribute type, u16string_view name) {
    list<mapping> mappings;

    loop_through_atts([&](const ATTRIBUTE_RECORD_HEADER& att, string_view, u16string_view att_name) -> bool {
        if (att.TypeCode != type || name != att_name)
            return true;

        if (att.FormCode == NTFS_ATTRIBUTE_FORM::RESIDENT_FORM)
            throw formatted_error("Attribute is resident");

        uint32_t cluster_size = dev.boot_sector->BytesPerSector * dev.boot_sector->SectorsPerCluster;

        read_nonresident_mappings(att, mappings, cluster_size, att.Form.Nonresident.ValidDataLength);

        return false;
    });

    return mappings;
}

ntfs::ntfs(const string& fn) {
    unsigned int sector_size = 512; // FIXME - find from device

#ifdef _WIN32
    bool drive = false;
    DWORD ret;
    wstring_convert<codecvt_utf8_utf16<char16_t>, char16_t> convert;
    u16string namew;

    if ((fn.length() == 2 || fn.length() == 3) && ((fn[0] >= 'A' && fn[0] <= 'Z') || (fn[0] >= 'a' && fn[0] <= 'z')) && fn[1] == ':' && (fn.length() == 2 || fn[2] == '\\')) {
        namew = u"\\\\.\\X:";
        namew[4] = fn[0];
        drive = true;
    } else
        namew = convert.from_bytes(fn.data(), fn.data() + fn.length());

    h = CreateFileW((WCHAR*)namew.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                    nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

    if (h == INVALID_HANDLE_VALUE)
        throw last_error("CreateFile", GetLastError());

    if (drive) {
        if (!DeviceIoControl(h, FSCTL_LOCK_VOLUME, nullptr, 0, nullptr, 0, &ret, nullptr)) {
            auto le = GetLastError();

            CloseHandle(h);

            throw last_error("FSCTL_LOCK_VOLUME", le);
        }
    }

#else
    fd = open(fn.c_str(), O_RDWR | O_EXCL);

    if (fd < 0)
        throw formatted_error("open returned {} (errno = {}).", fd, errno);
#endif

    // read NTFS_BOOT_SECTOR
    boot_sector_buf.resize((size_t)sector_align(sizeof(NTFS_BOOT_SECTOR), sector_size));
    seek(0);
    read(boot_sector_buf.data(), boot_sector_buf.size());
    boot_sector = reinterpret_cast<NTFS_BOOT_SECTOR*>(boot_sector_buf.data());

    // make sure is NTFS
    if (memcmp(boot_sector->FsName, NTFS_FS_NAME, sizeof(NTFS_FS_NAME) - 1))
        throw formatted_error("Device was not an NTFS volume.");

    if (boot_sector->ClustersPerMFTRecord < 0)
        file_record_size = 1ull << -boot_sector->ClustersPerMFTRecord;
    else
        file_record_size = (uint64_t)boot_sector->BytesPerSector * (uint64_t)boot_sector->SectorsPerCluster * (uint64_t)boot_sector->ClustersPerMFTRecord;

    mft.reset(new ntfs_file(*this, 0));

    ntfs_file vol_file(*this, NTFS_VOLUME_INODE);

    auto vi_str = vol_file.read(0, 0, ntfs_attribute::VOLUME_INFORMATION);

    auto vi = reinterpret_cast<VOLUME_INFORMATION*>(vi_str.data());

    if (vi->MajorVersion > 3 || (vi->MajorVersion == 3 && vi->MinorVersion > 1))
        throw formatted_error("Unsupported NTFS version {}.{}.", vi->MajorVersion, vi->MinorVersion);

    if (vi->Flags & NTFS_VOLUME_DIRTY)
        throw formatted_error("Cannot convert volume with dirty bit set.");
}

static buffer_t read_from_mappings(const list<mapping>& mappings, uint64_t start, uint32_t length, ntfs& dev) {
    uint32_t sector_size = dev.boot_sector->BytesPerSector;
    uint32_t cluster_size = sector_size * dev.boot_sector->SectorsPerCluster;
    buffer_t s(length);
    uint64_t cluster_start = start / cluster_size;
    uint64_t cluster_end = sector_align(start + length, cluster_size) / cluster_size;

    for (const auto& m : mappings) {
        if (m.vcn <= cluster_end && m.vcn + m.length >= cluster_start) {
            uint64_t read_start = max(start - (start % dev.boot_sector->BytesPerSector), m.vcn * cluster_size);
            uint64_t read_end = min(sector_align(start + length, dev.boot_sector->BytesPerSector), (m.vcn + m.length) * cluster_size);

            if (read_end == read_start)
                continue;

            buffer_t buf((uint32_t)(read_end - read_start));

            dev.seek(read_start + ((m.lcn - m.vcn) * cluster_size));
            dev.read(buf.data(), (uint32_t)(read_end - read_start));

            memcpy(s.data(), buf.data() + read_start - start, (size_t)min(read_end - read_start, length - read_start + start));
        }
    }

    return s;
}

static optional<buffer_t> btree_search(const index_root& ir, const list<mapping>& mappings, const index_node_header& inh,
                                     ntfs& dev, uint32_t key) {
    auto ent = reinterpret_cast<const index_entry*>((uint8_t*)&inh + inh.first_entry);

    do {
        if (ent->flags & INDEX_ENTRY_SUBNODE) {
            bool skip = false;

            if (!(ent->flags & INDEX_ENTRY_LAST)) {
                uint32_t v1 = *(uint32_t*)((uint8_t*)ent + sizeof(index_entry));

                if (v1 == key)
                    return buffer_t((uint8_t*)ent + sizeof(index_entry) + ent->stream_length, (uint8_t*)ent + ent->entry_length - sizeof(uint64_t));

                skip = key > v1;
            }

            if (!skip) {
                uint64_t vcn = ((MFT_SEGMENT_REFERENCE*)((uint8_t*)ent + ent->entry_length - sizeof(uint64_t)))->SegmentNumber;

                if (ir.bytes_per_index_record < dev.boot_sector->BytesPerSector * dev.boot_sector->SectorsPerCluster)
                    vcn *= dev.boot_sector->BytesPerSector;
                else
                    vcn *= (uint64_t)dev.boot_sector->BytesPerSector * (uint64_t)dev.boot_sector->SectorsPerCluster;

                auto data = read_from_mappings(mappings, vcn, ir.bytes_per_index_record, dev);

                auto& rec = *reinterpret_cast<index_record*>(data.data());

                if (rec.MultiSectorHeader.Signature != INDEX_RECORD_MAGIC)
                    throw formatted_error("Index record magic was not INDX.");

                process_fixups(&rec.MultiSectorHeader, ir.bytes_per_index_record, dev.boot_sector->BytesPerSector);

                return btree_search(ir, mappings, rec.header, dev, key);
            }
        } else if (!(ent->flags & INDEX_ENTRY_LAST)) {
            uint32_t v = *(uint32_t*)((uint8_t*)ent + sizeof(index_entry));

            if (v == key)
                return buffer_t((uint8_t*)ent + sizeof(index_entry) + ent->stream_length, (uint8_t*)ent + ent->entry_length);
            else if (v > key)
                break;
        }

        if (ent->flags & INDEX_ENTRY_LAST)
            break;

        ent = reinterpret_cast<const index_entry*>((uint8_t*)ent + ent->entry_length);
    } while (true);

    return nullopt;
}

string_view ntfs::find_sd(uint32_t id, ntfs_file& secure) {
    if (sd_list.count(id) > 0) {
        const auto& sd = sd_list.at(id);
        return {(char*)sd.data(), sd.size()};
    }

    auto ir_str = secure.read(0, 0, ntfs_attribute::INDEX_ROOT, u"$SII");
    auto ia = secure.read_mappings(ntfs_attribute::INDEX_ALLOCATION, u"$SII");

    const auto& ir = *reinterpret_cast<index_root*>(ir_str.data());

    auto ret = btree_search(ir, ia, ir.node_header, *this, id);

    if (!ret.has_value())
        return "";

    const auto& sde = *reinterpret_cast<const sd_entry*>(ret.value().data());

    auto sde2 = secure.read(sde.offset, sde.length, ntfs_attribute::DATA, u"$SDS");

    if (memcmp(&sde, sde2.data(), sizeof(sd_entry)))
        throw formatted_error("SD headers do not match.");

    auto sv = string_view((char*)sde2.data(), sde2.size()).substr(sizeof(sd_entry));
    buffer_t buf(sv.data(), sv.data() + sv.length());

    auto [it, success] = sd_list.emplace(make_pair(id, buffer_t{}));

    it->second.swap(buf);

    return string_view((char*)it->second.data(), it->second.size());
}

static void walk_btree(const index_root& ir, const list<mapping>& mappings, const index_node_header& inh, ntfs& dev,
                       const function<void(const index_entry&, string_view)>& func, unsigned int level) {
    auto ent = reinterpret_cast<const index_entry*>((uint8_t*)&inh + inh.first_entry);

    do {
        if (ent->flags & INDEX_ENTRY_SUBNODE) {
            uint64_t vcn = ((MFT_SEGMENT_REFERENCE*)((uint8_t*)ent + ent->entry_length - sizeof(uint64_t)))->SegmentNumber;

            if (ir.bytes_per_index_record < dev.boot_sector->BytesPerSector * dev.boot_sector->SectorsPerCluster)
                vcn *= dev.boot_sector->BytesPerSector;
            else
                vcn *= (uint64_t)dev.boot_sector->BytesPerSector * (uint64_t)dev.boot_sector->SectorsPerCluster;

            auto data = read_from_mappings(mappings, vcn, ir.bytes_per_index_record, dev);

            auto rec = reinterpret_cast<index_record*>(data.data());

            if (rec->MultiSectorHeader.Signature != INDEX_RECORD_MAGIC)
                throw formatted_error("Index record magic was not INDX.");

            process_fixups(&rec->MultiSectorHeader, ir.bytes_per_index_record, dev.boot_sector->BytesPerSector);

            walk_btree(ir, mappings, rec->header, dev, func, level + 1);
        } else
            func(*ent, string_view((const char*)ent + sizeof(index_entry), ent->stream_length));

        if (ent->flags & INDEX_ENTRY_LAST)
            break;

        ent = reinterpret_cast<const index_entry*>((uint8_t*)ent + ent->entry_length);
    } while (true);
}

void populate_skip_list(ntfs& dev, uint64_t inode, list<uint64_t>& skiplist) {
    ntfs_file file(dev, inode);

    if (!file.is_directory())
        return;

    auto ir_str = file.read(0, 0, ntfs_attribute::INDEX_ROOT, u"$I30");
    auto ia = file.read_mappings(ntfs_attribute::INDEX_ALLOCATION, u"$I30");

    const auto& ir = *reinterpret_cast<index_root*>(ir_str.data());

    skiplist.emplace_back(inode);

    walk_btree(ir, ia, ir.node_header, dev, [&](const index_entry& ent, string_view data) {
        if (data.empty())
            return;

        auto fn = reinterpret_cast<const FILE_NAME*>(data.data());

        if (fn->FileAttributes & FILE_ATTRIBUTE_DIRECTORY_MFT) {
            bool found = false;
            uint64_t dir_inode = ent.file_reference.SegmentNumber;

            for (auto n : skiplist) {
                if (n == dir_inode) {
                    found = true;
                    break;
                }
            }

            if (!found)
                populate_skip_list(dev, dir_inode, skiplist);
        }
    }, 0);
}

void ntfs_file::loop_through_atts(const function<bool(const ATTRIBUTE_RECORD_HEADER&, string_view, u16string_view)>& func) {
    auto att = reinterpret_cast<const ATTRIBUTE_RECORD_HEADER*>((uint8_t*)file_record + file_record->FirstAttributeOffset);
    size_t offset = file_record->FirstAttributeOffset;
    buffer_t attlist;

    while (true) {
        if (att->TypeCode == (enum ntfs_attribute)0xffffffff || att->RecordLength == 0)
            break;

        if (att->TypeCode == ntfs_attribute::ATTRIBUTE_LIST) {
            if (att->FormCode == NTFS_ATTRIBUTE_FORM::NONRESIDENT_FORM)
                attlist = read_nonresident_attribute(0, (uint32_t)att->Form.Nonresident.FileSize, att);
            else {
                attlist.resize(att->Form.Resident.ValueLength);

                memcpy(attlist.data(), (uint8_t*)att + att->Form.Resident.ValueOffset, att->Form.Resident.ValueLength);
            }

            break;
        }

        offset += att->RecordLength;
        att = reinterpret_cast<const ATTRIBUTE_RECORD_HEADER*>((uint8_t*)att + att->RecordLength);
    }

    if (!attlist.empty()) {
        vector<uint64_t> other_inodes;

        {
            auto ent = (const attribute_list_entry*)attlist.data();
            size_t left = attlist.size();

            while (true) {
                uint64_t file_reference = ent->file_reference.SegmentNumber;

                if (file_reference == inode) { // contained elsewhere in this inode
                    att = reinterpret_cast<const ATTRIBUTE_RECORD_HEADER*>((uint8_t*)file_record + file_record->FirstAttributeOffset);
                    offset = file_record->FirstAttributeOffset;

                    while (true) {
                        if (att->TypeCode == (enum ntfs_attribute)0xffffffff || att->RecordLength == 0)
                            break;

                        if (att->TypeCode == ent->type && att->NameLength == ent->name_length && att->Instance == ent->instance) {
                            if (att->NameLength == 0 || !memcmp((uint8_t*)file_record + offset + att->NameOffset, (uint8_t*)ent + ent->name_offset, att->NameLength * sizeof(char16_t))) {
                                string_view data;
                                u16string_view name;

                                if (att->FormCode == NTFS_ATTRIBUTE_FORM::RESIDENT_FORM)
                                    data = string_view((const char*)file_record + offset + att->Form.Resident.ValueOffset, att->Form.Resident.ValueLength);

                                if (att->NameLength != 0)
                                    name = u16string_view((char16_t*)((uint8_t*)file_record + offset + att->NameOffset), att->NameLength);

                                if (!func(*att, data, name))
                                    return;

                                break;
                            }
                        }

                        offset += att->RecordLength;
                        att = reinterpret_cast<const ATTRIBUTE_RECORD_HEADER*>((uint8_t*)att + att->RecordLength);
                    }
                } else {
                    bool found = false;

                    for (auto n : other_inodes) {
                        if (n == file_reference) {
                            found = true;
                            break;
                        }
                    }

                    if (!found)
                        other_inodes.push_back(file_reference);
                }

                if (left <= ent->record_length)
                    break;

                left -= ent->record_length;
                ent = (const attribute_list_entry*)((uint8_t*)ent + ent->record_length);
            }
        }

        if (!other_inodes.empty()) {
            for (auto file_reference : other_inodes) {
                ntfs_file oth(dev, file_reference);

                auto ent = (const attribute_list_entry*)attlist.data();
                auto left = attlist.size();

                while (true) {
                    if (ent->file_reference.SegmentNumber == file_reference) {
                        att = reinterpret_cast<const ATTRIBUTE_RECORD_HEADER*>((uint8_t*)oth.file_record + oth.file_record->FirstAttributeOffset);
                        offset = oth.file_record->FirstAttributeOffset;

                        while (true) {
                            if (att->TypeCode == (enum ntfs_attribute)0xffffffff || att->RecordLength == 0)
                                break;

                            if (att->TypeCode == ent->type && att->NameLength == ent->name_length && att->Instance == ent->instance) {
                                if (att->NameLength == 0 || !memcmp((uint8_t*)oth.file_record + offset + att->NameOffset, (uint8_t*)ent + ent->name_offset, att->NameLength * sizeof(char16_t))) {
                                    string_view data;
                                    u16string_view name;

                                    if (att->FormCode == NTFS_ATTRIBUTE_FORM::RESIDENT_FORM)
                                        data = string_view((const char*)oth.file_record + offset + att->Form.Resident.ValueOffset, att->Form.Resident.ValueLength);

                                    if (att->NameLength != 0)
                                        name = u16string_view((char16_t*)((uint8_t*)oth.file_record + offset + att->NameOffset), att->NameLength);

                                    if (!func(*att, data, name))
                                        return;

                                    break;
                                }
                            }

                            offset += att->RecordLength;
                            att = reinterpret_cast<const ATTRIBUTE_RECORD_HEADER*>((uint8_t*)att + att->RecordLength);
                        }
                    }

                    if (left <= ent->record_length)
                        break;

                    left -= ent->record_length;
                    ent = (const attribute_list_entry*)((uint8_t*)ent + ent->record_length);
                }
            }
        }

        return;
    }

    att = reinterpret_cast<const ATTRIBUTE_RECORD_HEADER*>((uint8_t*)file_record + file_record->FirstAttributeOffset);
    offset = file_record->FirstAttributeOffset;

    while (true) {
        if (att->TypeCode == (enum ntfs_attribute)0xffffffff || att->RecordLength == 0)
            break;

        string_view data;
        u16string_view name;

        if (att->FormCode == NTFS_ATTRIBUTE_FORM::RESIDENT_FORM)
            data = string_view((const char*)file_record + offset + att->Form.Resident.ValueOffset, att->Form.Resident.ValueLength);

        if (att->NameLength != 0)
            name = u16string_view((char16_t*)((uint8_t*)file_record + offset + att->NameOffset), att->NameLength);

        if (!func(*att, data, name))
            return;

        offset += att->RecordLength;
        att = reinterpret_cast<const ATTRIBUTE_RECORD_HEADER*>((uint8_t*)att + att->RecordLength);
    }
}

string ntfs_file::get_filename() {
    list<u16string> parts;
    ntfs_file* f = this;

    do {
        uint64_t dir_num = 0;

        f->loop_through_atts([&](const ATTRIBUTE_RECORD_HEADER& att, string_view res_data, u16string_view) -> bool {
            if (att.TypeCode != ntfs_attribute::FILE_NAME || att.FormCode != NTFS_ATTRIBUTE_FORM::RESIDENT_FORM)
                return true;

            auto fn = reinterpret_cast<const FILE_NAME*>(res_data.data());

            if (fn->Namespace == file_name_type::DOS)
                return true;

            if (fn->Parent.SegmentNumber != NTFS_ROOT_DIR_INODE)
                dir_num = fn->Parent.SegmentNumber;

            auto name = u16string_view(fn->FileName, fn->FileNameLength);

            parts.emplace_back(name);

            return false;
        });

        if (f != this)
            delete f;

        if (dir_num != 0)
            f = new ntfs_file(dev, dir_num);
        else
            break;
    } while (true);

    u16string retw;

    while (!parts.empty()) {
        retw += u"\\" + parts.back();
        parts.pop_back();
    }

    return utf16_to_utf8(retw);
}

void ntfs::seek(uint64_t pos) {
#ifdef _WIN32
    LARGE_INTEGER posli;

    posli.QuadPart = pos;

    if (!SetFilePointerEx(h, posli, nullptr, FILE_BEGIN))
        throw last_error("SetFilePointerEx", GetLastError());
#else
    if (lseek(fd, pos, SEEK_SET) == -1)
        throw formatted_error("Error seeking to {:x} (errno = {}).", pos, errno);
#endif
}

void ntfs::read(uint8_t* buf, size_t length) {
#ifdef _WIN32
    DWORD read;

    if (!ReadFile(h, buf, (DWORD)length, &read, nullptr))
        throw last_error("ReadFile", GetLastError());
#else
    auto pos = lseek(fd, 0, SEEK_CUR);
    auto orig_length = length;

    do {
        auto ret = ::read(fd, buf, length);

        if (ret < 0)
            throw formatted_error("Error reading {:x} bytes at {:x} (errno {}).", orig_length, pos, errno);

        if ((size_t)ret == length)
            break;

        buf += ret;
        length -= ret;
    } while (true);
#endif
}

void ntfs::write(const uint8_t* buf, size_t length) {
#ifdef _WIN32
    DWORD written;

    if (!WriteFile(h, buf, (DWORD)length, &written, nullptr))
        throw last_error("WriteFile", GetLastError());
#else
    auto pos = lseek(fd, 0, SEEK_CUR);
    auto orig_length = length;

    do {
        auto ret = ::write(fd, buf, length);

        if (ret < 0)
            throw formatted_error("Error writing {:x} bytes at {:x} (errno {}).", orig_length, pos, errno);

        if ((size_t)ret == length)
            break;

        buf += ret;
        length -= ret;
    } while (true);
#endif
}
