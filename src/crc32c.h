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

#include <stdint.h>

#ifndef _WIN32
#ifdef __i386__
#define __stdcall __attribute__((stdcall))
#elif defined(__x86_64__)
#define __stdcall __attribute__((ms_abi))
#else
#define __stdcall
#endif
#endif

#ifdef __cplusplus
extern "C"
{
#endif

#if defined(__i386__) || defined(__x86_64__)
uint32_t __stdcall calc_crc32c_hw(uint32_t seed, const uint8_t* msg, uint32_t msglen);
#endif

uint32_t __stdcall calc_crc32c_sw(uint32_t seed, const uint8_t* msg, uint32_t msglen);

typedef uint32_t (__stdcall *crc_func)(uint32_t seed, const uint8_t* msg, uint32_t msglen);

extern crc_func calc_crc32c;

#ifdef __cplusplus
}
#endif
