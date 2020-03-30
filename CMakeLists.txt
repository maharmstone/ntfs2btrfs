cmake_minimum_required(VERSION 3.14.3)

project(ntfs2btrfs VERSION 20200330)

configure_file(src/config.h.in src/config.h)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(SRC_FILES src/ntfs2btrfs.cpp
    src/ntfs.cpp
    src/crc32c.c)

if(MSVC)
    enable_language(ASM_MASM)
    set(SRC_FILES ${SRC_FILES} src/crc32c-masm.asm)
else()
    enable_language(ASM)
    set(SRC_FILES ${SRC_FILES} src/crc32c-gas.S)
endif()

add_executable(ntfs2btrfs ${SRC_FILES})

if(MSVC)
    target_compile_options(ntfs2btrfs PRIVATE /W4)
else()
    target_compile_options(ntfs2btrfs PRIVATE -Wall -Wextra -Wno-address-of-packed-member)
endif()

install(TARGETS ntfs2btrfs DESTINATION bin)
