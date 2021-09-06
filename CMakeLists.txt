if(MSVC)
    cmake_minimum_required(VERSION 3.15)
    cmake_policy(SET CMP0091 NEW)
else()
    cmake_minimum_required(VERSION 3.14.3)
endif()

project(ntfs2btrfs VERSION 20210523)

option(WITH_ZLIB "Include zlib support" ON)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/src/config.h.in ${CMAKE_CURRENT_BINARY_DIR}/config.h)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(fmt REQUIRED)

if(WITH_ZLIB)
    find_package(ZLIB REQUIRED)
endif()

set(SRC_FILES src/ntfs2btrfs.cpp
    src/ntfs.cpp
    src/decomp.cpp
    src/compress.cpp
    src/crc32c.c
    src/ebiggers/lzx_decompress.c
    src/ebiggers/lzx_common.c
    src/ebiggers/aligned_malloc.c
    src/ebiggers/decompress_common.c
    src/ebiggers/xpress_decompress.c)

if(MSVC)
    enable_language(ASM_MASM)
    set(SRC_FILES ${SRC_FILES} src/crc32c-masm.asm)
else()
    enable_language(ASM)
    set(SRC_FILES ${SRC_FILES} src/crc32c-gas.S)
endif()

add_executable(ntfs2btrfs ${SRC_FILES})
set_property(TARGET ntfs2btrfs PROPERTY
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

target_link_libraries(ntfs2btrfs fmt::fmt-header-only)

if(WITH_ZLIB)
    target_link_libraries(ntfs2btrfs ZLIB::ZLIB)
endif()

include_directories(${CMAKE_CURRENT_BINARY_DIR})

# Work around bug in MSVC version of cmake - see https://gitlab.kitware.com/cmake/cmake/-/merge_requests/4257
set(CMAKE_ASM_MASM_COMPILE_OPTIONS_MSVC_RUNTIME_LIBRARY_MultiThreaded         "")
set(CMAKE_ASM_MASM_COMPILE_OPTIONS_MSVC_RUNTIME_LIBRARY_MultiThreadedDLL      "")
set(CMAKE_ASM_MASM_COMPILE_OPTIONS_MSVC_RUNTIME_LIBRARY_MultiThreadedDebug    "")
set(CMAKE_ASM_MASM_COMPILE_OPTIONS_MSVC_RUNTIME_LIBRARY_MultiThreadedDebugDLL "")

if(MSVC)
    target_compile_options(ntfs2btrfs PRIVATE /W4)
else()
    target_compile_options(ntfs2btrfs PRIVATE -Wall -Wextra -Wno-address-of-packed-member -Wconversion -Wno-unknown-pragmas -Werror=pointer-arith)
endif()

install(TARGETS ntfs2btrfs DESTINATION bin)
