if(MSVC)
    cmake_minimum_required(VERSION 3.15)
    cmake_policy(SET CMP0091 NEW)
else()
    cmake_minimum_required(VERSION 3.14.3)
endif()

project(ntfs2btrfs VERSION 20200330)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/src/config.h.in ${CMAKE_CURRENT_BINARY_DIR}/config.h)

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
set_property(TARGET ntfs2btrfs PROPERTY
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

include_directories(${CMAKE_CURRENT_BINARY_DIR})

# Work around bug in MSVC version of cmake - see https://gitlab.kitware.com/cmake/cmake/-/merge_requests/4257
set(CMAKE_ASM_MASM_COMPILE_OPTIONS_MSVC_RUNTIME_LIBRARY_MultiThreaded         "")
set(CMAKE_ASM_MASM_COMPILE_OPTIONS_MSVC_RUNTIME_LIBRARY_MultiThreadedDLL      "")
set(CMAKE_ASM_MASM_COMPILE_OPTIONS_MSVC_RUNTIME_LIBRARY_MultiThreadedDebug    "")
set(CMAKE_ASM_MASM_COMPILE_OPTIONS_MSVC_RUNTIME_LIBRARY_MultiThreadedDebugDLL "")

if(MSVC)
    target_compile_options(ntfs2btrfs PRIVATE /W4)
else()
    target_compile_options(ntfs2btrfs PRIVATE -Wall -Wextra -Wno-address-of-packed-member)
endif()

install(TARGETS ntfs2btrfs DESTINATION bin)
