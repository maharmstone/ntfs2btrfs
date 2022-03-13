Ntfs2btrfs
==========

Ntfs2btrfs is a tool which does in-place conversion of Microsoft's NTFS
filesystem to the open-source filesystem Btrfs, much as `btrfs-convert`
does for ext2. The original image is saved as a reflink copy at
`image/ntfs.img`, and if you want to keep the conversion you can delete
this to free up space.

Although I believe this tool to be stable, please note that I take no
responsibility if something goes awry!

You're probably also interested in [WinBtrfs](https://github.com/maharmstone/btrfs),
which is a Btrfs filesystem driver for Windows.

Thanks to [Eric Biggers](https://github.com/ebiggers), who [successfully reverse-engineered](https://github.com/ebiggers/ntfs-3g-system-compression/) Windows 10's
"WOF compressed data", and whose code I've used here.

Usage
-----

On Windows, from an Administrator command prompt:

`ntfs2btrfs.exe D:\`

Bear in mind that it won't work with your boot drive or a drive containing a
pagefile that's currently in use.

On Linux, as root:

`ntfs2btrfs /dev/sda1`

Installation
------------

On Windows, go to the [Releases page](https://github.com/maharmstone/ntfs2btrfs/releases) and
download the latest Zip file, or use [Scoop](https://github.com/ScoopInstaller/Main/blob/master/bucket/ntfs2btrfs.json).

For Linux:
* [Arch](https://aur.archlinux.org/packages/ntfs2btrfs-git) (thanks to [nicman23](https://github.com/nicman23))
* [Fedora](https://src.fedoraproject.org/rpms/ntfs2btrfs) (thanks to [Conan-Kudo](https://github.com/Conan-Kudo))
* [Gentoo ebuild](https://raw.githubusercontent.com/maharmstone/ntfs2btrfs/master/ntfs2btrfs-20210923.ebuild)
* [Debian & Ubuntu](https://sid.ethz.ch/debian/ntfs2btrfs/) (thanks to [alexmyczko](https://github.com/alexmyczko))

For other distributions or operating systems, you will need to compile it yourself - see
below.

Changelog
---------

* 20210923
  * Added (Btrfs) compression support (zlib, lzo, and zstd)
  * Added support for other hash algorithms: xxhash, sha256, and blake2
  * Added support for rolling back to NTFS
  * Added support for NT4-style security descriptors
  * Increased conversion speed for volume with many inodes
  * Fixed bug when fragmented file was in superblock location
  * Fixed buffer overflow when reading security descriptors
  * Fixed bug where filesystems would be corrupted in a way that `btrfs check` doesn't pick up

* 20210523
  * Improved handling of large compressed files

* 20210402 (source code only release)
  * Fixes for compilation on non-amd64 architectures

* 20210105
  * Added support for NTFS compression
  * Added support for "WOF compressed data"
  * Fixed problems caused by sparse files
  * Miscellaneous bug fixes

* 20201108
  * Improved error handling
  * Added better message if NTFS is corrupted or unclean
  * Better handling of relocations

* 20200330
  * Initial release

Compilation
-----------

On Windows, open the source directory in a recent version of MSVC, right-click
on CMakeLists.txt, and click Compile.

On Linux:

    cmake .
    make

You'll also need [libfmt](https://github.com/fmtlib/fmt) installed - it should be
in your package manager.

Compression support requires zlib, lzo, and/or zstd - again, they will be in your
package manager. See also the cmake options WITH_ZLIB, WITH_LZO, and WITH_ZSTD,
if you want to disable this.

What works
----------

* Files
* Directories
* Symlinks
* Other reparse points
* Security descriptors
* Alternate data streams
* DOS attributes (hidden, system, etc.)
* Rollback to original NTFS image

What doesn't work
-----------------

* Windows' old extended attributes (you're not using these)
* Large (i.e >16KB) ADSes (you're not using these either)
* Preservation of LXSS metadata
* Preservation of the case-sensitivity flag
* Unusual cluster sizes (i.e. not 4 KB)
* Encrypted files

Can I boot Windows from Btrfs with this?
----------------------------------------

Yes, if the stars are right. See [Quibble](https://github.com/maharmstone/quibble).
