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

Usage
-----

On Windows, from an Administrator command prompt:

`ntfs2btrfs.exe D:\`

Bear in mind that it won't work with your boot drive or a drive with a
pagefile on it.

On Linux, as root:

`ntfs2btrfs /dev/sda1`

Installation
------------

On Windows, go to the [Releases page](https://github.com/maharmstone/ntfs2btrfs/releases) and
download the latest Zip file.

For Linux or other operating systems, you will need to compile it yourself - see
below.

Changelog
---------

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

What works
----------

* Files
* Directories
* Symlinks
* Other reparse points
* Security descriptors
* Alternate data streams
* DOS attributes (hidden, system, etc.)

What doesn't work
-----------------

* Rollback to original NTFS image
* Windows' old extended attributes (you're not using these)
* Large (i.e >16KB) ADSes (you're not using these either)
* Preservation of LXSS metadata
* Preservation of the case-sensitivity flag
* Unusual cluster sizes (i.e. not 4 KB)
* Compressed files (skipped for now)
* Encrypted files
* "WofCompressedData" (see https://devblogs.microsoft.com/oldnewthing/20190618-00/?p=102597)

Can I boot Windows from Btrfs with this?
----------------------------------------

Yes, if the stars are right. See [Quibble](https://github.com/maharmstone/quibble).
