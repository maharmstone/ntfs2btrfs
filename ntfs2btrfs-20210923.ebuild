# Copyright 2021 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=8

inherit cmake

DESCRIPTION="Conversion tool from NTFS to Btrfs"
HOMEPAGE="https://github.com/maharmstone/ntfs2btrfs"

if [[ ${PV} = *9999 ]]; then
    inherit git-r3
    EGIT_REPO_URI="https://github.com/maharmstone/ntfs2btrfs.git"
else
	SRC_URI="https://github.com/maharmstone/${PN}/archive/${PV}.tar.gz -> ${P}.tar.gz"
	KEYWORDS="~amd64 ~arm ~arm64 ~ppc64 ~x86"
fi

LICENSE="GPL-2"
SLOT="0"
IUSE="+zlib +lzo +zstd"

DEPEND="dev-libs/libfmt
	zlib? ( sys-libs/zlib )
	lzo? ( dev-libs/lzo )
	zstd? ( app-arch/zstd )"
RDEPEND="${DEPEND}"
BDEPEND=""

src_prepare() {
	cmake_src_prepare
}

src_configure() {
	local mycmakeargs=(
		-DWITH_ZLIB=$(usex zlib)
		-DWITH_LZO=$(usex lzo)
		-DWITH_ZSTD=$(usex zstd)
	)

	cmake_src_configure
}
