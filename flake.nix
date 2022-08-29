{
  description = "A tool for in-place conversion of Microsoft's NTFS filesystem to the open-source filesystem Btrfs, much as btrfs-convert does for ext2";

  inputs.nixpkgs.url = github:NixOS/nixpkgs/nixos-unstable;

  outputs = { self, nixpkgs }: {

    defaultPackage.x86_64-linux =
      with import nixpkgs { system = "x86_64-linux"; };
      stdenv.mkDerivation {
        name = "ntfs2btrfs";
        src = self;
        buildInputs = [
          cmake
          fmt_8
          pkg-config
          zlib
          lzo
          zstd
        ];
        buildPhase = ''
          cmake .
          make -j $NIX_BUILD_CORES
        '';
        installPhase = "mkdir -p $out/bin; install -t $out/bin ntfs2btrfs";
      };

  };
}
