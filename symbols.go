package artifact

// Shared string symbols for the pkgx artifact ecosystem — named once here so
// artifact, bk and pkgm reference constants instead of scattering magic literals.
// (The OCI media types live near their use in oci.go as MediaLayer*, and
// the manifest annotation keys in verify.go as *Annotation; those are already
// named constants — this file gathers the remaining recurring literals.)
const (
	// The artifact tarball extensions; ext also selects the OCI layer media type
	// on push.
	//
	// Measured on real artifact payloads (25 MiB coreutils, 68 MiB llvm/lib/clang),
	// same machine, pure-Go codecs:
	//
	//	codec       ratio        compress   decompress
	//	gzip -6     3.50x/4.45x  1.4s       0.2s
	//	xz          6.85x/7.97x  3.5s       0.9s
	//	zstd -19    7.40x/8.89x  1.1s       ~0.0s
	//
	// zstd beats xz on all three axes, and gzip is the worst of both worlds: the
	// poorest ratio AND a slower decompression than zstd. Every install pays the
	// decompression; the factory pays the compression once.
	ExtTarGz  = ".tar.gz"
	ExtTarXz  = ".tar.xz"
	ExtTarZst = ".tar.zst"

	// GlibcProject is the pkgx project that provides the C library + loader; it
	// is the implicit from-scratch root on linux and the artifact whose manifest
	// carries the glibc min-kernel annotation.
	GlibcProject = "gnu.org/glibc"
)
