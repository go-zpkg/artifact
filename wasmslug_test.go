package artifact

import "testing"

// TestOsSlugNamesTheWasmHosts is the defect this fixes, measured before the
// change: this package compiles and passes for js/wasm and wasip1/wasm, so it
// runs in a browser and under a WASI runtime — and there HostSlug() answered
//
//	"linux" / "wasm"
//
// A consumer asking the registry for linux/wasm artifacts gets nothing, forever,
// with no hint as to why. The two hosts also stay distinct: a WASI guest and a
// browser import different things, so a module built for one is not an artifact
// for the other.
func TestOsSlugNamesTheWasmHosts(t *testing.T) {
	for _, tc := range []struct{ goos, want string }{
		{"js", "js"},
		{"wasip1", "wasip1"},
		{"darwin", "darwin"},
		{"windows", "windows"},
		{"linux", "linux"},
		// A BSD is NAMED, not approximated. "An exotic unix is closer to linux
		// than to nothing" was the old reading, and it is wrong in the one way
		// that matters: a linux artifact on FreeBSD does not load. Nothing is a
		// refusal you can act on; almost-right is an ELF that fails at the
		// first exec, having been chosen by a resolution that said yes.
		{"freebsd", "freebsd"},
		{"openbsd", "openbsd"},
		{"netbsd", "netbsd"},
		{"dragonfly", "dragonfly"},
		// android IS linux-like, and the fallback still suits it.
		{"android", "linux"},
	} {
		if got := osSlug(tc.goos); got != tc.want {
			t.Errorf("osSlug(%q) = %q, want %q", tc.goos, got, tc.want)
		}
	}
	if osSlug("js") == osSlug("wasip1") {
		t.Error("a browser and a WASI guest must not share a slug")
	}
}

// TestWasmHostHasNoElfLoader: the honest half was already right, and must stay
// so. There is no ld-linux in a browser, and a staging routine that thought
// otherwise would pose a symlink to nothing.
func TestWasmHostHasNoElfLoader(t *testing.T) {
	if got := LoaderNameFor("wasm"); got != "" {
		t.Errorf("LoaderNameFor(wasm) = %q, want empty", got)
	}
}

// TestHostSlugIsUsableAsARegistryPath: whatever the host, the two halves must
// be non-empty and free of separators, because they are pasted straight into
// a versions.txt URL and an OCI platform.
func TestHostSlugIsUsableAsARegistryPath(t *testing.T) {
	for _, goos := range []string{"js", "wasip1", "darwin", "windows", "linux", "freebsd"} {
		for _, goarch := range []string{"wasm", "arm64", "amd64", "riscv64"} {
			osn, arch := osSlug(goos), archSlug(goarch)
			if osn == "" || arch == "" {
				t.Errorf("%s/%s → %q/%q: empty half", goos, goarch, osn, arch)
			}
			for _, s := range []string{osn, arch} {
				for _, bad := range []rune{'/', ' ', ':'} {
					for _, r := range s {
						if r == bad {
							t.Errorf("%s/%s → %q/%q: %q is not path-safe", goos, goarch, osn, arch, s)
						}
					}
				}
			}
		}
	}
}

// TestPlatformKeysCoverEveryHostSlug is the invariant the js/wasm suite
// discovered the hard way: a recipe scopes a dependency block by OS name, and a
// name absent from platformKeys is read as a PROJECT. Adding an OS to osSlug
// without adding it here turns `js:` into a dependency on a package called
// "js" — silently, since both are well-formed YAML.
func TestPlatformKeysCoverEveryHostSlug(t *testing.T) {
	for _, goos := range []string{"linux", "darwin", "windows", "js", "wasip1", "freebsd"} {
		slug := osSlug(goos)
		if !isPlatformKey(slug) {
			t.Errorf("osSlug(%q) = %q, which no recipe can scope a block to", goos, slug)
		}
		if !isPlatformKey(slug + "/wasm") {
			t.Errorf("%q/<arch> is not recognised as a platform key", slug)
		}
	}
	// And a project name must NOT be mistaken for a platform.
	for _, notAPlatform := range []string{"openssl.org", "gnu.org/glibc", "linuxbrew.org"} {
		if isPlatformKey(notAPlatform) {
			t.Errorf("%q was taken for a platform key", notAPlatform)
		}
	}
}

// The two lists have to agree. A slug osSlug can answer with, and that
// platformKeys does not carry, turns a recipe's `freebsd:` block into a
// dependency on a project called "freebsd" — the same way the js/wasm suite
// found it for `js:`.
func TestEverySlugIsAPlatformKey(t *testing.T) {
	for _, goos := range []string{
		"linux", "darwin", "windows", "js", "wasip1",
		"freebsd", "openbsd", "netbsd", "dragonfly", "android",
	} {
		if slug := osSlug(goos); !isPlatformKey(slug) {
			t.Errorf("osSlug(%q) = %q, which no recipe can scope a block to", goos, slug)
		}
	}
}
