package artifact

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// stagedClosure lays out a closure on disk under hostDir the way InstallFor
// would, and returns it.
func stagedClosure(t *testing.T, hostDir string) []Resolved {
	t.Helper()
	clo := []Resolved{
		{Project: "acme.org/tool", Version: ParseVer("1.2.3")},
		{Project: GlibcProject, Version: ParseVer("2.44.0")},
	}
	for _, r := range clo {
		prefix := filepath.Join(hostDir, r.Project, "v"+r.Version.Raw)
		for _, sub := range []string{"bin", "lib"} {
			if err := os.MkdirAll(filepath.Join(prefix, sub), 0o755); err != nil {
				t.Fatal(err)
			}
		}
	}
	bin := filepath.Join(hostDir, "acme.org/tool", "v1.2.3", "bin", "tool")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	// glibc's versioned sub-libdir, which LibDirs picks up by glob.
	if err := os.MkdirAll(filepath.Join(hostDir, GlibcProject, "v2.44.0", "lib", "glibc-2.44"), 0o755); err != nil {
		t.Fatal(err)
	}
	return clo
}

// TestStubBinsStagedBakesGuestPaths is the defect this API exists to prevent:
// a stub written on the builder must name the paths the GUEST will have, or
// every binary in the image points at a directory that does not exist there.
func TestStubBinsStagedBakesGuestPaths(t *testing.T) {
	root := t.TempDir()
	hostDir := filepath.Join(root, "rootfs", "pkgx")
	clo := stagedClosure(t, hostDir)
	defer fakeServer(t, map[string]fakePkg{
		"acme.org/tool": {versions: []string{"1.2.3"}, yaml: "provides:\n  - bin/tool\n"},
		GlibcProject:    {versions: []string{"2.44.0"}, yaml: "provides:\n  - lib/libc.so.6\n"},
	})()

	n, err := StubBinsStaged(clo, Stage{
		Dir:      hostDir,
		GuestDir: "/pkgx",
		Prefix:   filepath.Join(root, "rootfs", "usr"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("wrote %d stubs, want 1", n)
	}

	b, err := os.ReadFile(filepath.Join(root, "rootfs", "usr", "bin", "tool"))
	if err != nil {
		t.Fatal(err)
	}
	stub := string(b)
	if strings.Contains(stub, root) {
		t.Errorf("stub leaks the staging path %q:\n%s", root, stub)
	}
	if !strings.Contains(stub, `exec "/pkgx/acme.org/tool/v1.2.3/bin/tool"`) {
		t.Errorf("stub does not exec the guest path:\n%s", stub)
	}
	if !strings.Contains(stub, "/pkgx/"+GlibcProject+"/v2.44.0/lib/glibc-2.44") {
		t.Errorf("LD_LIBRARY_PATH was not rewritten to guest paths:\n%s", stub)
	}
}

// TestStubBinsUnstagedIsUnchanged: pkgm installs onto the machine it runs on,
// where staging and running paths are the same. That path must keep working
// byte for byte.
func TestStubBinsUnstagedIsUnchanged(t *testing.T) {
	root := t.TempDir()
	hostDir := filepath.Join(root, "pkgx")
	clo := stagedClosure(t, hostDir)
	defer fakeServer(t, map[string]fakePkg{
		"acme.org/tool": {versions: []string{"1.2.3"}, yaml: "provides:\n  - bin/tool\n"},
		GlibcProject:    {versions: []string{"2.44.0"}, yaml: "provides:\n  - lib/libc.so.6\n"},
	})()

	if _, err := StubBins(clo, hostDir, filepath.Join(root, "usr")); err != nil {
		t.Fatal(err)
	}

	b, err := os.ReadFile(filepath.Join(root, "usr", "bin", "tool"))
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(hostDir, "acme.org/tool", "v1.2.3", "bin", "tool")
	if !strings.Contains(string(b), `exec "`+want+`"`) {
		t.Errorf("unstaged stub changed:\n%s", b)
	}
}

// TestFindLoaderForTargetArch: the loader's ELF name is the TARGET's. Looking
// for the host's name in a rootfs staged for another arch finds nothing, and
// the image boots with no /lib/ld-linux at all.
func TestFindLoaderForTargetArch(t *testing.T) {
	dir := t.TempDir()
	libDir := filepath.Join(dir, GlibcProject, "v2.44.0", "lib", "glibc-2.44")
	if err := os.MkdirAll(libDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// s390x among them, and it is the one that matters here: its loader is
	// NOT named after the architecture, so a lookup built by extending
	// `ld-linux-<arch>.so.N` finds nothing in a tree where the file is
	// plainly there.
	for _, arch := range []string{"aarch64", "x86-64", "s390x"} {
		if err := os.WriteFile(filepath.Join(libDir, LoaderNameFor(arch)), []byte{0x7f, 'E', 'L', 'F'}, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	for _, arch := range []string{"aarch64", "x86-64", "s390x"} {
		got := FindLoaderFor(dir, arch)
		if filepath.Base(got) != LoaderNameFor(arch) {
			t.Errorf("FindLoaderFor(%s) = %q, want the %s loader", arch, got, arch)
		}
	}
	if got := FindLoaderFor(dir, "sparc64"); got != "" {
		t.Errorf("unknown arch resolved a loader: %q", got)
	}
}

// TestSetupScratchRootfsAtTargetLoader ties the pieces together: the staged
// rootfs must carry /lib and /lib64 symlinks named for the TARGET.
func TestSetupScratchRootfsAtTargetLoader(t *testing.T) {
	skipOnWASI(t, wasiNoSymlink)
	root := t.TempDir()
	target := "/pkgx/" + GlibcProject + "/v2.44.0/lib/glibc-2.44/ld-linux-x86-64.so.2"

	if err := SetupScratchRootfsAt(root, LoaderNameFor("x86-64"), target, "/pkgx/gnu.org/bash/v5.3/bin/bash"); err != nil {
		t.Fatal(err)
	}

	for _, d := range []string{"lib", "lib64"} {
		link := filepath.Join(root, d, "ld-linux-x86-64.so.2")
		got, err := os.Readlink(link)
		if err != nil {
			t.Fatalf("%s: %v", link, err)
		}
		if got != target {
			t.Errorf("%s -> %q, want %q", link, got, target)
		}
	}
	sh, err := os.Readlink(filepath.Join(root, "bin", "sh"))
	if err != nil {
		t.Fatal(err)
	}
	if sh != "/pkgx/gnu.org/bash/v5.3/bin/bash" {
		t.Errorf("/bin/sh -> %q", sh)
	}
}
