package artifact

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMergeClosures(t *testing.T) {
	a := []Resolved{{"a/x", ParseVer("1")}, {"b/y", ParseVer("2")}}
	b := []Resolved{{"b/y", ParseVer("2")}, {"c/z", ParseVer("3")}}
	got := MergeClosures(a, b)
	if len(got) != 3 {
		t.Fatalf("merged len=%d want 3", len(got))
	}
	seen := map[string]bool{}
	for _, r := range got {
		if seen[r.Project] {
			t.Errorf("duplicate project %s", r.Project)
		}
		seen[r.Project] = true
	}
}

func TestFindClosureBin(t *testing.T) {
	dir := t.TempDir()
	closure := []Resolved{{"gnu.org/bash", ParseVer("5.3.0")}}
	binDir := filepath.Join(dir, "gnu.org/bash", "v5.3.0", "bin")
	_ = os.MkdirAll(binDir, 0o755)
	_ = os.WriteFile(filepath.Join(binDir, "bash"), []byte("x"), 0o755)
	if got := FindClosureBin(closure, dir, "gnu.org/bash", "bash"); got == "" {
		t.Error("expected to find bash")
	}
	if got := FindClosureBin(closure, dir, "gnu.org/bash", "nope"); got != "" {
		t.Errorf("expected empty for missing bin, got %q", got)
	}
	if got := FindClosureBin(closure, dir, "not/in/closure", "x"); got != "" {
		t.Errorf("expected empty for absent project, got %q", got)
	}
}

func TestLoaderName(t *testing.T) {
	switch GOARCH() {
	case "aarch64":
		if LoaderName() != "ld-linux-aarch64.so.1" {
			t.Errorf("LoaderName=%q", LoaderName())
		}
	case "x86-64":
		if LoaderName() != "ld-linux-x86-64.so.2" {
			t.Errorf("LoaderName=%q", LoaderName())
		}
	}
}

func TestFindLoader(t *testing.T) {
	dir := t.TempDir()
	name := map[string]string{"aarch64": "ld-linux-aarch64.so.1", "x86-64": "ld-linux-x86-64.so.2"}[GOARCH()]
	if name == "" {
		t.Skip("unmapped arch")
	}
	ldDir := filepath.Join(dir, "gnu.org/glibc/v2.44.0/lib/glibc-2.44")
	_ = os.MkdirAll(ldDir, 0o755)
	_ = os.WriteFile(filepath.Join(ldDir, name), []byte("x"), 0o755)
	if got := FindLoader(dir); got == "" || filepath.Base(got) != name {
		t.Errorf("FindLoader = %q", got)
	}
	if got := FindLoader(t.TempDir()); got != "" {
		t.Errorf("expected empty for missing loader, got %q", got)
	}
}

func TestPrimaryBin(t *testing.T) {
	// prefer the bin matching the project leaf over first-listed
	if got := PrimaryBin("perl.org", []string{"bin/corelist", "bin/perl"}); got != "perl" {
		t.Errorf("PrimaryBin perl = %q", got)
	}
	// fall back to first when no leaf match
	if got := PrimaryBin("acme.org/tool", []string{"bin/foo", "bin/bar"}); got != "foo" {
		t.Errorf("PrimaryBin fallback = %q", got)
	}
	// no provides -> project leaf
	if got := PrimaryBin("gnu.org/wget", nil); got != "wget" {
		t.Errorf("PrimaryBin no-provides = %q", got)
	}
}

func TestBinNames(t *testing.T) {
	if n := BinNames("gnu.org/wget", []string{"bin/wget", "share/x"}); len(n) != 1 || n[0] != "wget" {
		t.Errorf("BinNames provides = %v", n)
	}
	if n := BinNames("acme.org/tool", nil); len(n) != 1 || n[0] != "tool" {
		t.Errorf("BinNames fallback = %v", n)
	}
}

func TestResolveBinPath(t *testing.T) {
	// On non-windows hosts ResolveBinPath is the identity, regardless of what
	// sits on disk. (The ".exe" preference is exercised on the windows runner.)
	dir := t.TempDir()
	bin := filepath.Join(dir, "tool")
	_ = os.WriteFile(bin, []byte("x"), 0o755)
	if got := ResolveBinPath(bin); got != bin {
		t.Errorf("ResolveBinPath = %q, want %q", got, bin)
	}
	// A path that already carries .exe is returned verbatim on every platform.
	if got := ResolveBinPath(bin + ".exe"); got != bin+".exe" {
		t.Errorf("ResolveBinPath(.exe) = %q", got)
	}
}

func TestIsELF(t *testing.T) {
	dir := t.TempDir()
	elfp := filepath.Join(dir, "elf")
	_ = os.WriteFile(elfp, []byte{0x7f, 'E', 'L', 'F', 0, 0}, 0o755)
	scriptp := filepath.Join(dir, "script")
	_ = os.WriteFile(scriptp, []byte("#!/bin/sh\necho hi\n"), 0o755)
	if !IsELF(elfp) {
		t.Error("elf magic not detected")
	}
	if IsELF(scriptp) {
		t.Error("script wrongly detected as ELF")
	}
	if IsELF(filepath.Join(dir, "missing")) {
		t.Error("missing file should be false")
	}
}

// TestSetupScratchRootfsAt: a builder stages a rootfs it is not running on, so
// it cannot write /lib and /bin — those belong to the host. The rooted variant
// writes the same loader and /bin/sh into a staging directory instead, for the
// TARGET architecture, which need not be the host's.
func TestSetupScratchRootfsAt(t *testing.T) {
	skipOnWASI(t, wasiNoSymlink)
	root := t.TempDir()
	name := LoaderNameFor("x86-64")
	if name != "ld-linux-x86-64.so.2" {
		t.Fatalf("loader name = %q", name)
	}
	if err := SetupScratchRootfsAt(root, name, "/pkgx/gnu.org/glibc/v2.44.0/lib/glibc-2.44/"+name, "/pkgx/gnu.org/bash/v5.3/bin/bash"); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"lib", "lib64"} {
		got, err := os.Readlink(filepath.Join(root, d, name))
		if err != nil || !strings.HasSuffix(got, name) {
			t.Errorf("%s/%s -> %q, %v", d, name, got, err)
		}
	}
	// BOTH names. /bin/bash is not a convenience: the world's scripts say
	// `#!/bin/bash`, and an unresolvable shebang fails as if the script
	// itself were missing — which is how gnu.org/readline's test reported
	// `fork/exec …/glibc/v2.44/bin/ldd: no such file or directory` for a
	// bin/ldd that was right there.
	for _, name := range []string{"sh", "bash"} {
		got, err := os.Readlink(filepath.Join(root, "bin", name))
		if err != nil || !strings.HasSuffix(got, "/bash") {
			t.Errorf("bin/%s -> %q, %v", name, got, err)
		}
	}
	// Idempotent: a second staging pass over the same directory is not an error.
	if err := SetupScratchRootfsAt(root, name, "/x/"+name, "/x/sh"); err != nil {
		t.Errorf("second pass: %v", err)
	}
	// Nothing to do is not an error either.
	if err := SetupScratchRootfsAt(t.TempDir(), "", "", ""); err != nil {
		t.Errorf("empty: %v", err)
	}
	// An unwritable root is reported, both for the loader and for the shell.
	file := filepath.Join(t.TempDir(), "afile")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := SetupScratchRootfsAt(file, name, "/x/"+name, ""); err == nil {
		t.Error("expected an error under a regular file (loader)")
	}
	if err := SetupScratchRootfsAt(file, "", "", "/x/sh"); err == nil {
		t.Error("expected an error under a regular file (shell)")
	}
	// An unknown architecture has no loader to name.
	if LoaderNameFor("mips") != "" {
		t.Error("unknown arch must yield no loader name")
	}
}

// A directory that exists but cannot be written to is the other way staging
// fails: MkdirAll succeeds on it, the symlink does not.
func TestSetupScratchRootfsAtReadOnlyDir(t *testing.T) {
	name := LoaderNameFor("aarch64")

	root := t.TempDir()
	for _, d := range []string{"lib", "lib64"} {
		if err := os.Mkdir(filepath.Join(root, d), 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(filepath.Join(root, d), 0o755) })
	}
	if err := SetupScratchRootfsAt(root, name, "/x/"+name, ""); err == nil {
		t.Skip("this filesystem lets root write a read-only directory")
	}

	root2 := t.TempDir()
	if err := os.Mkdir(filepath.Join(root2, "bin"), 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(root2, "bin"), 0o755) })
	if err := SetupScratchRootfsAt(root2, "", "", "/x/sh"); err == nil {
		t.Error("expected the shell symlink to fail in a read-only dir")
	}
}

// A recipe may name its binary after its own version. apache.org/apr-util
// provides exactly one program, `bin/apu-{{ version.major }}-config`, and taken
// verbatim that is a file that exists nowhere:
//
//	pkgx: command not found in the requested packages: apu-{{ version.major }}-config
//
// Six pantry recipes put a moustache in a bin/ name; five also list a plain one
// and were saved by it. This is the sixth, and it is published for darwin.
func TestBinNamesForExpandsTheVersion(t *testing.T) {
	provides := []string{"bin/apu-{{ version.major }}-config"}
	if got := BinNamesFor("apache.org/apr-util", provides, "1.6.3"); len(got) != 1 || got[0] != "apu-1-config" {
		t.Errorf("BinNamesFor = %v, want [apu-1-config]", got)
	}
	if got := PrimaryBinFor("apache.org/apr-util", provides, "1.6.3"); got != "apu-1-config" {
		t.Errorf("PrimaryBinFor = %q, want apu-1-config", got)
	}
	// marketing and raw spellings, and a name with no moustache at all
	for _, c := range []struct{ prov, ver, want string }{
		{"bin/python{{ version.marketing }}", "3.11.16", "python3.11"},
		{"bin/foo-{{version.raw}}", "2.0.1", "foo-2.0.1"},
		{"bin/plain", "1.0.0", "plain"},
	} {
		if got := BinNamesFor("p", []string{c.prov}, c.ver); len(got) != 1 || got[0] != c.want {
			t.Errorf("%q at %s -> %v, want [%s]", c.prov, c.ver, got, c.want)
		}
	}
}

// With no version the caller is asking what the recipe SAYS. Expanding there
// would turn a placeholder into an empty string — one unusable name traded for
// a different unusable name — so the text is returned untouched.
func TestBinNamesWithoutAVersionIsVerbatim(t *testing.T) {
	got := BinNames("apache.org/apr-util", []string{"bin/apu-{{ version.major }}-config"})
	if len(got) != 1 || got[0] != "apu-{{ version.major }}-config" {
		t.Errorf("BinNames = %v, want the name verbatim", got)
	}
}

// s390x's loader is not named after its architecture, and that is the whole
// reason this entry cannot be derived: the other two read
// `ld-linux-<arch>.so.N`, and extending that pattern gives
// `ld-linux-s390x.so.1`, which does not exist.
//
// The name is asserted LITERALLY rather than through LoaderNameFor, so a
// change to the table is a change to this test too. It comes from our own
// s390x artefacts — 362 `ld64.so.1 is NEEDED` in that lane's logs with no
// `ld-linux-*.so` at all, and `readelf -l` on the published libc.so.6
// (go-zpkg/bk#263).
func TestLoaderNameForS390x(t *testing.T) {
	if got := LoaderNameFor("s390x"); got != "ld64.so.1" {
		t.Errorf("LoaderNameFor(s390x) = %q, want ld64.so.1", got)
	}
	// And NOT what the neighbouring pattern would give.
	if got := LoaderNameFor("s390x"); got == "ld-linux-s390x.so.1" {
		t.Error("the s390x entry was derived from the pattern, not from an artefact")
	}
	// The architectures bk is tested on but builds no artifact for stay absent:
	// there is no artefact to read a name out of, and a derived one is the
	// defect this test exists for.
	for _, arch := range []string{"ppc64le", "riscv64", "loong64"} {
		if got := LoaderNameFor(arch); got != "" {
			t.Errorf("LoaderNameFor(%s) = %q — added without an artefact to read it from", arch, got)
		}
	}
}
