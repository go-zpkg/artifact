package artifact

import (
	"os"
	"path/filepath"
	"testing"
)

func abiStore(t *testing.T, project, version string) (string, Resolved) {
	t.Helper()
	dir := t.TempDir()
	r := Resolved{Project: project, Version: Ver{Raw: version, Nums: []int{2, 15, 4}}}
	if err := os.MkdirAll(filepath.Join(dir, project, "v"+version), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir, r
}

// One link per ABI the artifact provides, pointing at the concrete version.
//
// v<major> holds ONE version, which is what breaks a project that changes its
// soname inside a major: libxml2 2.13.9 and 2.15.4 both claim v2. An
// abi-<soname> link is the same late binding keyed on what decides
// compatibility.
func TestWriteABILinks(t *testing.T) {
	dir, r := abiStore(t, "gnome.org/libxml2", "2.15.4")
	old := abiAnnotations
	defer func() { abiAnnotations = old }()
	abiAnnotations = func(string, string, string, string) map[string]string {
		return map[string]string{ABIProvidesAnnotation: "libxml2.16.dylib,libxml2.dylib"}
	}

	writeABILinks(dir, r, "darwin", "aarch64")

	for _, soname := range []string{"libxml2.16.dylib", "libxml2.dylib"} {
		p := filepath.Join(dir, "gnome.org/libxml2", "abi-"+soname)
		got, err := os.Readlink(p)
		if err != nil {
			t.Fatalf("abi-%s: %v", soname, err)
		}
		if got != "v2.15.4" {
			t.Errorf("abi-%s -> %q, want v2.15.4", soname, got)
		}
	}
}

// Two lines of one project, each reachable by its own ABI. This is the whole
// point: under v<major> alone the second install would steal the first's
// consumers.
func TestWriteABILinksKeepsBothLines(t *testing.T) {
	dir := t.TempDir()
	proj := "gnome.org/libxml2"
	old := abiAnnotations
	defer func() { abiAnnotations = old }()

	for _, tc := range []struct{ ver, soname string }{
		{"2.13.9", "libxml2.2.dylib"},
		{"2.15.4", "libxml2.16.dylib"},
	} {
		if err := os.MkdirAll(filepath.Join(dir, proj, "v"+tc.ver), 0o755); err != nil {
			t.Fatal(err)
		}
		soname := tc.soname
		abiAnnotations = func(string, string, string, string) map[string]string {
			return map[string]string{ABIProvidesAnnotation: soname}
		}
		writeABILinks(dir, Resolved{Project: proj, Version: Ver{Raw: tc.ver}}, "darwin", "aarch64")
	}
	for _, tc := range []struct{ link, want string }{
		{"abi-libxml2.2.dylib", "v2.13.9"},
		{"abi-libxml2.16.dylib", "v2.15.4"},
	} {
		got, err := os.Readlink(filepath.Join(dir, proj, tc.link))
		if err != nil || got != tc.want {
			t.Errorf("%s -> %q (%v), want %s", tc.link, got, err, tc.want)
		}
	}
}

// An artifact published before the annotation existed gets no links, and nothing
// else changes. This step is inert on its own by design.
func TestWriteABILinksWithoutTheAnnotation(t *testing.T) {
	dir, r := abiStore(t, "acme.org/thing", "1.0.0")
	old := abiAnnotations
	defer func() { abiAnnotations = old }()
	for _, ann := range []map[string]string{nil, {}, {ABIProvidesAnnotation: ""}} {
		a := ann
		abiAnnotations = func(string, string, string, string) map[string]string { return a }
		writeABILinks(dir, r, "darwin", "aarch64")
	}
	ents, err := os.ReadDir(filepath.Join(dir, "acme.org/thing"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if len(e.Name()) > 4 && e.Name()[:4] == "abi-" {
			t.Errorf("a link was written without an annotation: %s", e.Name())
		}
	}
}

// A soname is a bare filename. Anything carrying a separator would put the
// link somewhere else entirely, so it is refused rather than trusted.
func TestWriteABILinksRefusesAPath(t *testing.T) {
	dir, r := abiStore(t, "acme.org/thing", "1.0.0")
	old := abiAnnotations
	defer func() { abiAnnotations = old }()
	abiAnnotations = func(string, string, string, string) map[string]string {
		return map[string]string{ABIProvidesAnnotation: "../escape.dylib, ,.,..,ok.1.dylib"}
	}
	writeABILinks(dir, r, "darwin", "aarch64")

	if _, err := os.Lstat(filepath.Join(dir, "acme.org", "abi-escape.dylib")); err == nil {
		t.Error("a link escaped the project directory")
	}
	ents, _ := os.ReadDir(filepath.Join(dir, "acme.org/thing"))
	n := 0
	for _, e := range ents {
		if len(e.Name()) > 4 && e.Name()[:4] == "abi-" {
			n++
			if e.Name() != "abi-ok.1.dylib" {
				t.Errorf("unexpected link %s", e.Name())
			}
		}
	}
	if n != 1 {
		t.Errorf("%d links written, want 1", n)
	}
}

// PlatformAnnotations reads back what a publish attached, from the
// per-platform manifest and not from a mirror.
func TestPlatformAnnotations(t *testing.T) {
	t.Setenv("ZPKG_VERIFY", "0")
	fr := newFakeRegistry(t, false)
	defer fr.close()
	c, err := NewOCIClient(fr.base("go-zpkg/artifacts"))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{ABIProvidesAnnotation: "libabi.7.dylib"}
	if _, err := c.PushWithReferrersAnnotated("abi.test", "1.0.0", "linux", "aarch64",
		makeGzTarball("x"), ".tar.gz", nil, want); err != nil {
		t.Fatal(err)
	}
	got, err := c.PlatformAnnotations("abi.test", "1.0.0", "linux", "aarch64")
	if err != nil {
		t.Fatal(err)
	}
	if got[ABIProvidesAnnotation] != "libabi.7.dylib" {
		t.Errorf("annotations = %v", got)
	}

	// A tag nobody published is an error, not an empty map: "this artifact
	// declares nothing" and "there is no such artifact" are different answers.
	if _, err := c.PlatformAnnotations("abi.test", "9.9.9", "linux", "aarch64"); err == nil {
		t.Error("an unpublished tag returned annotations")
	}
	if _, err := c.PlatformAnnotations("not a project", "1.0.0", "linux", "aarch64"); err == nil {
		t.Error("an unusable project name returned annotations")
	}
}
