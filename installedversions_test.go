package artifact

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// InstalledVersions is the other direction from PrefixOf: that one composes
// a path from a version somebody already resolved, this one asks the store
// what is actually there. Nothing asked that until a browser wanted to mark
// what you already have.
func TestInstalledVersions(t *testing.T) {
	dir := t.TempDir()
	for _, v := range []string{"v1.9", "v1.10", "v2.0.0"} {
		if err := os.MkdirAll(filepath.Join(dir, "gnu.org/bash", v, "bin"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// The aliases writeVersionLinks leaves beside them. Counted as
	// versions, one install would look like three.
	for _, a := range []string{"v*", "v2", "v2.0"} {
		if err := os.Symlink("v2.0.0", filepath.Join(dir, "gnu.org/bash", a)); err != nil {
			t.Fatal(err)
		}
	}
	// And things that are not versions at all.
	if err := os.MkdirAll(filepath.Join(dir, "gnu.org/bash", "var"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "gnu.org/bash", "v9.9"), []byte("a file"), 0o644); err != nil {
		t.Fatal(err)
	}

	got := InstalledVersions("gnu.org/bash", dir)
	if strings.Join(got, " ") != "2.0.0 1.10 1.9" {
		t.Errorf("InstalledVersions = %v, want [2.0.0 1.10 1.9]", got)
	}

	// NEWEST FIRST BY VERSION, and that is the whole reason this does not
	// just return the directory listing: alphabetically "v1.9" sorts above
	// "v1.10", so the first entry would be the wrong one to put beside a
	// project's name.
	if got[0] != "2.0.0" {
		t.Errorf("newest = %q", got[0])
	}
	if len(got) > 2 && got[1] != "1.10" {
		t.Errorf("second = %q, want 1.10 — a name sort would say 1.9", got[1])
	}

	// Nothing installed is not an error: it is the normal state of almost
	// every project in a catalogue of two thousand.
	if v := InstalledVersions("never.installed", dir); v != nil {
		t.Errorf("an absent project returned %v", v)
	}
	if v := InstalledVersions("gnu.org/bash", filepath.Join(dir, "no-such-store")); v != nil {
		t.Errorf("an absent store returned %v", v)
	}
}

// And it agrees with PrefixOf, which is the only other place the store's
// layout is written down on the reading side.
func TestInstalledVersionsAgreesWithPrefixOf(t *testing.T) {
	dir := t.TempDir()
	r := Resolved{Project: "zlib.net", Version: ParseVer("1.3.2")}
	prefix := PrefixOf("zlib.net", []Resolved{r}, dir)
	if err := os.MkdirAll(prefix, 0o755); err != nil {
		t.Fatal(err)
	}
	got := InstalledVersions("zlib.net", dir)
	if len(got) != 1 || got[0] != "1.3.2" {
		t.Fatalf("InstalledVersions = %v after creating %s", got, prefix)
	}
	if filepath.Join(dir, "zlib.net", "v"+got[0]) != prefix {
		t.Error("the two halves of the convention disagree")
	}
}
