package artifact

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAStoreSaysWhatItHolds(t *testing.T) {
	dir := t.TempDir()
	MarkStorePlatform(dir, "linux", "x86-64")

	osn, arch, ok := StorePlatform(dir)
	if !ok || osn != "linux" || arch != "x86-64" {
		t.Fatalf("read back %q/%q/%v", osn, arch, ok)
	}
	// ⛔ IT DOES NOT ARGUE WITH ITSELF. A second install must not rewrite the
	// marker — on a cluster thousands of ranks reach this line at once, and a
	// value that moves is a mismatch that is not real.
	MarkStorePlatform(dir, "linux", "aarch64")
	if osn, arch, _ := StorePlatform(dir); osn != "linux" || arch != "x86-64" {
		t.Errorf("the marker was overwritten: %q/%q", osn, arch)
	}
}

// ⛔ SILENCE IS AGREEMENT. Every store written before the marker existed says
// nothing, and refusing to run on those would break the installed base to fix
// a case none of them is in.
func TestAStoreThatDoesNotSayIsNotAMismatch(t *testing.T) {
	dir := t.TempDir()
	if _, _, ok := StorePlatform(dir); ok {
		t.Fatal("an unmarked store must not claim a platform")
	}
	if err := CheckStorePlatform(dir, "linux", "aarch64"); err != nil {
		t.Errorf("an unmarked store must pass: %v", err)
	}
}

// The case this exists for: a store populated by one architecture, read by
// another, over a shared filesystem.
func TestASharedStoreOfTheWrongArchitectureIsRefusedWithAnExplanation(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "pkgx")
	MarkStorePlatform(dir, "linux", "x86-64")

	err := CheckStorePlatform(dir, "linux", "aarch64")
	if err == nil {
		t.Fatal("want an error")
	}
	// The message has to carry what a person needs to act: both platforms,
	// the directory, and the way out.
	for _, want := range []string{"linux/x86-64", "linux/aarch64", dir, "{platform}"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the message omits %q: %v", want, err)
		}
	}
	// And the matching platform passes, or the check would refuse everything.
	if err := CheckStorePlatform(dir, "linux", "x86-64"); err != nil {
		t.Errorf("the right platform must pass: %v", err)
	}
}

// ⛔ A MARKER NOBODY CAN WRITE IS NOT A FAILURE. A read-only store is somebody's
// deliberate arrangement — a materialised squashfs on a compute node is exactly
// that — and refusing to run because a note could not be left would break the
// case this was written to help.
func TestAnUnwritableStoreIsNotAnError(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ro")
	if err := os.MkdirAll(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

	MarkStorePlatform(dir, "linux", "x86-64") // must not panic, must not fail
	if _, _, ok := StorePlatform(dir); ok {
		t.Skip("this filesystem ignored the read-only mode; the case cannot be posed here")
	}
	if err := CheckStorePlatform(dir, "linux", "aarch64"); err != nil {
		t.Errorf("a store that could not say must not be a mismatch: %v", err)
	}
}

// ⛔ THE WIRING, which is the one line that would otherwise go untested.
// MarkStorePlatform is called from InstallFor, and a marker that is written
// only by the tests is a feature nobody has. Driven through the early return
// for a prefix that is already present, so no network is needed: the point is
// that the store learns its platform on the way past, not that an artifact
// arrives.
func TestInstallForTellsTheStoreItsPlatform(t *testing.T) {
	store := t.TempDir()
	r := Resolved{Project: "tool.org", Version: ParseVer("1.0.0")}
	if err := os.MkdirAll(filepath.Join(store, "tool.org", "v1.0.0"), 0o755); err != nil {
		t.Fatal(err)
	}

	installed, err := InstallFor(r, store, "linux", "x86-64")
	if err != nil || installed {
		t.Fatalf("InstallFor = %v/%v, want false/nil for a prefix already there", installed, err)
	}
	osn, arch, ok := StorePlatform(store)
	if !ok || osn != "linux" || arch != "x86-64" {
		t.Fatalf("the store was not told its platform: %q/%q/%v", osn, arch, ok)
	}
	// And now it can refuse the other architecture, which is the whole point.
	if err := CheckStorePlatform(store, "linux", "aarch64"); err == nil {
		t.Error("a store that knows it holds x86-64 must refuse aarch64")
	}
}

// ⛔ AN INVALID PROJECT NAME MARKS NOTHING. The name check builds the path
// that gets written to, so it runs first; a store must not learn a platform
// from a call that was refused.
func TestARefusedInstallDoesNotMarkTheStore(t *testing.T) {
	store := t.TempDir()
	if _, err := InstallFor(Resolved{Project: "../..", Version: ParseVer("1.0")}, store, "linux", "x86-64"); err == nil {
		t.Fatal("a traversing project name must be refused")
	}
	if _, _, ok := StorePlatform(store); ok {
		t.Error("a refused install told the store its platform")
	}
}

// A marker somebody truncated, emptied or edited by hand says nothing rather
// than something wrong: a half value would be a mismatch nobody can explain.
func TestAMalformedMarkerSaysNothing(t *testing.T) {
	for _, body := range []string{"", "\n", "linux", "/x86-64", "linux/", "   "} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, StorePlatformFile), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, _, ok := StorePlatform(dir); ok {
			t.Errorf("%q was read as a platform", body)
		}
		if err := CheckStorePlatform(dir, "linux", "aarch64"); err != nil {
			t.Errorf("%q must not be a mismatch: %v", body, err)
		}
	}
	// Trailing whitespace is ordinary, and must still read.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, StorePlatformFile), []byte(" darwin/aarch64 \n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if osn, arch, ok := StorePlatform(dir); !ok || osn != "darwin" || arch != "aarch64" {
		t.Errorf("read back %q/%q/%v", osn, arch, ok)
	}
}
