package artifact

import (
	"os"
	"path/filepath"
	"testing"
)

// ⛔⛔ "ALREADY INSTALLED" MUST MEAN THE REQUESTED PREFIX IS THERE.
//
// InstallFor renames the unpacked tree onto `dest`, the directory the ARTIFACT
// carries — which is not always the version that was requested. A rebuild is
// published as `3.3.11_1` and still unpacks to `v3.3.11`.
//
// So installing a rebuild into a store that already held `v3.3.11` renamed
// onto an occupied directory, took the concurrent-install branch, and
// returned (false, nil): "already installed". Nothing was installed. The
// caller then ran a binary under a prefix that had never been created and
// got a bare "no such file or directory" — go-zpkg/bk#386, found on the
// first real use of the rebuild counter.
//
// Measured before the fix, against the published fftw.org 3.3.11_1:
//
//	Install         -> fresh=false err=<nil>
//	stat(v3.3.11_1) -> no such file or directory
//
// ⛔⛔ THE AMBIGUITY IS NOW UNCONSTRUCTIBLE, AND THIS TESTS THAT RATHER THAN
// THE OLD BRANCH. renameOrExplain used to TAKE `dest` from its caller, which
// is how `dest` came to be the archive's directory and could disagree with
// what was asked for. It now computes `dest` from the requested version and
// the build's hash, so there is no wrong destination left to detect — the
// property to check is that a rebuild and its base end up in DIFFERENT
// directories, with neither overwriting the other.
//
// Driven through the real install, not through the helper: a test of a
// helper's contract proves nothing once the contract has moved, and the
// defect bk#386 describes is about what ends up on disk.
func TestARebuildDoesNotLandOnTheVersionItSupersedes(t *testing.T) {
	defer fakeServer(t, map[string]fakePkg{
		"acme.org": {
			versions: []string{"1.2.3", "1.2.3_1"},
			yaml:     "provides:\n  - bin/tool\n",
			files:    map[string]string{"bin/tool": "base"},
		},
	})()
	dir := t.TempDir()

	if _, err := Install(Resolved{"acme.org", ParseVer("1.2.3")}, dir); err != nil {
		t.Fatalf("installing the base: %v", err)
	}
	if _, err := Install(Resolved{"acme.org", ParseVer("1.2.3_1")}, dir); err != nil {
		t.Fatalf("installing the rebuild: %v", err)
	}

	// Both are on disk, each under its own hashed directory, and the rebuild
	// did not land on the base. This is the half bk#386 got wrong: it
	// reported success having installed nothing.
	builds := InstalledBuilds("acme.org", dir)
	if len(builds) != 2 {
		t.Fatalf("InstalledBuilds = %v, want the base AND the rebuild", builds)
	}
	seen := map[string]bool{}
	for _, b := range builds {
		seen[b.Raw] = true
		if b.Variant == "" {
			t.Errorf("%s was installed without a hash in its path", b.Raw)
		}
		// And each really is a directory holding the payload, not an empty
		// shell or a link — "already installed" must mean the files are there.
		p := StoreBuildPrefix(dir, "acme.org", b, b.Variant)
		if _, err := os.Stat(filepath.Join(p, "bin", "tool")); err != nil {
			t.Errorf("%s has no payload: %v", b.Raw, err)
		}
	}
	for _, want := range []string{"1.2.3", "1.2.3_1"} {
		if !seen[want] {
			t.Errorf("%s is missing: %v", want, builds)
		}
	}
}

// AND A GENUINE CONCURRENT INSTALL IS STILL SILENT. `dest` is now unique to
// one build, so an occupied one can only mean another worker installed THIS
// build — which is the thing the old code had to infer from a second stat
// that raced against it.
func TestAGenuineConcurrentInstallIsStillReportedAsAlreadyPresent(t *testing.T) {
	dir := t.TempDir()
	v := ParseVer("1.2.3")
	const hash = "aaaaaaaaaaaaaaaa"
	if err := os.MkdirAll(StoreBuildPrefix(dir, "acme.org", v, hash), 0o755); err != nil {
		t.Fatal(err)
	}
	fresh, err := renameOrExplain(filepath.Join(dir, "nonexistent-src"), dir, "acme.org", v, hash)
	if err != nil {
		t.Fatalf("a concurrent install was reported as a failure: %v", err)
	}
	if fresh {
		t.Error("a concurrent install was reported as fresh")
	}
}

// A rename that fails for a reason that is NOT an occupied destination is
// still an error: "already installed" must not swallow a full disk or a
// permission denial.
func TestARenameThatFailsForAnotherReasonIsStillAnError(t *testing.T) {
	dir := t.TempDir()
	v := ParseVer("1.2.3")
	if _, err := renameOrExplain(filepath.Join(dir, "nonexistent-src"), dir, "acme.org", v, "aaaaaaaaaaaaaaaa"); err == nil {
		t.Error("renaming a source that does not exist was reported as success")
	}
}
