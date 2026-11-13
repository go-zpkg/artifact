package artifact

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ⛔⛔ THIS FILE USED TO TEST THE VERSION ALIASES. IT NOW TESTS THAT THERE ARE
// NONE, AND THE HISTORY IS THE REASON.
//
// `writeVersionLinks` wrote `v{maj}`, `v{maj}.{min}` and `v*` beside each
// install — pkgx's convenience aliases — and `aliasAdvances` existed because
// the first version rewrote them unconditionally. Installing an OLDER line of
// a project then demoted the aliases onto it:
//
//	v*    -> v2.13.9   (after installing 2.13.9 beside 2.15.4)
//	v2    -> v2.13.9
//
// and every consumer bound to `v2` loaded the older library — the failure the
// ABI lines exist to end, reached from the other side. The fix was careful,
// and it was a careful fix to a problem created by having the alias at all.
//
// Each of those paths names a VERSION and not a BUILD. A store that offers
// one offers a way to address a package without saying which build is meant,
// which is the defect the hashed layout exists to end, one directory up. So
// they are gone, and the only thing left worth asserting is their absence.

// installAt makes the real directory an install makes: hashed, with a payload.
func installAt(t *testing.T, pkgxDir, project, raw string) string {
	t.Helper()
	v := ParseVer(raw)
	hash := StoreHash(v, "digest:"+project+"@"+raw, "")
	dir := StoreBuildPrefix(pkgxDir, project, v, hash)
	if err := os.MkdirAll(filepath.Join(dir, "lib"), 0o755); err != nil {
		t.Fatal(err)
	}
	return hash
}

// ⛔ EVERY ENTRY IN A PROJECT'S DIRECTORY CARRIES A HASH. Not `v2.15.4`, not
// `v2`, not `v2.15`, not `v*` — and not as a symlink either, because a
// symlink is a path too and the point is that no path addresses a version.
func TestAProjectDirectoryHoldsOnlyHashedBuilds(t *testing.T) {
	pkgx := t.TempDir()
	const proj = "gnome.org/libxml2"
	installAt(t, pkgx, proj, "2.15.4")
	installAt(t, pkgx, proj, "2.13.9")

	ents, err := os.ReadDir(filepath.Join(pkgx, proj))
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 2 {
		t.Fatalf("%d entries, want exactly the two builds: %v", len(ents), entryNames(ents))
	}
	for _, e := range ents {
		if !strings.Contains(e.Name(), variantSep) {
			t.Errorf("%q names a version and not a build", e.Name())
		}
		if e.Type()&os.ModeSymlink != 0 {
			t.Errorf("%q is a symlink — a link is a path too, and this one addresses a version", e.Name())
		}
		if _, ok := ParseStoreDirName(e.Name()); !ok {
			t.Errorf("%q does not read back as a build directory", e.Name())
		}
	}
}

// ⛔⛔ THE DEFECT THE OLD ALIAS LOGIC EXISTED FOR CANNOT RECUR, and this is
// the assertion that says why: installing an OLDER line after a newer one
// changes nothing about the newer one. There is no alias to demote.
func TestInstallingAnOlderLineCannotDemoteTheNewerOne(t *testing.T) {
	pkgx := t.TempDir()
	const proj = "gnome.org/libxml2"
	newHash := installAt(t, pkgx, proj, "2.15.4")
	newer := StoreBuildPrefix(pkgx, proj, ParseVer("2.15.4"), newHash)

	before, err := os.Stat(newer)
	if err != nil {
		t.Fatal(err)
	}
	installAt(t, pkgx, proj, "2.13.9")
	after, err := os.Stat(newer)
	if err != nil {
		t.Fatalf("the newer build went away when an older one was installed: %v", err)
	}
	if !os.SameFile(before, after) {
		t.Error("the newer build was replaced by installing an older line")
	}

	// And both are still addressable, each by its own hash.
	if got := InstalledBuilds(proj, pkgx); len(got) != 2 {
		t.Errorf("InstalledBuilds = %v, want both lines", got)
	}
}

// A VIEW is where a default lives, and it is outside the store — which is
// what lets a shared NFS export stay read-only and lets a container compute
// its own links at creation time.
func TestADefaultIsAViewAndNotAStoreEntry(t *testing.T) {
	// ⛔ A VIEW IS MADE OF SYMLINKS, AND WASI HAS NONE. Every other test in
	// this file asserts the ABSENCE of links, which needs no symlink support
	// — this one creates them, so it is the only one that has to skip.
	skipOnWASI(t, wasiNoSymlink)
	store := t.TempDir()
	view := t.TempDir()
	const proj = "a.org"
	hash := installAt(t, store, proj, "1.0.0")

	if err := LinkView(view, store, proj, ParseVer("1.0.0"), hash); err != nil {
		t.Fatal(err)
	}
	// The view has the version-named path…
	if _, err := os.Lstat(filepath.Join(view, proj, "v1.0.0")); err != nil {
		t.Errorf("the view has no v1.0.0: %v", err)
	}
	// …and the store still does not.
	if _, err := os.Lstat(filepath.Join(store, proj, "v1.0.0")); err == nil {
		t.Error("LinkView wrote into the STORE: a default is not a property of the store")
	}
}

// entryNames, not `names`: the package already has a `names` for DepNodes.
func entryNames(ents []os.DirEntry) []string {
	out := make([]string, 0, len(ents))
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out
}
