package artifact

import (
	"os"
	"path/filepath"
	"testing"
)

// ⛔⛔ THE DEFECT THIS FILE IS THE CONTROL FOR.
//
// Before storepath.go, the installed path was `<dir>/<project>/v<version>`,
// composed inline at nine call sites. Two artifacts of one version that differ
// only in build options resolve to the same directory, so the second install
// meets the first and renameOrExplain refuses:
//
//	already holds other content … the artifact carries v3.3.11
//
// Correct behaviour on a wrong layout. The fix is not to relax the refusal —
// it is the only thing standing between a user and a silently replaced
// prefix — but to give the two builds different addresses.
func TestTwoBuildsOfOneVersionGetDifferentPrefixes(t *testing.T) {
	ver := Ver{Raw: "3.3.11", Nums: []int{3, 3, 11}}
	with := ver
	with.Variant = Concrete{Variants: Variants{"cuda": {"true"}}}.Hash()
	without := ver
	without.Variant = Concrete{Variants: Variants{"cuda": {"false"}}}.Hash()

	if with.Variant == "" || without.Variant == "" {
		t.Fatalf("a declared variant hashed to nothing: %q / %q", with.Variant, without.Variant)
	}
	a := StorePrefix("/store", "fftw.org", with)
	b := StorePrefix("/store", "fftw.org", without)
	if a == b {
		t.Fatalf("+cuda and ~cuda share a prefix: %s", a)
	}
	// And neither of them may collide with an artifact whose identity is simply
	// not recorded — that is a third, distinct thing.
	if c := StorePrefix("/store", "fftw.org", ver); c == a || c == b {
		t.Fatalf("an unrecorded identity collided with a recorded one: %s", c)
	}
}

// An artifact that arrived with no spec annotation keeps the path it has always
// had. Nothing is migrated and nothing is re-fetched: the layout extends, it
// does not move.
func TestAnUnrecordedIdentityKeepsThePlainPath(t *testing.T) {
	v := Ver{Raw: "1.2.13", Nums: []int{1, 2, 13}}
	want := filepath.Join("/store", "zlib.net", "v1.2.13")
	if got := StorePrefix("/store", "zlib.net", v); got != want {
		t.Errorf("StorePrefix = %q, want %q", got, want)
	}
}

// ⛔ A DIRECTORY NAME IS READ BACK BY THE SAME RULE THAT WROTE IT, and the
// hash is cut BEFORE ParseVer sees the name. Without that order a variant
// directory parses as a version whose Raw is `3.3.11-habcdefghij012345`: a
// string that matches no constraint, sorts below every real 3.3.11, and names
// a release that does not exist.
func TestAStoreDirectoryRoundTrips(t *testing.T) {
	for _, v := range []Ver{
		{Raw: "3.3.11", Nums: []int{3, 3, 11}},
		{Raw: "3.3.11", Nums: []int{3, 3, 11}, Variant: Concrete{Variants: Variants{"cuda": {"true"}}}.Hash()},
		{Raw: "1.1.1w", Nums: []int{1, 1, 1}},
		{Raw: "1.8.2_3", Nums: []int{1, 8, 2}, Rebuild: 3},
	} {
		name := StoreDirName(v)
		got, ok := ParseStoreDirName(name)
		if !ok {
			t.Errorf("%q did not read back as a version directory", name)
			continue
		}
		if got.Raw != v.Raw || got.Variant != v.Variant || got.Rebuild != v.Rebuild {
			t.Errorf("%q → Raw=%q Variant=%q Rebuild=%d; want %q, %q, %d",
				name, got.Raw, got.Variant, got.Rebuild, v.Raw, v.Variant, v.Rebuild)
		}
	}
}

// The aliases writeVersionLinks leaves beside the real directories, and a
// version that merely LOOKS like it carries a hash.
func TestWhatIsNotAVersionDirectory(t *testing.T) {
	for _, name := range []string{"v", "v*", "vendor", "bin", ".tmp", "1.2.3"} {
		if _, ok := ParseStoreDirName(name); ok {
			t.Errorf("%q was read as a version directory", name)
		}
	}
	// ⛔ `v1` AND `v1.2` ARE NOT ON THAT LIST, AND THE FIRST RUN OF THIS TEST
	// IS WHY. They are legitimate version spellings — an artifact really can be
	// version 1 — so nothing in the NAME tells them from the aliases
	// writeVersionLinks writes. What tells them apart is that the aliases are
	// SYMLINKS: os.ReadDir lstats, so their IsDir is false and InstalledBuilds
	// never offers them here. Asserting the name was asserting the wrong half
	// of the mechanism, and it would have passed only by forbidding a version
	// the registry can publish.
	if _, ok := ParseStoreDirName("v1"); !ok {
		t.Error("v1 was rejected by name — version 1 is a version")
	}
	// `-h2` is not hashLen characters, so it belongs to the version.
	v, ok := ParseStoreDirName("v1.0-h2")
	if !ok || v.Raw != "1.0-h2" || v.Variant != "" {
		t.Errorf("v1.0-h2 → ok=%v Raw=%q Variant=%q; the suffix is too short to be a hash", ok, v.Raw, v.Variant)
	}
}

// ⛔ TWO BUILDS ON DISK ARE ONE VERSION TO A CALLER ASKING ABOUT VERSIONS.
// `pkgx ls fftw.org` saying "3.3.11, 3.3.11" would be a defect report in the
// user's eyes, and the second entry carries no information they can act on.
func TestInstalledVersionsAndBuildsAnswerDifferentQuestions(t *testing.T) {
	dir := t.TempDir()
	hashA := Concrete{Variants: Variants{"cuda": {"true"}}}.Hash()
	hashB := Concrete{Variants: Variants{"cuda": {"false"}}}.Hash()
	for _, name := range []string{"v3.3.11", "v3.3.11-h" + hashA, "v3.3.11-h" + hashB, "v3.3.10"} {
		if err := os.MkdirAll(filepath.Join(dir, "fftw.org", name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// The alias, written the way writeVersionLinks writes it: a symlink.
	// Counted as a version it would make two installs look like three.
	if err := os.Symlink("v3.3.11", filepath.Join(dir, "fftw.org", "v3")); err != nil {
		t.Fatal(err)
	}
	vs := InstalledVersions("fftw.org", dir)
	if len(vs) != 2 || vs[0] != "3.3.11" || vs[1] != "3.3.10" {
		t.Errorf("InstalledVersions = %v, want [3.3.11 3.3.10]", vs)
	}
	builds := InstalledBuilds("fftw.org", dir)
	if len(builds) != 4 {
		t.Fatalf("InstalledBuilds = %v, want four (three of 3.3.11, one of 3.3.10)", builds)
	}
	// Newest first still holds across builds, and 3.3.10 is last.
	if builds[len(builds)-1].Raw != "3.3.10" {
		t.Errorf("InstalledBuilds is not newest-first: %v", builds)
	}
	// ⛔ AND NONE OF THEM IS NAMED AFTER ITS DIRECTORY. This is the assertion
	// that fails if the hash is cut after ParseVer rather than before.
	for _, b := range builds {
		if b.Raw != "3.3.11" && b.Raw != "3.3.10" {
			t.Errorf("a build is named %q — the variant hash leaked into the version", b.Raw)
		}
	}
}

// The directory name and the registry tag suffix are the same idea, and they
// must not drift into two spellings of it.
func TestTheStoreAndTheRegistryAgreeOnTheSuffix(t *testing.T) {
	c := Concrete{Platform: "linux/x86-64", Variants: Variants{"cuda": {"true"}}}
	tag := "3.3.11" + c.VariantTag()
	raw, hash := SplitVariantHash(tag)
	dirName := StoreDirName(Ver{Raw: raw, Variant: hash})
	if dirName != "v"+tag {
		t.Errorf("store directory %q does not match registry tag %q", dirName, tag)
	}
}
