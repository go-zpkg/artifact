package artifact

import "testing"

// A companion is what a recipe says belongs in the same environment as itself,
// and some packages are unusable without theirs: rust-lang.org ships
// bin/cargo-clippy and bin/cargo-fmt and NO cargo, because cargo is the
// separate rust-lang.org/cargo project it names in `companions:`. Not reading
// the key is how a build that declares rust-lang.org and runs `cargo` died with
// `"cargo": executable file not found in $PATH` (#65).
func TestCompanionsAreRead(t *testing.T) {
	recipe := "dependencies:\n" +
		"  common.org/lib: '*'\n" +
		"companions:\n" +
		"  rust-lang.org/cargo: '*'\n" +
		"provides:\n  - bin/rustc\n"
	defer crossPantry(t, map[string]string{"rust-lang.org": recipe}, nil)()

	comps, err := CompanionsFor("rust-lang.org", "darwin", "aarch64")
	if err != nil {
		t.Fatal(err)
	}
	if comps["rust-lang.org/cargo"] != "*" {
		t.Errorf("companions = %v, want rust-lang.org/cargo", comps)
	}
	// A companion is not a dependency and must not become one.
	deps, _, err := FetchMetaFor("rust-lang.org", "darwin", "aarch64")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := deps["rust-lang.org/cargo"]; ok {
		t.Errorf("a companion leaked into the dependency map: %v", deps)
	}
}

// Companions are platform-keyed exactly as dependencies are — the two share
// their reduction — so reading them through the wrong slug gives the wrong
// environment just as silently.
func TestCompanionsArePlatformKeyed(t *testing.T) {
	recipe := "companions:\n" +
		"  common.org/tool: '*'\n" +
		"  linux:\n" +
		"    linux.org/only: '*'\n" +
		"  darwin:\n" +
		"    darwin.org/only: '*'\n"
	defer crossPantry(t, map[string]string{"x.org/tool": recipe}, nil)()

	for _, tc := range []struct{ osn, arch, want, notWant string }{
		{"linux", "x86-64", "linux.org/only", "darwin.org/only"},
		{"darwin", "aarch64", "darwin.org/only", "linux.org/only"},
	} {
		comps, err := CompanionsFor("x.org/tool", tc.osn, tc.arch)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := comps[tc.want]; !ok {
			t.Errorf("%s/%s: %s missing: %v", tc.osn, tc.arch, tc.want, comps)
		}
		if _, ok := comps[tc.notWant]; ok {
			t.Errorf("%s/%s: %s leaked: %v", tc.osn, tc.arch, tc.notWant, comps)
		}
		if _, ok := comps["common.org/tool"]; !ok {
			t.Errorf("%s/%s: unkeyed companion dropped: %v", tc.osn, tc.arch, comps)
		}
	}
}

// The overwhelming majority of recipes declare no companions at all. An absent
// key is an empty set, not an error.
func TestNoCompanionsIsNotAnError(t *testing.T) {
	defer crossPantry(t, map[string]string{"x.org/plain": "provides:\n  - bin/plain\n"}, nil)()
	comps, err := CompanionsFor("x.org/plain", "linux", "x86-64")
	if err != nil {
		t.Fatal(err)
	}
	if len(comps) != 0 {
		t.Errorf("companions = %v, want none", comps)
	}
}

// A recipe that cannot be fetched is an error, not an empty set: silently
// treating "I could not look" as "there are none" is the shape this whole
// issue took.
func TestCompanionsPropagateAFetchFailure(t *testing.T) {
	defer crossPantry(t, map[string]string{}, nil)()
	if _, err := CompanionsFor("x.org/absent", "linux", "x86-64"); err == nil {
		t.Error("a missing recipe reported no companions instead of an error")
	}
}

// A recipe that does not parse is an error too. Same reason as a fetch failure:
// an unreadable answer must not read as "none".
func TestCompanionsPropagateAParseFailure(t *testing.T) {
	defer crossPantry(t, map[string]string{"x.org/bad": "companions:\n  - this is a list\n  not: a map\n"}, nil)()
	if _, err := CompanionsFor("x.org/bad", "linux", "x86-64"); err == nil {
		t.Error("an unparseable recipe reported no companions instead of an error")
	}
}
