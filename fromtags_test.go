package artifact

import "testing"

// ⛔ THE DEFECT, VERBATIM. `pkgs request nodejs.org` reported
//
//	state     published for darwin/aarch64 at 26.8.1
//
// an hour after 26.12.1 was published, because it ordered the tag listing
// with sort.Strings and "26.8.1" > "26.12.1" as text. Every fact under
// that line was then read off the index of the wrong version.
func TestTheNewestIsNumericNotAlphabetical(t *testing.T) {
	// The real listing, in the order a registry is free to return it.
	tags := []string{"26.8.0", "26.12.1", "26.8.1", "26.9.0", "26.10.3"}
	vs := VersionsFromTags(tags)
	if len(vs) != 5 {
		t.Fatalf("read %d version(s) from %d tag(s): %v", len(vs), len(tags), vs)
	}
	if got := vs[len(vs)-1].Raw; got != "26.12.1" {
		t.Errorf("newest = %q, want 26.12.1 — sorted as text, 26.8.1 wins", got)
	}
	// Oldest first, all the way: a caller may walk the list, not just its end.
	want := []string{"26.8.0", "26.8.1", "26.9.0", "26.10.3", "26.12.1"}
	for i, w := range want {
		if vs[i].Raw != w {
			t.Errorf("position %d is %q, want %q (full order: %v)", i, vs[i].Raw, w, vs)
		}
	}
}

// ⛔ ORDERING IS ONE OF THREE RULES, and a caller who copies only the
// ordering still gets the other two wrong. These two are what IsVersionTag
// plus a sort cannot do.
func TestItDropsForeignFlavoursAndFoldsSpellings(t *testing.T) {
	// "1.0.0" and "v1.0.0" are ONE version. Left separate, the pick depends
	// on the registry's listing order.
	if vs := VersionsFromTags([]string{"1.0.0", "v1.0.0"}); len(vs) != 1 {
		t.Errorf("two spellings of one version became %d: %v", len(vs), vs)
	}
	// A tag built against some other glibc is never this client's. The
	// flavour here cannot be the host's, whatever machine runs the suite.
	vs := VersionsFromTags([]string{"2.44", "2.44-glibc0.0.1"})
	if len(vs) != 1 {
		t.Fatalf("a foreign flavour was kept: %v", vs)
	}
	if vs[0].RegistryTag() != "2.44" {
		t.Errorf("tag = %q, want the unflavoured 2.44", vs[0].RegistryTag())
	}
}

// ⛔ RegistryTag IS NOT Raw. A caller that asked the registry for `Raw`
// where the tag is flavoured gets "platform not in index" — which reads as
// "we do not publish that for you" and means "I asked for a tag that does
// not exist".
func TestRegistryTagIsTheTagNotTheVersion(t *testing.T) {
	plain := ParseVer("1.2.3")
	if plain.RegistryTag() != "1.2.3" {
		t.Errorf("an unflavoured version's tag is %q", plain.RegistryTag())
	}
	flavoured := Ver{Raw: "2.44", Tag: "2.44-glibc2.27.0"}
	if got := flavoured.RegistryTag(); got != "2.44-glibc2.27.0" {
		t.Errorf("RegistryTag = %q, want the flavoured tag", got)
	}
	if flavoured.Raw == flavoured.RegistryTag() {
		t.Error("the fixture does not distinguish the two, so it proves nothing")
	}
}

// Nothing in, nothing out — and a listing that is ONLY referrer tags is
// empty, not one version. ghcr has no referrers API, so ORAS parks
// attestations as `sha256-<digest>` in the same listing.
func TestATagListingWithNoVersionIsEmpty(t *testing.T) {
	for _, tags := range [][]string{
		nil,
		{},
		{"sha256-1b6d86777009e1e502260a9408da230cfc8a5e6d6fd6f8a339d7b77348e6c330"},
		{"latest", "main"},
	} {
		if vs := VersionsFromTags(tags); len(vs) != 0 {
			t.Errorf("VersionsFromTags(%v) = %v, want none", tags, vs)
		}
	}
}
