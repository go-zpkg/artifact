package artifact

import (
	"slices"
	"testing"
)

// ⛔⛔ A REBUILD IS NOT A SPELLING OF THE VERSION IT REBUILDS.
//
// tagSpellings exists because `1.2` and `1.2.0` are one release written two
// ways, and it already refuses to drop a NON-ZERO component — "26.8.1" must
// never suggest "26.8.0", because that is a different release and answering
// about it made `pkgs ls` advertise a node nobody could install.
//
// It built those alternatives from v.Nums alone, and the rebuild counter is
// not in v.Nums. So for `3.3.11_1` it emitted:
//
//	3.3.11_1, 3.3.11, 3.3.11.0
//
// and `3.3.11` is the artifact WITHOUT the rebuild — a different build of the
// same sources, which is the whole reason the counter exists. PublishedTagFor
// walks these and asks the registry about each, so a lock pinning the rebuilt
// artifact would have been told "published" on finding the un-rebuilt one, and
// `bk catalog` would have advertised a rebuild that does not exist.
//
// That is the same defect rebuild_test.go was written about — "a lock pinning
// the REBUILT artifact would therefore have installed the un-rebuilt one, the
// vulnerable one, and said nothing" — arriving by a second route after the
// comparator was fixed against the first.
func TestARebuildHasNoShorterSpelling(t *testing.T) {
	got := tagSpellings(ParseVer("3.3.11_1"))
	if len(got) != 1 || got[0] != "3.3.11_1" {
		t.Errorf("tagSpellings(3.3.11_1) = %v, want exactly [3.3.11_1]", got)
	}
	// Named explicitly, because this is the one that does damage: it is a
	// DIFFERENT BUILD, and the registry answering about it is a wrong yes.
	if slices.Contains(got, "3.3.11") {
		t.Error("the un-rebuilt 3.3.11 is offered as a spelling of the rebuild 3.3.11_1")
	}
}

// AND THE ORDINARY CASE IS UNCHANGED, without which the fix above could be
// "return only the raw tag, always" — which would break the zero-extension
// this function exists for.
func TestAPlainVersionKeepsItsSpellings(t *testing.T) {
	got := tagSpellings(ParseVer("1.2"))
	for _, want := range []string{"1.2", "1.2.0"} {
		if !slices.Contains(got, want) {
			t.Errorf("tagSpellings(1.2) = %v, want it to contain %q", got, want)
		}
	}
	// And still no dropping of a non-zero component.
	if slices.Contains(tagSpellings(ParseVer("26.8.1")), "26.8.0") {
		t.Error("26.8.0 is offered as a spelling of 26.8.1")
	}
}

// A `_N` TAG IS A VERSION TAG, so a listing shows it rather than filtering it
// out as junk. Without this the counter would be written and then invisible,
// which is the shape of every half-wired field in this repository.
func TestARebuildTagIsListedAsAVersion(t *testing.T) {
	for _, tag := range []string{"3.3.11_1", "v3.3.11_1", "3.3.11"} {
		if !isVersionTag(tag) {
			t.Errorf("isVersionTag(%q) = false, so the rebuild would never be listed", tag)
		}
	}
	// And the referrer tags still are not versions.
	if isVersionTag("sha256-deadbeef") {
		t.Error("a referrer tag was read as a version")
	}
}

// ⛔ AND A REBUILD SORTS AFTER THE BUILD IT SUPERSEDES, which is what makes
// "the newest" pick it. cmpVer already does this; asserted here beside the
// spelling rule because the two together are what "supersedes" means, and a
// test for one without the other would let half of it rot.
func TestARebuildSupersedesTheVersionItRebuilds(t *testing.T) {
	plain, rebuilt := ParseVer("3.3.11"), ParseVer("3.3.11_1")
	if cmpVer(plain, rebuilt) >= 0 {
		t.Error("3.3.11_1 does not sort after 3.3.11, so the newest is not the rebuild")
	}
	if cmpVer(ParseVer("3.3.11_2"), rebuilt) <= 0 {
		t.Error("_2 does not sort after _1")
	}
	// A rebuild never outranks a real version bump.
	if cmpVer(ParseVer("3.3.11_9"), ParseVer("3.3.12")) >= 0 {
		t.Error("a rebuild outranks the next release")
	}
}
