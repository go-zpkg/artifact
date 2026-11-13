package artifact

import (
	"slices"
	"testing"
)

// raws is the Raw of each selected version, for assertions that care about
// WHICH versions survived rather than how they sort.
func raws(vs []Ver) []string {
	out := make([]string, len(vs))
	for i, v := range vs {
		out[i] = v.Raw
	}
	return out
}

// ⛔⛔ A REBUILD MUST NOT DELETE THE BUILD IT SUPERSEDES FROM THE LISTING.
//
// numericKey read v.Nums alone and the rebuild counter is not in v.Nums, so
// `3.3.11` and `3.3.11_1` shared one key, selectVersions kept one and dropped
// the other. Superseding is a question of ORDER — cmpVer answers it, and
// TestARebuildSupersedesTheVersionItRebuilds pins that — not a licence to
// delete the loser from the candidate list.
//
// Measured on ghcr.io/go-zpkg/packages/fftw.org, which publishes both tags:
// VersionsFor returned 3.3.11_1 alone, so `=3.3.11` resolved to NOTHING while
// the artifact sat in the registry, pullable. Rebuilding an artifact silently broke
// every lock that pinned the version it rebuilt.
func TestARebuildDoesNotHideTheVersionItRebuilds(t *testing.T) {
	got := raws(selectVersions([]string{"3.3.10", "3.3.11", "3.3.11_1"}, ""))
	for _, want := range []string{"3.3.10", "3.3.11", "3.3.11_1"} {
		if !slices.Contains(got, want) {
			t.Errorf("selectVersions dropped %q; got %v", want, got)
		}
	}
	// AND the rebuild still sorts last, so "the newest" is still the rebuild.
	// Without this the fix could be "never dedup", which would reinstate the
	// listing-order dependence selectVersions exists to remove.
	if len(got) > 0 && got[len(got)-1] != "3.3.11_1" {
		t.Errorf("the newest is %q, want the rebuild 3.3.11_1 (got %v)", got[len(got)-1], got)
	}
}

// Several rebuilds of one version are several artifacts, and each is pinnable.
func TestEveryRebuildOfAVersionSurvives(t *testing.T) {
	got := raws(selectVersions([]string{"1.8.2", "1.8.2_1", "1.8.2_2"}, ""))
	if len(got) != 3 {
		t.Errorf("selectVersions = %v, want all three builds", got)
	}
}

// AND THE DEDUP THIS KEY EXISTS FOR IS UNTOUCHED — without this control, the
// fix could be "put the raw tag in the key", which would let gnu.org/glibc's
// 2.44 and 2.44.0 both through and reinstate the defect numericKey was written
// against: two glibc trees installed side by side.
//
// Both halves are asserted, because a rebuild counter in the key must not stop
// two SPELLINGS of one build from collapsing either.
func TestTwoSpellingsOfOneBuildStillCollapse(t *testing.T) {
	if got := selectVersions([]string{"2.44", "2.44.0"}, ""); len(got) != 1 {
		t.Errorf("selectVersions(2.44, 2.44.0) = %v, want one version", raws(got))
	}
	if got := selectVersions([]string{"3.3.11_1", "v3.3.11_1"}, ""); len(got) != 1 {
		t.Errorf("selectVersions(3.3.11_1, v3.3.11_1) = %v, want one build", raws(got))
	}
}

// The identity itself, stated directly: equal keys mean "the same artifact".
func TestNumericKeySeparatesBuildsAndJoinsSpellings(t *testing.T) {
	for _, c := range []struct {
		a, b string
		same bool
	}{
		{"3.3.11", "3.3.11_1", false},   // different builds
		{"3.3.11_1", "3.3.11_2", false}, // different builds
		{"3.3.11_1", "v3.3.11_1", true}, // one build, two spellings
		{"2.44", "2.44.0", true},        // one release, two spellings
	} {
		ka, kb := numericKey(ParseVer(c.a)), numericKey(ParseVer(c.b))
		if (ka == kb) != c.same {
			t.Errorf("numericKey(%q)=%q, numericKey(%q)=%q; same=%v, want %v",
				c.a, ka, c.b, kb, ka == kb, c.same)
		}
	}
}
