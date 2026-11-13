package artifact

import (
	"strings"
	"testing"
)

// ⛔ A SHORTER SPELLING IS ONLY THE SAME VERSION WHEN WHAT IT DROPS IS ZERO.
//
// Measured on the published registry, 2026-10-22: nodejs.org 26.8.1 has no
// linux/x86-64 artifact and 26.8.0 does. `publishedTagFor` walks these
// spellings and asks the registry about each, so with "26.8.0" in the list
// for 26.8.1 it got a hit on a DIFFERENT RELEASE and answered yes. `bk
// catalog` then recorded 26.8.1 as the version linux/x86-64 carries, the
// published catalogue advertised a node nobody could install, and the
// 26.8.0 that platform does have became unreachable — `pkgs ls nodejs.org`
// named one version and it was the wrong one.
//
// The same function answers "is this lock's pin published", where a yes
// about a neighbouring version is worse still: a lock exists to say that
// nothing moved.
func TestAShorterSpellingMustDropOnlyZeroes(t *testing.T) {
	for _, c := range []struct {
		version string
		want    []string // every spelling, in order
	}{
		// The case that caused it. Nothing may suggest 26.8 or 26.8.0.
		{"26.8.1", []string{"26.8.1", "26.8.1.0"}},
		// The case the shortening exists for: a trailing zero really is the
		// same release, written two ways. (`1.35.0.0` rides along because a
		// longer spelling of the same release is harmless.)
		{"1.35.0", []string{"1.35.0", "1.35.0.0", "1.35"}},
		{"1.0.0", []string{"1.0.0", "1.0.0.0", "1.0", "1"}},
		// Two components: the `.0` extension is a longer spelling of the
		// same version and stays.
		{"1.2", []string{"1.2", "1.2.0"}},
		{"7", []string{"7", "7.0"}},
	} {
		got := tagSpellings(ParseVer(c.version))
		if strings.Join(got, " ") != strings.Join(c.want, " ") {
			t.Errorf("tagSpellings(%s) = %v, want %v", c.version, got, c.want)
		}
	}
}

// ⛔ THE CONTROL, in the form the defect took: no spelling of a version may
// name a different release. Checked as a property over a spread of versions
// rather than by listing cases, because the defect was a general rule that
// looked right on the examples its author had in mind.
func TestNoSpellingNamesAnotherRelease(t *testing.T) {
	for _, v := range []string{
		"26.8.1", "1.2.3", "0.0.1", "10.4.0", "3.14.7", "1.1.1w",
		"2.47.0", "8.3.5", "0.1.0", "9.0.4", "26.10.0",
	} {
		parsed := ParseVer(v)
		for _, s := range tagSpellings(parsed) {
			other := ParseVer(s)
			// Same release means: equal once both are padded with zeroes.
			if !sameRelease(parsed.Nums, other.Nums) {
				t.Errorf("tagSpellings(%s) offers %q, which is release %v not %v",
					v, s, other.Nums, parsed.Nums)
			}
		}
	}
}

func sameRelease(a, b []int) bool {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		var x, y int
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if x != y {
			return false
		}
	}
	return true
}

// ⛔ WHAT THIS FIX DOES *NOT* COVER, recorded because finding it and saying
// nothing is how the next person re-discovers it.
//
// The rule above is about dropping NUMERIC components. Two shapes drop
// something else, and this test pins today's behaviour so that changing it
// is a decision rather than an accident:
//
//	1.1.1w          → also offers "1.1.1"
//	1.0.0+glibc2.28 → parses to Nums [1 0 0 28], Tag "", and offers "1.0.0.28"
//
// ⛔ The first is the same class as the defect fixed above: openssl 1.1.1
// and 1.1.1w are different releases, so a probe for one that hits the other
// would answer about the wrong software. It is NOT fixed here because
// nothing was measured breaking because of it — this registry carries no
// openssl 1.x at all — and inventing a fix for an unmeasured defect is how
// an audit fabricates them. It is written down instead.
//
// The second shows the `v.Tag != ""` guard in tagSpellings never fires for
// a version that came through ParseVer, which puts the flavour in Nums.
func TestTheShapesThisRuleDoesNotJudge(t *testing.T) {
	for _, c := range []struct{ version, alsoOffers string }{
		{"1.1.1w", "1.1.1"},
		{"1.0.0+glibc2.28", "1.0.0.28"},
	} {
		got := tagSpellings(ParseVer(c.version))
		found := false
		for _, s := range got {
			if s == c.alsoOffers {
				found = true
			}
		}
		if !found {
			t.Errorf("tagSpellings(%s) = %v no longer offers %q — if that was deliberate, "+
				"update this test and say which defect it closes", c.version, got, c.alsoOffers)
		}
	}
}
