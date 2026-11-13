package artifact

import (
	"slices"
	"strings"
	"testing"
)

// ⛔⛔ A VARIANT MUST NOT DELETE ITS SIBLING FROM THE LISTING.
//
// This is the defect numericKey already carries a comment about, in its third
// costume. It read v.Nums alone, so `3.3.11` and `3.3.11_1` shared a key and
// selectVersions dropped one; the rebuild counter joined the key. A variant
// hash names a different BUILD of one version — different options, different
// closure, different bytes — and leaving it out would collapse them the same
// way.
func TestTwoVariantsOfAVersionBothSurvive(t *testing.T) {
	const a, b = "aaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb"
	got := selectVersions([]string{"3.3.11", "3.3.11-h" + a, "3.3.11-h" + b}, "")
	if len(got) != 3 {
		t.Fatalf("selectVersions = %v, want three builds", raws(got))
	}
	var variants []string
	for _, v := range got {
		if v.Raw != "3.3.11" {
			t.Errorf("Raw = %q, want the VERSION without its variant suffix", v.Raw)
		}
		variants = append(variants, v.Variant)
	}
	for _, want := range []string{"", a, b} {
		if !slices.Contains(variants, want) {
			t.Errorf("variant %q missing from %v", want, variants)
		}
	}
}

// Raw is the version; the TAG is where that build lives. A pull that used Raw
// would fetch the unvariant artifact for every variant.
func TestAVariantKeepsTheTagToPull(t *testing.T) {
	const h = "abcdefghij234567"
	got := selectVersions([]string{"3.3.11-h" + h}, "")
	if len(got) != 1 {
		t.Fatalf("selectVersions = %v", raws(got))
	}
	if got[0].Raw != "3.3.11" || got[0].Variant != h {
		t.Errorf("got Raw=%q Variant=%q", got[0].Raw, got[0].Variant)
	}
	if got[0].tag() != "3.3.11-h"+h {
		t.Errorf("tag() = %q, want the full registry tag", got[0].tag())
	}
}

// ⛔ A HASH IS NOT AN ORDER, so cmpVer must ignore it. Ordering by the hash
// would invent a preference the registry never expressed — and it would be a
// stable-looking one, which is worse than an obvious coin flip.
func TestAVariantDoesNotOrder(t *testing.T) {
	a := Ver{Raw: "3.3.11", Nums: []int{3, 3, 11}, Variant: "aaaaaaaaaaaaaaaa"}
	b := Ver{Raw: "3.3.11", Nums: []int{3, 3, 11}, Variant: "zzzzzzzzzzzzzzzz"}
	if cmpVer(a, b) != 0 {
		t.Errorf("cmpVer ordered two variants of one version: %d", cmpVer(a, b))
	}
	// And a real version bump still outranks any variant of the older one.
	if cmpVer(b, Ver{Raw: "3.3.12", Nums: []int{3, 3, 12}}) >= 0 {
		t.Error("a variant outranks the next release")
	}
}

// ⛔⛔ AND THE PICK REFUSES RATHER THAN GUESSES. Two variants compare equal, so
// "the newest" is whichever the sort left last — the same command would
// install a different artifact tomorrow.
func TestAnAmbiguousVariantIsRefusedAndNamesTheCandidates(t *testing.T) {
	vs := []Ver{
		{Raw: "3.3.11", Nums: []int{3, 3, 11}, Variant: "aaaaaaaaaaaaaaaa"},
		{Raw: "3.3.11", Nums: []int{3, 3, 11}, Variant: "bbbbbbbbbbbbbbbb"},
	}
	sibs := variantSiblings(vs, vs[0])
	if len(sibs) != 1 || sibs[0] != "bbbbbbbbbbbbbbbb" {
		t.Errorf("variantSiblings = %v, want the other build", sibs)
	}
	// The plain build is named as such rather than as an empty string, so the
	// message reads as a choice and not as a missing value.
	withPlain := []Ver{
		{Raw: "3.3.11", Nums: []int{3, 3, 11}},
		{Raw: "3.3.11", Nums: []int{3, 3, 11}, Variant: "aaaaaaaaaaaaaaaa"},
	}
	if got := variantSiblings(withPlain, withPlain[1]); len(got) != 1 || got[0] != "(no variant)" {
		t.Errorf("variantSiblings = %v, want the unvariant build named", got)
	}
}

// ⛔ A DIFFERENT VERSION IS NOT A SIBLING. Without this the guard would refuse
// every project that has more than one version — which is every project.
func TestOnlyTheSameVersionAreSiblings(t *testing.T) {
	vs := []Ver{
		{Raw: "3.3.10", Nums: []int{3, 3, 10}, Variant: "aaaaaaaaaaaaaaaa"},
		{Raw: "3.3.11", Nums: []int{3, 3, 11}, Variant: "bbbbbbbbbbbbbbbb"},
	}
	for i := range vs {
		if got := variantSiblings(vs, vs[i]); len(got) != 0 {
			t.Errorf("variantSiblings(%s) = %v, want none", vs[i].Raw, got)
		}
	}
	// Nor is a different rebuild of the same version: _1 supersedes the base
	// by ORDER, which is a question cmpVer already answers.
	reb := []Ver{
		{Raw: "1.8.2", Nums: []int{1, 8, 2}},
		{Raw: "1.8.2_1", Nums: []int{1, 8, 2}, Rebuild: 1},
	}
	if got := variantSiblings(reb, reb[0]); len(got) != 0 {
		t.Errorf("a rebuild was read as a variant sibling: %v", got)
	}
}

// ⛔⛔ THE 1371 TAGS ALREADY PUBLISHED MUST READ EXACTLY AS BEFORE. None carries
// a variant hash, so this whole mechanism has to be invisible to them — and a
// version that merely LOOKS like it has one must not lose part of itself.
func TestPublishedTagsAreUnaffected(t *testing.T) {
	for _, c := range []struct{ tag, raw, variant string }{
		{"3.3.11", "3.3.11", ""},
		{"1.8.2_1", "1.8.2_1", ""},
		{"v2.44.0", "2.44.0", ""},
		{"1.0-h2", "1.0-h2", ""},     // too short to be a hash
		{"20260728", "20260728", ""}, // llvm-mingw's date version
		{"1.1.1w", "1.1.1w", ""},     // openssl's letter suffix
	} {
		got := selectVersions([]string{c.tag}, "")
		if len(got) != 1 {
			t.Fatalf("selectVersions(%q) = %v", c.tag, raws(got))
		}
		if got[0].Raw != c.raw || got[0].Variant != c.variant {
			t.Errorf("%q → Raw=%q Variant=%q; want %q, %q", c.tag, got[0].Raw, got[0].Variant, c.raw, c.variant)
		}
		// And nothing gained a Tag it did not need: an unsuffixed tag pulls
		// by its version, as it always has.
		if c.variant == "" && got[0].Tag != "" && !strings.Contains(c.tag, "glibc") {
			t.Errorf("%q acquired Tag=%q", c.tag, got[0].Tag)
		}
	}
}

// The glibc flavour is the older spelling and still works: it comes off
// first, outermost, and a legacy tag resolves as it did.
func TestTheGlibcFlavourStillReadsFirst(t *testing.T) {
	got := selectVersions([]string{"8.20.0-glibc2.27.0"}, "2.27.0")
	if len(got) != 1 {
		t.Fatalf("selectVersions = %v", raws(got))
	}
	if got[0].Raw != "8.20.0" || got[0].Variant != "" {
		t.Errorf("got Raw=%q Variant=%q", got[0].Raw, got[0].Variant)
	}
	if got[0].tag() != "8.20.0-glibc2.27.0" {
		t.Errorf("tag() = %q", got[0].tag())
	}
}
