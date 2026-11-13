package artifact

import (
	"sort"
	"testing"
)

// ⛔⛔ A REBUILD WAS INVISIBLE, AND AN EXACT PIN LIED ABOUT IT.
//
// ParseVer stops each component at the first non-digit, so `1.8.2_1` and
// `1.8.2` both yielded Nums [1 8 2] and compared EQUAL. Measured 2026-10-10,
// before this existed:
//
//	1.8.2   satisfies "=1.8.2_1" ? true
//	1.8.2_1 satisfies "=1.8.2"   ? true
//
// A lock pinning the REBUILT artifact would therefore have installed the
// un-rebuilt one — the vulnerable one, since a rebuild is what a toolchain
// security fix produces — and said nothing. Writing such a tag before fixing
// this would have shipped exactly that.
func TestARebuildIsNotTheSameVersion(t *testing.T) {
	if ParseVer("1.8.2").Satisfies("=1.8.2_1") {
		t.Error("the un-rebuilt artifact satisfies an exact pin on the rebuild")
	}
	if ParseVer("1.8.2_1").Satisfies("=1.8.2") {
		t.Error("the rebuilt artifact satisfies an exact pin on the original")
	}
	// And each still matches itself, without which the two above would pass
	// on a comparator that matched nothing.
	if !ParseVer("1.8.2_1").Satisfies("=1.8.2_1") {
		t.Error("a rebuild does not match its own exact pin")
	}
	if !ParseVer("1.8.2").Satisfies("=1.8.2") {
		t.Error("a plain version no longer matches its own exact pin")
	}
}

// ABSENT MEANS ZERO, which is Debian's rule for its own revision and, here,
// the literal state of the registry: 0 of 1371 published version strings
// carry one.
func TestAnAbsentRebuildIsZero(t *testing.T) {
	if got := ParseVer("1.8.2").Rebuild; got != 0 {
		t.Errorf("Rebuild = %d, want 0", got)
	}
	if got := ParseVer("1.8.2_3").Rebuild; got != 3 {
		t.Errorf("Rebuild = %d, want 3", got)
	}
	// The Raw keeps the suffix: it is the registry TAG to pull from.
	if got := ParseVer("1.8.2_3").Raw; got != "1.8.2_3" {
		t.Errorf("Raw = %q, want 1.8.2_3", got)
	}
	// And the numeric components are the UPSTREAM version, unchanged — a
	// rebuild is the same software.
	if got := ParseVer("1.8.2_3").Nums; len(got) != 3 || got[0] != 1 || got[1] != 8 || got[2] != 2 {
		t.Errorf("Nums = %v, want [1 8 2]", got)
	}
}

// ⛔ IT ORDERS NUMERICALLY, not as text: `_10` is above `_2`. And a real
// version bump still dominates any number of rebuilds of the one below it.
func TestRebuildsOrderNumericallyAndBelowTheNextVersion(t *testing.T) {
	in := []string{"1.8.2_10", "1.8.3", "1.8.2", "1.8.2_2", "1.8.2_1"}
	sort.Slice(in, func(i, j int) bool { return cmpVer(ParseVer(in[i]), ParseVer(in[j])) < 0 })
	want := []string{"1.8.2", "1.8.2_1", "1.8.2_2", "1.8.2_10", "1.8.3"}
	for i := range want {
		if in[i] != want[i] {
			t.Fatalf("ordered %v, want %v", in, want)
		}
	}
}

// ⛔⛔ A VERSION THAT MERELY CONTAINS AN UNDERSCORE IS NOT A REBUILD.
//
// `_` is admitted by ValidateVersionString because it is ordinary in versions
// elsewhere, so `2026_09_25` is a shape this parser can meet — and reading
// its `_25` as a rebuild would turn one release into the 25th build of
// another. The discriminator is that the part BEFORE the underscore must be
// dotted, which every version in this registry is and a date-like one is not.
func TestAnUnderscoreIsNotAlwaysARebuild(t *testing.T) {
	for _, s := range []string{
		"2026_09_25", // a date, no dot before the underscore
		"1_2",        // likewise
		"1.0_beta",   // not digits after it
		"1.0_",       // nothing after it
		"_1",         // nothing before it
	} {
		v := ParseVer(s)
		if v.Rebuild != 0 {
			t.Errorf("%q read as rebuild %d", s, v.Rebuild)
		}
		if v.Raw != s {
			t.Errorf("%q was rewritten to %q", s, v.Raw)
		}
	}
	// THE POSITIVE CONTROL: the same function does recognise a real one, so
	// the five above are not passing on a parser that never finds any.
	if ParseVer("1.8.2_1").Rebuild != 1 {
		t.Error("no rebuild is recognised at all, so the negatives prove nothing")
	}

	// ⛔ THE LAST UNDERSCORE, NOT THE FIRST, and none of the cases above can
	// tell the two apart — a mutation swapping LastIndexByte for IndexByte
	// survived until this line existed. It needs TWO underscores with a
	// dotted head: bk appends `_N` to a version it already resolved, so in
	// `1.0_2_3` the version is `1.0_2` and the rebuild is 3. Reading it the
	// other way finds `2_3`, which is not a number, and silently treats a
	// third rebuild as no rebuild at all.
	if v := ParseVer("1.0_2_3"); v.Rebuild != 3 {
		t.Errorf("1.0_2_3 read as rebuild %d, want 3", v.Rebuild)
	}
}

// AND A REBUILD IS STILL A VERSION STRING THE GUARDS ACCEPT: the terminal
// safety check has to let it through, or the resolver refuses its own tags.
func TestARebuildPassesTheVersionStringGuard(t *testing.T) {
	if err := ValidateVersionString("1.8.2_1"); err != nil {
		t.Errorf("a rebuild tag is refused as a version string: %v", err)
	}
}
