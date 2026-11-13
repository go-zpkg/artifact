package artifact

import (
	"strings"
	"testing"
)

// ⛔⛔ THE QUESTION THIS TYPE EXISTS FOR: two builds of ONE version that differ
// only in a build option must not share an identity. Before Concrete they
// shared a tag, and the only way to publish both was the `_N` counter, which
// is an order and not a choice.
func TestTwoVariantsOfOneVersionHaveDifferentHashes(t *testing.T) {
	with := Concrete{Variants: Variants{"cuda": {"true"}}}
	without := Concrete{Variants: Variants{"cuda": {"false"}}}
	if with.Hash() == without.Hash() {
		t.Fatalf("+cuda and ~cuda share the hash %q", with.Hash())
	}
	if with.Hash() == "" || without.Hash() == "" {
		t.Error("a declared variant must produce a hash")
	}
}

// The same spec hashes alike however its maps and slices were built: a hash
// that depended on map iteration order would give ONE build two identities,
// and the registry would hold the same artifact twice under different names.
func TestTheHashDoesNotDependOnOrder(t *testing.T) {
	a := Concrete{
		Platform: "linux/x86-64",
		Variants: Variants{"cuda": {"true"}, "fabrics": {"ofi", "verbs"}},
		Deps: []Dep{
			{Project: "gnu.org/glibc", Version: "2.44.0", Hash: "aaaa"},
			{Project: "openssl.org", Version: "3.5.8", Hash: "bbbb"},
		},
	}
	b := Concrete{
		Platform: "linux/x86-64",
		Variants: Variants{"fabrics": {"verbs", "ofi"}, "cuda": {"true"}},
		Deps: []Dep{
			{Project: "openssl.org", Version: "3.5.8", Hash: "bbbb"},
			{Project: "gnu.org/glibc", Version: "2.44.0", Hash: "aaaa"},
		},
	}
	if a.Hash() != b.Hash() {
		t.Errorf("one spec, two hashes:\n  %q\n  %q", a.Canonical(), b.Canonical())
	}
}

// ⛔ THE DELIMITERS ARE LOAD-BEARING. Concatenation without one lets two
// different specs produce identical bytes — {"ab","c"} against {"a","bc"} —
// a collision manufactured by the encoding rather than found.
func TestTheCanonicalFormCannotBeForgedByConcatenation(t *testing.T) {
	for _, c := range []struct{ a, b Concrete }{
		{Concrete{Variants: Variants{"ab": {"c"}}}, Concrete{Variants: Variants{"a": {"bc"}}}},
		// ⛔ THE CASE THAT BROKE THE FIRST ENCODING. Two values must not equal
		// one value holding the separator — and a Concrete built from a
		// registry annotation never passes the parser that refuses it, so the
		// ENCODING has to be injective rather than the validator.
		{Concrete{Variants: Variants{"x": {"a", "b"}}}, Concrete{Variants: Variants{"x": {"a" + canonSep + "b"}}}},
		// The length prefix must also survive a value that looks like one.
		{Concrete{Variants: Variants{"x": {"1:a"}}}, Concrete{Variants: Variants{"x": {"a"}}}},
		// And a dep's three fields must not slide into one another.
		{Concrete{Deps: []Dep{{Project: "a", Version: "bc", Hash: "d"}}},
			Concrete{Deps: []Dep{{Project: "ab", Version: "c", Hash: "d"}}}},
	} {
		if c.a.Canonical() == c.b.Canonical() {
			t.Errorf("two specs share a canonical form: %q", c.a.Canonical())
		}
	}
}

// ⛔⛔ THE PLATFORM IS IN THE HASH, because reuse across operating systems is
// otherwise silently wrong: Spack's os_compatible map is DIRECTIONAL, and a
// identity that omits the platform lets a darwin artifact answer a linux pin.
func TestThePlatformIsPartOfTheIdentity(t *testing.T) {
	lin := Concrete{Platform: "linux/x86-64", Variants: Variants{"cuda": {"true"}}}
	mac := Concrete{Platform: "darwin/aarch64", Variants: Variants{"cuda": {"true"}}}
	if lin.Hash() == mac.Hash() {
		t.Error("two platforms share a hash")
	}
	// And the platform alone is enough to be an identity: an artifact we know
	// only the platform of is still a different thing per platform.
	if (Concrete{Platform: "linux/x86-64"}).Hash() == "" {
		t.Error("a platform-only spec has no hash")
	}
}

// ⛔⛔ glibc IS A DEPENDENCY, NOT A SPECIAL CASE. It used to be a `-glibc<X>`
// tag suffix with its own splitter and its own branch in selectVersions — a
// second spelling of identity, the shape of defect that let numericKey drop
// a published version three times over.
func TestAGlibcDifferenceIsJustADependencyDifference(t *testing.T) {
	old := Concrete{Deps: []Dep{{Project: "gnu.org/glibc", Version: "2.27.0", Hash: "x"}}}
	new_ := Concrete{Deps: []Dep{{Project: "gnu.org/glibc", Version: "2.44.0", Hash: "y"}}}
	if old.Hash() == new_.Hash() {
		t.Error("two glibc builds share a hash")
	}
}

// ⛔ THE RECIPE'S PLAN IS IN THE HASH, which answers the original question
// without anybody declaring a variant: a change to the resolved build
// produces different bytes, so it must produce a different identity.
func TestARecipeEditChangesTheIdentity(t *testing.T) {
	if (Concrete{Recipe: "sha256:aaa"}).Hash() == (Concrete{Recipe: "sha256:bbb"}).Hash() {
		t.Error("two plans share a hash")
	}
}

// ⛔⛔ A GRAFTED ARTIFACT IS A NEW ITEM, and the ungrafted one stays reachable.
// Guix is explicit that grafting does not pretend to leave identity alone:
// `guix build bash` and `guix build bash --no-grafts` name different store
// items. Our field has to be in the canonical form from the start, because
// adding it later would change every hash already issued.
func TestAGraftIsItsOwnIdentityAndNamesItsOrigin(t *testing.T) {
	plain := Concrete{Platform: "linux/x86-64", Deps: []Dep{{Project: "openssl.org", Version: "3.5.8", Hash: "old"}}}
	grafted := plain
	grafted.Deps = []Dep{{Project: "openssl.org", Version: "3.5.9", Hash: "new"}}
	grafted.Graft = plain.Hash()

	if grafted.Hash() == plain.Hash() {
		t.Fatal("a graft shares the hash of what it grafted")
	}
	if grafted.Graft != plain.Hash() {
		t.Error("a graft does not name its origin")
	}
	// A rebuild that reached the same closure HONESTLY is not the same thing
	// as a graft of it, and must not be confused with one: the bytes differ
	// (one was patched in place, the other compiled).
	rebuilt := grafted
	rebuilt.Graft = ""
	if rebuilt.Hash() == grafted.Hash() {
		t.Error("a graft and a real build of the same closure share a hash")
	}
}

// A spec that records nothing has no address, and that is the honest answer:
// every tag published before this existed carries no hash because nothing
// recorded one.
func TestAnEmptySpecHasNoHash(t *testing.T) {
	if got := (Concrete{}).Hash(); got != "" {
		t.Errorf("Hash() = %q, want empty", got)
	}
	if got := (Concrete{}).VariantTag(); got != "" {
		t.Errorf("VariantTag() = %q, want empty", got)
	}
}

// ⛔ THE INSTALL PREFIX IS NOT PART OF WHAT A ARTIFACT IS. Nix: "One cannot copy
// a store object to a store with a different store directory" — a cache stops
// being shareable the moment identity depends on where the reader keeps it,
// and having no fixed prefix is only an advantage while this holds.
func TestTheHashIgnoresWhereTheArtifactWillLand(t *testing.T) {
	c := Concrete{Platform: "linux/x86-64", Variants: Variants{"cuda": {"true"}}}
	before := c.Hash()
	t.Setenv("ZPKG_DIR", "/scratch/someone/pkgx")
	if after := c.Hash(); after != before {
		t.Errorf("the hash moved with ZPKG_DIR: %q then %q", before, after)
	}
	if strings.Contains(c.Canonical(), "/scratch") {
		t.Error("the canonical form names an install prefix")
	}
}

// The hash has to survive a tag: OCI allows [a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}
// and nothing else, which is why this is base32 and not base64.
func TestTheHashFitsAnOCITag(t *testing.T) {
	h := Concrete{Variants: Variants{"cuda": {"true"}}}.Hash()
	if len(h) != hashLen {
		t.Errorf("hash %q is %d characters, want %d", h, len(h), hashLen)
	}
	for i := 0; i < len(h); i++ {
		if c := h[i]; !((c >= 'a' && c <= 'z') || (c >= '2' && c <= '7')) {
			t.Errorf("hash %q holds %q, which an OCI tag refuses", h, c)
		}
	}
}

func TestVariantTagRoundTrips(t *testing.T) {
	c := Concrete{Variants: Variants{"cuda": {"true"}}}
	ver, hash := SplitVariantHash("3.3.11" + c.VariantTag())
	if ver != "3.3.11" || hash != c.Hash() {
		t.Errorf("round trip = %q, %q; want %q, %q", ver, hash, "3.3.11", c.Hash())
	}
}

// ⛔ A SUFFIX THAT MERELY LOOKS LIKE A HASH IS NOT ONE. Reading "1.0-h2" as a
// truncated hash would silently change which artifact a pin means.
func TestOnlyAnExactHashIsReadAsOne(t *testing.T) {
	for _, tag := range []string{"3.3.11", "1.0-h2", "1.0-hABCDEFGHIJ012345", "1.0-h" + strings.Repeat("a", hashLen+1), "-habcdefghij012345"} {
		if _, h := SplitVariantHash(tag); h != "" {
			t.Errorf("SplitVariantHash(%q) read %q as a hash", tag, h)
		}
	}
}

// --- the request side ------------------------------------------------------

// ⛔⛔ `~` IS OUR TILDE RANGE OPERATOR TOO. pkgx spells a version range ~5.44
// and Spack spells a disabled variant ~cuda; the digit after the tilde tells
// them apart, and getting it wrong turns a range into a variant named "5.44"
// that nothing declares.
func TestATildeRangeIsNotAVariant(t *testing.T) {
	if _, err := ParseConstraints("~5.44"); err == nil {
		t.Error("~5.44 parsed as a variant")
	}
	cs, err := ParseConstraints("~cuda")
	if err != nil {
		t.Fatalf("~cuda: %v", err)
	}
	if got := cs["cuda"].Values; len(got) != 1 || got[0] != "false" {
		t.Errorf("~cuda = %v, want [false]", got)
	}
}

// ⛔⛔ `=` AND `:=` ARE DIFFERENT REQUESTS, and conflating them was the design
// error this type exists to fix. `fabrics=ofi` asks for a build that has ofi;
// `fabrics:=ofi` asks for one that has ofi AND NOTHING ELSE. Answering the
// second with the first hands someone a binary linked against a fabric
// library their machine does not have.
func TestAtLeastIsNotExactly(t *testing.T) {
	have := Variants{"fabrics": {"ofi", "verbs"}}

	atLeast, err := ParseConstraints("fabrics=ofi")
	if err != nil {
		t.Fatal(err)
	}
	if !atLeast.Satisfies(have) {
		t.Error("fabrics=ofi was refused by a build that has ofi")
	}

	exactly, err := ParseConstraints("fabrics:=ofi")
	if err != nil {
		t.Fatal(err)
	}
	if exactly.Satisfies(have) {
		t.Error("fabrics:=ofi was answered by a build that also has verbs")
	}
	if !exactly.Satisfies(Variants{"fabrics": {"ofi"}}) {
		t.Error("fabrics:=ofi was refused by the build that is exactly it")
	}
}

// ⛔ EXACTNESS AND PROPAGATION BELONG TO THE REQUEST, NOT TO THE ARTIFACT. Once
// concretised a node holds one definite set, and how it was asked for is not
// part of what it IS — otherwise two artifacts reached by different questions
// would hash apart while being the same bytes.
func TestTheRequestShapeIsNotInTheIdentity(t *testing.T) {
	a := Concrete{Variants: Variants{"fabrics": {"ofi"}}}
	b := Concrete{Variants: Variants{"fabrics": {"ofi"}}}
	if a.Hash() != b.Hash() {
		t.Error("two identical artifacts hash apart")
	}
	// The constraint type carries the question; Variants cannot express it,
	// which is the point.
	cs, err := ParseConstraints("++debug fabrics:=ofi")
	if err != nil {
		t.Fatal(err)
	}
	if !cs["debug"].Propagate {
		t.Error("++debug did not propagate")
	}
	if !cs["fabrics"].Exact {
		t.Error("fabrics:=ofi was not exact")
	}
}

func TestParseConstraintsSpellings(t *testing.T) {
	cs, err := ParseConstraints("+cuda ~mpi fabrics=verbs,ofi cppflags==-g ~~debug")
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{
		"cuda": "true", "mpi": "false", "cppflags": "-g", "debug": "false",
	} {
		if got := cs[name].Values; len(got) != 1 || got[0] != want {
			t.Errorf("%s = %v, want [%s]", name, got, want)
		}
	}
	if got := cs["fabrics"].Values; len(got) != 2 || got[0] != "ofi" || got[1] != "verbs" {
		t.Errorf("fabrics = %v, want [ofi verbs] sorted", got)
	}
	if !cs["cppflags"].Propagate || !cs["debug"].Propagate {
		t.Error("the == and ~~ forms must propagate")
	}
	// And a rendering of the matching artifact reads back the human way.
	if got := (Variants{"cuda": {"true"}, "mpi": {"false"}, "fabrics": {"verbs", "ofi"}}).String(); got != "+cuda fabrics=ofi,verbs ~mpi" {
		t.Errorf("String() = %q", got)
	}
}

// ⛔ A NAME OR VALUE CARRYING A CANONICAL SEPARATOR COULD FORGE ANOTHER SPEC'S
// IDENTITY, so the parser bounds what can ever reach the canonical form.
func TestVariantNamesAndValuesAreBounded(t *testing.T) {
	for _, bad := range []string{"+cu\x00da", "+cu da", "+1cuda", "+", "~", "cuda", "+cu-da", "=80", "x=", "x=a\x00b"} {
		if _, err := ParseConstraints(bad); err == nil {
			t.Errorf("ParseConstraints(%q) was accepted", bad)
		}
	}
	// A value may hold what a NAME may not: "c++" and "-O3" are real values.
	for _, good := range []string{"languages=c,c++", "cppflags=-O3"} {
		if _, err := ParseConstraints(good); err != nil {
			t.Errorf("ParseConstraints(%q) = %v", good, err)
		}
	}
}

func TestTheSameVariantTwiceDisagreeing(t *testing.T) {
	if _, err := ParseConstraints("+cuda ~cuda"); err == nil {
		t.Error("+cuda ~cuda was accepted")
	}
	if _, err := ParseConstraints("fabrics=ofi fabrics:=ofi"); err == nil {
		t.Error("= and := on one variant was accepted")
	}
	// Saying the same thing twice is not a conflict.
	if _, err := ParseConstraints("+cuda +cuda"); err != nil {
		t.Errorf("+cuda +cuda: %v", err)
	}
}

// A constraint on a variant the artifact does not carry is not satisfied: a
// build with no `cuda` variant is not a build with cuda off, it is a build
// that was never asked the question.
func TestAnAbsentVariantSatisfiesNothing(t *testing.T) {
	cs, err := ParseConstraints("~cuda")
	if err != nil {
		t.Fatal(err)
	}
	if cs.Satisfies(Variants{}) {
		t.Error("~cuda was answered by an artifact with no cuda variant")
	}
	// And a variant present with the WRONG value is refused, which is the
	// other half: the first check is about presence, this one about value.
	if cs.Satisfies(Variants{"cuda": {"true"}}) {
		t.Error("~cuda was answered by a build with cuda on")
	}
}

// ⛔ THE DEP ORDER IS TOTAL, down to the hash. Two builds that differ only in
// which build of one dependency they used must sort deterministically, or the
// canonical form depends on the order the caller happened to append them —
// the defect the sort exists to remove, surviving in its own tie-break.
func TestDepsSortByEveryField(t *testing.T) {
	// Same project, differing version: the second comparison decides.
	byVersion := Concrete{Deps: []Dep{
		{Project: "p", Version: "2", Hash: "a"},
		{Project: "p", Version: "1", Hash: "a"},
	}}
	reversed := Concrete{Deps: []Dep{
		{Project: "p", Version: "1", Hash: "a"},
		{Project: "p", Version: "2", Hash: "a"},
	}}
	if byVersion.Hash() != reversed.Hash() {
		t.Error("deps differing by version do not sort stably")
	}
	// Same project AND version, differing hash: the third decides. This is
	// the real case — one project, two builds, in one closure.
	byHash := Concrete{Deps: []Dep{
		{Project: "p", Version: "1", Hash: "b"},
		{Project: "p", Version: "1", Hash: "a"},
	}}
	flipped := Concrete{Deps: []Dep{
		{Project: "p", Version: "1", Hash: "a"},
		{Project: "p", Version: "1", Hash: "b"},
	}}
	if byHash.Hash() != flipped.Hash() {
		t.Error("deps differing by hash do not sort stably")
	}
	// And they are still two different closures from one with a single dep.
	if byHash.Hash() == (Concrete{Deps: []Dep{{Project: "p", Version: "1", Hash: "a"}}}).Hash() {
		t.Error("two builds of one dep collapsed into one")
	}
}

// Rendering nothing is "", not "+" or a stray separator: the catalogue prints
// this beside a project name.
func TestRenderingNoVariants(t *testing.T) {
	if got := (Variants{}).String(); got != "" {
		t.Errorf("String() = %q, want empty", got)
	}
}

// Bool is how a caller asks the common question without re-deriving the
// spelling. A multi-valued variant has no boolean answer, and saying "false"
// for it would be a wrong answer rather than a missing one.
func TestBool(t *testing.T) {
	v := Variants{
		"cuda":    {"true"},
		"mpi":     {"false"},
		"fabrics": {"ofi", "verbs"},
		"level":   {"3"},
	}
	for _, c := range []struct {
		name    string
		val, ok bool
	}{
		{"cuda", true, true},
		{"mpi", false, true},
		{"fabrics", false, false}, // multi-valued: not a boolean
		{"level", false, false},   // not a boolean value
		{"absent", false, false},
	} {
		val, ok := v.Bool(c.name)
		if val != c.val || ok != c.ok {
			t.Errorf("Bool(%q) = %v, %v; want %v, %v", c.name, val, ok, c.val, c.ok)
		}
	}
}
