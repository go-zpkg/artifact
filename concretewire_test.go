package artifact

import (
	"strings"
	"testing"
)

func sampleSpec() Concrete {
	return Concrete{
		Platform: "linux/x86-64",
		Variants: Variants{"cuda": {"true"}, "fabrics": {"ofi", "verbs"}},
		Deps: []Dep{
			{Project: "gnu.org/glibc", Version: "2.44.0", Hash: "aaaaaaaaaaaaaaaa"},
			{Project: "openssl.org", Version: "3.5.8", Hash: "bbbbbbbbbbbbbbbb"},
		},
		Recipe: "sha256:deadbeef",
	}
}

// The spec survives the wire unchanged — and "unchanged" is tested by the
// HASH, not by comparing fields: the hash is what identity means, so a round
// trip that preserved every field but reordered a value list would pass a
// field comparison and still be a different artifact.
func TestSpecRoundTrips(t *testing.T) {
	want := sampleSpec()
	got, err := UnmarshalSpec(MarshalSpec(want))
	if err != nil {
		t.Fatal(err)
	}
	if got.Hash() != want.Hash() {
		t.Errorf("hash %q after the wire, %q before\n  %s", got.Hash(), want.Hash(), MarshalSpec(want))
	}
}

// MarshalSpec returns no error because encoding/json cannot fail on this
// type. That is a claim about every value it can be handed, so it is tested
// with the bytes most likely to break an encoder rather than asserted in a
// comment alone — quotes, angle brackets, a NUL, a long digest.
func TestMarshalSurvivesAwkwardBytes(t *testing.T) {
	c := Concrete{
		Platform: "linux/x86-64",
		Variants: Variants{
			"cflags": {"-O3 \"quoted\"", "a" + canonSep + "b", "héllo"},
			"langs":  {"c++", "<&>"},
		},
		Recipe: "sha256:" + strings.Repeat("f", 64),
	}
	got, err := UnmarshalSpec(MarshalSpec(c))
	if err != nil {
		t.Fatalf("awkward bytes did not survive: %v", err)
	}
	if got.Hash() != c.Hash() {
		t.Errorf("hash changed across the wire: %q then %q", c.Hash(), got.Hash())
	}
}

// ⛔⛔ INVALID UTF-8 IS REFUSED AT THE DOOR, BECAUSE THE WIRE CANNOT CARRY IT.
// encoding/json replaces invalid UTF-8 with U+FFFD rather than failing, so
// the value that comes back is not the value that went out, its hash is not
// the hash that went out, and a perfectly honest artifact fails its own
// verification. Found by putting a stray \xff in a variant value and watching
// the hash change across the wire.
//
// Both halves are asserted: the door refuses it, and if one ever reached a
// Concrete anyway the wire would NOT silently preserve it — which is why the
// refusal has to be at the door and not in the encoder.
func TestInvalidUTF8IsRefusedBecauseTheWireCannotCarryIt(t *testing.T) {
	if _, err := ParseConstraints("cflags=\xff\xfe"); err == nil {
		t.Error("invalid UTF-8 was accepted as a variant value")
	}
	// The property that forces the refusal, stated as a measurement rather
	// than as a belief about encoding/json.
	bad := Concrete{Variants: Variants{"cflags": {"\xff\xfe"}}}
	got, err := UnmarshalSpec(MarshalSpec(bad))
	if err != nil {
		t.Fatal(err)
	}
	if got.Hash() == bad.Hash() {
		t.Error("invalid UTF-8 survived JSON; the door could be opened again")
	}
}

// An empty spec marshals to something a manifest can carry without claiming
// anything: the artifacts published before this existed are not described, and
// saying so is the truth about all 1371 of them.
func TestAnEmptySpecCarriesNoClaim(t *testing.T) {
	got, err := UnmarshalSpec(MarshalSpec(Concrete{}))
	if err != nil {
		t.Fatal(err)
	}
	if !got.IsZero() {
		t.Errorf("an empty spec came back as %+v", got)
	}
}

// ⛔⛔ A SPEC THAT DOES NOT HASH TO ITS OWN ADDRESS IS A CLAIM, NOT A
// DESCRIPTION. Both halves come from the publisher — the tag says -h<hash>,
// the annotation says what that hash is of — so reading the second without
// checking it against the first lets an artifact tagged as the plain build
// describe itself as the CUDA one, or the reverse. The reverse is the one
// that matters: the lie points at "this is the build you asked for".
func TestASpecThatDisagreesWithItsTagIsRefused(t *testing.T) {
	real := sampleSpec()
	s := MarshalSpec(real)

	_, err := VerifySpec(s, "zzzzzzzzzzzzzzzz")
	if err == nil {
		t.Fatal("a spec was accepted under the wrong hash")
	}
	for _, want := range []string{real.Hash(), "zzzzzzzzzzzzzzzz", "does not match"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err = %v, want it to contain %q", err, want)
		}
	}
	if _, err := VerifySpec(s, real.Hash()); err != nil {
		t.Errorf("the matching pair was refused: %v", err)
	}
	// Malformed JSON fails here too, before any hash is computed: a spec
	// that cannot be read is not a spec that disagrees.
	if _, err := VerifySpec("{", real.Hash()); err == nil {
		t.Error("malformed JSON passed verification")
	}
}

// ⛔ THE SUBSTITUTION THAT MATTERS: same version, variant swapped. Nothing
// about the version string changes, so a reader that compared versions sees
// no difference at all.
func TestAVariantCannotBeSwappedUnderItsHash(t *testing.T) {
	withCuda := sampleSpec()
	without := sampleSpec()
	without.Variants = Variants{"cuda": {"false"}, "fabrics": {"ofi", "verbs"}}

	if _, err := VerifySpec(MarshalSpec(without), withCuda.Hash()); err == nil {
		t.Fatal("a ~cuda artifact passed as the +cuda one")
	}
}

// A tag with no hash makes no claim, so there is nothing to verify against.
// That is every artifact in the registry today, and refusing them would be
// refusing the whole pantry.
func TestAnUnhashedTagLeavesTheSpecUnverified(t *testing.T) {
	got, err := VerifySpec(MarshalSpec(sampleSpec()), "")
	if err != nil {
		t.Fatalf("VerifySpec with no claim = %v", err)
	}
	if got.Hash() != sampleSpec().Hash() {
		t.Error("the spec came back changed")
	}
}

// ⛔ MALFORMED JSON IS AN ERROR ABOUT THE ANNOTATION, named, rather than an
// empty spec that would read as "this artifact declares no variants" — which
// is a statement, and a false one.
func TestMalformedAnnotation(t *testing.T) {
	for _, bad := range []string{"", "{", "not json", "[]", `{"variants":"no"}`} {
		if _, err := UnmarshalSpec(bad); err == nil {
			t.Errorf("UnmarshalSpec(%q) was accepted", bad)
		} else if !strings.Contains(err.Error(), SpecAnnotation) {
			t.Errorf("err = %v, want it to name the annotation", err)
		}
	}
}

// ⛔⛔ AND THE FORGERY THE CANONICAL FORM WAS HARDENED FOR ARRIVES HERE. An
// annotation is the one route into a Concrete that never passes
// ParseConstraints, so a value holding the canonical separator reaches the
// hash directly. The length-prefixed encoding is what makes that harmless.
func TestAnAnnotationCannotForgeAnotherSpecsHash(t *testing.T) {
	two := Concrete{Variants: Variants{"x": {"a", "b"}}}
	joined := Concrete{Variants: Variants{"x": {"a" + canonSep + "b"}}}

	ga, err := UnmarshalSpec(MarshalSpec(two))
	if err != nil {
		t.Fatal(err)
	}
	gb, err := UnmarshalSpec(MarshalSpec(joined))
	if err != nil {
		t.Fatal(err)
	}
	if ga.Hash() == gb.Hash() {
		t.Error("an annotation forged another spec's hash through the wire")
	}
	if ga.Hash() != two.Hash() || gb.Hash() != joined.Hash() {
		t.Error("the wire changed a hash")
	}
}

// --- against a registry ----------------------------------------------------

// SpecOf reads the annotation off a published manifest and checks it against
// the hash in the tag. Tested against the fake registry the rest of this
// package uses, so the manifest is a real one.
func TestSpecOfReadsAndVerifies(t *testing.T) {
	fr := newFakeRegistry(t, false)
	defer fr.close()
	withDist(t, fr.base("go-zpkg/artifacts"))
	c, err := NewOCIClient(DistBase)
	if err != nil {
		t.Fatal(err)
	}

	spec := sampleSpec()
	tag := "1.0.0-h" + spec.Hash()
	if _, err := c.PushWithReferrersAnnotated("spec.test", tag, "linux", "x86-64",
		makeGzTarball("x"), ExtTarGz, nil,
		map[string]string{SpecAnnotation: MarshalSpec(spec)}); err != nil {
		t.Fatal(err)
	}

	got, ok, err := c.SpecOf("spec.test", tag, "linux", "x86-64")
	if err != nil || !ok {
		t.Fatalf("SpecOf = %v, ok=%v", err, ok)
	}
	if got.Hash() != spec.Hash() {
		t.Errorf("hash %q, want %q", got.Hash(), spec.Hash())
	}
}

// ⛔⛔ AND A ARTIFACT TAGGED AS ONE BUILD WHILE DESCRIBING ANOTHER IS REFUSED
// AT THE REGISTRY, which is where the lie would actually arrive.
func TestSpecOfRefusesATagThatDisagrees(t *testing.T) {
	fr := newFakeRegistry(t, false)
	defer fr.close()
	withDist(t, fr.base("go-zpkg/artifacts"))
	c, err := NewOCIClient(DistBase)
	if err != nil {
		t.Fatal(err)
	}

	without := sampleSpec()
	without.Variants = Variants{"cuda": {"false"}}
	// Tagged as the +cuda build, describing the ~cuda one.
	tag := "1.0.0-h" + sampleSpec().Hash()
	if _, err := c.PushWithReferrersAnnotated("liar.test", tag, "linux", "x86-64",
		makeGzTarball("x"), ExtTarGz, nil,
		map[string]string{SpecAnnotation: MarshalSpec(without)}); err != nil {
		t.Fatal(err)
	}

	_, ok, err := c.SpecOf("liar.test", tag, "linux", "x86-64")
	if err == nil {
		t.Fatal("an artifact passed while describing a different build")
	}
	if ok {
		t.Error("a refused spec was reported as present")
	}
	if !strings.Contains(err.Error(), "liar.test") {
		t.Errorf("err = %v, want it to name the project", err)
	}
}

// ⛔ A ARTIFACT WITH NO SPEC IS NOT AN ERROR. That is every artifact published
// before this existed, and "we do not know what options this was built with"
// is the truth about all of them — reporting it as a fault would refuse the
// whole registry.
func TestSpecOfOnAArtifactWithoutOne(t *testing.T) {
	fr := newFakeRegistry(t, false)
	defer fr.close()
	withDist(t, fr.base("go-zpkg/artifacts"))
	c, err := NewOCIClient(DistBase)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.PushWithReferrersAnnotated("plain.test", "1.0.0", "linux", "x86-64",
		makeGzTarball("x"), ExtTarGz, nil, nil); err != nil {
		t.Fatal(err)
	}
	spec, ok, err := c.SpecOf("plain.test", "1.0.0", "linux", "x86-64")
	if err != nil {
		t.Fatalf("SpecOf = %v", err)
	}
	if ok || !spec.IsZero() {
		t.Errorf("an undescribed artifact reported a spec: ok=%v %+v", ok, spec)
	}
	// An unpublished version is a real lookup failure, not a silent absence.
	if _, _, err := c.SpecOf("plain.test", "9.9.9", "linux", "x86-64"); err == nil {
		t.Error("an unpublished version reported no spec instead of failing")
	}
}
