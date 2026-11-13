package artifact

import (
	"encoding/json"
	"strings"
	"testing"
)

// ⛔⛔ WITHOUT A VERSION, A NEWER PAYLOAD IS MISREAD RATHER THAN REFUSED.
// encoding/json drops fields it does not know, silently — so a v2 spec
// carrying a new identity-bearing field parses cleanly as a v1 spec that
// happens to lack it.
//
// The artifact is not installed either way, because VerifySpec recomputes the
// hash and a dropped field moves it. But the message would be "the artifact
// does not match its own description", which reads as tampering and sends
// its reader hunting an attacker. This is the test that keeps the true
// message — "published by a newer release" — reachable.
func TestAPayloadFromANewerReleaseSaysSoRatherThanLookingForged(t *testing.T) {
	future := `{"v":` + itoa(SpecVersion+1) + `,"platform":"linux/x86-64","something-new":"x"}`

	_, err := UnmarshalSpec(future)
	if err == nil {
		t.Fatal("a payload from a newer release was accepted")
	}
	for _, want := range []string{"newer release", "format version"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not say %q: %v", want, err)
		}
	}
	// ⛔ AND IT MUST NOT READ AS TAMPERING. That is the entire reason the
	// field exists; an error that mentioned the hash would be the failure
	// this replaces.
	if strings.Contains(err.Error(), "does not match its own description") {
		t.Errorf("a version mismatch is reported as a forged spec: %v", err)
	}
}

// The version is WRITTEN, and written always — every other field is
// `omitempty`, so an empty spec is `{}` and an omitted version would make
// "before versions existed" and "version 0" the same bytes.
func TestTheVersionIsAlwaysWritten(t *testing.T) {
	for _, c := range []Concrete{
		{},
		{Platform: "linux/x86-64"},
		{Variants: Variants{"cuda": {"true"}}},
	} {
		s := MarshalSpec(c)
		var raw map[string]any
		if err := json.Unmarshal([]byte(s), &raw); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
		v, ok := raw["v"]
		if !ok {
			t.Errorf("no version in %s", s)
			continue
		}
		if int(v.(float64)) != SpecVersion {
			t.Errorf("version = %v in %s, want %d", v, s, SpecVersion)
		}
	}
}

// ⛔ THE VERSION IS NOT PART OF THE IDENTITY. The hash is taken over
// Canonical(), not over this JSON, so adding the field did not move a single
// hash — which is what let it ship without invalidating anything. A test,
// because the two are easy to confuse and the cost of confusing them is
// every published tag.
func TestTheVersionFieldDoesNotMoveTheHash(t *testing.T) {
	c := Concrete{Platform: "linux/x86-64", Variants: Variants{"cuda": {"true"}}}
	// Known-good: the hash is a function of Canonical(), and Canonical()
	// mentions no version.
	if strings.Contains(c.Canonical(), "\"v\"") {
		t.Error("the canonical form carries the wire version — the identity would move on a format change")
	}
	before := c.Hash()
	if before == "" {
		t.Fatal("a non-empty spec hashed to nothing")
	}
	// Round-tripping through the versioned wire form returns the same spec,
	// and so the same hash.
	got, err := UnmarshalSpec(MarshalSpec(c))
	if err != nil {
		t.Fatal(err)
	}
	if got.Hash() != before {
		t.Errorf("round trip moved the hash: %s -> %s", before, got.Hash())
	}
}

// A payload at the CURRENT version, and one from before the field existed,
// are both read. The second cannot occur in the registry — nothing has ever
// published a spec — but refusing it would be a rule with no stated reason.
func TestCurrentAndUnversionedPayloadsAreBothRead(t *testing.T) {
	for _, s := range []string{
		`{"v":1,"platform":"linux/x86-64"}`,
		`{"platform":"linux/x86-64"}`,
	} {
		c, err := UnmarshalSpec(s)
		if err != nil {
			t.Errorf("%s: %v", s, err)
			continue
		}
		if c.Platform != "linux/x86-64" {
			t.Errorf("%s -> platform %q", s, c.Platform)
		}
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
