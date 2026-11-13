package artifact

import (
	"strings"
	"testing"
)

// ⛔⛔ THE DEFAULT IS THAT WE ARE THE ONLY DISTRIBUTION.
//
// UpstreamDist was `https://dist.pkgx.dev`, compiled in and always on, so any
// lookup our own registry could not answer silently became a question asked
// of another project. That is right for a mirror with a gap-filler and wrong
// for a distribution: a project we do not carry must SAY SO.
func TestNoUpstreamByDefault(t *testing.T) {
	if UpstreamDist != "" {
		t.Errorf("UpstreamDist = %q, want empty: an upstream is opt-in", UpstreamDist)
	}
	if haveUpstream() {
		t.Error("haveUpstream() is true with nothing configured")
	}
}

// "none" is the explicit off, spelled as ZPKG_PANTRY_OVERLAY spells it. A
// second spelling for the same idea is what this repository keeps paying for.
func TestNoneTurnsTheUpstreamOff(t *testing.T) {
	old := UpstreamDist
	t.Cleanup(func() { UpstreamDist = old })

	UpstreamDist = "none"
	if haveUpstream() {
		t.Error(`UpstreamDist="none" was read as an upstream`)
	}
	UpstreamDist = "https://example.invalid/dist"
	if !haveUpstream() {
		t.Error("a configured upstream was not seen")
	}
}

// The variable is read, which is the half a flag most often misses: parsed
// and then ignored.
func TestUpstreamComesFromTheEnvironment(t *testing.T) {
	old := UpstreamDist
	t.Cleanup(func() { UpstreamDist = old })
	UpstreamDist = ""

	applyEnv(func(k string) string {
		if k == "ZPKG_UPSTREAM_DIST" {
			return "https://example.invalid/dist/"
		}
		return ""
	})
	if UpstreamDist != "https://example.invalid/dist" {
		t.Errorf("UpstreamDist = %q, want the env value with its trailing slash trimmed", UpstreamDist)
	}
}

// ⛔⛔ THE MESSAGE MUST NOT CLAIM A SEARCH THAT DID NOT HAPPEN. bothPlacesLooked
// says "neither X nor Y publishes it", which is true when two were consulted
// and a lie when one was. Naming a second registry that was never configured
// sends the reader to check it.
func TestTheMessageNamesOnlyThePlacesLooked(t *testing.T) {
	oldDist, oldUp := DistBase, UpstreamDist
	t.Cleanup(func() { DistBase, UpstreamDist = oldDist, oldUp })
	DistBase, UpstreamDist = "oci://registry.invalid/ours", ""

	err := notCarried("acme.org", "linux", "x86-64")
	if err == nil {
		t.Fatal("notCarried returned no error")
	}
	got := err.Error()
	for _, want := range []string{"acme.org", "linux/x86-64", "registry.invalid/ours", "ZPKG_UPSTREAM_DIST"} {
		if !strings.Contains(got, want) {
			t.Errorf("message %q, want it to contain %q", got, want)
		}
	}
	if strings.Contains(got, "neither") {
		t.Errorf("message %q says \"neither\" with one place consulted", got)
	}

	// The control: with an upstream configured, the two-place wording is the
	// correct one and must survive.
	UpstreamDist = "https://upstream.invalid"
	both := bothPlacesLooked(&httpStatusError{url: "https://upstream.invalid/x", status: 404}, "acme.org", "linux", "x86-64")
	if both == nil || !strings.Contains(both.Error(), "neither") {
		t.Errorf("with an upstream configured the message should name both: %v", both)
	}
}

// ⛔ AND IT IS REACHED FROM THE RESOLVER, not only callable. A project absent
// from our registry with no upstream configured must come back as "we do not
// carry it", without a fetch to a URL nobody set.
func TestAnAbsentProjectWithNoUpstreamIsNotCarried(t *testing.T) {
	fr := newFakeRegistry(t, false)
	defer fr.close()
	withDist(t, fr.base("go-zpkg/packages"))

	oldUp := UpstreamDist
	t.Cleanup(func() { UpstreamDist = oldUp })
	UpstreamDist = ""

	_, _, err := versionsForSourced("never.published", "linux", "x86-64")
	if err == nil {
		t.Fatal("an unpublished project resolved")
	}
	if !strings.Contains(err.Error(), "ZPKG_UPSTREAM_DIST") {
		t.Errorf("err = %v, want the no-upstream answer", err)
	}
}
