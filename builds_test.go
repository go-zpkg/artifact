package artifact

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ⛔ A PROJECT NAME CONTAINS SLASHES, and a third of the pantry is named that
// way. `github.com/gabime/spdlog` must not parse as project
// `github.com/gabime` with build `spdlog` — the split is on the LAST slash
// AND only when what follows looks like a hash.
func TestABuildRefIsNotConfusedWithAProjectName(t *testing.T) {
	for _, c := range []struct{ in, rest, hash string }{
		{"fftw.org", "fftw.org", ""},
		{"fftw.org@3.3.11", "fftw.org@3.3.11", ""},
		{"fftw.org@3.3.11/7k2mq4xv", "fftw.org@3.3.11", "7k2mq4xv"},
		{"github.com/gabime/spdlog@1.2.3/7k2mq4xv", "github.com/gabime/spdlog@1.2.3", "7k2mq4xv"},
		// ⛔ PROJECT NAMES, AND EVERY ONE OF THESE DEFEATED THE FIRST RULE.
		// It split on the last slash when the tail "looked like a hash",
		// on the claim that a pantry component would fall outside base32's
		// alphabet or be too long. base32 is a–z plus 2–7, so it covers
		// very nearly every lowercase word, and all four parsed as hashes.
		{"github.com/gabime/spdlog", "github.com/gabime/spdlog", ""},
		{"x.org/pciaccess", "x.org/pciaccess", ""},
		{"wpewebkit.org/libwpe", "wpewebkit.org/libwpe", ""},
		{"gnome.org/libxml2", "gnome.org/libxml2", ""},
		// No `@version`, so no hash — whatever the tail looks like.
		{"a.org/abcdefghijklmnop", "a.org/abcdefghijklmnop", ""},
		// With a version, the tail is checked for shape so a typo is caught
		// here rather than later as "no build matches".
		{"a.org@1/b", "a.org@1/b", ""},
		{"a.org@1/abc", "a.org@1/abc", ""},
		{"a.org@1/abcdefghijklmnopq", "a.org@1/abcdefghijklmnopq", ""},
		{"a.org@1/abc1", "a.org@1/abc1", ""},   // base32 has no 1
		{"a.org@1/dead0", "a.org@1/dead0", ""}, // nor 0
		{"a.org@1/dead8", "a.org@1/dead8", ""}, // nor 8
	} {
		rest, hash := ParseBuildRef(c.in)
		if rest != c.rest || hash != c.hash {
			t.Errorf("ParseBuildRef(%q) = (%q, %q), want (%q, %q)", c.in, rest, hash, c.rest, c.hash)
		}
	}
}

// ⛔⛔ A PREFIX THAT MATCHES TWO BUILDS IS A QUESTION, NOT A CHOICE. Picking
// the first would give a different answer the day another build is
// published — the same "there is no newest one" the resolver already
// refuses on, reintroduced in the thing that was supposed to answer it.
func TestMatchingABuildPrefixIsExactlyOneOrAnError(t *testing.T) {
	// ⛔ VALID base32 ONLY — a–z and 2–7, with no 0, 1, 8 or 9. The first
	// draft of this test used `…bnd8rf3x`, which isVariantHash rejects, so
	// the fixtures were not hashes at all and BuildsOf found nothing on
	// disk. A fixture outside the alphabet tests the wrong thing silently.
	builds := []Build{
		{Version: Ver{Raw: "3.3.11", Variant: "7k2mq4xvbnd5rf3x"}},
		{Version: Ver{Raw: "3.3.11", Variant: "7k2zzzzzzzzzzzzz"}},
		{Version: Ver{Raw: "3.3.11", Variant: "q6w3zc5tmr2jp7vd"}},
	}

	got, err := MatchBuild(builds, "q6w")
	if err != nil {
		t.Fatalf("an unambiguous prefix failed: %v", err)
	}
	if got.Hash() != "q6w3zc5tmr2jp7vd" {
		t.Errorf("matched %q", got.Hash())
	}

	// Ambiguous: names BOTH candidates so the next attempt can be longer.
	_, err = MatchBuild(builds, "7k2")
	if err == nil {
		t.Fatal("an ambiguous prefix was resolved")
	}
	for _, want := range []string{"7k2mq4xvbnd5rf3x", "7k2zzzzzzzzzzzzz", "say more of the hash"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not mention %q: %v", want, err)
		}
	}

	// No match: lists what there IS, because the usual cause is a typo and
	// the usual fix is seeing the real ones.
	_, err = MatchBuild(builds, "zzzz")
	if err == nil {
		t.Fatal("a prefix matching nothing was resolved")
	}
	if !strings.Contains(err.Error(), "q6w3zc5tmr2jp7vd") {
		t.Errorf("the error does not list the builds that exist: %v", err)
	}
	// And an empty set says so rather than printing an empty list.
	if _, err := MatchBuild(nil, "abcd"); err == nil || !strings.Contains(err.Error(), "none") {
		t.Errorf("an empty set gave %v", err)
	}
}

// ⛔⛔ A REGISTRY THAT COULD NOT BE REACHED IS AN ERROR, AND THE INSTALLED
// HALF IS STILL RETURNED. An unobtained answer must not read as "nothing is
// published" — that is how a user concludes a build does not exist and
// rebuilds it. But the store half needs no network and is a true answer to
// half the question, so withholding it would be its own kind of lie.
func TestAnUnreachableRegistryIsAnErrorThatStillReportsWhatIsInstalled(t *testing.T) {
	dir := t.TempDir()
	v := Ver{Raw: "3.3.11", Nums: []int{3, 3, 11}, Variant: "7k2mq4xvbnd5rf3x"}
	if err := os.MkdirAll(StoreBuildPrefix(dir, "fftw.org", v, v.Variant), 0o755); err != nil {
		t.Fatal(err)
	}
	// A dist that cannot answer.
	old := DistBase
	DistBase = "oci://127.0.0.1:1/nothing"
	resetOCICache()
	t.Cleanup(func() { DistBase = old; resetOCICache() })

	got, err := BuildsOf("fftw.org", "3.3.11", dir, "linux", "x86-64")
	if err == nil {
		t.Error("an unreachable registry was reported as no published builds")
	}
	if len(got) != 1 || got[0].Hash() != v.Variant {
		t.Fatalf("installed builds = %v, want the one on disk", got)
	}
	if got[0].Installed == "" {
		t.Error("the installed build does not say where it is")
	}
	if got[0].Published {
		t.Error("a build was marked published by a registry that did not answer")
	}
}

// Several builds of one version, listed together, each with its hash and
// where it is.
func TestBuildsOfListsEveryBuildOfOneVersion(t *testing.T) {
	dir := t.TempDir()
	for _, h := range []string{"7k2mq4xvbnd5rf3x", "q6w3zc5tmr2jp7vd"} {
		v := Ver{Raw: "3.3.11", Nums: []int{3, 3, 11}, Variant: h}
		if err := os.MkdirAll(StoreBuildPrefix(dir, "fftw.org", v, h), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// And one of a DIFFERENT version, which must not appear.
	other := Ver{Raw: "3.3.10", Nums: []int{3, 3, 10}, Variant: "aaaaaaaaaaaaaaaa"}
	if err := os.MkdirAll(StoreBuildPrefix(dir, "fftw.org", other, other.Variant), 0o755); err != nil {
		t.Fatal(err)
	}

	old := DistBase
	DistBase = "oci://127.0.0.1:1/nothing"
	resetOCICache()
	t.Cleanup(func() { DistBase = old; resetOCICache() })

	got, _ := BuildsOf("fftw.org", "3.3.11", dir, "linux", "x86-64")
	if len(got) != 2 {
		t.Fatalf("got %d builds, want the two of 3.3.11: %v", len(got), got)
	}
	// ⛔ SORTED BY HASH, because builds of one version are SIBLINGS. Any
	// order that looked like precedence would invent one — and cmpVer
	// ignores the hash for exactly that reason.
	if got[0].Hash() != "7k2mq4xvbnd5rf3x" || got[1].Hash() != "q6w3zc5tmr2jp7vd" {
		t.Errorf("order = %q, %q", got[0].Hash(), got[1].Hash())
	}
	for _, b := range got {
		if b.Version.Raw != "3.3.11" {
			t.Errorf("a build of %s came back", b.Version.Raw)
		}
		if filepath.Base(b.Installed) != StoreBuildDirName(b.Version, b.Hash()) {
			t.Errorf("Installed = %q", b.Installed)
		}
	}
}
