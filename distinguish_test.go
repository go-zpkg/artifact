package artifact

import (
	"strings"
	"testing"
)

func spec(platform, recipe string, deps ...Dep) Concrete {
	return Concrete{Platform: platform, Recipe: recipe, Deps: deps}
}

// ⛔⛔ THE WHOLE POINT: TWO HASHES ARE UNUSABLE AND THE LINE BESIDE THEM IS
// WHAT MAKES THEM A CHOICE. Two builds differing in one dependency must be
// told apart by that dependency and by nothing else — the 53 they agree on
// are noise, and printing them buries the one that matters.
func TestDistinguishNamesOnlyTheAxisThatDiffers(t *testing.T) {
	a := spec("linux/x86-64", "sha256:aaaa",
		Dep{Project: "openssl.org", Version: "3.6.4", Hash: "aaaaaaaaaaaaaaaa"},
		Dep{Project: "zlib.net", Version: "1.3.2", Hash: "cccccccccccccccc"})
	b := spec("linux/x86-64", "sha256:aaaa",
		Dep{Project: "openssl.org", Version: "1.1.1w", Hash: "bbbbbbbbbbbbbbbb"},
		Dep{Project: "zlib.net", Version: "1.3.2", Hash: "cccccccccccccccc"})

	got := Distinguish([]Concrete{a, b})
	if len(got) != 2 {
		t.Fatalf("got %d lines for 2 specs", len(got))
	}
	if !strings.Contains(got[0], "openssl.org 3.6.4") || !strings.Contains(got[1], "openssl.org 1.1.1w") {
		t.Errorf("the differing dependency is not named: %q / %q", got[0], got[1])
	}
	// ⛔ THE AGREEING DEPENDENCY MUST NOT BE THERE. This is the assertion
	// that keeps the line short enough to read; without it the function
	// degrades into printing the whole closure and nobody notices.
	for _, line := range got {
		if strings.Contains(line, "zlib.net") {
			t.Errorf("a dependency both builds share was printed: %q", line)
		}
	}
	if got[0] == got[1] {
		t.Error("two builds described identically: the list is still unusable")
	}
}

// Same version of a dependency, different BUILD of it. The version alone
// would describe the two rows identically, which is the failure this case
// exists to prevent.
func TestDistinguishSeparatesTwoBuildsOfOneDependencyVersion(t *testing.T) {
	a := spec("linux/x86-64", "sha256:aaaa", Dep{Project: "openssl.org", Version: "3.6.4", Hash: "aaaaaaaaaaaaaaaa"})
	b := spec("linux/x86-64", "sha256:aaaa", Dep{Project: "openssl.org", Version: "3.6.4", Hash: "bbbbbbbbbbbbbbbb"})
	got := Distinguish([]Concrete{a, b})
	if got[0] == got[1] {
		t.Fatalf("the two rows read alike: %q", got[0])
	}
	for _, line := range got {
		if !strings.Contains(line, "openssl.org 3.6.4/") {
			t.Errorf("the dependency's own build is not shown: %q", line)
		}
	}
}

// ⛔⛔ A RECIPE CHANGE IS THE COMMONEST REASON TWO BUILDS OF A VERSION EXIST,
// and it is invisible in the closure. With nothing printed, the two rows
// would be identical and the list would look broken rather than informative.
func TestDistinguishSaysWhenOnlyTheRecipeDiffers(t *testing.T) {
	a := spec("linux/x86-64", "sha256:1111eeee", Dep{Project: "zlib.net", Version: "1.3.2", Hash: "cccccccccccccccc"})
	b := spec("linux/x86-64", "sha256:2222ffff", Dep{Project: "zlib.net", Version: "1.3.2", Hash: "cccccccccccccccc"})
	got := Distinguish([]Concrete{a, b})
	for _, line := range got {
		if !strings.Contains(line, "different recipe") {
			t.Errorf("a recipe-only difference was not reported: %q", line)
		}
	}
	if got[0] == got[1] {
		t.Errorf("both rows say the same thing, so neither identifies a build: %q", got[0])
	}
}

// Variants are the axis this was designed around, even though the factory
// does not yet produce them: when it does, they must read the way a person
// writes them.
func TestDistinguishRendersVariantsTheWayPeopleWriteThem(t *testing.T) {
	a := Concrete{Platform: "linux/x86-64", Recipe: "sha256:a", Variants: Variants{"cuda": {"true"}, "mpi": {"true"}}}
	b := Concrete{Platform: "linux/x86-64", Recipe: "sha256:a", Variants: Variants{"cuda": {"false"}, "mpi": {"true"}}}
	got := Distinguish([]Concrete{a, b})
	if !strings.Contains(got[0], "+cuda") || !strings.Contains(got[1], "~cuda") {
		t.Errorf("variants = %q / %q", got[0], got[1])
	}
	// mpi is the same in both, so it is not part of the difference.
	for _, line := range got {
		if strings.Contains(line, "mpi") {
			t.Errorf("a shared variant was printed: %q", line)
		}
	}
}

// ⛔ A DEPENDENCY ONE BUILD HAS AND THE OTHER DOES NOT IS A DIFFERENCE. It
// would otherwise be invisible: the project is absent from one spec, so a
// naive comparison of shared keys never looks at it.
func TestDistinguishReportsADependencyOnlyOneBuildHas(t *testing.T) {
	a := spec("linux/x86-64", "sha256:a", Dep{Project: "cuda.nvidia.com", Version: "12.4", Hash: "aaaaaaaaaaaaaaaa"})
	b := spec("linux/x86-64", "sha256:a")
	got := Distinguish([]Concrete{a, b})
	if !strings.Contains(got[0], "cuda.nvidia.com 12.4") {
		t.Errorf("the extra dependency is not named: %q", got[0])
	}
	if !strings.Contains(got[1], "no cuda.nvidia.com") {
		t.Errorf("its absence is not stated: %q", got[1])
	}
}

// ⛔ A SPEC THAT RECORDS NOTHING GETS AN EMPTY LINE, NOT AN INVENTED ONE.
// Every artifact published before identities existed is one of these, and the
// caller has to be able to tell "we know nothing" from "we know it is plain".
func TestDistinguishLeavesAnUnknownBuildUndescribed(t *testing.T) {
	got := Distinguish([]Concrete{{}, spec("linux/x86-64", "sha256:a")})
	if got[0] != "" {
		t.Errorf("a build nothing records was described anyway: %q", got[0])
	}
	if got[1] == "" {
		t.Error("the known build lost its description because another was unknown")
	}
}

// One build has nothing to be told apart from, so the whole of what was
// recorded is the useful answer — summarised, because 54 dependencies is not
// an answer anyone reads.
func TestDescribeSummarisesASingleBuild(t *testing.T) {
	c := spec("linux/x86-64", "sha256:0123456789abcdef",
		Dep{Project: "openssl.org", Version: "3.6.4", Hash: "aaaaaaaaaaaaaaaa"})
	got := Describe(c)
	for _, want := range []string{"linux/x86-64", "1 dependency", "01234567"} {
		if !strings.Contains(got, want) {
			t.Errorf("Describe = %q, want %q in it", got, want)
		}
	}
	if strings.Contains(got, "openssl.org") {
		t.Errorf("Describe printed the closure instead of summarising it: %q", got)
	}
	if Describe(Concrete{}) != "" {
		t.Error("a spec that records nothing was described")
	}
	// Plural, because "1 dependencies" is the kind of thing a reader stops
	// trusting a tool over.
	two := spec("linux/x86-64", "sha256:aa",
		Dep{Project: "a.org", Version: "1"}, Dep{Project: "b.org", Version: "2"})
	if !strings.Contains(Describe(two), "2 dependencies") {
		t.Errorf("Describe = %q", Describe(two))
	}
}

// Degenerate inputs must not panic or invent differences.
func TestDistinguishHandlesNoneAndOne(t *testing.T) {
	if got := Distinguish(nil); len(got) != 0 {
		t.Errorf("Distinguish(nil) = %v", got)
	}
	got := Distinguish([]Concrete{spec("linux/x86-64", "sha256:a", Dep{Project: "z.org", Version: "1"})})
	if len(got) != 1 {
		t.Fatalf("got %d lines for 1 spec", len(got))
	}
	// Nothing to differ from, so nothing is claimed to differ.
	if got[0] != "" {
		t.Errorf("a lone build was described as differing from something: %q", got[0])
	}
}

// Platform and graft are axes too, and a listing that spans platforms must
// say so rather than showing two rows that look identical.
func TestDistinguishReportsPlatformAndGraft(t *testing.T) {
	a := spec("linux/x86-64", "sha256:a")
	b := spec("darwin/aarch64", "sha256:a")
	got := Distinguish([]Concrete{a, b})
	if !strings.Contains(got[0], "linux/x86-64") || !strings.Contains(got[1], "darwin/aarch64") {
		t.Errorf("platform = %q / %q", got[0], got[1])
	}

	g := spec("linux/x86-64", "sha256:a")
	g.Graft = "abcdefghijklmnop"
	plain := spec("linux/x86-64", "sha256:a")
	got = Distinguish([]Concrete{g, plain})
	if !strings.Contains(got[0], "grafted from abcdefghijklmnop") {
		t.Errorf("the graft is not named: %q", got[0])
	}
	if !strings.Contains(got[1], "not grafted") {
		t.Errorf("its absence is not stated: %q", got[1])
	}
}
