package artifact

import (
	"testing"
	"time"
)

func withDeps(hash string, deps ...Dep) Build {
	return Build{
		Version: Ver{Raw: "3.3.11", Variant: hash},
		Spec:    Concrete{Platform: "linux/x86-64", Recipe: "sha256:a", Deps: deps},
	}
}

func goDep(v string) Dep { return Dep{Project: "go.dev", Version: v, Hash: "h" + v} }

// ⛔⛔ THE ORDER A READER ACTUALLY MEANS BY "NEWER": a build made against a
// later toolchain comes first. There is no build date, but the CLOSURE is
// recorded — so this is a comparison of two facts rather than an inference,
// and it is exactly the comparison a CVE rebuild creates.
func TestAnEarlierToolchainIsAnEarlierBuild(t *testing.T) {
	withList(t, map[string][]Withdrawal{})
	// `aaa…` sorts first by hash, so a key that did nothing would leave the
	// OLD toolchain in front.
	old := withDeps("aaaaaaaaaaaaaaaa", goDep("1.27.3"))
	recent := withDeps("zzzzzzzzzzzzzzzz", goDep("1.27.4"))

	got := SortBuilds("fftw.org", []Build{old, recent}, ByClosure)
	if h := hashesOf(got); h[0] != "zzzzzzzzzzzzzzzz" {
		t.Errorf("order = %v, want the later toolchain first", h)
	}
	// And the relation itself, stated directly.
	if !closureIsLater(recent.Spec, old.Spec) {
		t.Error("1.27.4 is not reported as later than 1.27.3")
	}
	if closureIsLater(old.Spec, recent.Spec) {
		t.Error("the relation is not antisymmetric")
	}
}

// ⛔⛔ TWO BUILDS THAT EACH LEAD ON A DIFFERENT DEPENDENCY ARE INCOMPARABLE,
// and saying otherwise would be the invented order this codebase keeps
// refusing. They tie, and the tie falls back to the hash so the output is
// still stable.
func TestTwoClosuresThatEachLeadOnSomethingAreIncomparable(t *testing.T) {
	withList(t, map[string][]Withdrawal{})
	a := withDeps("aaaaaaaaaaaaaaaa", goDep("1.27.4"), Dep{Project: "zlib.net", Version: "1.3.1"})
	b := withDeps("bbbbbbbbbbbbbbbb", goDep("1.27.3"), Dep{Project: "zlib.net", Version: "1.3.2"})

	if closureIsLater(a.Spec, b.Spec) || closureIsLater(b.Spec, a.Spec) {
		t.Error("one of two incomparable closures was declared later")
	}
	got := SortBuilds("fftw.org", []Build{b, a}, ByClosure)
	if h := hashesOf(got); h[0] != "aaaaaaaaaaaaaaaa" {
		t.Errorf("the tie did not fall back to the hash: %v", h)
	}
}

// ⛔ ONLY SHARED DEPENDENCIES ARE COMPARED. A build that gained a dependency
// the other does not have is a different SHAPE, not a later version of it;
// treating the extra edge as "newer" would say the CUDA build supersedes the
// plain one, which is a statement about taste and not about time.
func TestAnExtraDependencyIsNotLaterness(t *testing.T) {
	plain := withDeps("aaaaaaaaaaaaaaaa", goDep("1.27.3"))
	cuda := withDeps("bbbbbbbbbbbbbbbb", goDep("1.27.3"), Dep{Project: "cuda.nvidia.com", Version: "12.4"})
	if closureIsLater(cuda.Spec, plain.Spec) || closureIsLater(plain.Spec, cuda.Spec) {
		t.Error("an extra dependency was read as being later")
	}
}

// ⛔ A SPEC THAT RECORDS NOTHING IS NEITHER LATER NOR EARLIER. Every artifact
// published before identities existed is one of those, and ranking it
// against a described build would compare a fact with a blank.
func TestABuildWithNoSpecIsNeverOrdered(t *testing.T) {
	withList(t, map[string][]Withdrawal{})
	known := withDeps("bbbbbbbbbbbbbbbb", goDep("1.27.4"))
	unknown := Build{Version: Ver{Raw: "3.3.11"}}
	if closureIsLater(known.Spec, unknown.Spec) || closureIsLater(unknown.Spec, known.Spec) {
		t.Error("a build nothing records took part in the ordering")
	}
	// It still appears, and the sort does not panic or drop it.
	got := SortBuilds("fftw.org", []Build{known, unknown}, ByClosure)
	if len(got) != 2 {
		t.Fatalf("a build was dropped: %v", hashesOf(got))
	}
}

// ⛔⛔ THREE BUILDS WHERE ONE PAIR IS COMPARABLE AND THE THIRD IS NOT. This is
// the case a chain cannot express and the reason the rank is a COUNT — and
// the case where a partial order used directly as a `less` function would
// give sort a comparator that is not a strict weak ordering.
func TestAPartialOrderOverThreeBuildsDoesNotConfuseTheSort(t *testing.T) {
	withList(t, map[string][]Withdrawal{})
	older := withDeps("aaaaaaaaaaaaaaaa", goDep("1.27.3"))
	newer := withDeps("bbbbbbbbbbbbbbbb", goDep("1.27.4"))
	apart := withDeps("cccccccccccccccc", Dep{Project: "zlib.net", Version: "1.3.2"})

	got := SortBuilds("fftw.org", []Build{older, apart, newer}, ByClosure)
	h := hashesOf(got)
	if len(h) != 3 {
		t.Fatalf("builds were lost: %v", h)
	}
	// The one thing that must hold: the superseded build is not first, and
	// the build that supersedes it comes before it.
	var iNew, iOld int
	for i, s := range h {
		switch s {
		case "bbbbbbbbbbbbbbbb":
			iNew = i
		case "aaaaaaaaaaaaaaaa":
			iOld = i
		}
	}
	if iNew > iOld {
		t.Errorf("the later toolchain sorted after the earlier one: %v", h)
	}
	// Stable across input orders, which a broken comparator would not be.
	again := hashesOf(SortBuilds("fftw.org", []Build{newer, older, apart}, ByClosure))
	for i := range h {
		if h[i] != again[i] {
			t.Fatalf("two input orders gave %v and %v", h, again)
		}
	}
}

// The key parses, and the ones that came before it still do.
func TestClosureIsASortKey(t *testing.T) {
	if got, err := ParseBuildOrder("closure"); err != nil || got != ByClosure {
		t.Fatalf("ParseBuildOrder(closure) = %q, %v", got, err)
	}
	withList(t, map[string][]Withdrawal{})
	// And it does not disturb the other keys' tie-breaking.
	a := at("bbbbbbbbbbbbbbbb", time.Time{}, "")
	b := at("aaaaaaaaaaaaaaaa", time.Time{}, "")
	if h := hashesOf(SortBuilds("fftw.org", []Build{a, b}, ByClosure)); h[0] != "aaaaaaaaaaaaaaaa" {
		t.Errorf("two specless builds did not fall back to the hash: %v", h)
	}
}
