package artifact

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withList installs a withdrawal list for one test, bypassing the file and
// the sync.Once — which is read once per process and cannot be re-read.
func withList(t *testing.T, m map[string][]Withdrawal) {
	t.Helper()
	old := withdrawnFor
	t.Cleanup(func() { withdrawnFor = old })
	withdrawnFor = func(project string) []Withdrawal { return m[project] }
}

func buildOf(version, hash string) Build {
	return Build{Version: Ver{Raw: version, Variant: hash}, Published: true}
}

// ⛔⛔ THE CASE THIS EXISTS FOR: the package is fine, the source is fine, and
// the TOOLCHAIN it was compiled with had a CVE. The fixed artefact is another
// build of the SAME version — which is only nameable because a build has an
// identity, and is the first thing the hashed layout buys that a
// version-addressed store could not do at all.
func TestABuildIsWithdrawnWithoutCondemningItsVersion(t *testing.T) {
	const proj, ver = "fftw.org", "3.3.11"
	const bad, good = "27o3ysxva6swayci", "rnp44isdgdtzxcit"
	withList(t, map[string][]Withdrawal{proj: {{
		Version: ver, Hash: bad, Because: "CVE-2026-1234", SupersededBy: good,
	}}})

	w, yes := WithdrawalOf(proj, ver, bad)
	if !yes {
		t.Fatal("the withdrawn build was not recognised")
	}
	if w.Because != "CVE-2026-1234" || w.SupersededBy != good {
		t.Errorf("withdrawal = %+v", w)
	}
	// The sibling is untouched: the VERSION is not condemned.
	if _, yes := WithdrawalOf(proj, ver, good); yes {
		t.Error("withdrawing one build condemned its sibling")
	}
	// And a reader is told where to go.
	if s := w.String(); !strings.Contains(s, "CVE-2026-1234") || !strings.Contains(s, "→ rnp44i") {
		t.Errorf("String = %q, want the reason and the replacement", s)
	}
}

// ⛔⛔ RANK, NOT FILTER. The rule is deprecated.go's and the reason is the
// same: a lock pins a build, and a lock that stops resolving is a worse
// defect than the one being fixed.
func TestTheOnlyBuildStaysResolvableEvenWithdrawn(t *testing.T) {
	const proj, ver, only = "fftw.org", "3.3.11", "27o3ysxva6swayci"
	withList(t, map[string][]Withdrawal{proj: {{Version: ver, Hash: only, Because: "CVE-2026-1234"}}})

	keep, aside := PreferNotWithdrawn(proj, []Build{buildOf(ver, only)})
	if len(keep) != 1 || keep[0].Hash() != only {
		t.Fatalf("the only build was filtered away: keep=%v aside=%v", keep, aside)
	}
	if len(aside) != 0 {
		t.Errorf("it was reported as set aside while also being the answer: %v", aside)
	}
}

// With a clean sibling, the withdrawn one is set aside — a stated reason, not
// an invented order.
func TestACleanSiblingIsPreferredOverAWithdrawnOne(t *testing.T) {
	const proj, ver = "fftw.org", "3.3.11"
	const bad, good = "27o3ysxva6swayci", "rnp44isdgdtzxcit"
	withList(t, map[string][]Withdrawal{proj: {{Version: ver, Hash: bad, Because: "CVE-2026-1234"}}})

	keep, aside := PreferNotWithdrawn(proj, []Build{buildOf(ver, bad), buildOf(ver, good)})
	if len(keep) != 1 || keep[0].Hash() != good {
		t.Fatalf("keep = %v, want only %s", keep, good)
	}
	if len(aside) != 1 || aside[0].Hash() != bad {
		t.Fatalf("aside = %v, want %s", aside, bad)
	}
}

// ⛔ AND TWO CLEAN SIBLINGS ARE STILL AMBIGUOUS. Setting aside a build
// somebody recorded a reason for is not a licence to order the rest.
func TestTwoCleanSiblingsAreStillAmbiguous(t *testing.T) {
	const proj, ver = "fftw.org", "3.3.11"
	withList(t, map[string][]Withdrawal{proj: {{Version: ver, Hash: "zzzzzzzzzzzzzzzz", Because: "CVE-0"}}})
	keep, _ := PreferNotWithdrawn(proj, []Build{buildOf(ver, "aaaaaaaaaaaaaaaa"), buildOf(ver, "bbbbbbbbbbbbbbbb")})
	if len(keep) != 2 {
		t.Fatalf("keep = %v, want both: nothing says which of the two to take", keep)
	}
}

// ⛔⛔ A WITHDRAWAL WITH NO HASH CONDEMNS THE WHOLE VERSION — a flaw in the
// SOURCE rather than in how it was compiled — but an entry naming one build
// says something more specific and must win. A reader taking the first match
// would report "the source is bad" for the build whose own entry says it is
// the FIXED one.
func TestAnExactWithdrawalWinsOverAWholeVersionOne(t *testing.T) {
	const proj, ver = "fftw.org", "3.3.11"
	const fixed = "rnp44isdgdtzxcit"
	withList(t, map[string][]Withdrawal{proj: {
		{Version: ver, Because: "CVE-SOURCE"},
		{Version: ver, Hash: fixed, Because: "CVE-SOURCE", SupersededBy: fixed},
	}})

	// Any other build of the version is caught by the wide entry.
	if w, yes := WithdrawalOf(proj, ver, "aaaaaaaaaaaaaaaa"); !yes || w.Because != "CVE-SOURCE" {
		t.Errorf("the whole-version withdrawal did not catch a build: %+v %v", w, yes)
	}
	// The one named explicitly gets ITS entry, with the replacement.
	w, yes := WithdrawalOf(proj, ver, fixed)
	if !yes || w.SupersededBy != fixed {
		t.Errorf("the exact entry did not win: %+v", w)
	}
	// And another version is untouched.
	if _, yes := WithdrawalOf(proj, "3.3.10", ""); yes {
		t.Error("a withdrawal reached a version it does not name")
	}
}

// The note under a listing names each withdrawn build and says it is still
// resolvable, because a reader who sees "withdrawn" and nothing else will
// assume it is gone.
func TestTheNoteNamesEachWithdrawnBuildAndSaysItStillResolves(t *testing.T) {
	const proj, ver = "fftw.org", "3.3.11"
	const bad = "27o3ysxva6swayci"
	withList(t, map[string][]Withdrawal{proj: {{Version: ver, Hash: bad, Because: "CVE-2026-1234"}}})

	note := WithdrawnNote(proj, []Build{buildOf(ver, bad), buildOf(ver, "rnp44isdgdtzxcit")})
	for _, want := range []string{bad, "CVE-2026-1234", "ranked last", "resolvable"} {
		if !strings.Contains(note, want) {
			t.Errorf("note = %q, want %q in it", note, want)
		}
	}
	if strings.Contains(note, "rnp44isdgdtzxcit") {
		t.Errorf("a clean build was listed as withdrawn: %q", note)
	}
	if WithdrawnNote(proj, []Build{buildOf(ver, "rnp44isdgdtzxcit")}) != "" {
		t.Error("a note was printed with nothing to report")
	}
	// A hashless artifact can be withdrawn too, and must be nameable in the note.
	withList(t, map[string][]Withdrawal{proj: {{Version: ver, Because: "CVE-X"}}})
	if n := WithdrawnNote(proj, []Build{buildOf(ver, "")}); !strings.Contains(n, "(none)") {
		t.Errorf("note = %q, want the hashless artifact named", n)
	}
}

// ⛔ AN UNREADABLE OR UNPARSABLE FILE IS WARNED ABOUT AND MEANS AN EMPTY
// LIST — it is NOT replaced by the default. An operator who named a file has
// said what they want, and quietly substituting something else hides their
// mistake behind working behaviour.
func TestABrokenListIsReportedAndNotSubstituted(t *testing.T) {
	for _, tc := range []struct{ name, write string }{
		{"unparsable", "{not json"},
		{"unreadable", ""}, // "" = do not create the file at all
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "w.json")
			if tc.write != "" {
				if err := os.WriteFile(p, []byte(tc.write), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			var errb bytes.Buffer
			old := deprecationOut
			deprecationOut = &errb
			t.Cleanup(func() { deprecationOut = old })
			t.Setenv(WithdrawnEnv, p)

			if got := loadWithdrawn(); len(got) != 0 {
				t.Errorf("a broken list produced entries: %v", got)
			}
			if !strings.Contains(errb.String(), WithdrawnEnv) {
				t.Errorf("nothing was said about the broken file: %q", errb.String())
			}
			// ⛔ AND IT IS NOT THE DEFAULT. Substituting it would hide the
			// operator's mistake behind working behaviour — the direction
			// deprecated.go names as the surprising one to avoid.
			if got := loadWithdrawn(); got != nil {
				t.Errorf("a broken list fell back to a list: %v", got)
			}
		})
	}
	// An unset variable is the default, which is the no-op.
	t.Setenv(WithdrawnEnv, "")
	if got := loadWithdrawn(); len(got) != len(DefaultWithdrawn) {
		t.Errorf("unset = %v, want the default", got)
	}
}
