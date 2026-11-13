package artifact

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func at(hash string, when time.Time, installed string) Build {
	return Build{Version: Ver{Raw: "3.3.11", Variant: hash}, Installed: installed, InstalledAt: when}
}

func hashesOf(builds []Build) []string {
	out := make([]string, len(builds))
	for i, b := range builds {
		out[i] = b.Hash()
	}
	return out
}

// ⛔⛔ THE WITHDRAWN BUILDS GO LAST, AND THAT IS THE ONLY JUDGEMENT IN ANY OF
// THESE KEYS — made by a person and written in the withdrawal list, not
// inferred here.
func TestByStatusPutsWithdrawnBuildsLast(t *testing.T) {
	const bad, good = "aaaaaaaaaaaaaaaa", "zzzzzzzzzzzzzzzz"
	withList(t, map[string][]Withdrawal{"fftw.org": {{Version: "3.3.11", Hash: bad, Because: "CVE-1"}}})

	// `bad` sorts first by hash, so a key that did nothing would leave it there.
	got := SortBuilds("fftw.org", []Build{at(bad, time.Time{}, ""), at(good, time.Time{}, "")}, ByStatus)
	if h := hashesOf(got); h[0] != good || h[1] != bad {
		t.Errorf("order = %v, want the clean build first", h)
	}
}

// ⛔ EVERY KEY FALLS BACK TO THE HASH. Without it, two builds that tie keep
// whatever order they arrived in — a map walk — so the same command would
// print a different list twice and a reader would stop believing either.
func TestEveryKeyIsStableOnATie(t *testing.T) {
	withList(t, map[string][]Withdrawal{})
	for _, by := range BuildOrders {
		a, b := at("bbbbbbbbbbbbbbbb", time.Time{}, ""), at("aaaaaaaaaaaaaaaa", time.Time{}, "")
		first := hashesOf(SortBuilds("fftw.org", []Build{a, b}, by))
		second := hashesOf(SortBuilds("fftw.org", []Build{b, a}, by))
		if first[0] != second[0] || first[1] != second[1] {
			t.Errorf("%s: two input orders gave %v and %v", by, first, second)
		}
		if first[0] != "aaaaaaaaaaaaaaaa" {
			t.Errorf("%s: the tie did not fall back to the hash: %v", by, first)
		}
	}
}

// Most recently installed first, and the ones that are not installed at all
// go last whatever the zero time would otherwise do.
func TestByInstalledOrdersWhatThisMachineHasAndPutsTheRestLast(t *testing.T) {
	withList(t, map[string][]Withdrawal{})
	old := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	recent := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	got := SortBuilds("fftw.org", []Build{
		at("aaaaaaaaaaaaaaaa", time.Time{}, ""),  // not installed
		at("bbbbbbbbbbbbbbbb", old, "/s/old"),    //
		at("cccccccccccccccc", recent, "/s/new"), //
	}, ByInstalled)
	if h := hashesOf(got); h[0] != "cccccccccccccccc" || h[1] != "bbbbbbbbbbbbbbbb" || h[2] != "aaaaaaaaaaaaaaaa" {
		t.Errorf("order = %v, want newest, older, not-installed", h)
	}
}

// ⛔⛔ THE ABSENCE OF A BUILD DATE IS EXPLAINED, NOT LEFT TO LOOK LIKE AN
// OVERSIGHT. A reader who asks to sort by date is asking for something a
// published artifact cannot carry: the timestamp is pinned so a re-publish is
// byte-identical, so every artifact has the SAME instant.
func TestThereIsNoDateKeyAndTheReasonIsSayable(t *testing.T) {
	if _, err := ParseBuildOrder("date"); err == nil {
		t.Fatal("a date key was accepted; there is no build date to sort by")
	} else if !strings.Contains(err.Error(), "status") {
		t.Errorf("the refusal does not name the alternatives: %v", err)
	}
	for _, want := range []string{"pinned", "byte-identical", "--sort=installed"} {
		if !strings.Contains(WhyNoDate, want) {
			t.Errorf("WhyNoDate does not say %q: %q", want, WhyNoDate)
		}
	}
	// And the keys that DO exist parse.
	for _, o := range BuildOrders {
		if got, err := ParseBuildOrder(string(o)); err != nil || got != o {
			t.Errorf("ParseBuildOrder(%q) = %q, %v", o, got, err)
		}
	}
}

// installedAt reads the DIRECTORY's own mtime. A file inside it carries the
// timestamp the archive recorded, which the publisher pinned — so reading one
// would report the pinned epoch and call it an install date.
func TestInstalledAtReadsTheDirectoryAndNotItsContents(t *testing.T) {
	dir := t.TempDir()
	build := filepath.Join(dir, "v3.3.11-haaaaaaaaaaaaaaaa")
	if err := os.MkdirAll(filepath.Join(build, "lib"), 0o755); err != nil {
		t.Fatal(err)
	}
	// A file stamped in 2001, as an extracted artifact's files are.
	f := filepath.Join(build, "lib", "libz.so")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	pinned := time.Date(2001, 9, 9, 1, 46, 40, 0, time.UTC)
	if err := os.Chtimes(f, pinned, pinned); err != nil {
		t.Fatal(err)
	}

	got := installedAt(build)
	if got.IsZero() {
		t.Fatal("no time for an installed build")
	}
	if got.Equal(pinned) {
		t.Errorf("the pinned file timestamp was reported as the install date: %s", got)
	}
	// Not installed, and unreadable, are both the zero time rather than now.
	if !installedAt("").IsZero() {
		t.Error("an empty path produced a time")
	}
	if !installedAt(filepath.Join(dir, "absent")).IsZero() {
		t.Error("a missing directory produced a time")
	}
}
