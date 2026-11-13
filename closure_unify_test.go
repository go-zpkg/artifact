package artifact

import (
	"strings"
	"testing"
)

// gettextFixture is the real shape that exposed this: one library two packages
// pin to different majors. gnu.org/gettext 0.26 and 1.0.0 ship the SAME
// libintl.8.dylib at compatibility version 13, so the majors here are the
// project's own numbering and not an ABI boundary — but the resolver cannot
// know that, and installs one prefix.
func gettextFixture() map[string]fakePkg {
	return map[string]fakePkg{
		"gnu.org/gettext": {versions: []string{"0.25.1", "0.26", "1.0.0"}, yaml: "provides:\n  - bin/msgfmt\n"},
		"gnome.org/glib": {versions: []string{"2.89.4"},
			yaml: "dependencies:\n  gnu.org/gettext: ^0.21\n"},
		"freedesktop.org/fontconfig": {versions: []string{"2.18.3"},
			yaml: "dependencies:\n  gnu.org/gettext: ^1\n"},
		"acme.org/newish": {versions: []string{"1.0.0"},
			yaml: "dependencies:\n  gnu.org/gettext: '>=0.25'\n"},
		// asks for the SAME constraint as glib: one demand, not two.
		"acme.org/echo": {versions: []string{"1.0.0"},
			yaml: "dependencies:\n  gnu.org/gettext: ^0.21\n"},
	}
}

// TestClosureUnifiesEveryConstraint: a project reached twice must satisfy BOTH
// demands, not the first one to arrive.
//
// The old walk kept the first constraint and dropped the rest, so a closure
// containing a `>=0.25` and a `^0.21` could resolve to 1.0.0 — satisfying the
// one it happened to see and silently breaking the other.
func TestClosureUnifiesEveryConstraint(t *testing.T) {
	defer fakeServer(t, gettextFixture())()
	osn, arch := HostSlug()
	got, err := ResolveClosureFor(map[string]string{
		"gnome.org/glib":  "*",
		"acme.org/newish": "*",
	}, osn, arch)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range got {
		if r.Project != "gnu.org/gettext" {
			continue
		}
		// ^0.21 AND >=0.25 -> the newest 0.x, not the newest overall.
		if r.Version.Raw != "0.26" {
			t.Errorf("gettext = %s, want 0.26 (the newest satisfying BOTH)", r.Version.Raw)
		}
		return
	}
	t.Fatalf("gettext not in the closure: %v", got)
}

// TestClosureRefusesAConflictAndNamesWho: two constraints that cannot hold
// together are an error, not a coin flip.
//
// Measured before this change: twelve resolutions of the same roots picked
// gettext 0.26 eight times and 1.0.0 four times, because the walk was seeded
// from a Go map. Whichever lost, its package could not load — and nothing said
// so at resolution time.
func TestClosureRefusesAConflictAndNamesWho(t *testing.T) {
	defer fakeServer(t, gettextFixture())()
	osn, arch := HostSlug()
	_, err := ResolveClosureFor(map[string]string{
		"gnome.org/glib":             "*",
		"freedesktop.org/fontconfig": "*",
	}, osn, arch)
	if err == nil {
		t.Fatal("want a refusal for ^0.21 AND ^1, got a resolution")
	}
	// The reader has to know WHICH packages disagree, or the message sends them
	// grepping the whole pantry.
	for _, want := range []string{"gnu.org/gettext", `"^0.21"`, `"^1"`, "gnome.org/glib", "freedesktop.org/fontconfig"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %s: %v", want, err)
		}
	}
}

// TestClosureCountsARepeatedDemandOnce: two packages asking for the identical
// constraint are one demand. Listing it twice would make the error message
// name the same string twice and read like a conflict with itself.
func TestClosureCountsARepeatedDemandOnce(t *testing.T) {
	defer fakeServer(t, gettextFixture())()
	osn, arch := HostSlug()
	got, err := ResolveClosureFor(map[string]string{
		"gnome.org/glib": "*",
		"acme.org/echo":  "*",
	}, osn, arch)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range got {
		if r.Project == "gnu.org/gettext" && r.Version.Raw != "0.26" {
			t.Errorf("gettext = %s, want 0.26", r.Version.Raw)
		}
	}
}

// TestClosureIsDeterministic: the same roots resolve to the same closure every
// time. Go randomises map iteration, so a walk seeded from one is a closure
// that changes between runs.
func TestClosureIsDeterministic(t *testing.T) {
	defer fakeServer(t, gettextFixture())()
	osn, arch := HostSlug()
	roots := map[string]string{"gnome.org/glib": "*", "acme.org/newish": "*"}
	var first string
	for i := 0; i < 8; i++ {
		got, err := ResolveClosureFor(roots, osn, arch)
		if err != nil {
			t.Fatal(err)
		}
		var b strings.Builder
		for _, r := range got {
			b.WriteString(r.Project + "@" + r.Version.Raw + " ")
		}
		if i == 0 {
			first = b.String()
			continue
		}
		if b.String() != first {
			t.Fatalf("run %d differs:\n  %s\n  %s", i, first, b.String())
		}
	}
}

// TestSatisfiesAllAndQuoteAll covers the two helpers directly: an empty
// constraint set is met by anything (a project reached only as a dependency of
// something that named no version), and one constraint must still read the way
// it always did.
func TestSatisfiesAllAndQuoteAll(t *testing.T) {
	if !satisfiesAll(ParseVer("1.2.3"), nil) {
		t.Error("an empty constraint set must be satisfied by anything")
	}
	if satisfiesAll(ParseVer("1.2.3"), []string{"^1", "^2"}) {
		t.Error("^1 AND ^2 cannot both hold")
	}
	if got := quoteAll([]string{"^1"}); got != `"^1"` {
		t.Errorf("one constraint = %s", got)
	}
	if got := quoteAll([]string{"^1", ">=2"}); got != `"^1" AND ">=2"` {
		t.Errorf("two constraints = %s", got)
	}
}
