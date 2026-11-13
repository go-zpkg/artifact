package artifact

import (
	"strings"
	"testing"
)

// ⛔ A COUNT IS NOT AN ANSWER, AND THIS ONE READ AS A VERSION. The message
// used to end "(available: 1)", which beside a constraint of "=1.7.1" reads
// as a claim about version 1 — measured 2026-10-08 on the author of the
// sentence, seconds after writing it. A count also withholds the one fact
// that ends the problem: WHICH versions exist.
func TestAvailableVersionsNamesThemNewestFirst(t *testing.T) {
	vs := []Ver{ParseVer("1.6.0"), ParseVer("1.7.1"), ParseVer("1.8.2")}
	got := availableVersions(vs)
	if got != "1.8.2 1.7.1 1.6.0" {
		t.Errorf("availableVersions = %q, want newest first", got)
	}
	// ⛔ THE REGRESSION ITSELF: a bare count, which is what this replaces.
	if got == "3" {
		t.Errorf("still a count: %q", got)
	}
}

// A PROJECT CAN CARRY HUNDREDS, so the list is capped — but the total is
// still stated, because "six versions" and "six hundred" are different
// problems and the reader must be able to tell them apart.
func TestAvailableVersionsCapsTheListAndSaysTheTotal(t *testing.T) {
	var vs []Ver
	for i := 0; i < 40; i++ {
		vs = append(vs, ParseVer("1.0."+string(rune('0'+i%10))))
	}
	got := availableVersions(vs)
	// Count the VERSIONS, not the spaces: the "… (40 in all)" tail has
	// spaces of its own, and counting those measured the suffix instead of
	// the cap it was meant to check.
	listed, _, _ := strings.Cut(got, " … ")
	if n := len(strings.Fields(listed)); n != 6 {
		t.Errorf("listed %d versions, want 6: %q", n, got)
	}
	if !strings.Contains(got, "40 in all") {
		t.Errorf("the total is missing: %q", got)
	}
}

// AN EMPTY LIST SAYS SO. "available: " with nothing after it reads as a
// truncated message rather than an answer.
func TestAvailableVersionsOfNoneSaysSo(t *testing.T) {
	if got := availableVersions(nil); got != "none" {
		t.Errorf("availableVersions(nil) = %q, want none", got)
	}
}

// AND THE SENTENCE ITSELF, through the real resolver against a real listing:
// a unit test on the helper cannot show that the helper is actually reached.
func TestUnsatisfiableConstraintNamesTheVersionsItHas(t *testing.T) {
	up, _ := upstreamVersionsServer(t, "plain.org", "linux", "aarch64", []string{"1.0.0", "1.1.0"})
	oldDist := DistBase
	DistBase = up
	defer func() { DistBase = oldDist }()

	_, err := PickVersionForAll("plain.org", []string{"=9.9.9"}, "linux", "aarch64")
	if err == nil {
		t.Fatal("a constraint nothing satisfies resolved")
	}
	got := err.Error()
	if !strings.Contains(got, "1.1.0") || !strings.Contains(got, "1.0.0") {
		t.Errorf("the versions it does have are not named: %q", got)
	}
	if strings.Contains(got, "available: 2") {
		t.Errorf("still a count: %q", got)
	}
}

// ⛔ NO CONSTRAINT MUST NOT PRINT AN EMPTY ONE.
//
// Reported from the field on 2026-10-12: `pkgx hugo version` asks for any
// version, so collectGraph drops the "*" ("nothing to intersect") and
// PickVersionForAll is called with NO constraints. quoteAll rendered "" and
// the sentence read
//
//	no version of opentofu.org satisfies  AND is published for darwin/aarch64 (available: 1.12.5…)
//
// — two spaces where the reason should be, blaming a constraint that does not
// exist. With nothing constrained the platform is the whole of what went
// wrong, so the clause is omitted rather than filled with "any version".
func TestNoConstraintOmitsTheSatisfiesClause(t *testing.T) {
	fr := newFakeRegistry(t, false)
	base := fr.base("go-zpkg/artifacts")
	old := DistBase
	DistBase = base
	resetOCICache()
	t.Cleanup(func() { DistBase = old; resetOCICache() })

	c, err := NewOCIClient(base)
	if err != nil {
		t.Fatal(err)
	}
	// Published for linux only, so darwin reaches the "absent" arm.
	if _, err := c.PushWithReferrers("only.test", "1.2.3", "linux", "x86-64", makeGzTarball("linux"), ".tar.gz", nil); err != nil {
		t.Fatal(err)
	}

	_, err = PickVersionForAll("only.test", nil, "darwin", "aarch64")
	if err == nil {
		t.Fatal("an unpublished platform resolved")
	}
	got := err.Error()
	// ⛔ THE REGRESSION ITSELF: the hole, in either spelling.
	if strings.Contains(got, "satisfies  AND") || strings.Contains(got, `satisfies "" `) {
		t.Errorf("the empty constraint is still printed: %q", got)
	}
	if strings.Contains(got, "satisfies") {
		t.Errorf("nothing was constrained, so the clause should be gone: %q", got)
	}
	// And it still says what went wrong and what exists.
	for _, want := range []string{"not published", "darwin/aarch64", "1.2.3"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q from: %q", want, got)
		}
	}
}

// The control for the test above: WITH a constraint the clause is still there,
// quoted. Without this, removing the clause unconditionally would pass.
func TestAConstraintIsStillQuotedInTheMessage(t *testing.T) {
	fr := newFakeRegistry(t, false)
	base := fr.base("go-zpkg/artifacts")
	old := DistBase
	DistBase = base
	resetOCICache()
	t.Cleanup(func() { DistBase = old; resetOCICache() })

	c, err := NewOCIClient(base)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.PushWithReferrers("other.test", "1.2.3", "linux", "x86-64", makeGzTarball("linux"), ".tar.gz", nil); err != nil {
		t.Fatal(err)
	}

	_, err = PickVersionForAll("other.test", []string{"^1"}, "darwin", "aarch64")
	if err == nil {
		t.Fatal("an unpublished platform resolved")
	}
	if got := err.Error(); !strings.Contains(got, `satisfies "^1" AND is published`) {
		t.Errorf("the constraint clause is gone when there IS a constraint: %q", got)
	}
}

// No versions and no constraint: there is nothing to say about satisfying
// either, so the sentence says the one thing that is true.
func TestNoVersionsAndNoConstraintSaysSo(t *testing.T) {
	up, _ := upstreamVersionsServer(t, "empty.org", "linux", "aarch64", nil)
	old := DistBase
	DistBase = up
	t.Cleanup(func() { DistBase = old })

	_, err := PickVersionForAll("empty.org", nil, "linux", "aarch64")
	if err == nil {
		t.Fatal("a project with no versions resolved")
	}
	got := err.Error()
	if !strings.Contains(got, "no versions of empty.org are known") {
		t.Errorf("got %q", got)
	}
	if strings.Contains(got, "satisfies") {
		t.Errorf("it still mentions satisfying nothing: %q", got)
	}
}

// ⛔ "NOT PUBLISHED HERE" IS NOT AN AUTH FAILURE, and must not read like one.
//
// Reported from the field on 2026-10-12. `pkgx openstack --version` against
// the signed registry answered:
//
//	resolve opendev.org/openstack/python-openstackclient v10.4.0:
//	  GET ".../manifests/10.4.0": GET "https://ghcr.io/token?scope=…":
//	  response status code 403: denied: requested access to the resource is denied
//
// ghcr answers 403 at the TOKEN endpoint for a repository that does not
// exist, so for an anonymous read that is "we do not carry this" — which
// repoAbsent already decided for the version listing while this path handed
// the transport error straight out. The same condition had two voices
// depending on which call noticed first.
//
// The underlying error is KEPT, wrapped: a reader debugging a genuine
// credential problem still needs the status, and a message that threw it away
// would trade one blind spot for another.
func TestAnAbsentRepositorySaysSoRatherThanTheTransportError(t *testing.T) {
	fr := newFakeRegistry(t, false)
	base := fr.base("go-zpkg/artifacts")
	old := DistBase
	DistBase = base
	resetOCICache()
	t.Cleanup(func() { DistBase = old; resetOCICache() })

	c, err := NewOCIClient(base)
	if err != nil {
		t.Fatal(err)
	}
	// Never pushed: the repository does not exist.
	_, err = c.PlatformAnnotations("never.pushed", "1.0.0", "linux", "x86-64")
	if err == nil {
		t.Fatal("a repository that was never pushed resolved")
	}
	got := err.Error()
	if !strings.Contains(got, "is not published in") {
		t.Errorf("it does not say the registry lacks it: %q", got)
	}
	if !strings.Contains(got, "never.pushed") {
		t.Errorf("it does not name the project: %q", got)
	}
	// The transport detail survives, for the case where it IS the problem.
	if !strings.Contains(got, "404") && !strings.Contains(got, "403") && !strings.Contains(got, "not found") {
		t.Errorf("the underlying status was thrown away: %q", got)
	}
}
