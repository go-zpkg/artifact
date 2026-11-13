package artifact

import (
	"slices"
	"strings"
	"testing"
	"time"
)

// ⛔⛔ THE LIBRARY'S DEFAULT IS NOT EMPTY, which is the whole point of this
// file. The ranking failed to reach the fleet twice by being inert: first
// behind an environment variable nobody set, then behind an activation that
// lived in one module's `internal` package. A default that starts empty is the
// same defect waiting for the next binary.
func TestTheLibraryCarriesTheListWithoutAnyActivation(t *testing.T) {
	if len(DefaultDeprecated) == 0 {
		t.Fatal("DefaultDeprecated is empty, so the EOL ranking is inert again")
	}
	if len(DefaultDeprecated["openssl.org"]) == 0 {
		t.Error("openssl.org has no deprecated lines, which is what this was built for")
	}
}

// ⛔ A LINE CANNOT BE BOTH. Listing a line that is still supported is the
// expensive mistake: it would push `^3` off the 3.5 LTS onto something older,
// quietly, with no error anywhere. Both halves of the measurement are
// recorded so that edit fails here instead of shipping.
func TestNoSupportedLineIsListedAsDeprecated(t *testing.T) {
	for project, supported := range KnownSupported {
		for _, line := range supported {
			if slices.Contains(KnownDeprecated[project], line) {
				t.Errorf("%s %s is listed as BOTH supported and deprecated", project, line)
			}
		}
	}
}

// Every project named in one half must be named in the other: a project with
// deprecated lines and no recorded supported line has had only half its
// verdict written down, and nothing would catch the day its last supported
// line is deprecated too.
func TestBothHalvesCoverTheSameProjects(t *testing.T) {
	for project := range KnownDeprecated {
		if len(KnownSupported[project]) == 0 {
			t.Errorf("%s has deprecated lines but no supported ones recorded", project)
		}
	}
	for project := range KnownSupported {
		if _, ok := KnownDeprecated[project]; !ok {
			t.Errorf("%s has supported lines but no deprecated ones recorded", project)
		}
	}
}

// The date is the only thing that distinguishes a current judgement from one a
// release left behind, and a date that does not parse is no date at all. In
// the future it is a typo, not a measurement.
func TestTheListIsDated(t *testing.T) {
	d, err := time.Parse(time.DateOnly, KnownDeprecatedAsOf)
	if err != nil {
		t.Fatalf("KnownDeprecatedAsOf = %q: %v", KnownDeprecatedAsOf, err)
	}
	if d.After(time.Now().UTC().AddDate(0, 0, 1)) {
		t.Errorf("KnownDeprecatedAsOf %s is in the future", KnownDeprecatedAsOf)
	}
}

// ⛔ EVERY LINE IS A PREFIX OF A REAL VERSION STRING, not a version itself.
// `deprecatedLine` matches a raw version against these by line, so "3.6" must
// cover 3.6.4 while "3.6.4" would cover only itself — writing a full version
// here would silently narrow the list to one release.
func TestTheListHoldsLinesNotVersions(t *testing.T) {
	for project, lines := range KnownDeprecated {
		for _, line := range lines {
			switch {
			case line == "":
				// deprecatedLine skips an empty entry, so it silently covers
				// nothing while reading as a rule.
				t.Errorf("%s has an empty line, which matches nothing", project)
			case strings.HasPrefix(line, "."), strings.HasSuffix(line, "."):
				t.Errorf("%s line %q is not a dotted prefix", project, line)
			case strings.Count(line, ".") > 2:
				// A full version still matches itself, so it reads as if the
				// whole line were covered while covering one release — the
				// kind of entry that looks right in review.
				t.Errorf("%s line %q has four components: a release, not a line", project, line)
			}
		}
	}
}
