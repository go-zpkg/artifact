package artifact

import (
	"encoding/json"
	"os"
	"testing"
)

// Measured against the REAL published catalogue, because the defect only
// shows at its scale: `pkgx search rg` returned 625 projects, of which 550
// matched only because "rg" is inside ".org".
//
// Skipped when the catalogue is not to hand, so the suite does not depend
// on a file nobody else has — but when it IS there, these are the numbers
// that decide whether the rule is right.
func TestSearchNoiseAgainstTheRealCatalogue(t *testing.T) {
	const path = "/private/tmp/claude-501/-Users-david-delavennat-Documents-VCS-GIT-localhost/" +
		"33aa3e72-4f98-478f-99a4-837c37d18cc5/scratchpad/pub2.json"
	b, err := os.ReadFile(path)
	if err != nil {
		t.Skip("no published catalogue to hand")
	}
	var c Catalog
	if err := json.Unmarshal(b, &c); err != nil {
		t.Skip("not a catalogue")
	}

	for _, tc := range []struct {
		query string
		first string // "" = do not pin the first hit, only the count
		max   int
	}{
		{"rg", "crates.io/ripgrep", 10},
		{"ssl", "", 10},
		{"videolan", "", 20},
		{"jpeg", "", 30},
	} {
		got := c.Search(tc.query)
		if len(got) == 0 {
			t.Errorf("%q found nothing", tc.query)
			continue
		}
		if len(got) > tc.max {
			t.Errorf("%q returned %d hits (was 625 for rg before the label rule)", tc.query, len(got))
		}
		t.Logf("%-10q %4d hits, first %s (%s)", tc.query, len(got), got[0].Project, got[0].Why)
	}

	// THE CONTROLS the rule could have broken, and the reason it is a
	// LENGTH rule and not a cleverer one.
	//
	// "ssl" must still reach openssl.org — a label-boundary rule would
	// have dropped it, since "ssl" starts no label of "openssl.org", and
	// that was my first attempt.
	if !reaches(c.Search("ssl"), "openssl.org") {
		t.Error("openssl.org is no longer found by \"ssl\"")
	}
	// And a query naming a HOST must still reach a project whose leaf is
	// something else entirely.
	if !reaches(c.Search("videolan"), "code.videolan.org/rist/librist") {
		t.Error("a host query no longer reaches its project")
	}
	// A two-character query still finds its COMMAND, which is what short
	// queries are actually for.
	if !reaches(c.Search("rg"), "crates.io/ripgrep") {
		t.Error("rg no longer finds ripgrep")
	}
}

func reaches(hits []SearchHit, project string) bool {
	for _, h := range hits {
		if h.Project == project {
			return true
		}
	}
	return false
}
