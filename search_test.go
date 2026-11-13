package artifact

import (
	"strings"
	"testing"
)

func searchCatalog() Catalog {
	return Catalog{
		Generated: "2026-10-06T09:00:00Z",
		Projects: []CatalogProject{
			{Project: "crates.io/ripgrep", Provides: []string{"rg"}},
			{Project: "stedolan.github.io/jq", Provides: []string{"jq"}},
			{Project: "openssl.org", Provides: []string{"openssl"}},
			{Project: "python.org", Provides: []string{"python", "python3", "pydoc"}},
			{Project: "gnu.org/bash", Provides: []string{"bash", "sh"}},
			// Sorts BEFORE crates.io alphabetically, deliberately: with a
			// name like rgbds.gbdev.io the exact-match test passed on the
			// tie-break instead of on the ranking, and the mutation that
			// removes the exact-command rank still left `rg` in the right
			// order.
			{Project: "aardvark.io/rgbds", Provides: []string{"rgbasm", "rgblink"}},
			{Project: "agpt.co", Summary: "an experimental attempt to make GPT-4 autonomous"},
			{Project: "nothing.example", Provides: []string{"zzz"}},
		},
	}
}

// The case the whole thing exists for: you know the COMMAND and not the
// package. `rg` is crates.io/ripgrep, which no amount of guessing at the
// project name reaches, and which a prefix completion on "rg" never will.
func TestSearchFindsAPackageByTheCommandItProvides(t *testing.T) {
	c := searchCatalog()
	got := c.Search("rg")
	if len(got) == 0 {
		t.Fatal("no results for rg")
	}
	if got[0].Project != "crates.io/ripgrep" {
		t.Errorf("first hit = %s, want crates.io/ripgrep", got[0].Project)
	}
	if got[0].Why != "command" || got[0].Match != "rg" {
		t.Errorf("the reader is not told WHY: %+v", got[0])
	}
	// rgbds also matches, by prefix, and must come AFTER: a command named
	// exactly what you typed is what you meant.
	var names []string
	for _, h := range got {
		names = append(names, h.Project)
	}
	if len(got) < 2 || got[1].Project != "aardvark.io/rgbds" {
		t.Errorf("ranking = %v, want the exact command first then the prefix", names)
	}
}

// Ranking is by HOW it matched, not by how often.
func TestSearchRanksExactBeforeSubstring(t *testing.T) {
	c := searchCatalog()
	for _, tc := range []struct {
		query, first, why string
	}{
		{"rg", "crates.io/ripgrep", "command"},
		{"jq", "stedolan.github.io/jq", "command"},
		{"python", "python.org", "command"},
		{"ssl", "openssl.org", "name"},
		{"autonomous", "agpt.co", "summary"},
	} {
		got := c.Search(tc.query)
		if len(got) == 0 {
			t.Errorf("%q found nothing", tc.query)
			continue
		}
		if got[0].Project != tc.first || got[0].Why != tc.why {
			t.Errorf("%q → %s (%s), want %s (%s)", tc.query, got[0].Project, got[0].Why, tc.first, tc.why)
		}
	}
}

// One project, one line. A package matching on its name AND on two of its
// commands is still one answer; listing it three times would push the next
// real answer off the screen.
func TestSearchReportsAProjectOnce(t *testing.T) {
	c := searchCatalog()
	got := c.Search("python")
	seen := map[string]int{}
	for _, h := range got {
		seen[h.Project]++
	}
	if seen["python.org"] != 1 {
		t.Errorf("python.org appears %d times", seen["python.org"])
	}
	// And the reason given is the BEST one, not the last one looked at.
	if got[0].Why != "command" {
		t.Errorf("why = %q, want the strongest reason", got[0].Why)
	}
}

// Same query, same order, every time: the Projects slice comes off a
// registry and its order is not ours to rely on.
func TestSearchIsStable(t *testing.T) {
	c := searchCatalog()
	first := c.Search("p")
	for i := 0; i < 20; i++ {
		got := c.Search("p")
		if len(got) != len(first) {
			t.Fatalf("run %d returned %d hits, first run %d", i, len(got), len(first))
		}
		for j := range got {
			if got[j].Project != first[j].Project {
				t.Fatalf("run %d differs at %d: %s vs %s", i, j, got[j].Project, first[j].Project)
			}
		}
	}
}

func TestSearchEmptyQuery(t *testing.T) {
	c := searchCatalog()
	if got := c.Search("   "); got != nil {
		t.Errorf("a blank query returned %d hits", len(got))
	}
	if got := c.Search("nothing-matches-this"); got != nil {
		t.Errorf("a query with no match returned %v", got)
	}
}

// Case does not matter to somebody at a prompt.
func TestSearchIsCaseInsensitive(t *testing.T) {
	c := searchCatalog()
	got := c.Search("GPT-4")
	if len(got) != 1 || got[0].Project != "agpt.co" {
		t.Errorf("case-insensitive summary search = %v", got)
	}
	if !strings.Contains(got[0].Match, "GPT-4") {
		t.Errorf("the match shown lost its case: %q", got[0].Match)
	}
}
