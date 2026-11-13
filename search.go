package artifact

import (
	"sort"
	"strings"
)

// Searching the catalogue.
//
// # WHY NOT A DESCRIPTION SEARCH
//
// `nix search`, `guix search` and `spack list -s` all match against a
// package's description, and that is the right design for a collection that
// HAS descriptions. This one does not. Measured on the 1907 recipes of the
// pantry this catalogue is built from:
//
//	1592  declare `provides` — the commands they put on PATH
//	   6  carry a `summary` or a `description`
//
// A search over prose would find six packages. So the searchable surface
// here is the COMMAND NAMES, and that turns out to be the question people
// arrive with anyway: you know the command and not the package. `rg` is
// `crates.io/ripgrep`; no amount of guessing at the project name reaches
// it, and a prefix completion on "rg" never will either.
//
// The summary is searched too, because the six cost nothing. It is not what
// makes this useful.

// minSubstringQuery is the shortest query that may match inside a name.
//
// Two characters is not a search, it is a sieve: every `.org` project
// contains "rg". Three is where it starts meaning something — "ssl" finds
// openssl.org, "jpg" finds the image tools — and a two-character query is
// almost always a COMMAND, which matches exactly and by prefix regardless
// of this.
const minSubstringQuery = 3

// SearchHit is one result, with the reason it matched.
type SearchHit struct {
	Project string
	// Why names the field that matched, for a reader deciding whether a
	// result is the one they meant: "command", "name" or "summary". An
	// unexplained list of 40 projects is a list nobody reads to the end.
	Why string
	// Match is the matching value — the command name for a command hit, so
	// `rg` appears beside `crates.io/ripgrep` and the reader sees WHY.
	Match string

	rank int
}

// Search ranks the catalogue against a free-text query, best first.
//
// Ranking is by HOW the thing matched, not by how often: a command called
// exactly what you typed is what you meant, every time, and no amount of
// substring frequency elsewhere should outrank it.
//
//	0  a command named exactly this        rg      → crates.io/ripgrep
//	1  a project whose last segment is this jq     → stedolan.github.io/jq
//	2  a command starting with this        py      → python.org (bin/python3)
//	3  a project segment containing this   ssl     → openssl.org
//	4  the full project path containing it  gnu    → gnu.org/bash
//	5  the summary containing it
//
// Ties break on the project name, so the same query gives the same order
// every time. A catalogue is a Go map nowhere, but the Projects slice comes
// off a registry and its order is not ours to rely on.
func (c *Catalog) Search(query string) []SearchHit {
	q := strings.ToLower(strings.TrimSpace(query))
	if q == "" {
		return nil
	}
	var out []SearchHit
	for _, p := range c.Projects {
		if h, ok := scoreProject(p, q); ok {
			out = append(out, h)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].rank != out[j].rank {
			return out[i].rank < out[j].rank
		}
		return out[i].Project < out[j].Project
	})
	return out
}

// scoreProject returns the BEST reason a project matches, not every reason.
//
// One project, one line: a package that matches on its name and on two of
// its commands is still one answer, and listing it three times would push
// the next real answer off the screen.
func scoreProject(p CatalogProject, q string) (SearchHit, bool) {
	best := SearchHit{Project: p.Project, rank: -1}
	take := func(rank int, why, match string) {
		if best.rank == -1 || rank < best.rank {
			best.rank, best.Why, best.Match = rank, why, match
		}
	}
	for _, cmd := range p.Provides {
		switch {
		case cmd == q:
			take(0, "command", cmd)
		case strings.HasPrefix(cmd, q):
			take(2, "command", cmd)
		}
	}
	leaf := p.Project
	if i := strings.LastIndex(leaf, "/"); i >= 0 {
		leaf = leaf[i+1:]
	}
	lower := strings.ToLower(p.Project)
	switch {
	case strings.ToLower(leaf) == q:
		take(1, "name", p.Project)
	case len(q) < minSubstringQuery:
		// Too short to mean anything as a SUBSTRING of a name. Measured
		// on the published catalogue: `search rg` returned 625 projects,
		// of which 550 matched only because "rg" sits inside ".org" —
		// the one result anybody wanted was first, and 550 lines of
		// noise stood behind it.
		//
		// A length rule rather than a cleverer one, because the obvious
		// cleverer rule is wrong: requiring the match to START a label
		// would drop ".org" and would ALSO drop "ssl" inside
		// "openssl.org", which is the best answer to that query. The
		// thing short queries are good for is commands, and those still
		// match exactly and by prefix above.
	case strings.Contains(strings.ToLower(leaf), q):
		take(3, "name", p.Project)
	case strings.Contains(lower, q):
		take(4, "name", p.Project)
	}
	if s := strings.ToLower(p.Summary); s != "" && strings.Contains(s, q) {
		take(5, "summary", p.Summary)
	}
	if best.rank == -1 {
		return SearchHit{}, false
	}
	return best, true
}
