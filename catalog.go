package artifact

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

// A CATALOGUE, because a registry you cannot enumerate cannot be browsed.
//
// # THE MEASUREMENT THAT MADE THIS NECESSARY
//
// An anonymous client can ask ghcr what VERSIONS a project has and cannot ask
// what PROJECTS exist. Measured against ghcr.io/go-zpkg/packages:
//
//	GET /v2/_catalog                               403  (no token issued)
//	GET /v2/go-zpkg/packages/_catalog              403  (no token issued)
//	GET /v2/go-zpkg/packages/zlib.net/tags/list    200  ["1.3.2", …]
//
// The registry API's catalogue endpoint is not served, so `gnu.org/<TAB>`
// has nothing to read. Nix, Guix and Spack all answer this from a LOCAL
// index — a flake/eval cache, a channel checkout, a package repo — and the
// pkgx-native equivalent of a local index is an artefact in the registry
// itself.
//
// # A CATALOGUE IS AN ORDINARY ARTIFACT
//
// The same move `members` made for sets: rather than a second kind of
// artefact with its own publishing, signing and mirroring, the catalogue is
// pushed through the path an artifact takes. It is therefore signed, attested,
// cached by the pull-through registry and verified on install by everything
// that already does those things — and a scratch image gets it in ONE pull,
// with no registry API beyond the one it already uses to fetch packages.
type Catalog struct {
	// Generated is RFC3339 UTC. A catalogue is a snapshot and says so: a
	// reader deciding whether to refresh wants the age, and a reader
	// reporting "no such project" should be able to say how old its answer
	// is rather than implying the registry was asked just now.
	Generated string           `json:"generated"`
	Projects  []CatalogProject `json:"projects"`
	// Dropped counts version strings refused as unreadable while parsing,
	// and is NOT part of the file: it describes this reading of it.
	//
	// It exists so the dropping is not silent. A guard that quietly
	// removes things leaves a reader comparing a short list against their
	// memory, so `pkgx catalog` prints this count when it is not zero —
	// and on a catalogue our own factory published it should never be
	// anything else.
	Dropped int `json:"-"`
}

// CatalogProject is one project as the catalogue knows it.
type CatalogProject struct {
	Project string `json:"project"`
	// Versions newest-first, as a reader wants them. Empty is legal and
	// means "named by the pantry, nothing published" — which is the honest
	// answer for most of a pantry on most architectures, and is different
	// from the project not existing.
	//
	// ⛔ IN PRACTICE THE PUBLISHED CATALOGUE CARRIES EXACTLY ONE, and a
	// reader writing against this field needs to know that before they
	// build on the plural.
	//
	// `bk catalog --versions` writes `[]string{v}` — the newest version
	// THIS platform really carries, probed newest-first and stopped at the
	// first hit, because the newest tag is not published for every
	// architecture and the ordinary case then costs one request per project
	// instead of N. Counted 2026-10-08 on the three catalogues published
	// 2026-10-06: 1430, 1371 and 1369 entries, and **not one** of them has
	// a second version.
	//
	// So this answers "what would I get" and not "what can I choose from".
	// The second question goes to PublishedTagFor against the registry —
	// which is also why a catalogue cannot be used to decide whether some
	// OLDER version is installable here, a mistake this field's plural
	// invites.
	Versions []string `json:"versions,omitempty"`
	// Platforms as `os/arch`, sorted. Also legal empty, for the same reason.
	Platforms []string `json:"platforms,omitempty"`
	Summary   string   `json:"summary,omitempty"`
	// Deps are the project's declared RUNTIME dependencies, reduced for the
	// platform this catalogue is for, sorted.
	//
	// They are here so the dependency tree can be walked with NO NETWORK
	// and no pantry: `pkgx --graph` answers the same question by resolving
	// against the registry, which a scratch image cannot do before it has
	// one, and which nobody can do on a train.
	//
	// RUNTIME only, deliberately. A build dependency is paid once by the
	// factory and is not in anybody's installed closure; showing it under a
	// node would answer a question the person browsing did not ask.
	Deps []string `json:"deps,omitempty"`
	// Provides are the COMMAND names this project puts on PATH, without
	// their `bin/` prefix, sorted.
	//
	// Here because it is the only metadata in this pantry a search can
	// work on. Counted in the PUBLISHED catalogue of 2026-10-06, with
	// `go run ./internal/catstat` in go-zpkg/pkgx, and the two platforms
	// agree: of 1908 projects, 1582 declare `provides` — 4592 command
	// names on linux/aarch64, 4498 on darwin/aarch64 — and SIX carry a
	// summary. `nix search` and `guix search` look in the description,
	// which is the right design for a collection that HAS descriptions;
	// here it would find almost nothing.
	//
	// The figures carry their date and their instrument on purpose: an
	// earlier revision of this comment said "1907 recipes, 1592 provides"
	// with neither, and by the time anyone compared, both numbers had
	// moved and nothing said whether the difference was drift or a defect.
	//
	// And it answers the question people actually arrive with. You know
	// the command, not the package: `rg` is `crates.io/ripgrep`, which no
	// amount of guessing at the name reaches.
	Provides []string `json:"provides,omitempty"`
}

// CatalogProject implements the one thing a tree browser needs beyond the
// list: what sits under a node.

// Node is one entry under a tree node, as `pkgx ls` and tab-completion show
// it.
type Node struct {
	// Name is the FULL project path of a leaf, or the path of the interior
	// node including its trailing segment — never a bare segment, so a
	// caller can complete straight onto it without reassembling anything.
	Name string
	// Leaf is true when Name is itself a published project.
	//
	// Leaf and Interior are NOT exclusive, and that is not a corner case:
	// `curl.se` is a project and `curl.se/ca-certs` lives under it. A tree
	// that made them exclusive would hide one of the two.
	Leaf bool
	// Under is how many projects sit strictly below Name. Zero for a pure
	// leaf.
	Under int
}

// Children returns what is available directly under a node, sorted.
//
// prefix is "" for the roots, or a node path with or without a trailing
// slash. Only the NEXT path segment is expanded: `github.com` yields
// `github.com/besser82`, not `github.com/besser82/libxcrypt`, because a
// completion that jumped two levels would skip the choice the user is making.
func (c *Catalog) Children(prefix string) []Node {
	prefix = strings.TrimSuffix(prefix, "/")
	want := ""
	if prefix != "" {
		want = prefix + "/"
	}
	byName := map[string]*Node{}
	for _, p := range c.Projects {
		if want != "" && !strings.HasPrefix(p.Project, want) {
			continue
		}
		rest := strings.TrimPrefix(p.Project, want)
		if rest == "" {
			// The node itself is a project. Not a child of itself.
			continue
		}
		seg, deeper, _ := strings.Cut(rest, "/")
		full := want + seg
		n := byName[full]
		if n == nil {
			n = &Node{Name: full}
			byName[full] = n
		}
		if deeper == "" {
			n.Leaf = true
		} else {
			n.Under++
		}
	}
	out := make([]Node, 0, len(byName))
	for _, n := range byName {
		out = append(out, *n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Lookup returns one project's entry, and whether the catalogue has it.
func (c *Catalog) Lookup(project string) (CatalogProject, bool) {
	for _, p := range c.Projects {
		if p.Project == project {
			return p, true
		}
	}
	return CatalogProject{}, false
}

// ProvidersOf returns every project that puts this COMMAND on PATH, sorted.
//
// The inverse of Provides, and the question people actually arrive with: you
// know `hugo`, not `gohugo.io`. Reported from the field on 2026-10-12 —
// `pkgx hugo version` answered
//
//	no recipe for hugo in …pantry-overlay… or …pkgxdev/pantry…
//
// while `pkgx search hugo` in the same store already printed
// `gohugo.io  hugo`. The mapping was in the catalogue and only the search path
// consulted it.
//
// ⛔ It returns a LIST, and the singular case is the caller's to insist on.
// Returning one project would mean picking between two providers of the same
// command, and there is no basis in this data for that choice: `provides` says
// what a project puts on PATH, not which project owns the name. A caller that
// wants to run something must refuse an ambiguous word and say which projects
// it was between — guessing silently would run the wrong program under the
// right name, which is the one outcome worse than an error.
//
// An empty command returns nothing rather than everything: it is what an
// empty argument looks like, and `provides` holds no empty strings.
func (c *Catalog) ProvidersOf(command string) []string {
	if command == "" {
		return nil
	}
	var out []string
	for _, p := range c.Projects {
		for _, cmd := range p.Provides {
			if cmd == command {
				out = append(out, p.Project)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

// Complete returns the completions for a partially typed project name.
//
// It is Children of the enclosing node, filtered by the partial segment. A
// node with exactly one child still returns that one rather than jumping to
// its grandchild: a shell completes to the common prefix and the user decides
// whether to descend.
func (c *Catalog) Complete(partial string) []Node {
	node, seg := "", partial
	if i := strings.LastIndex(partial, "/"); i >= 0 {
		node, seg = partial[:i], partial[i+1:]
	}
	var out []Node
	for _, n := range c.Children(node) {
		last := n.Name
		if i := strings.LastIndex(last, "/"); i >= 0 {
			last = last[i+1:]
		}
		if strings.HasPrefix(last, seg) {
			out = append(out, n)
		}
	}
	return out
}

// DepTree is the dependency subtree under a project, as a browser shows it.
//
// # WHY A SEPARATE SHAPE FROM Children
//
// A node has two kinds of thing under it and they are not the same
// question. `gnu.org` has `gnu.org/bash` under it because of how it is
// NAMED; `curl.se` has `openssl.org` under it because of what it NEEDS.
// Nix, Guix and Spack keep the two apart as well — `guix graph` and
// `nix-tree` walk the dependency graph, and neither is how you find out
// what a channel contains.
//
// depth 0 means "no limit". `guix graph --max-depth` exists because a full
// transitive graph of anything interesting is pages long, and the first
// level is what a person reads.
func (c *Catalog) DepTree(project string, depth int) []DepNode {
	index := c.index()
	edges := func(p string) []string { return index[p].Deps }
	return walkGraph(index, edges, project, depth)
}

// Dependents is the SAME walk in the other direction: who needs this.
//
// # WHY THE OTHER DIRECTION IS A DIFFERENT QUESTION
//
// `ls --tree` answers "what does this need", which is what you ask before
// installing something. "Who needs this" is what you ask before CHANGING
// something, and no amount of descending answers it. Every comparable tool
// has it, each with its own emphasis:
//
//   - `spack dependents [-t]`: direct, or transitive with -t.
//   - `guix refresh --list-dependent`: what would need REBUILDING, and the
//     manual says plainly that it only approximates that.
//   - `nix why-depends A B`: not a list at all but a shortest PATH, which
//     is a third question and is WhyDepends below.
//
// # WHAT IT COVERS, AND WHAT IT DOES NOT
//
// The catalogue's `deps` are RUNTIME dependencies, reduced for one
// platform. So this is the runtime blast radius on THIS platform: who would
// load different bytes if this project changed.
//
// It is NOT the rebuild set. A build dependency is paid once by the factory
// and is not in anybody's installed closure, so it is not in the catalogue
// and cannot be in this answer. Guix's command is about rebuilds and says
// it approximates them; this one is about closures and is exact for what it
// covers — saying which is better than implying the other.
func (c *Catalog) Dependents(project string, depth int) []DepNode {
	index := c.index()
	rev := map[string][]string{}
	for _, p := range c.Projects {
		for _, d := range p.Deps {
			rev[d] = append(rev[d], p.Project)
		}
	}
	edges := func(p string) []string { return rev[p] }
	return walkGraph(index, edges, project, depth)
}

// WhyDepends is the shortest path from `from` to `to` through runtime
// dependencies, including both ends, or nil when there is none.
//
// Nix's question, and it is not answerable from either tree above: a reader
// looking at a closure wants to know WHICH link put something there, and a
// transitive list says it is there without saying why. Shortest because
// that is the explanation a person can hold — `nix why-depends` makes the
// same choice.
//
// Breadth-first, so the first path found is a shortest one. Ties are broken
// by name, so two runs on one catalogue give the same answer; an
// explanation that changes between runs is one nobody can quote.
func (c *Catalog) WhyDepends(from, to string) []string {
	index := c.index()
	if from == to {
		return []string{from}
	}
	prev := map[string]string{from: ""}
	queue := []string{from}
	for len(queue) > 0 {
		p := queue[0]
		queue = queue[1:]
		kids := append([]string(nil), index[p].Deps...)
		sort.Strings(kids)
		for _, d := range kids {
			if _, seen := prev[d]; seen {
				continue
			}
			prev[d] = p
			if d == to {
				var path []string
				for n := to; n != ""; n = prev[n] {
					path = append(path, n)
				}
				for i, j := 0, len(path)-1; i < j; i, j = i+1, j-1 {
					path[i], path[j] = path[j], path[i]
				}
				return path
			}
			queue = append(queue, d)
		}
	}
	return nil
}

func (c *Catalog) index() map[string]CatalogProject {
	index := make(map[string]CatalogProject, len(c.Projects))
	for _, p := range c.Projects {
		index[p.Project] = p
	}
	return index
}

// walkGraph is the shared walk, because the hard part is the DAG marking
// and one copy of a subtle thing is worth two of anything.
//
// `edges` is what hangs under a node: its dependencies going down, its
// dependents going up. Everything else — the ordering, the repeat marking,
// the depth bound, what a Known node is — is the same question in both
// directions and was already answered once here.
func walkGraph(index map[string]CatalogProject, edges func(string) []string, root string, depth int) []DepNode {
	seen := map[string]bool{root: true}
	var walk func(string, int) []DepNode
	walk = func(p string, level int) []DepNode {
		if depth > 0 && level >= depth {
			return nil
		}
		kids := append([]string(nil), edges(p)...)
		sort.Strings(kids)

		// THE WHOLE LEVEL IS MARKED BEFORE ANY OF IT IS DESCENDED INTO.
		//
		// A DAG, not a tree: a project reached twice is named again and not
		// expanded a second time, or a diamond turns a readable tree into
		// pages of the same subtree — `pkgx --graph` says the same in its
		// own comment.
		//
		// Marking level-by-level rather than as the walk goes decides WHICH
		// of the two occurrences gets expanded, and the first version of
		// this got it backwards: curl declares openssl and zlib, openssl
		// declares zlib, and a depth-first mark expanded zlib UNDER OPENSSL
		// and showed curl's own direct dependency as a repeat. A project's
		// direct dependencies are the ones a reader came for.
		var fresh []string
		for _, d := range kids {
			if !seen[d] {
				seen[d] = true
				fresh = append(fresh, d)
			}
		}
		isFresh := map[string]bool{}
		for _, d := range fresh {
			isFresh[d] = true
		}

		out := make([]DepNode, 0, len(kids))
		for _, d := range kids {
			n := DepNode{Project: d}
			if e, ok := index[d]; ok {
				n.Known = true
				if len(e.Versions) > 0 {
					n.Version = e.Versions[0]
				}
			}
			if isFresh[d] {
				n.Under = walk(d, level+1)
			} else {
				n.Repeat = true
			}
			out = append(out, n)
		}
		return out
	}
	return walk(root, 0)
}

// DepNode is one dependency, and what hangs under it.
type DepNode struct {
	Project string
	Version string
	// Known is false for a dependency the catalogue does not list. It
	// happens, and saying so is the point: a name with nothing behind it is
	// a hole in the catalogue or a project that resolves from somewhere
	// else, and a browser that printed it like any other node would hide
	// both.
	Known  bool
	Repeat bool // already shown higher up; not descended into
	Under  []DepNode
}

// Age is how old the catalogue is, in words. A browser that cannot reach the
// registry should still say what it is showing rather than imply it is now.
func (c *Catalog) Age(now time.Time) string {
	t, err := time.Parse(time.RFC3339, c.Generated)
	if err != nil {
		return "of unknown age"
	}
	d := now.UTC().Sub(t)
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%d minute(s) old", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d hour(s) old", int(d.Hours()))
	}
	return fmt.Sprintf("%d day(s) old", int(d.Hours()/24))
}

// MarshalCatalog renders a catalogue deterministically: projects sorted,
// versions and platforms sorted within each.
//
// Deterministic because the artefact is signed and attested like an artifact,
// and a catalogue whose bytes moved for no reason would make every rebuild
// look like a change — the same argument the lock makes for sorting its pins.
func MarshalCatalog(c Catalog) ([]byte, error) {
	out := Catalog{Generated: c.Generated, Projects: append([]CatalogProject(nil), c.Projects...)}
	sort.Slice(out.Projects, func(i, j int) bool { return out.Projects[i].Project < out.Projects[j].Project })
	for i := range out.Projects {
		sort.Strings(out.Projects[i].Platforms)
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		// Unreachable: every field is a string or a slice of strings.
		return nil, err
	}
	return append(b, '\n'), nil
}

// UnmarshalCatalog is the other direction, refusing a document that is not
// one rather than returning an empty catalogue.
//
// An empty catalogue and an unreadable one must not look alike: the first
// says the registry is empty, the second says we failed to ask, and a
// browser that confused them would tell a user their package does not exist.
func UnmarshalCatalog(b []byte) (Catalog, error) {
	var c Catalog
	if err := json.Unmarshal(b, &c); err != nil {
		return Catalog{}, fmt.Errorf("catalog: %w", err)
	}
	if c.Generated == "" && c.Projects == nil {
		return Catalog{}, fmt.Errorf("catalog: no `generated` and no `projects` — this is not a catalogue")
	}
	// A catalogue is pulled from a registry and read by `pkgx ls`, by
	// `search`, and by EVERY <TAB>. Its names end up in URLs and registry
	// references, so they are checked once here rather than at each of
	// those call sites — and the whole catalogue is refused, because one
	// forged name in a list means the list was written by somebody who
	// wanted it to do something else.
	for i := range c.Projects {
		p := &c.Projects[i]
		if err := ValidateProjectName(p.Project); err != nil {
			return Catalog{}, fmt.Errorf("catalog: %w", err)
		}
		// The two fields that are TEXT and reach a terminal. A name is
		// refused because a bad one means somebody wanted something; a
		// summary is stripped, because it is cosmetic and refusing a
		// whole catalogue over one paragraph would deny service for a
		// typo. See displayText.
		p.Summary = displayText(p.Summary, summaryLimit)
		for j, cmd := range p.Provides {
			p.Provides[j] = displayText(cmd, commandLimit)
		}
		// A VERSION IS NEITHER OF THOSE TWO CASES, and it took a probe to
		// see it: `pkgx ls` printed a catalogue's versions RAW, so a
		// version carrying ESC[2K and a carriage return rewrote its own
		// line as a different, reassuring one. Measured:
		//
		//	evil.org   1.0.0^[[2K^Mcurl.se  8.20  verified by maintainers
		//
		// It is a KEY — it becomes a tag and a directory — so it cannot be
		// cleaned and shown like a summary; a cleaned key would select
		// something other than what it says.
		//
		// But it is NOT refused like a name either, and the asymmetry is
		// deliberate. A version string reaches a published catalogue from
		// an upstream recipe's `versions:` spec, resolved against GitHub's
		// tags — content a recipe author controls. Refusing the whole
		// catalogue would hand any one of them a switch that turns off
		// `pkgx ls`, `search` and every <TAB> for everybody.
		//
		// So the unusable version is DROPPED and COUNTED. The project
		// stays listed, which is the state the type already documents as
		// legal: named by the pantry, nothing this client can fetch.
		kept := p.Versions[:0]
		for _, v := range p.Versions {
			if ValidateVersionString(v) != nil {
				c.Dropped++
				continue
			}
			kept = append(kept, v)
		}
		p.Versions = kept
		// Platforms get the same treatment for the same reason. Only one
		// tool prints them today, which is exactly the argument people use
		// for leaving a field unchecked until something new prints it.
		plat := p.Platforms[:0]
		for _, s := range p.Platforms {
			if ValidatePlatformSlug(s) != nil {
				c.Dropped++
				continue
			}
			plat = append(plat, s)
		}
		p.Platforms = plat
		for _, d := range p.Deps {
			if err := ValidateProjectName(d); err != nil {
				return Catalog{}, fmt.Errorf("catalog: %s declares %w", p.Project, err)
			}
		}
	}
	return c, nil
}

// CatalogProjectName is the reserved project the catalogue is published
// under. A project name rather than a special path, because that is what
// makes it an ordinary artifact.
//
// ⛔⛔ THIS NAME ADDRESSES A PUBLISHED ARTEFACT, AND THE RENAME MOVED THE NAME
// WITHOUT MOVING THE ARTEFACT. The go-pkgx → go-zpkg pass (#192) rewrote it
// from `go-pkgx.dev/catalog` to `go-zpkg.github.io/catalog`. Nothing publishes
// that, so every `zpks catalog update` on defaults has failed since, and a
// FROM-scratch image built around the result has no catalogue in it at all:
//
//	zpks: catalog update: go-zpkg.github.io/catalog is not published in
//	ghcr.io/go-pkgx/packages/go-zpkg.github.io/catalog … 403: denied
//
// Measured 2026-11-04 with ghcrprobe, anonymously, against a positive control
// so that "absent" could not be the probe failing:
//
//	ghcr.io/go-pkgx/packages/gnu.org/bash                 PRESENT (control)
//	ghcr.io/go-pkgx/packages/go-pkgx.dev/catalog          PRESENT
//	ghcr.io/go-pkgx/packages/go-zpkg.github.io/catalog    ABSENT
//	ghcr.io/go-pkgx/packages/go-pkgx.dev/catalog (as .github.io) ABSENT
//
// It is the SECOND constant this happened to — see DistBase in zpkg.go, where
// the same pass pointed the whole fleet at an empty registry. The rule both
// of them earned: a constant that addresses something published follows the
// artefact, and moves only after a copy has run and been verified.
const CatalogProjectName = "go-pkgx.dev/catalog"

// CatalogVersion is the version it is published as. One moving tag rather
// than a dated series: a catalogue is a cache of the registry, every reader
// wants the newest, and a hundred dated versions of it would be a hundred
// things to garbage-collect.
const CatalogVersion = "1"

// CatalogTarball packs a catalogue into the shape an artifact layer has: a
// gzipped tar holding one file, `catalog.json`.
//
// A real tar, not gzipped JSON wearing a tar media type. The manifest says
// `…layer.tar+gzip` and a reader that believes it — `tar tzf`, or any tool
// that unpacks an artifact — must not be lied to for the sake of fifteen lines.
func CatalogTarball(c Catalog) ([]byte, error) {
	body, err := MarshalCatalog(c)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	// A fixed mode and a zero mtime, so the same catalogue gives the same
	// bytes and therefore the same digest. The push path already pins the
	// manifest's created-time for this reason.
	if err := tw.WriteHeader(&tar.Header{
		Name: CatalogFileName, Mode: 0o644, Size: int64(len(body)),
		Typeflag: tar.TypeReg, ModTime: time.Unix(0, 0).UTC(),
	}); err != nil {
		return nil, err
	}
	if _, err := tw.Write(body); err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// CatalogFromTarball is the other direction.
func CatalogFromTarball(b []byte) (Catalog, error) {
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return Catalog{}, fmt.Errorf("catalog: %w", err)
	}
	defer zr.Close()
	tr := tar.NewReader(zr)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return Catalog{}, fmt.Errorf("catalog: %w", err)
		}
		if h.Name != CatalogFileName {
			continue
		}
		// Bounded. A catalogue is a list of names; anything the size of a
		// artifact in this slot is not one, and reading it into memory because
		// the tar said to is how a reader becomes the attack.
		body, err := io.ReadAll(io.LimitReader(tr, CatalogMaxBytes+1))
		if err != nil {
			return Catalog{}, fmt.Errorf("catalog: %w", err)
		}
		if len(body) > CatalogMaxBytes {
			return Catalog{}, fmt.Errorf("catalog: %s is larger than %d bytes", CatalogFileName, CatalogMaxBytes)
		}
		return UnmarshalCatalog(body)
	}
	return Catalog{}, fmt.Errorf("catalog: the archive holds no %s", CatalogFileName)
}

const (
	// CatalogFileName is the one file a catalogue layer holds.
	CatalogFileName = "catalog.json"
	// CatalogMaxBytes bounds what a reader will take from that file. The
	// whole pkgx pantry is ~1900 projects; 32 MiB is two orders of magnitude
	// of headroom and still refuses an artifact-sized surprise.
	CatalogMaxBytes = 32 << 20
)

// PublishCatalog pushes a catalogue for ONE platform, through the path a
// artifact takes.
//
// Per platform, and that is not an accident of the signature. What is
// available differs by architecture — the s390x lane has a fraction of what
// linux/x86-64 has — so a single catalogue would tell most readers that
// packages are available which, for them, are not. `bk weather` exists
// because that asymmetry is real.
func PublishCatalog(c *OCIClient, cat Catalog, osn, arch string) error {
	tgz, err := CatalogTarball(cat)
	if err != nil {
		return err
	}
	return c.Push(CatalogProjectName, CatalogVersion, osn, arch, tgz, ExtTarGz)
}

// FetchCatalog pulls the catalogue for one platform, and VERIFIES it.
//
// # WHY A LIST OF NAMES NEEDS A SIGNATURE
//
// This was the one path that brought artifact bytes onto a machine without
// the fail-closed check every other artifact gets — which is precisely what
// the comment above verifyPulled promised could not happen. It was missed
// because a catalogue "is only a list of names", and that is the wrong way
// round: a list of names is what a person then TYPES.
//
// Someone able to serve a forged catalogue — a compromised mirror, or a
// ZPKG_DIST pointed somewhere by a script — cannot make the install path
// accept an unsigned artifact, because that path still verifies. What they
// can do is decide what `<TAB>` offers, and a near-miss name offered at the
// prompt is the whole of a typosquat. The attack is on the reader, not on
// the installer, and the signature is the only thing that answers it.
//
// It also matters MORE than for an ordinary artifact now, not less: since
// the catalogue became a file on disk, it is fetched once and then read by
// every completion for days. An artifact is verified each time it is pulled;
// this one is verified once and trusted thereafter.
func FetchCatalog(c *OCIClient, osn, arch string) (Catalog, error) {
	b, _, err := c.Pull(CatalogProjectName, CatalogVersion, osn, arch)
	if err != nil {
		return Catalog{}, err
	}
	if err := verifyPulled(c, CatalogProjectName, CatalogVersion, osn, arch, b); err != nil {
		return Catalog{}, err
	}
	return CatalogFromTarball(b)
}

// summaryLimit and commandLimit bound two strings that arrive from a
// recipe and are printed. A line that overflows a terminal is its own kind
// of noise, and an unbounded field in a published artefact is an invitation.
const (
	summaryLimit = 200
	commandLimit = 64
)
