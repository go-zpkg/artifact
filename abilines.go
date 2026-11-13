package artifact

import (
	"fmt"
	"sort"
	"strings"
)

// pickOne is a seam: choosing a version needs a registry, partitioning does
// not, and the partition is the part worth testing.
var pickOne = PickVersionForAll

// pickABILines answers the demands on a project with SEVERAL versions, when no
// one version can meet them all and it is provably safe to hold both.
//
// This is what a resolver that only intersects cannot do. open-mpi.org does not
// resolve today for exactly one reason:
//
//	no version of gnome.org/libxml2 satisfies ">=2.14" AND "~2.13";
//	  asked for by >=2.14 (open-mpi.org/hwloc), ~2.13 (gnu.org/gettext)
//
// Both demands are correct. libxml2 broke its ABI inside major 2 — 2.13.9 ships
// libxml2.2.dylib and 2.15.4 ships libxml2.16.dylib — so hwloc and gettext are
// not arguing about a version, they are describing two different libraries that
// happen to share a name. Spack calls the same policy `unify: when_possible`.
//
// SAFE means one thing, and it is measured rather than assumed: the chosen
// versions must ship DISJOINT sonames. Then no binary can bind to the wrong
// one — each records the soname it was linked against, Mach-O through its ABI
// line and ELF through the soname itself — and nothing is interposed. Two
// versions that ship the SAME soname are a genuine conflict and stay refused,
// because whichever the loader reached first would silently be wrong.
//
// A version whose artifact declares no sonames at all is treated as unknown, not
// as empty: it is skipped and the refusal stands. Guessing here would produce
// exactly the failure the whole mechanism exists to prevent.
//
// What this does NOT settle is the profile collision Guix refuses: both
// versions put a bin directory on PATH, and two xmllint cannot both be first.
// The newest line leads, deterministically, because the versions are returned
// newest-first — the same order `v*` already means.
func pickABILines(project string, constraints []string, osn, arch string) ([]Ver, error) {
	if len(constraints) < 2 {
		return nil, fmt.Errorf("one demand cannot be split")
	}
	groups := partitionConstraints(project, constraints, osn, arch)
	if len(groups) < 2 {
		return nil, fmt.Errorf("the demands do not separate into satisfiable groups")
	}
	var vers []Ver
	for _, g := range groups {
		v, err := pickOne(project, g, osn, arch)
		if err != nil {
			return nil, err
		}
		vers = append(vers, v)
	}
	if err := sonamesDisjoint(project, vers, osn, arch); err != nil {
		return nil, err
	}
	// Newest first: the leading line is the one that owns PATH, and `v*`
	// already means the same thing.
	sort.Slice(vers, func(i, j int) bool { return cmpVer(vers[i], vers[j]) > 0 })
	return vers, nil
}

// partitionConstraints splits the demands into groups that each have a
// published version, greedily: a demand joins the first group that still
// resolves with it, and starts a new one otherwise.
//
// Greedy is not guaranteed minimal, and does not need to be — any valid
// partition is an answer, and fewer groups is a preference, not a requirement.
// The demands are walked in the order the graph collected them, which is
// deterministic, so the partition is too.
func partitionConstraints(project string, constraints []string, osn, arch string) [][]string {
	var groups [][]string
	for _, c := range constraints {
		placed := false
		for i, g := range groups {
			if _, err := pickOne(project, append(append([]string{}, g...), c), osn, arch); err == nil {
				groups[i] = append(g, c)
				placed = true
				break
			}
		}
		if placed {
			continue
		}
		if _, err := pickOne(project, []string{c}, osn, arch); err != nil {
			// A demand nothing satisfies on its own is not a split, it is a
			// dead constraint: let the caller report the original refusal.
			return nil
		}
		groups = append(groups, []string{c})
	}
	return groups
}

// sonamesDisjoint reports whether these versions can coexist: every soname is
// shipped by at most one of them, and every one of them declares some.
func sonamesDisjoint(project string, vers []Ver, osn, arch string) error {
	owner := map[string]string{}
	for _, v := range vers {
		list := Annotation(abiAnnotations(project, v.tag(), osn, arch), ABIProvidesAnnotation)
		var any bool
		for _, s := range strings.Split(list, ",") {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			any = true
			if prev, dup := owner[s]; dup {
				return fmt.Errorf("%s %s and %s both ship %s, so one would shadow the other",
					project, prev, v.Raw, s)
			}
			owner[s] = v.Raw
		}
		if !any {
			return fmt.Errorf("%s %s declares no sonames, so it cannot be shown to coexist", project, v.Raw)
		}
	}
	return nil
}
