package artifact

import (
	"fmt"
	"sort"
	"strings"
)

// Distinguish says what each build IS, in the only terms that help: the axes
// on which it differs from the others it is listed beside.
//
// ⛔⛔ A LIST OF HASHES IS UNUSABLE AND THAT IS NOT A PRESENTATION DETAIL. A
// hash is opaque by construction; shown two of them, a reader has no way to
// pick, and the command that printed them has handed over its own problem.
// Nix pays exactly this price — a store path says WHICH build and never WHAT
// build — and the answer everywhere else is to keep the spec queryable:
// `spack find libdwarf +debug`, conda's info/hash_input.json. We publish the
// spec on the manifest for this reason; this is the function that uses it.
//
// ⛔ IT DESCRIBES THE DIFFERENCE, NOT THE BUILD. A full spec is 54
// dependencies, identical in 53 of them, and printing it per row buries the
// one edge that matters in a screen of agreement. What a reader asked is "how
// do these differ", so that is what is answered — the same reason `diff`
// exists rather than printing both files.
//
// The result is parallel to the input: one line per spec, "" for a spec that
// records nothing. A caller must say so rather than printing an empty cell —
// see the note zpks prints for an artifact published before identities existed.
func Distinguish(specs []Concrete) []string {
	out := make([]string, len(specs))
	if len(specs) == 0 {
		return out
	}
	// ⛔ THE AXES ARE COMPUTED ACROSS ALL OF THEM FIRST. Deciding per row what
	// to show would let two rows describe themselves on different axes, which
	// reads as two unrelated facts rather than as a comparison.
	vars := differingVariants(specs)
	deps := differingDeps(specs)
	plat := differs(specs, func(c Concrete) string { return c.Platform })
	recipe := differs(specs, func(c Concrete) string { return c.Recipe })
	graft := differs(specs, func(c Concrete) string { return c.Graft })

	for i, c := range specs {
		if c.IsZero() {
			continue
		}
		var parts []string
		if plat {
			parts = append(parts, c.Platform)
		}
		for _, n := range vars {
			parts = append(parts, renderVariant(n, c.Variants[n]))
		}
		for _, p := range deps {
			parts = append(parts, renderDep(p, c))
		}
		if graft {
			if c.Graft == "" {
				parts = append(parts, "not grafted")
			} else {
				parts = append(parts, "grafted from "+c.Graft)
			}
		}
		// ⛔⛔ THE RECIPE IS THE LAST RESORT AND IT MUST NOT BE SILENT. Two
		// builds whose closures and options are identical differ because the
		// RECIPE changed — a rebuild after a pantry edit, which is one of the
		// commonest reasons two builds of a version exist. With nothing
		// printed, those two rows would be identical and the list would look
		// broken.
		if len(parts) == 0 && recipe {
			parts = append(parts, "built from a different recipe ("+shortDigest(c.Recipe)+")")
		}
		out[i] = strings.Join(parts, " ")
	}
	return out
}

// differingVariants lists the variant names whose value is not the same in
// every spec, sorted so two runs read alike.
func differingVariants(specs []Concrete) []string {
	seen := map[string]string{}
	var differ []string
	for _, c := range specs {
		for n := range c.Variants {
			seen[n] = ""
		}
	}
	for n := range seen {
		var want string
		var set bool
		for _, c := range specs {
			got := strings.Join(sortedCopy(c.Variants[n]), ",")
			if !set {
				want, set = got, true
				continue
			}
			if got != want {
				differ = append(differ, n)
				break
			}
		}
	}
	sort.Strings(differ)
	return differ
}

// differingDeps lists the projects whose resolved edge is not the same in
// every spec: a different version, or the same version built differently.
func differingDeps(specs []Concrete) []string {
	seen := map[string]bool{}
	for _, c := range specs {
		for _, d := range c.Deps {
			seen[d.Project] = true
		}
	}
	var differ []string
	for p := range seen {
		var want string
		var set bool
		for _, c := range specs {
			got := depEdge(c, p)
			if !set {
				want, set = got, true
				continue
			}
			if got != want {
				differ = append(differ, p)
				break
			}
		}
	}
	sort.Strings(differ)
	return differ
}

// depEdge is how one spec resolved a project, or "" when it does not depend
// on it at all — which is itself a difference worth reporting.
func depEdge(c Concrete, project string) string {
	for _, d := range c.Deps {
		if d.Project == project {
			return d.Version + " " + d.Hash
		}
	}
	return ""
}

// renderDep writes one edge the way a reader compares them: the version when
// the versions differ, and the version plus a short hash when they do not —
// because "openssl.org 3.6.4" twice would say the two builds are the same on
// the one axis the row exists to tell apart.
func renderDep(project string, c Concrete) string {
	for _, d := range c.Deps {
		if d.Project != project {
			continue
		}
		if d.Hash == "" {
			return project + " " + d.Version
		}
		return project + " " + d.Version + "/" + shortHashPrefix(d.Hash)
	}
	return "no " + project
}

func renderVariant(name string, vals []string) string {
	switch v := sortedCopy(vals); {
	case len(v) == 0:
		return "~" + name
	case len(v) == 1 && v[0] == "true":
		return "+" + name
	case len(v) == 1 && v[0] == "false":
		return "~" + name
	default:
		return name + "=" + strings.Join(v, ",")
	}
}

// shortHashPrefix is enough of a dependency's hash to tell two apart in a
// line a person reads, and never enough to be mistaken for the whole one.
func shortHashPrefix(h string) string {
	if len(h) <= 6 {
		return h
	}
	return h[:6]
}

func shortDigest(d string) string {
	if i := strings.IndexByte(d, ':'); i >= 0 {
		d = d[i+1:]
	}
	if len(d) <= 8 {
		return d
	}
	return d[:8]
}

func differs(specs []Concrete, of func(Concrete) string) bool {
	if len(specs) < 2 {
		return false
	}
	first := of(specs[0])
	for _, c := range specs[1:] {
		if of(c) != first {
			return true
		}
	}
	return false
}

func sortedCopy(v []string) []string {
	out := append([]string(nil), v...)
	sort.Strings(out)
	return out
}

// Describe is Distinguish for a single spec with nothing to compare against:
// the whole of what was recorded, which is what `zpks builds` falls back to
// when a version has exactly one build.
//
// ⛔ A SUMMARY, NOT THE CLOSURE. Printing 54 dependencies answers a question
// nobody asked with a page nobody reads; the count is the honest short form,
// and the full list has its own command.
func Describe(c Concrete) string {
	if c.IsZero() {
		return ""
	}
	parts := []string{c.Platform}
	if s := c.Variants.String(); s != "" {
		parts = append(parts, s)
	}
	parts = append(parts, fmt.Sprintf("%s, recipe %s", plural(len(c.Deps), "dependency", "dependencies"), shortDigest(c.Recipe)))
	if c.Graft != "" {
		parts = append(parts, "grafted from "+c.Graft)
	}
	return strings.Join(parts, " · ")
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}
