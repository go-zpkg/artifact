package artifact

import (
	"sort"
	"testing"
)

// A resolved closure is a flat list, and the question an operator composing an
// environment actually has — WHY is this the version — is answered by the
// edges. GraphFor keeps them.
//
// The fixture is a diamond: two packages both need lib.org/z, one of them
// tightly. The tight one is what decides, and nothing in a flat closure says so.
func TestGraphForKeepsTheEdges(t *testing.T) {
	osn, arch := HostSlug()
	versions := map[string][]string{
		"app.org/main/" + osn + "/" + arch: {"1.0.0"},
		"lib.org/a/" + osn + "/" + arch:    {"1.4.0"},
		"lib.org/b/" + osn + "/" + arch:    {"2.0.0"},
		"lib.org/z/" + osn + "/" + arch:    {"2.1.0", "3.0.0"},
	}
	defer crossPantry(t, map[string]string{
		"app.org/main": "dependencies:\n  lib.org/a: ^1\n  lib.org/b: '*'\nprovides:\n  - bin/main\n",
		"lib.org/a":    "dependencies:\n  lib.org/z: ^2\nprovides:\n  - lib/liba.so\n",
		"lib.org/b":    "dependencies:\n  lib.org/z: '*'\nprovides:\n  - lib/libb.so\n",
		"lib.org/z":    "provides:\n  - lib/libz.so\n",
	}, versions)()

	g, err := GraphFor(map[string]string{"app.org/main": "*"}, osn, arch)
	if err != nil {
		t.Fatal(err)
	}

	if len(g.Roots) != 1 || g.Roots[0] != "app.org/main" {
		t.Fatalf("Roots = %v", g.Roots)
	}
	if len(g.Versions) != 4 {
		t.Fatalf("Versions = %v, want 4 projects", g.Versions)
	}
	// lib.org/a's ^2 decides, although lib.org/b would have taken 3.0.0.
	if got := g.Versions["lib.org/z"].Raw; got != "2.1.0" {
		t.Errorf("lib.org/z = %s, want 2.1.0 — the tighter constraint must decide", got)
	}

	// The edges leaving the root.
	var on []string
	for _, e := range g.Deps["app.org/main"] {
		on = append(on, e.On+" "+e.Constraint)
	}
	sort.Strings(on)
	if len(on) != 2 || on[0] != "lib.org/a ^1" || on[1] != "lib.org/b *" {
		t.Errorf("Deps[app.org/main] = %v", on)
	}

	// The edges pointing AT the contested project, which is the answer to "why
	// 2.1.0": two askers, and one of them said ^2.
	var asks []string
	for _, e := range g.Asks["lib.org/z"] {
		asks = append(asks, e.Of+" "+e.Constraint)
	}
	sort.Strings(asks)
	if len(asks) != 2 || asks[0] != "lib.org/a ^2" || asks[1] != "lib.org/b *" {
		t.Errorf("Asks[lib.org/z] = %v", asks)
	}
}

// A project the operator named directly is recorded as asked for by nobody, so
// a renderer can tell a root from a pulled-in dependency.
func TestGraphForMarksRoots(t *testing.T) {
	osn, arch := HostSlug()
	versions := map[string][]string{"solo.org/tool/" + osn + "/" + arch: {"1.0.0"}}
	defer crossPantry(t, map[string]string{
		"solo.org/tool": "provides:\n  - bin/tool\n",
	}, versions)()

	g, err := GraphFor(map[string]string{"solo.org/tool": "^1"}, osn, arch)
	if err != nil {
		t.Fatal(err)
	}
	asks := g.Asks["solo.org/tool"]
	if len(asks) != 1 || asks[0].Of != "" || asks[0].Constraint != "^1" {
		t.Fatalf("Asks[solo.org/tool] = %+v, want one edge from nobody with ^1", asks)
	}
	if len(g.Deps) != 0 {
		t.Errorf("Deps = %v, want none", g.Deps)
	}
}

// A closure that cannot be resolved fails the same way the resolver does: the
// graph is a view of the resolution, not a second implementation that might
// disagree with it.
func TestGraphForFailsLikeTheResolver(t *testing.T) {
	osn, arch := HostSlug()
	versions := map[string][]string{
		"app.org/x/" + osn + "/" + arch: {"1.0.0"},
		"lib.org/z/" + osn + "/" + arch: {"2.1.0"},
	}
	defer crossPantry(t, map[string]string{
		"app.org/x": "dependencies:\n  lib.org/z: ^9\nprovides:\n  - bin/x\n",
		"lib.org/z": "provides:\n  - lib/libz.so\n",
	}, versions)()

	if _, err := GraphFor(map[string]string{"app.org/x": "*"}, osn, arch); err == nil {
		t.Fatal("an unsatisfiable closure produced a graph")
	}
}

// And a project that does not exist fails during the WALK, before any version
// is picked — the other of the two ways this can go wrong.
func TestGraphForFailsOnAnUnknownProject(t *testing.T) {
	osn, arch := HostSlug()
	defer crossPantry(t, map[string]string{
		"known.org/tool": "provides:\n  - bin/tool\n",
	}, map[string][]string{"known.org/tool/" + osn + "/" + arch: {"1.0.0"}})()

	if _, err := GraphFor(map[string]string{"nowhere.org/nothing": "*"}, osn, arch); err == nil {
		t.Fatal("a graph was produced for a project that does not exist")
	}
}
