package artifact

import (
	"strings"
	"testing"
)

// Review of go-zpkg/artifact#261: a version scope is read against the package's version.

const tkRecipe = "dependencies:\n" +
	"  tcl-lang.org: ^8\n" +
	"  \">=9\":\n" +
	"    tcl-lang.org: ^9\n" +
	"provides:\n  - bin/wish\n"

func tkPantry(t *testing.T) func() {
	osn, arch := HostSlug()
	slug := "/" + osn + "/" + arch
	return crossPantry(t, map[string]string{
		"tcl-lang.org/tk":     tkRecipe,
		"tcl-lang.org/expect": "dependencies:\n  tcl-lang.org: ^8\nprovides:\n  - bin/expect\n",
		"tcl-lang.org":        "provides:\n  - bin/tclsh\n",
	}, map[string][]string{
		"tcl-lang.org/tk" + slug:     {"8.6.18", "9.0.4"},
		"tcl-lang.org/expect" + slug: {"5.45.4"},
		"tcl-lang.org" + slug:        {"8.6.17", "9.0.3"},
	})
}

func resolvedVersion(t *testing.T, got []Resolved, project string) string {
	t.Helper()
	for _, r := range got {
		if r.Project == project {
			return r.Version.Raw
		}
	}
	t.Fatalf("%s not in %v", project, got)
	return ""
}

// A closure rooted at tk 8.6.18 must ask for tcl ^8: the ">=9" scope does not
// hold for it. v0.102.0 unioned the scope, so tcl was asked for ^9.
func TestClosureRootedAtOldTkResolvesTclCaret8(t *testing.T) {
	defer tkPantry(t)()
	osn, arch := HostSlug()
	got, err := ResolveClosureFor(map[string]string{"tcl-lang.org/tk": "=8.6.18"}, osn, arch)
	if err != nil {
		t.Fatal(err)
	}
	if v := resolvedVersion(t, got, "tcl-lang.org"); !strings.HasPrefix(v, "8.") {
		t.Errorf("tcl resolved to %s, want 8.x", v)
	}
}

// tk 8.6.18 together with expect (tcl ^8) has one answer. v0.102.0 asked for
// {^8, ^9} on tcl, which nothing satisfies.
func TestOldTkTogetherWithExpectResolvesWithoutConflict(t *testing.T) {
	defer tkPantry(t)()
	osn, arch := HostSlug()
	got, err := ResolveClosureFor(map[string]string{
		"tcl-lang.org/tk": "=8.6.18", "tcl-lang.org/expect": "*"}, osn, arch)
	if err != nil {
		t.Fatalf("conflict: %v", err)
	}
	if v := resolvedVersion(t, got, "tcl-lang.org"); !strings.HasPrefix(v, "8.") {
		t.Errorf("tcl resolved to %s, want 8.x", v)
	}
}

// The scope still holds for a version it names.
func TestNewTkKeepsItsScope(t *testing.T) {
	defer tkPantry(t)()
	osn, arch := HostSlug()
	got, err := ResolveClosureFor(map[string]string{"tcl-lang.org/tk": "^9"}, osn, arch)
	if err != nil {
		t.Fatal(err)
	}
	if v := resolvedVersion(t, got, "tcl-lang.org"); !strings.HasPrefix(v, "9.") {
		t.Errorf("tcl resolved to %s, want 9.x", v)
	}
}

func TestScopeVerdictForCandidates(t *testing.T) {
	v := func(s ...string) []Ver {
		var out []Ver
		for _, x := range s {
			out = append(out, ParseVer(x))
		}
		return out
	}
	for _, c := range []struct {
		name  string
		key   string
		cands []Ver
		want  bool
	}{
		{"unknown unions", ">=9", nil, true},
		{"all satisfy", ">=9", v("9.0.1", "9.0.4"), true},
		{"none satisfy", ">=9", v("8.6.17", "8.6.18"), false},
		{"mixed unions", ">=9", v("8.6.18", "9.0.4"), true},
		{"unparseable is fail-open", ">=9", []Ver{{}}, true},
	} {
		if got := ScopeApplies(c.key, c.cands); got != c.want {
			t.Errorf("%s: ScopeApplies(%q) = %v, want %v", c.name, c.key, got, c.want)
		}
	}
}

func TestReduceDepsAtAVersion(t *testing.T) {
	m := map[string]any{"a.org": "1", ">=9": map[string]any{"a.org": "9", "b.org": "*"}}
	for _, c := range []struct {
		ver  string
		want string
		n    int
	}{{"8.1", "1", 1}, {"9.0.1", "9", 2}, {"", "9", 2}} {
		got := ReduceDeps(m, "linux", "x86-64", c.ver)
		if got["a.org"] != c.want || len(got) != c.n {
			t.Errorf("version %q: %v, want a.org=%s and %d entries", c.ver, got, c.want, c.n)
		}
	}
}

func TestReduceDepKeysNestedPlatformInScopeAndOrder(t *testing.T) {
	m := map[string]any{
		"a.org":        "1",
		"linux":        map[string]any{"a.org": "2"},
		"linux/x86-64": map[string]any{"a.org": "3"},
		">=2": map[string]any{
			"linux":  map[string]any{"b.org": "x"},
			"darwin": map[string]any{"c.org": "y"},
		},
	}
	for i := 0; i < 50; i++ {
		got := reduceDepsFor(m, "linux", "x86-64", []Ver{ParseVer("2.1")})
		if got["a.org"] != "3" || got["b.org"] != "x" || len(got) != 2 {
			t.Fatalf("run %d: %v", i, got)
		}
	}
	if got := reduceDepsFor(m, "linux", "x86-64", []Ver{ParseVer("1.0")}); len(got) != 1 || got["a.org"] != "3" {
		t.Errorf("scope applied to 1.0: %v", got)
	}
}
