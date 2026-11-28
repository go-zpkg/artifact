package artifact

import (
	"errors"
	"strings"
	"testing"
)

// Fewest path elements first, whatever the names sort like: a one-sided block
// is the less specific, so the os/arch block overrides it.
func TestReduceDepKeysPlatformSpecificityBeatsName(t *testing.T) {
	m := map[string]any{
		"z":   map[string]any{"a.org": "bare"},
		"a/b": map[string]any{"a.org": "both"},
	}
	all := func(k string) (bool, bool) { return k == "z" || k == "a/b", true }
	for i := 0; i < 50; i++ {
		if got := ReduceDepKeys(m, all, nil); got["a.org"] != "both" {
			t.Fatalf("run %d: %v", i, got)
		}
	}
}

func scopeInPlatformPantry(t *testing.T, deps string, versions map[string][]string) func() {
	osn, _ := HostSlug()
	return crossPantry(t, map[string]string{
		"x.org/p": "dependencies:\n  " + osn + ":\n" + deps + "provides:\n  - bin/p\n",
		"y.org":   "provides:\n  - bin/y\n",
	}, versions)
}

// A scope nested INSIDE a platform block must make the walk read the versions
// too: without them the scope is unioned and a ^9 demand is made of a package
// that is 8.x.
func TestScopeNestedInPlatformBlockIsReadAgainstVersions(t *testing.T) {
	osn, arch := HostSlug()
	slug := "/" + osn + "/" + arch
	defer scopeInPlatformPantry(t, "    \">=9\":\n      y.org: ^9\n", map[string][]string{
		"x.org/p" + slug: {"8.1.0"},
		"y.org" + slug:   {"8.0.0", "9.0.0"},
	})()
	got, err := ResolveClosureFor(map[string]string{"x.org/p": "*"}, osn, arch)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range got {
		if r.Project == "y.org" {
			t.Fatalf("a >=9 scope applied to p 8.1.0: %v", got)
		}
	}
}

// A walk that cannot read something refuses; it does not read it as absent.
func TestCollectGraphRefusesWhatItCannotRead(t *testing.T) {
	osn, arch := HostSlug()
	slug := "/" + osn + "/" + arch

	t.Run("recipe missing", func(t *testing.T) {
		defer crossPantry(t, map[string]string{}, nil)()
		_, err := ResolveClosureFor(map[string]string{"x.org/gone": "*"}, osn, arch)
		if err == nil {
			t.Fatal("resolved a project with no recipe")
		}
		// The first failure is the answer, not eight more walks and a verdict
		// that the closure "does not settle".
		if strings.Contains(err.Error(), "settle") {
			t.Errorf("a read failure was reported as non-convergence: %v", err)
		}
	})
	t.Run("dependencies not a mapping", func(t *testing.T) {
		defer crossPantry(t, map[string]string{"x.org/p": "dependencies: [a, b]\n"}, nil)()
		_, err := ResolveClosureFor(map[string]string{"x.org/p": "*"}, osn, arch)
		if err == nil || !strings.Contains(err.Error(), "dependencies") {
			t.Errorf("a recipe whose dependencies are malformed: err = %v", err)
		}
	})
	t.Run("versions of a scoped recipe unreadable", func(t *testing.T) {
		defer crossPantry(t, map[string]string{"x.org/p": tkRecipe}, map[string][]string{
			"x.org/p" + slug: {"1.0.0"},
		})()
		old := versionsForScope
		versionsForScope = func(string, string, string) ([]Ver, error) { return nil, errors.New("registry down") }
		defer func() { versionsForScope = old }()
		_, err := ResolveClosureFor(map[string]string{"x.org/p": "*"}, osn, arch)
		if err == nil || !strings.Contains(err.Error(), "listing versions") {
			t.Errorf("a scope read with no list of versions: err = %v", err)
		}
	})
}
