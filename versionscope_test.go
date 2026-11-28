package artifact

import (
	"errors"
	"testing"
)

// go-zpkg/artifact#260: a recipe scopes a dependency block to its OWN version
// with a key such as `">=9"` (tcl-lang.org/tk). reduceDeps read the key as a
// project, so the closure carried a project called ">=9" and zpkx refused it
// (`zpkx: >=9: artifact: not a project name`).
func tkDeps() map[string]any {
	return map[string]any{
		"x.org/x11": "^1",
		">=9":       map[string]any{"zlib.net": "^1", "gnu.org/make": "*"},
		"linux":     map[string]any{"gnu.org/gcc": "*"},
	}
}

func TestReduceDepsDoesNotEmitAVersionScopeKeyAsAProject(t *testing.T) {
	got := reduceDeps(tkDeps(), "linux", "x86-64")
	for p := range got {
		if err := ValidateProjectName(p); err != nil {
			if !errors.Is(err, ErrBadProjectName) {
				t.Fatalf("unexpected error %v", err)
			}
			t.Errorf("reduceDeps emitted %q as a project: %v", p, err)
		}
	}
}

// The scope's own dependencies are kept (unioned: no package version is known
// to this walk), beside the plain and platform ones.
func TestReduceDepsUnionsAVersionScopeBlock(t *testing.T) {
	got := reduceDeps(tkDeps(), "linux", "x86-64")
	want := map[string]string{"x.org/x11": "^1", "zlib.net": "^1", "gnu.org/make": "*", "gnu.org/gcc": "*"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for p, c := range want {
		if got[p] != c {
			t.Errorf("%s = %q, want %q (got %v)", p, got[p], c, got)
		}
	}
}

// The scoped constraint is the more specific statement and overrides the plain
// one, and a platform block inside a scope is reduced for the host, not
// emitted as a project called "linux". Run repeatedly: map order must not
// decide.
func TestReduceDepsScopeOverridesAndHonoursNestedPlatform(t *testing.T) {
	m := map[string]any{
		"zlib.net": "^1",
		"^2":       map[string]any{"zlib.net": "^1.3", "linux": map[string]any{"gnu.org/gcc": "*"}, "darwin": map[string]any{"apple.com/x": "*"}},
		"<1":       map[string]any{"zlib.net": "^1.1"},
	}
	for i := 0; i < 50; i++ {
		got := reduceDeps(m, "linux", "x86-64")
		// sorted scope keys: "<1" then "^2", so ^2 is applied last.
		if got["zlib.net"] != "^1.3" || got["gnu.org/gcc"] != "*" || len(got) != 2 {
			t.Fatalf("run %d: got %v", i, got)
		}
	}
}
