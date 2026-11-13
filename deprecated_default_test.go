package artifact

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// resetDeprecated clears the latch so each case starts from nothing. The
// production path deliberately reads the list once; a test that cannot reset it
// would only ever exercise whichever case ran first.
func resetDeprecated(t *testing.T) {
	t.Helper()
	prevSet, prevDefault := deprecatedSet, DefaultDeprecated
	t.Cleanup(func() {
		deprecatedOnce = sync.Once{}
		deprecatedSet, DefaultDeprecated = prevSet, prevDefault
	})
	deprecatedOnce = sync.Once{}
	deprecatedSet, DefaultDeprecated = nil, nil
}

// TestDefaultDeprecatedIsUsedWhenTheEnvIsUnset is the behaviour that makes the
// feature actually do something: shipped with the environment variable as its
// only source, it changed no answer for anybody.
func TestDefaultDeprecatedIsUsedWhenTheEnvIsUnset(t *testing.T) {
	resetDeprecated(t)
	t.Setenv(DeprecatedEnv, "")
	DefaultDeprecated = map[string][]string{"openssl.org": {"3.6", "3.4"}}

	if got := deprecatedLines("openssl.org"); len(got) != 2 {
		t.Fatalf("deprecatedLines = %v, want the default's two lines", got)
	}
	if _, dead := deprecatedLine("3.6.4", deprecatedLines("openssl.org")); !dead {
		t.Error("3.6.4 is not seen as deprecated through the default")
	}
	if _, dead := deprecatedLine("3.5.8", deprecatedLines("openssl.org")); dead {
		t.Error("3.5.8 is deprecated through the default, and must not be")
	}
}

// ⛔ TestTheEnvWinsOverTheDefault: an operator who names a file gets that file
// and nothing else. A union would be worse than either: it would silently add
// lines they did not ask for.
func TestTheEnvWinsOverTheDefault(t *testing.T) {
	resetDeprecated(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "dep.json")
	if err := os.WriteFile(path, []byte(`{"zlib.net":["1.2"]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv(DeprecatedEnv, path)
	DefaultDeprecated = map[string][]string{"openssl.org": {"3.6"}}

	if got := deprecatedLines("zlib.net"); len(got) != 1 || got[0] != "1.2" {
		t.Errorf("the named file was not used: %v", got)
	}
	if got := deprecatedLines("openssl.org"); len(got) != 0 {
		t.Errorf("the default leaked in beside the named file: %v", got)
	}
}

// ⛔ TestABrokenEnvFileDoesNotFallBackToTheDefault is the one that protects the
// operator from a silent substitution. Before a default existed, an unreadable
// file could return quietly because the outcome was identical either way; now
// the two differ, and choosing the default would hide their mistake behind
// behaviour that looks like it worked.
func TestABrokenEnvFileDoesNotFallBackToTheDefault(t *testing.T) {
	for _, c := range []struct{ name, contents string }{
		{"missing", ""},            // the file is never written
		{"unparsable", "not json"}, // written, but not JSON
	} {
		t.Run(c.name, func(t *testing.T) {
			resetDeprecated(t)
			var warn bytes.Buffer
			prev := deprecationOut
			deprecationOut = &warn
			t.Cleanup(func() { deprecationOut = prev })

			path := filepath.Join(t.TempDir(), "dep.json")
			if c.contents != "" {
				if err := os.WriteFile(path, []byte(c.contents), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv(DeprecatedEnv, path)
			DefaultDeprecated = map[string][]string{"openssl.org": {"3.6"}}

			if got := deprecatedLines("openssl.org"); len(got) != 0 {
				t.Errorf("fell back to the default for a %s file: %v", c.name, got)
			}
			if !strings.Contains(warn.String(), DeprecatedEnv) {
				t.Errorf("a %s file was ignored SILENTLY; stderr was %q", c.name, warn.String())
			}
		})
	}
}

// TestNoDefaultAndNoEnvIsTodaysBehaviour: the feature must be invisible when
// nothing supplies a list, or every existing caller changes answer on upgrade.
func TestNoDefaultAndNoEnvIsTodaysBehaviour(t *testing.T) {
	resetDeprecated(t)
	t.Setenv(DeprecatedEnv, "")
	if got := deprecatedLines("openssl.org"); len(got) != 0 {
		t.Errorf("with no default and no env, got %v", got)
	}
}
