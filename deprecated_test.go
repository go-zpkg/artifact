package artifact

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// opensslLike serves the openssl lines that matter: 3.5 (supported), 3.6
// (end-of-life), and 4.0 (a different soname, a different tree).
func opensslLike(t *testing.T, dead []string) {
	t.Helper()
	up, _ := upstreamVersionsServer(t, "openssl.org", "linux", "x86-64",
		[]string{"3.4.7", "3.5.0", "3.5.8", "3.6.0", "3.6.4", "4.0.2"})
	oldDist, oldDead, oldOut := DistBase, deprecatedLines, deprecationOut
	DistBase = up
	deprecatedLines = func(string) []string { return dead }
	t.Cleanup(func() { DistBase, deprecatedLines, deprecationOut = oldDist, oldDead, oldOut })
}

func pick(t *testing.T, c string) (string, string) {
	t.Helper()
	var buf bytes.Buffer
	deprecationOut = &buf
	v, err := PickVersionForAll("openssl.org", []string{c}, "linux", "x86-64")
	if err != nil {
		t.Fatalf("%s: %v", c, err)
	}
	return v.Raw, buf.String()
}

// The preference table. Each row says what is chosen and whether it warns.
//
// ⛔ `^3.6.4` IS THE ROW THAT DISCRIMINATES RANK FROM FILTER: it admits only a
// deprecated version. An implementation that removes deprecated candidates
// before choosing behaves identically on every other row and fails this one.
func TestDeprecatedLineIsRankedLastNeverRemoved(t *testing.T) {
	opensslLike(t, []string{"3.6", "3.4"})
	rows := []struct {
		c    string
		want string
		warn bool
	}{
		{"^3", "3.5.8", false},    // the defect: was 3.6.4
		{"^3.5", "3.5.8", false},  // admits 3.5.x and 3.6.x
		{"~3.5", "3.5.8", false},  // already on a supported line
		{"=3.6.4", "3.6.4", true}, // exact pin: resolves, deprecated or not
		{"^3.6.4", "3.6.4", true}, // admits ONLY a deprecated version
		{"~3.6", "3.6.4", true},   // names the dead line precisely
		{"=3.4.7", "3.4.7", true},
		{"^4", "4.0.2", false}, // never reaches across the soname boundary
		{"*", "4.0.2", false},
	}
	for _, r := range rows {
		got, out := pick(t, r.c)
		if got != r.want {
			t.Errorf("%s resolved %s, want %s", r.c, got, r.want)
		}
		if warned := out != ""; warned != r.warn {
			t.Errorf("%s warned=%v (%q), want %v", r.c, warned, out, r.warn)
		}
		if r.warn && !strings.Contains(out, "end-of-life") {
			t.Errorf("%s: warning does not say why: %q", r.c, out)
		}
	}
}

// All candidates deprecated: still resolves (the newest), and says so.
func TestAllDeprecatedResolvesAndWarns(t *testing.T) {
	opensslLike(t, []string{"3", "4"})
	got, out := pick(t, "^3")
	if got != "3.6.4" {
		t.Errorf("resolved %s, want the newest, 3.6.4", got)
	}
	if !strings.Contains(out, "3.6.4") {
		t.Errorf("no warning naming the version: %q", out)
	}
}

// No list is today's behaviour exactly: newest satisfier, silent. An absent,
// missing or empty file all mean no list.
func TestNoDeprecationListBehavesAsBefore(t *testing.T) {
	for name, dead := range map[string][]string{"nil": nil, "empty": {}} {
		t.Run(name, func(t *testing.T) {
			opensslLike(t, dead)
			for c, want := range map[string]string{"^3": "3.6.4", "^3.5": "3.6.4", "=3.5.0": "3.5.0", "*": "4.0.2"} {
				if got, out := pick(t, c); got != want || out != "" {
					t.Errorf("%s -> %s %q, want %s silent", c, got, out, want)
				}
			}
		})
	}
}

func TestDeprecatedFileMissingOrUnparsableMeansEmpty(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	good := filepath.Join(dir, "good.json")
	if err := os.WriteFile(good, []byte(`{"openssl.org":["3.6"]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	load := func(path string) []string {
		deprecatedOnce, deprecatedSet = sync.Once{}, nil
		t.Setenv(DeprecatedEnv, path)
		var buf bytes.Buffer
		old := deprecationOut
		deprecationOut = &buf
		defer func() { deprecationOut = old }()
		return deprecatedLines("openssl.org")
	}
	// ⛔ UNSET NOW MEANS THE LIBRARY'S LIST, not an empty one. That is the
	// whole of go-zpkg/artifact#186: an activation each binary had to remember
	// reached pkgx and not pkgm, so the installer resolved `openssl.org@^3`
	// to the end-of-life 3.6.4 while pkgx gave 3.5.8.
	//
	// The three cases below are unchanged and are the reason this test still
	// earns its place: a file that was NAMED and cannot be read is still
	// empty, never a silent fall back to the default. An operator who named a
	// file has said what they want.
	if got := load(""); len(got) == 0 {
		t.Error("unset: got an empty list, so the library default is inert")
	}
	if got := load(filepath.Join(dir, "nope.json")); got != nil {
		t.Errorf("missing file must not fall back to the default: %v", got)
	}
	if got := load(filepath.Join(dir, "nope.json")); got != nil {
		t.Errorf("missing: %v", got)
	}
	if got := load(bad); got != nil {
		t.Errorf("unparsable: %v", got)
	}
	if got := load(good); len(got) != 1 || got[0] != "3.6" {
		t.Errorf("good file: %v", got)
	}
}

// A line holds its releases on a component boundary: 3.6 is not 3.60.
func TestDeprecatedLineBoundary(t *testing.T) {
	for raw, want := range map[string]bool{"3.6.4": true, "3.6": true, "3.60.1": false, "3.5.8": false, "3.6.0-rc1": true} {
		if _, got := deprecatedLine(raw, []string{"3.6"}); got != want {
			t.Errorf("%s: %v want %v", raw, got, want)
		}
	}
}
