package artifact

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// THE POSITIVE CONTROL FIRST, and it is the one that matters: every name
// the published catalogue actually carries must still be valid. A rule
// tightened too far refuses everything and reports green.
//
// These are real, taken from the 1908-project catalogue: the deepest
// (four segments), the longest, and the shapes that look odd but are not.
func TestEveryRealProjectNameIsAccepted(t *testing.T) {
	for _, p := range []string{
		"zlib.net",
		"gnu.org/bash",
		"gnu.org/gcc/libstdcxx",
		"github.com/GoogleContainerTools/container-structure-test",
		"code.videolan.org/rist/librist",
		"csie.ntu.edu.tw/cjlin/liblinear",
		"stedolan.github.io/jq",
		"curl.se/ca-certs",
		"x.org/font-util",
		"info-zip.org/zip",
		"freedesktop.org/poppler-qt5",
		"crates.io/ripgrep",
		"rgbds.gbdev.io",
		"agpt.co",
		"go-zpkg.github.io/catalog", // the catalogue's own name
		"tcl-lang.org",
		"llvm.org",
		"c-ares.org",
		"libzip.org",
		"google.com/boringssl",
	} {
		if err := ValidateProjectName(p); err != nil {
			t.Errorf("a REAL project name was refused: %q: %v", p, err)
		}
	}
}

// And the shapes that must not get through. `..` is the obvious one; the
// others are the reason this is an allowlist and not a list of dangerous
// spellings — a denylist inherits the blind spots of whoever wrote it.
func TestATraversingNameIsRefused(t *testing.T) {
	for _, p := range []string{
		"../../../../attacker/repo/main",
		"zlib.net/../../../../attacker",
		"..",
		".",
		"./zlib.net",
		"zlib.net/..",
		"..%2f..%2fattacker", // percent-encoded, which reached a different path
		"/etc/passwd",
		"zlib.net/",
		"/zlib.net",
		"zlib.net//sub",
		"zlib.net\\..\\attacker", // a backslash is a separator somewhere
		"",
		"zlib.net?ref=attacker",
		"zlib.net#fragment",
		"zlib.net:1234",
		"zlib net",
		"zlib.net\nmore",
		"zlib.net\x00",
		"a/b/c/d/e/f/g/h/i", // nine segments
		strings.Repeat("a", maxProjectName+1),
	} {
		err := ValidateProjectName(p)
		if err == nil {
			t.Errorf("accepted %q", p)
			continue
		}
		if !errors.Is(err, ErrBadProjectName) {
			t.Errorf("%q: error does not wrap ErrBadProjectName: %v", p, err)
		}
	}
}

// THE REASON IT EXISTS, through the code that was vulnerable.
//
// Go sends a request path verbatim — it does not clean `..` — and
// raw.githubusercontent.com answers a traversing path with a 307 to the
// normalised one, which the client follows. Measured before the fix:
// httpGet reached 1270 bytes of ANOTHER repository's README.
//
// Driven against a local server, so the test proves the refusal rather
// than depending on GitHub continuing to redirect.
func TestATraversingNameNeverReachesTheNetwork(t *testing.T) {
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = append(asked, r.URL.Path)
		w.WriteHeader(404)
	}))
	defer srv.Close()

	old := PantryBase
	PantryBase = srv.URL + "/pkgxdev/pantry/main/projects"
	defer func() { PantryBase = old }()

	_, _, err := fetchSide(PantryBase, "../../../../attacker/repo/main")
	if err == nil {
		t.Error("a traversing name was looked up")
	}
	if len(asked) != 0 {
		t.Errorf("it reached the network: %v", asked)
	}

	// The positive control: a real name still does reach it, or the test
	// above would pass on a function that never asks anything.
	asked = nil
	_, _, _ = fetchSide(PantryBase, "zlib.net")
	if len(asked) == 0 {
		t.Error("a valid name was not looked up either — the guard refuses everything")
	}
}

// A LOCK is fetched from a repository and acted on, so one forged name
// refuses the whole file: a lock is a set, and a set with a hostile member
// was written by somebody who wanted it to do something else.
func TestALockWithATraversingNameIsRefused(t *testing.T) {
	src := "lockfile_version = 1\nlocked = {\n" +
		"  \"zlib.net\" = { version = \"1.3.2\", spec = \"sha256:a\" }\n" +
		"  \"../../../../attacker\" = { version = \"1.0.0\", spec = \"sha256:b\" }\n}\n"
	if _, err := ParseLock([]byte(src), "evil.lock.hcl"); err == nil {
		t.Fatal("a lock naming a traversal was accepted")
	} else if !errors.Is(err, ErrBadProjectName) {
		t.Errorf("err = %v", err)
	}
}

// A CATALOGUE is pulled from a registry and read by every <TAB>. Both the
// project names and the DEPENDENCY names, since a tree walks into those.
func TestACatalogueWithATraversingNameIsRefused(t *testing.T) {
	for name, body := range map[string]string{
		"a project": `{"generated":"2026-10-06T09:00:00Z","projects":[{"project":"../../attacker"}]}`,
		"a dependency": `{"generated":"2026-10-06T09:00:00Z","projects":` +
			`[{"project":"curl.se","deps":["../../attacker"]}]}`,
	} {
		if _, err := UnmarshalCatalog([]byte(body)); err == nil {
			t.Errorf("%s: accepted", name)
		} else if !errors.Is(err, ErrBadProjectName) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	// And a real catalogue still parses, or this rule has eaten the
	// feature it was meant to protect.
	if _, err := UnmarshalCatalog([]byte(
		`{"generated":"2026-10-06T09:00:00Z","projects":[{"project":"gnu.org/gcc/libstdcxx","deps":["zlib.net"]}]}`,
	)); err != nil {
		t.Errorf("a valid catalogue was refused: %v", err)
	}
}
