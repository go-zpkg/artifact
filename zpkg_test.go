package artifact

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"github.com/go-attest/sign"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"oras.land/oras-go/v2/registry/remote/errcode"
)

// --- version parsing / comparison / constraints -----------------------------

func TestParseVerAndCmp(t *testing.T) {
	if got := ParseVer("v1.2.3").Nums; fmt.Sprint(got) != "[1 2 3]" {
		t.Fatalf("ParseVer nums = %v", got)
	}
	// non-numeric tail (openssl 1.1.1w) truncates at the letter → 1.1.1.
	if got := ParseVer("1.1.1w").Nums; fmt.Sprint(got) != "[1 1 1]" {
		t.Fatalf("ParseVer 1.1.1w = %v", got)
	}
	cases := []struct {
		a, b string
		want int
	}{
		{"1.2.3", "1.2.3", 0},
		{"1.2.0", "1.2", 0},
		{"1.3", "1.2.9", 1},
		{"1.2", "1.10", -1},
	}
	for _, c := range cases {
		if got := cmpVer(ParseVer(c.a), ParseVer(c.b)); got != c.want {
			t.Errorf("cmp(%s,%s)=%d want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestSatisfies(t *testing.T) {
	cases := []struct {
		v, c string
		want bool
	}{
		{"1.2.3", "*", true},
		{"1.2.3", "", true},
		{"1.2.3", "^1.2", true},
		{"2.0.0", "^1.2", false},
		{"1.2.3", "~1.2", true},
		{"1.3.0", "~1.2", false},
		{"2.6.4", "~2", true},  // major-only tilde matches any 2.x
		{"3.0.0", "~2", false}, // but not 3.x
		{"2.0.9", "~2", true},
		{"1.2.3", ">=1.2.0", true},
		{"1.1.0", ">=1.2.0", false},
		{"1.2.3", "=1.2.3", true},
		{"1.2.4", "=1.2.3", false},
		{"1.2.3", "'^1'", true}, // quoted
		{"0.9.0", "^1", false},
		// upper-bound operators (build-dep pins like `llvm.org: <19`)
		{"18.1.8", "<19", true},
		{"19.0.0", "<19", false},
		{"20.1.0", "<19", false},
		{"16.0.6", "<19", true},
		{"19.0.0", "<=19", true},
		{"19.0.1", "<=19", false},
		{"18.0.0", "<= 19", true}, // spaced upper bound
		{"20.0.0", ">19", true},
		{"19.0.0", ">19", false},
		{"18.9.9", ">19", false},
		{"19.5.0", "> 19", true}, // spaced lower bound
	}
	for _, c := range cases {
		if got := ParseVer(c.v).satisfies(c.c); got != c.want {
			t.Errorf("%s satisfies %q = %v want %v", c.v, c.c, got, c.want)
		}
	}
}

func TestSatisfiesSpacedGE(t *testing.T) {
	if !ParseVer("1.5.0").satisfies(">= 1.2.0") {
		t.Error("spaced >= should parse")
	}
}

// --- host slug --------------------------------------------------------------

func TestHostSlug(t *testing.T) {
	osn, arch := HostSlug()
	// DERIVED, not copied. This list used to be written out here, and its own
	// comment said why that was wrong — "a test that hardcodes the platforms it
	// expects to run on fails the day it runs somewhere new, which is the day
	// you most want it green". It then did exactly that: the BSD lanes went red
	// the day osSlug stopped calling OpenBSD "linux", on a change that made
	// them MORE correct.
	//
	// isPlatformKey is the contract anyway — a slug a recipe cannot scope a
	// block to is a slug that turns `freebsd:` into a project — so asserting it
	// tests the real rule and cannot drift from the list it checks.
	if !isPlatformKey(osn) {
		t.Errorf("os slug = %q, which no recipe can scope a block to", osn)
	}
	if arch == "" {
		t.Error("empty arch slug")
	}
	if GOOS() != osn || GOARCH() != arch {
		t.Errorf("GOOS/GOARCH wrappers disagree with HostSlug")
	}
}

// --- fakePkgx: an in-memory dist.pkgx.dev + pantry --------------------------

type fakePkg struct {
	versions   []string
	yaml       string
	files      map[string]string            // path within prefix -> contents (regular files)
	filesByVer map[string]map[string]string // per-version override of files (for soname-drift tests)
	xzOnly     bool
	noArtifact map[string]bool // versions listed in versions.txt but with no artifact (404)
}

func fakeServer(t *testing.T, pkgs map[string]fakePkg) func() {
	t.Helper()
	osn, arch := HostSlug()
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/")
		// pantry: <project>/package.yml
		if strings.HasSuffix(p, "/package.yml") {
			proj := strings.TrimSuffix(p, "/package.yml")
			if pk, ok := pkgs[proj]; ok {
				fmt.Fprint(w, pk.yaml)
				return
			}
			http.NotFound(w, r)
			return
		}
		// versions.txt
		if strings.HasSuffix(p, "/versions.txt") {
			proj := strings.TrimSuffix(p, "/"+osn+"/"+arch+"/versions.txt")
			if pk, ok := pkgs[proj]; ok {
				fmt.Fprint(w, strings.Join(pk.versions, "\n"))
				return
			}
			http.NotFound(w, r)
			return
		}
		// artifact: <project>/<os>/<arch>/v<ver>.tar.(gz|xz)
		for proj, pk := range pkgs {
			pfx := proj + "/" + osn + "/" + arch + "/v"
			if !strings.HasPrefix(p, pfx) {
				continue
			}
			rest := strings.TrimPrefix(p, pfx)
			if pk.xzOnly && strings.HasSuffix(rest, ".tar.gz") {
				http.NotFound(w, r) // force xz fallback
				return
			}
			// A version present in versions.txt but with no published artifact 404s
			// for both extensions (exercises the install-failure/continue paths).
			if v := strings.TrimSuffix(strings.TrimSuffix(rest, ".tar.gz"), ".tar.xz"); pk.noArtifact[v] {
				http.NotFound(w, r)
				return
			}
			if strings.HasSuffix(rest, ".tar.gz") {
				ver := strings.TrimSuffix(rest, ".tar.gz")
				files := pk.files
				if pk.filesByVer != nil {
					if f, ok := pk.filesByVer[ver]; ok {
						files = f
					}
				}
				w.Write(makeArtifactGz(t, proj, ver, files))
				return
			}
		}
		http.NotFound(w, r)
	})
	// The fixture is a static-HTTP dist serving UNSIGNED artifacts, so the
	// fail-closed check refuses every install through it — correctly, now that
	// the install path enforces it too. Tests that exercise verification itself
	// set ZPKG_VERIFY back on explicitly.
	t.Setenv("ZPKG_VERIFY", "0")
	// PantryOverlay defaults to the LIVE go-zpkg/pantry-overlay and is consulted
	// BEFORE PantryBase, so leaving it set meant a fixture recipe was silently
	// replaced by the real one for any project the overlay happens to carry.
	// gnu.org/help2man entered the overlay on 2026-09-12 and TestFetchRuntimeEnv
	// began reading that recipe instead of its own: the PERL5LIB assertion still
	// passed (the fixture was copied from the real recipe) while the invented
	// MAJOR key was simply absent. A test must not depend on another repository's
	// contents, nor on the network being there.
	overlay := PantryOverlay
	PantryOverlay = ""
	DistBase, PantryBase = srv.URL, srv.URL
	return func() {
		PantryOverlay = overlay
		srv.Close()
	}
}

// makeArtifactGz builds a gzip'd tar with the pkgx <project>/v<ver>/... layout.
func makeArtifactGz(t *testing.T, project, ver string, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	prefix := project + "/v" + ver + "/"
	// a directory entry + a symlink + the regular files
	_ = tw.WriteHeader(&tar.Header{Name: prefix, Typeflag: tar.TypeDir, Mode: 0o755})
	_ = tw.WriteHeader(&tar.Header{Name: prefix + "lnk", Typeflag: tar.TypeSymlink, Linkname: "bin"})
	for rel, content := range files {
		_ = tw.WriteHeader(&tar.Header{Name: prefix + rel, Typeflag: tar.TypeReg, Mode: 0o755, Size: int64(len(content))})
		_, _ = tw.Write([]byte(content))
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func TestFetchVersionsAndPick(t *testing.T) {
	defer fakeServer(t, map[string]fakePkg{
		"acme.org/tool": {versions: []string{"1.0.0", "1.2.0", "2.0.0"}, yaml: "provides:\n  - bin/tool\n"},
	})()
	vs, err := FetchVersions("acme.org/tool")
	if err != nil || len(vs) != 3 {
		t.Fatalf("versions err=%v n=%d", err, len(vs))
	}
	v, err := PickVersion("acme.org/tool", "^1.0")
	if err != nil || v.Raw != "1.2.0" {
		t.Fatalf("pick ^1.0 = %v (%v)", v.Raw, err)
	}
	if _, err := PickVersion("acme.org/tool", "^9"); err == nil {
		t.Fatal("expected no-match error for ^9")
	}
}

// upstreamVersionsServer spins a fake upstream pkgx dist that serves a project's
// per-arch versions.txt, and records how many times it was hit. It is used to
// prove the OCI-registry version listing falls back to the upstream dist for
// build-time deps not published to the OCI DistBase.
func upstreamVersionsServer(t *testing.T, project, osn, arch string, versions []string) (url string, hits *int) {
	t.Helper()
	var n int
	want := "/" + project + "/" + osn + "/" + arch + "/versions.txt"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		if r.URL.Path != want {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, strings.Join(versions, "\n"))
	}))
	t.Cleanup(srv.Close)
	return srv.URL, &n
}

// TestVersionsForOCIEmptyFallsBackToUpstream: when the OCI registry lists zero
// versions for a project (a build-dep not published there), VersionsFor falls
// back to the upstream pkgx dist so the concrete install version resolves.
func TestVersionsForOCIEmptyFallsBackToUpstream(t *testing.T) {
	fr := newFakeRegistry(t, false)
	defer fr.close()
	// The repo exists but carries no tags → ListTags returns an empty slice, no
	// error (the exact shape a not-yet-mirrored build-dep produces on ghcr).
	fr.mu.Lock()
	fr.tags["go-zpkg/packages/llvm.org"] = map[string]bool{}
	fr.mu.Unlock()

	up, hits := upstreamVersionsServer(t, "llvm.org", "linux", "aarch64",
		[]string{"16.0.6", "18.1.8", "20.1.0"})
	oldDist, oldUp := DistBase, UpstreamDist
	DistBase, UpstreamDist = fr.base("go-zpkg/packages"), up
	defer func() { DistBase, UpstreamDist = oldDist, oldUp; resetOCICache() }()
	resetOCICache()

	vs, err := VersionsFor("llvm.org", "linux", "aarch64")
	if err != nil {
		t.Fatalf("VersionsFor: %v", err)
	}
	if len(vs) != 3 || vs[0].Raw != "16.0.6" || vs[2].Raw != "20.1.0" {
		t.Fatalf("upstream fallback versions = %v", vs)
	}
	if *hits == 0 {
		t.Error("expected the upstream dist to be consulted")
	}
	// And the build-time constraint form pkgx uses ("<19") selects the highest
	// satisfying version from that fallback list.
	var best Ver
	for _, ver := range vs {
		if ver.satisfies("<19") {
			best = ver
		}
	}
	if best.Raw != "18.1.8" {
		t.Fatalf("highest <19 = %q, want 18.1.8", best.Raw)
	}
}

// TestVersionsForOCINonEmptyShortCircuits: when the OCI registry has versions,
// VersionsFor returns them and never consults the upstream dist.
func TestVersionsForOCINonEmptyShortCircuits(t *testing.T) {
	t.Setenv("ZPKG_VERIFY", "0")
	fr := newFakeRegistry(t, false)
	defer fr.close()
	c, err := NewOCIClient(fr.base("go-zpkg/packages"))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Push("acme.org/tool", "2.5.0", "linux", "aarch64", makeGzTarball("x"), ".tar.gz"); err != nil {
		t.Fatal(err)
	}
	up, hits := upstreamVersionsServer(t, "acme.org/tool", "linux", "aarch64", []string{"9.9.9"})
	oldDist, oldUp := DistBase, UpstreamDist
	DistBase, UpstreamDist = fr.base("go-zpkg/packages"), up
	defer func() { DistBase, UpstreamDist = oldDist, oldUp; resetOCICache() }()
	resetOCICache()

	vs, err := VersionsFor("acme.org/tool", "linux", "aarch64")
	if err != nil || len(vs) != 1 || vs[0].Raw != "2.5.0" {
		t.Fatalf("OCI versions = %v err=%v", vs, err)
	}
	if *hits != 0 {
		t.Errorf("upstream dist must not be consulted when OCI has versions (hits=%d)", *hits)
	}
}

// TestVersionsForOCIEmptyUpstreamError: a failing upstream dist propagates its
// error through the fallback.
func TestVersionsForOCIEmptyUpstreamError(t *testing.T) {
	fr := newFakeRegistry(t, false)
	defer fr.close()
	fr.mu.Lock()
	fr.tags["go-zpkg/packages/ghost.org"] = map[string]bool{}
	fr.mu.Unlock()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", 500)
	}))
	defer up.Close()
	oldDist, oldUp := DistBase, UpstreamDist
	DistBase, UpstreamDist = fr.base("go-zpkg/packages"), up.URL
	defer func() { DistBase, UpstreamDist = oldDist, oldUp; resetOCICache() }()
	resetOCICache()
	if _, err := VersionsFor("ghost.org", "linux", "aarch64"); err == nil {
		t.Fatal("expected upstream HTTP error to propagate")
	}
}

// TestVersionsForNonOCIDist: a plain static-HTTP DistBase still lists versions
// directly (no OCI, no fallback).
func TestVersionsForNonOCIDist(t *testing.T) {
	up, _ := upstreamVersionsServer(t, "plain.org", "linux", "aarch64", []string{"1.0.0", "1.1.0"})
	oldDist := DistBase
	DistBase = up // non-oci:// → httpVersionsFor(DistBase, ...)
	defer func() { DistBase = oldDist }()
	vs, err := VersionsFor("plain.org", "linux", "aarch64")
	if err != nil || len(vs) != 2 || vs[1].Raw != "1.1.0" {
		t.Fatalf("non-OCI versions = %v err=%v", vs, err)
	}
}

func TestFetchMeta(t *testing.T) {
	osn, _ := HostSlug()
	yml := "dependencies:\n  dep.org/lib: ^1.1\n  " + osn + ":\n    plat.org/only: '*'\n  win/x:\n    no.org/pe: '*'\nprovides:\n  - bin/tool\n"
	defer fakeServer(t, map[string]fakePkg{"acme.org/tool": {yaml: yml}})()
	deps, provides, err := FetchMeta("acme.org/tool")
	if err != nil {
		t.Fatal(err)
	}
	if deps["dep.org/lib"] != "^1.1" || deps["plat.org/only"] != "*" {
		t.Fatalf("deps = %v", deps)
	}
	if _, ok := deps["no.org/pe"]; ok {
		t.Errorf("non-host platform dep leaked: %v", deps)
	}
	if len(provides) != 1 || provides[0] != "bin/tool" {
		t.Errorf("provides = %v", provides)
	}
}

func TestResolveClosureAndInstall(t *testing.T) {
	defer fakeServer(t, map[string]fakePkg{
		"acme.org/tool": {
			versions: []string{"1.0.0"},
			yaml:     "dependencies:\n  dep.org/lib: '*'\nprovides:\n  - bin/tool\n",
			files:    map[string]string{"bin/tool": "#!bin\n", "lib/libx.so": "x"},
		},
		"dep.org/lib": {
			versions: []string{"2.3.0"},
			yaml:     "provides:\n  - bin/lib\n",
			files:    map[string]string{"lib/libdep.so": "d"},
			xzOnly:   false,
		},
	})()
	closure, err := ResolveClosure(map[string]string{"acme.org/tool": "*"})
	if err != nil {
		t.Fatal(err)
	}
	if len(closure) != 2 {
		t.Fatalf("closure len = %d", len(closure))
	}
	dir := t.TempDir()
	for _, r := range closure {
		fresh, err := Install(r, dir)
		if err != nil || !fresh {
			t.Fatalf("install %s fresh=%v err=%v", r.Project, fresh, err)
		}
	}
	// second install is cached
	if fresh, _ := Install(closure[0], dir); fresh {
		t.Error("expected cached on second install")
	}
	// Extracted under the HASHED path, and NO version-only path beside it —
	// not `v1.0.0`, not `v1`. Each of those names a version rather than a
	// build, which is the thing the layout exists to make unsayable.
	if _, err := os.Stat(filepath.Join(StorePrefix(dir, "acme.org/tool", ParseVer("1.0.0")), "bin", "tool")); err != nil {
		t.Errorf("missing extracted bin: %v", err)
	}
	for _, gone := range []string{"v1.0.0", "v1", "v*"} {
		if _, err := os.Lstat(filepath.Join(dir, "acme.org/tool", gone)); err == nil {
			t.Errorf("%s exists: a path that names a version and not a build", gone)
		}
	}
	// ⛔ THE CLOSURE'S PATHS NAME THE HASHED BUILDS. LD_LIBRARY_PATH and a
	// stub are written once and used for as long as the process lives;
	// naming `v1.0.0` would make them follow whatever that alias is later
	// made to mean. The alias is for the rpath baked into published binaries,
	// which cannot be rewritten; everything computed HERE names the build.
	lp := LibPath(closure, dir)
	for _, p := range []string{
		StorePrefix(dir, "acme.org/tool", ParseVer("1.0.0")),
		StorePrefix(dir, "dep.org/lib", ParseVer("2.3.0")),
	} {
		if !strings.Contains(p, variantSep) {
			t.Fatalf("installed prefix carries no hash: %s", p)
		}
		if !strings.Contains(lp, filepath.Join(p, "lib")) {
			t.Errorf("libpath %q does not contain %q", lp, filepath.Join(p, "lib"))
		}
	}
	// PrefixOf resolves an in-closure project, "" for an absent one.
	if got := PrefixOf("dep.org/lib", closure, dir); got != StorePrefix(dir, "dep.org/lib", ParseVer("2.3.0")) {
		t.Errorf("PrefixOf in-closure = %q", got)
	}
	if got := PrefixOf("not/here", closure, dir); got != "" {
		t.Errorf("PrefixOf absent = %q, want empty", got)
	}
}

func TestInstallArtifactConcurrent(t *testing.T) {
	defer fakeServer(t, map[string]fakePkg{
		"acme.org/tool": {
			versions: []string{"1.0.0"},
			yaml:     "provides:\n  - bin/tool\n",
			files:    map[string]string{"bin/tool": "#!x\n", "lib/libx.so": "x"},
		},
	})()
	dir := t.TempDir()
	r := Resolved{"acme.org/tool", ParseVer("1.0.0")}
	// Many workers install the same artifact into one ZPKG_DIR at once.
	errs := make(chan error, 12)
	for i := 0; i < 12; i++ {
		go func() { _, e := Install(r, dir); errs <- e }()
	}
	for i := 0; i < 12; i++ {
		if e := <-errs; e != nil {
			t.Errorf("concurrent install error: %v", e)
		}
	}
	// exactly one clean prefix, no leftover temp dirs
	if _, err := os.Stat(filepath.Join(StorePrefix(dir, "acme.org/tool", ParseVer("1.0.0")), "bin", "tool")); err != nil {
		t.Errorf("missing extracted bin after concurrent install: %v", err)
	}
	// ⛔ AND EXACTLY ONE. Several workers racing on one build must leave one
	// directory, not one per worker: `dest` is the same hashed path for all
	// of them, which is what makes the race benign.
	if got := InstalledBuilds("acme.org/tool", dir); len(got) != 1 {
		t.Errorf("InstalledBuilds = %v, want exactly one build", got)
	}
	tmps, _ := filepath.Glob(filepath.Join(dir, ".tmp-*"))
	if len(tmps) != 0 {
		t.Errorf("stray temp dirs: %v", tmps)
	}
}

func TestInstallArtifactXZFallback(t *testing.T) {
	// gzip 404s -> exercises the .tar.xz branch error path (no xz body served).
	defer fakeServer(t, map[string]fakePkg{
		"xz.org/only": {versions: []string{"1.0.0"}, yaml: "provides:\n  - bin/only\n", xzOnly: true},
	})()
	_, err := Install(Resolved{"xz.org/only", ParseVer("1.0.0")}, t.TempDir())
	if err == nil {
		t.Fatal("expected error when neither gz nor a valid xz is served")
	}
}

func TestFetchArtifactServerError(t *testing.T) {
	t.Setenv("ZPKG_VERIFY", "0") // status-code path: an HTTP dist is unverifiable by design
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", 500)
	}))
	defer srv.Close()
	old := DistBase
	DistBase = srv.URL
	defer func() { DistBase = old }()
	_, _, _, err := fetchArtifact(Resolved{"a/b", ParseVer("1.0.0")}, "linux", "x86-64")
	if err == nil {
		t.Fatal("want error on 500")
	}
}

func TestHTTPGetError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", 404)
	}))
	defer srv.Close()
	if _, err := httpGet(srv.URL); err == nil {
		t.Fatal("want error on 404")
	}
	if _, err := httpGet("http://127.0.0.1:0/bad"); err == nil {
		t.Fatal("want error on dial fail")
	}
}

func TestDirDefault(t *testing.T) {
	// Empty config so ZPKG_DIR resolution depends only on the environment.
	setConfigPath(t, filepath.Join(t.TempDir(), "absent.hcl2"))
	t.Setenv("ZPKG_DIR", "")
	t.Setenv("HOME", "/tmp/homeX")
	// ⛔ `.zpkg`, AND THE NAME IS THE ASSERTION. `~/.pkgx` is upstream pkgx's
	// store — its own documentation says so — and upstream can sit on the
	// same PATH as us since the rename. Two implementations writing one
	// directory under two layouts is the collision the rename removed; this
	// test is what keeps it removed.
	if got := Dir(); got != "/tmp/homeX/.zpkg" {
		t.Errorf("default Dir = %q, want the store to be OURS", got)
	}
	t.Setenv("ZPKG_DIR", "/custom")
	if got := Dir(); got != "/custom" {
		t.Errorf("env Dir = %q", got)
	}
}

func TestNewHTTPClient(t *testing.T) {
	if NewHTTPClient() == nil {
		t.Fatal("nil client")
	}
}

func TestPlatformMatches(t *testing.T) {
	if !platformMatches("linux", "linux", "x86-64") {
		t.Error("os match")
	}
	if !platformMatches("linux/x86-64", "linux", "x86-64") {
		t.Error("os/arch match")
	}
	if platformMatches("darwin", "linux", "x86-64") {
		t.Error("should not match")
	}
	if !isPlatformKey("linux/aarch64") || isPlatformKey("openssl.org") {
		t.Error("isPlatformKey")
	}
}

func TestDecodeProvides(t *testing.T) {
	osn, _ := HostSlug()
	for name, c := range map[string]struct {
		in   any
		want []string
	}{
		"a list of paths":       {[]any{"bin/x", "bin/y"}, []string{"bin/x", "bin/y"}},
		"a platform map":        {map[string]any{osn: []any{"bin/x"}, "other": []any{"bin/y"}}, []string{"bin/x"}},
		"a platform we are not": {map[string]any{"other": []any{"bin/y"}}, nil},
		// Neither a list nor a platform map. A scalar `provides: bin/x` is not
		// the shape the pantry uses, and inventing a one-item list from it
		// would accept a spelling nothing else in the fleet does.
		"a scalar": {"just-a-string", nil},
		"absent":   {nil, nil},
		// A list with a non-string in it is refused WHOLE. Taking the strings
		// and dropping the rest would hand the caller a shorter list that
		// looks complete.
		"a list with a number": {[]any{"bin/x", int64(3)}, nil},
	} {
		got := decodeProvides(c.in)
		if len(got) != len(c.want) {
			t.Errorf("%s: provides = %v, want %v", name, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%s: provides = %v, want %v", name, got, c.want)
				break
			}
		}
	}
}

// A field that is present but the wrong shape is a DEFECT, and must be said
// so. Reading `env: [not a map]` as "no env" would install a package whose
// consumers silently lack the environment it declares they need.
func TestMapFieldTellsAbsentFromMalformed(t *testing.T) {
	doc := map[string]any{
		"runtime": map[string]any{"env": map[string]any{"K": "v"}},
		"broken":  []any{"not a map"},
		"nulled":  nil,
	}
	if m, err := mapField(doc, "runtime", "env"); err != nil || m["K"] != "v" {
		t.Errorf("a present mapping: %v, %v", m, err)
	}
	if m, err := mapField(doc, "absent"); err != nil || m != nil {
		t.Errorf("an absent key is not an error: %v, %v", m, err)
	}
	if m, err := mapField(doc, "nulled"); err != nil || m != nil {
		t.Errorf("an explicit null is absent, not malformed: %v, %v", m, err)
	}
	if _, err := mapField(doc, "broken"); err == nil {
		t.Error("a list where a mapping belongs must be an error")
	}
	// And the message names the PATH it failed at, not just the leaf: "env"
	// alone does not say which of a recipe's blocks is wrong.
	if _, err := mapField(map[string]any{"runtime": map[string]any{"env": []any{1}}}, "runtime", "env"); err == nil {
		t.Error("want an error")
	} else if !strings.Contains(err.Error(), "runtime.env") {
		t.Errorf("the message must name the path: %v", err)
	}
}

// constraintText renders a constraint the way the resolver reads it, and an
// author may write one that looks like a number.
func TestConstraintText(t *testing.T) {
	for name, c := range map[string]struct{ in, want any }{
		"text":                  {"^3", "^3"},
		"an integer constraint": {int64(1), "1"},
		"a fractional one":      {1.5, "1.5"},
		"absent":                {nil, ""},
		// Not a scalar: "" reaches the resolver as "any version", which is what
		// the decode this replaces produced too.
		"a mapping": {map[string]any{"a": 1}, ""},
		"a list":    {[]any{1}, ""},
	} {
		if got := constraintText(c.in); got != c.want {
			t.Errorf("%s: constraintText = %q, want %q", name, got, c.want)
		}
	}
}

func TestUntarVariants(t *testing.T) {
	dest := t.TempDir()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	_ = tw.WriteHeader(&tar.Header{Name: "d/", Typeflag: tar.TypeDir, Mode: 0o755})
	_ = tw.WriteHeader(&tar.Header{Name: "d/f", Typeflag: tar.TypeReg, Mode: 0o644, Size: 3})
	_, _ = tw.Write([]byte("abc"))
	_ = tw.WriteHeader(&tar.Header{Name: "d/s", Typeflag: tar.TypeSymlink, Linkname: "f"})
	_ = tw.WriteHeader(&tar.Header{Name: "d/h", Typeflag: tar.TypeLink, Linkname: "d/f"})
	tw.Close()
	if err := untar(&buf, dest); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dest, "d/f")); string(b) != "abc" {
		t.Errorf("reg = %q", b)
	}
	if tgt, _ := os.Readlink(filepath.Join(dest, "d/s")); tgt != "f" {
		t.Errorf("symlink = %q", tgt)
	}
}

func TestUntarUnsafePath(t *testing.T) {
	dest := t.TempDir()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	_ = tw.WriteHeader(&tar.Header{Name: "../evil", Typeflag: tar.TypeReg, Size: 1})
	_, _ = tw.Write([]byte("x"))
	tw.Close()
	if err := untar(&buf, dest); err == nil {
		t.Fatal("expected unsafe-path error")
	}
}

// TestPantryOverlay: a recipe present in the overlay is served from there; one
// absent from the overlay falls back to PantryBase.
func TestPantryOverlay(t *testing.T) {
	osn, _ := HostSlug()
	overridden := "dependencies:\n  openssl.org: '*'\nprovides:\n  - bin/curl\n"
	upstream := "dependencies:\n  openssl.org: ^1.1\nprovides:\n  - bin/curl\n"
	base := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/curl.se/package.yml":
			fmt.Fprint(w, upstream)
		case "/zlib.net/package.yml":
			fmt.Fprint(w, "provides:\n  - lib/libz."+osn+"\n")
		default:
			http.NotFound(w, r)
		}
	}))
	defer base.Close()
	overlay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/curl.se/package.yml" {
			fmt.Fprint(w, overridden)
			return
		}
		http.NotFound(w, r) // overlay only carries curl.se
	}))
	defer overlay.Close()

	ob, op := PantryBase, PantryOverlay
	defer func() { PantryBase, PantryOverlay = ob, op }()
	PantryBase, PantryOverlay = base.URL, overlay.URL

	// overlay hit -> corrected constraint
	deps, _, err := FetchMeta("curl.se")
	if err != nil || deps["openssl.org"] != "*" {
		t.Fatalf("overlay hit: deps=%v err=%v (want openssl.org=*)", deps, err)
	}
	// overlay miss -> fall back to base (must still resolve)
	if _, _, err := FetchMeta("zlib.net"); err != nil {
		t.Fatalf("overlay miss fallback: %v", err)
	}
	// with no overlay, base is used verbatim
	PantryOverlay = ""
	deps, _, err = FetchMeta("curl.se")
	if err != nil || deps["openssl.org"] != "^1.1" {
		t.Fatalf("no overlay: deps=%v err=%v (want openssl.org=^1.1)", deps, err)
	}
}

func TestApplyEnvOverlay(t *testing.T) {
	ob := PantryOverlay
	defer func() { PantryOverlay = ob }()
	PantryOverlay = ""
	applyEnv(func(k string) string {
		if k == "ZPKG_PANTRY_OVERLAY" {
			return "https://ov.example/projects/"
		}
		return ""
	})
	if PantryOverlay != "https://ov.example/projects" {
		t.Errorf("PantryOverlay = %q", PantryOverlay)
	}
}

// The overlay defaults ON, and to OUR overlay, because DistBase defaults to OUR
// registry and the two have to agree. They did not, and it was silent: the
// published cargo links openssl 3 and says so, upstream's recipe does not
// mention openssl at all, so a default `pkgm install rust-lang.org/cargo`
// installed 1.1.1w and the binary died on a library nothing had installed —
// with the corrected recipe sitting in the overlay, unread.
func TestOverlayDefaultsToOurs(t *testing.T) {
	ob := PantryOverlay
	defer func() { PantryOverlay = ob }()
	PantryOverlay = "https://raw.githubusercontent.com/go-zpkg/pantry-overlay/main/projects"
	applyEnv(func(string) string { return "" })
	if PantryOverlay == "" {
		t.Fatal("an unset ZPKG_PANTRY_OVERLAY turned the overlay off")
	}
	if !strings.Contains(PantryOverlay, "go-zpkg/pantry-overlay") {
		t.Errorf("PantryOverlay = %q, want our overlay", PantryOverlay)
	}
}

// "none" is how a caller says no overlay. An empty value cannot mean it: an
// unset variable and one set to nothing are the same string here, and
// defaulting on an unset variable is the whole point.
func TestOverlayCanBeTurnedOff(t *testing.T) {
	ob := PantryOverlay
	defer func() { PantryOverlay = ob }()
	PantryOverlay = "https://ov.example/projects"
	applyEnv(func(k string) string {
		if k == "ZPKG_PANTRY_OVERLAY" {
			return "none"
		}
		return ""
	})
	if PantryOverlay != "" {
		t.Errorf("PantryOverlay = %q, want it off", PantryOverlay)
	}
}

// TestFetchRuntimeEnv: a package declaring `runtime: env:` is declaring what its
// CONSUMERS need. help2man bundles the perl module Locale::gettext into its own
// prefix and publishes PERL5LIB so it is findable; without that export it dies
// with "Can't locate Locale/gettext.pm in @INC", which is exactly how
// gnu.org/libidn2 failed to build.
func TestFetchRuntimeEnv(t *testing.T) {
	defer fakeServer(t, map[string]fakePkg{
		"gnu.org/help2man": {
			versions: []string{"1.49.3"},
			yaml: "runtime:\n  env:\n    PERL5LIB: \"{{prefix}}/lib/perl5:{{prefix}}/libexec/lib/perl5:$PERL5LIB\"\n" +
				"    MAJOR: \"{{version.major}}.{{ version.minor }}\"\nprovides:\n  - bin/help2man\n",
		},
		"plain.org": {versions: []string{"1.0.0"}, yaml: "provides:\n  - bin/plain\n"},
	})()

	env, err := FetchRuntimeEnv("gnu.org/help2man", "/pkgx/gnu.org/help2man/v1.49.3", "1.49.3")
	if err != nil {
		t.Fatal(err)
	}
	want := "/pkgx/gnu.org/help2man/v1.49.3/lib/perl5:/pkgx/gnu.org/help2man/v1.49.3/libexec/lib/perl5:$PERL5LIB"
	if env["PERL5LIB"] != want {
		t.Errorf("PERL5LIB = %q\nwant %q", env["PERL5LIB"], want)
	}
	// the shell reference survives expansion: the value chains onto whatever the
	// caller already had, which is how two packages both contribute to one var.
	if !strings.Contains(env["PERL5LIB"], "$PERL5LIB") {
		t.Error("the $VAR chain must be preserved verbatim for the shell")
	}
	if env["MAJOR"] != "1.49" {
		t.Errorf("version parts = %q, want 1.49", env["MAJOR"])
	}
	// a package with no runtime env yields an empty map, not an error
	if env, err := FetchRuntimeEnv("plain.org", "/p", "1.0.0"); err != nil || len(env) != 0 {
		t.Errorf("plain package: env=%v err=%v", env, err)
	}
	// an unserved project is an error
	if _, err := FetchRuntimeEnv("absent.org", "/p", "1.0.0"); err == nil {
		t.Error("expected an error for an unserved project")
	}
}

func TestExpandRecipeVars(t *testing.T) {
	for in, want := range map[string]string{
		"{{prefix}}/lib":         "/p/lib",
		"{{ prefix }}/lib":       "/p/lib",
		"v{{version}}":           "v2.3.4",
		"v{{ version.raw }}":     "v2.3.4",
		"{{version.marketing}}":  "2.3",
		"{{version.major}}":      "2",
		"{{version.minor}}":      "3",
		"a{{ hw.concurrency }}b": "ab", // unknown at install time: dropped, never literal
		"nothing":                "nothing",
	} {
		if got := expandRecipeVars(in, "/p", "2.3.4"); got != want {
			t.Errorf("expandRecipeVars(%q) = %q, want %q", in, got, want)
		}
	}
	// a version with fewer components still answers for the parts asked of it
	if got := expandRecipeVars("{{version.minor}}", "/p", "7"); got != "0" {
		t.Errorf("missing component = %q, want 0", got)
	}
}

// A malformed recipe is an error, not silently no env.
func TestFetchRuntimeEnvBadYAML(t *testing.T) {
	defer fakeServer(t, map[string]fakePkg{
		"bad.org": {versions: []string{"1.0.0"}, yaml: "runtime:\n  env: [this is not a map]\n"},
	})()
	if _, err := FetchRuntimeEnv("bad.org", "/p", "1.0.0"); err == nil {
		t.Error("expected a parse error")
	}
}

// TestHTTPGetRetriesTransient: every recipe and every version listing is one GET
// against raw.githubusercontent, which 503s under load. Two kernel builds in a
// row died seven minutes in — after fetching and configuring a whole kernel — on
// a single 503, because the GET was single-shot.
func TestHTTPGetRetriesTransient(t *testing.T) {
	old := sleep
	sleep = func(time.Duration) {}
	defer func() { sleep = old }()

	var hits int
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		if hits < 3 {
			http.Error(w, "later", http.StatusServiceUnavailable)
			return
		}
		fmt.Fprint(w, "ok")
	}))
	defer s.Close()

	body, err := httpGet(s.URL)
	if err != nil || string(body) != "ok" {
		t.Fatalf("body=%q err=%v; a transient 503 must be retried", body, err)
	}
	if hits != 3 {
		t.Errorf("hits = %d, want 3 (two failures then success)", hits)
	}

	// A 404 is an ANSWER — "no such project" — and must not be retried.
	hits = 0
	s404 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		http.NotFound(w, nil)
	}))
	defer s404.Close()
	if _, err := httpGet(s404.URL); err == nil {
		t.Error("a 404 must still be an error")
	}
	if hits != 1 {
		t.Errorf("404 attempted %d times, want 1", hits)
	}

	// A status that never recovers is reported after the attempts are spent.
	hits = 0
	s503 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	defer s503.Close()
	if _, err := httpGet(s503.URL); err == nil {
		t.Error("a permanent 503 must fail")
	}
	if hits != httpGetAttempts {
		t.Errorf("attempted %d times, want %d", hits, httpGetAttempts)
	}

	// A transport error is retried too, and reported when it persists.
	if _, err := httpGet("http://127.0.0.1:1/nope"); err == nil {
		t.Error("a dead endpoint must fail")
	}
}

// TestInstallForTargetPlatform: a builder stages a rootfs for the platform it
// is BUILDING, not the one it runs on — a linux/x86-64 image assembled from a
// darwin/arm64 laptop must fetch the linux/x86-64 artifact.
func TestInstallForTargetPlatform(t *testing.T) {
	setGoos(t, "darwin")
	setGoarch(t, "aarch64")
	t.Setenv("ZPKG_VERIFY", "0") // a bare HTTP fixture carries no signatures

	tarball := makeArtifactGz(t, "tool.org", "1.0.0", map[string]string{"bin/tool": "x"})
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = append(asked, r.URL.Path)
		if strings.HasSuffix(r.URL.Path, "/linux/x86-64/v1.0.0.tar.gz") {
			_, _ = w.Write(tarball)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	old := DistBase
	DistBase = srv.URL
	defer func() { DistBase = old }()

	dir := t.TempDir()
	if _, err := InstallFor(Resolved{"tool.org", ParseVer("1.0.0")}, dir, "linux", "x86-64"); err != nil {
		t.Fatalf("InstallFor: %v", err)
	}
	for _, p := range asked {
		if strings.Contains(p, "darwin") || strings.Contains(p, "aarch64") {
			t.Errorf("asked the HOST platform: %s", p)
		}
	}
	if _, err := os.Stat(filepath.Join(StorePrefix(dir, "tool.org", ParseVer("1.0.0")), "bin", "tool")); err != nil {
		t.Errorf("not extracted: %v", err)
	}
	// Install keeps meaning "the host": same fixture, and it must MISS.
	if _, err := Install(Resolved{"other.org", ParseVer("1.0.0")}, t.TempDir()); err == nil {
		t.Error("Install must still resolve for the host platform")
	}
}

// TestPickVersionForSkipsUnpublishedPlatform is the linux-headers episode in
// miniature: a mirror wave lands 7.2.1 for arm64 only, and resolving x86-64
// must NOT pick it — the tag listing spans platforms, the artifact does not.
//
// Before this, staging a sovereign rootfs died with
//
//	install kernel.org/linux-headers 7.2.1: no artifact for
//	kernel.org/linux-headers v7.2.1 (linux/x86-64): platform not in index
//
// naming a version nobody had asked for.
func TestPickVersionForSkipsUnpublishedPlatform(t *testing.T) {
	fr := newFakeRegistry(t, false)
	oldDist, oldUp := DistBase, UpstreamDist
	base := fr.base("go-zpkg/artifacts")
	DistBase = base
	// Any fallback to the upstream dist would mask the behaviour under test.
	UpstreamDist = "https://upstream.invalid"
	resetOCICache()
	t.Cleanup(func() {
		DistBase, UpstreamDist = oldDist, oldUp
		resetOCICache()
	})

	c, err := NewOCIClient(base)
	if err != nil {
		t.Fatal(err)
	}
	// 7.1.8 on both arches; 7.2.1 on arm64 only.
	for _, a := range []string{"x86-64", "aarch64"} {
		if _, err := c.PushWithReferrers("hdr.test", "7.1.8", "linux", a, makeGzTarball("b"), ".tar.gz", nil); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.PushWithReferrers("hdr.test", "7.2.1", "linux", "aarch64", makeGzTarball("b"), ".tar.gz", nil); err != nil {
		t.Fatal(err)
	}

	// aarch64 gets the newest; x86-64 steps over it to the one it can install.
	if v, err := PickVersionFor("hdr.test", "*", "linux", "aarch64"); err != nil || v.Raw != "7.2.1" {
		t.Errorf("aarch64: got %q err=%v, want 7.2.1", v.Raw, err)
	}
	if v, err := PickVersionFor("hdr.test", "*", "linux", "x86-64"); err != nil || v.Raw != "7.1.8" {
		t.Errorf("x86-64: got %q err=%v, want 7.1.8", v.Raw, err)
	}

	// A constraint only the unpublished version satisfies must say so, and say
	// which version it stepped over — the old message blamed the constraint.
	_, err = PickVersionFor("hdr.test", "=7.2.1", "linux", "x86-64")
	if err == nil {
		t.Fatal("=7.2.1 on x86-64 should fail")
	}
	if !strings.Contains(err.Error(), "7.2.1") || !strings.Contains(err.Error(), "not published here") {
		t.Errorf("error should name the version and why: %v", err)
	}
}

// TestFetchArtifactUsesCacheButTrustsTheRegistry: the pull-through cache serves
// the bytes and the REGISTRY still says whether they are the right ones.
//
// The cache exists because staging a sovereign rootfs pulls ~2 GiB per job. It
// must not become ZPKG_DIST: zot cannot list the tags of a repository it has
// not synced, so resolution would fall back to the upstream dist and ask for a
// VERSION where our registry uses a TAG — gnu.org/bash is published as `5.3`,
// not `5.3.0` — and the pull 404s on a tag that never existed.
func TestFetchArtifactUsesCacheButTrustsTheRegistry(t *testing.T) {
	real := newFakeRegistry(t, false)
	cache := newFakeRegistry(t, false)
	realBase, cacheBase := real.base("go-zpkg/artifacts"), cache.base("go-zpkg/artifacts")

	kp, err := sign.Generate()
	if err != nil {
		t.Fatal(err)
	}
	oldKey := SigningPublicKey
	SigningPublicKey = kp.PublicKeyString()
	oldDist, oldCache := DistBase, CacheBase
	DistBase, CacheBase = realBase, cacheBase
	resetOCICache()
	t.Cleanup(func() {
		SigningPublicKey = oldKey
		DistBase, CacheBase = oldDist, oldCache
		resetOCICache()
	})

	body := makeGzTarball("payload")
	rc, err := NewOCIClient(realBase)
	if err != nil {
		t.Fatal(err)
	}
	cc, err := NewOCIClient(cacheBase)
	if err != nil {
		t.Fatal(err)
	}
	pushSignedArtifact(t, rc, "c.test", kp, body, true)
	pushSignedArtifact(t, cc, "c.test", kp, body, true)

	r := Resolved{Project: "c.test", Version: ParseVer("1.0.0")}
	read := func(what string) []byte {
		t.Helper()
		f, _, _, err := fetchArtifact(r, "linux", "x86-64")
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		defer f.Close()
		b, err := io.ReadAll(f)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	if !bytes.Equal(read("warm cache"), body) {
		t.Error("warm cache returned the wrong bytes")
	}

	// A cache that does not carry it must not fail the install — the registry does.
	CacheBase = cache.base("go-zpkg/empty")
	resetOCICache()
	if !bytes.Equal(read("cache miss"), body) {
		t.Error("a cache miss did not fall back to the registry")
	}

	// A cache serving DIFFERENT bytes is rejected, and the registry answers
	// instead. This is the property that makes the cache safe to add at all:
	// it is an optimisation, never an authority.
	other := newFakeRegistry(t, false)
	oc, err := NewOCIClient(other.base("go-zpkg/artifacts"))
	if err != nil {
		t.Fatal(err)
	}
	pushSignedArtifact(t, oc, "c.test", kp, makeGzTarball("tampered"), true)
	CacheBase = other.base("go-zpkg/artifacts")
	resetOCICache()
	if !bytes.Equal(read("tampered cache"), body) {
		t.Error("a cache serving different bytes was trusted")
	}
}

// TestFetchRuntimeEnvPlatformBlock: `runtime: env:` is not a flat table. A
// recipe may key part of it by platform, and rust-lang.org/cargo does — which
// made our pkgx answer
//
//	cannot read rust-lang.org/cargo's runtime env:
//	  rust-lang.org/cargo/package.yml: yaml: unmarshal errors:
//	  line 15: cannot unmarshal !!map into string
//
// and lose the WHOLE runtime env, not just the platform half. Every crates.io
// recipe then built without cargo's environment.
func TestFetchRuntimeEnvPlatformBlock(t *testing.T) {
	osn, arch := HostSlug()
	other := "darwin"
	if osn == "darwin" {
		other = "linux"
	}
	yml := "runtime:\n  env:\n" +
		"    FLAT: \"{{prefix}}/flat\"\n" +
		"    LIST:\n      - a\n      - \"{{prefix}}/b\"\n" +
		"    " + osn + ":\n      HERE: \"{{prefix}}/here\"\n" +
		"    " + osn + "/" + arch + ":\n      EXACT: \"1\"\n" +
		"    " + other + ":\n      ELSEWHERE: \"no\"\n" +
		"provides:\n  - bin/x\n"
	defer fakeServer(t, map[string]fakePkg{
		"plat.test": {versions: []string{"1.0.0"}, yaml: yml},
	})()

	env, err := FetchRuntimeEnv("plat.test", "/opt/plat", "1.0.0")
	if err != nil {
		t.Fatalf("a platform block must not fail the whole read: %v", err)
	}
	for k, want := range map[string]string{
		"FLAT":  "/opt/plat/flat",
		"LIST":  "a /opt/plat/b",
		"HERE":  "/opt/plat/here",
		"EXACT": "1",
	} {
		if env[k] != want {
			t.Errorf("%s = %q, want %q", k, env[k], want)
		}
	}
	if _, ok := env["ELSEWHERE"]; ok {
		t.Errorf("another platform's block leaked in: %v", env)
	}
}

// TestPickVersionForTriesEveryTagSpelling: our registry carries more than one
// spelling of the same version, and they do not hold the same platforms.
// gnu.org/tar has the linux artifacts under `1.35` and the darwin ones under
// `1.35.0`; selectVersions collapses both to ONE candidate, so the spelling
// that wins may be the one lacking this platform. Checking only it reported
//
//	no version of gnu.org/tar satisfies "*" AND is published for linux/x86-64
//	  (available: 1; satisfy but not published here: 1.35.0)
//
// while the artifacts sat under the other tag — which blocked every recipe
// depending on tar.
func TestPickVersionForTriesEveryTagSpelling(t *testing.T) {
	fr := newFakeRegistry(t, false)
	base := fr.base("go-zpkg/artifacts")
	old := DistBase
	DistBase = base
	resetOCICache()
	t.Cleanup(func() { DistBase = old; resetOCICache() })

	c, err := NewOCIClient(base)
	if err != nil {
		t.Fatal(err)
	}
	// The two spellings, each carrying a DIFFERENT platform.
	if _, err := c.PushWithReferrers("tar.test", "1.35", "linux", "x86-64", makeGzTarball("linux"), ".tar.gz", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := c.PushWithReferrers("tar.test", "1.35.0", "darwin", "aarch64", makeGzTarball("darwin"), ".tar.gz", nil); err != nil {
		t.Fatal(err)
	}

	v, err := PickVersionFor("tar.test", "*", "linux", "x86-64")
	if err != nil {
		t.Fatalf("linux/x86-64 is published under the other spelling: %v", err)
	}
	if v.tag() != "1.35" {
		t.Errorf("tag = %q, want the spelling that carries linux (1.35)", v.tag())
	}

	if v, err := PickVersionFor("tar.test", "*", "darwin", "aarch64"); err != nil || v.tag() != "1.35.0" {
		t.Errorf("darwin: tag %q err %v, want 1.35.0", v.tag(), err)
	}

	// A platform neither spelling carries is still a clean refusal.
	if _, err := PickVersionFor("tar.test", "*", "linux", "aarch64"); err == nil {
		t.Error("a platform no spelling carries must still fail")
	}
}

// TestFetchRuntimeEnvPlatformSupplements: inside a platform block a LIST
// supplements what the flat block set, while a scalar replaces it.
//
// That rule is libpkgx's, not a guess — platform_reduce says
//
//	// if user specifies an array then we assume we are supplementing
//	// otherwise we are replacing.
//
// and I had it replacing in both cases until I read the reference.
func TestFetchRuntimeEnvPlatformSupplements(t *testing.T) {
	osn, arch := HostSlug()
	yml := "runtime:\n  env:\n" +
		"    CFLAGS: \"-O2\"\n" +
		"    REPLACED: \"flat\"\n" +
		"    " + osn + ":\n" +
		"      CFLAGS:\n        - \"-fPIC\"\n" +
		"      REPLACED: \"platform\"\n" +
		"provides:\n  - bin/x\n"
	defer fakeServer(t, map[string]fakePkg{
		"supp.test": {versions: []string{"1.0.0"}, yaml: yml},
	})()

	env, err := FetchRuntimeEnv("supp.test", "/opt/s", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if env["CFLAGS"] != "-O2 -fPIC" {
		t.Errorf("a list must supplement: CFLAGS = %q, want %q", env["CFLAGS"], "-O2 -fPIC")
	}
	if env["REPLACED"] != "platform" {
		t.Errorf("a scalar must replace: REPLACED = %q, want %q", env["REPLACED"], "platform")
	}
	_ = arch
}

// makeGzTarballAt builds a REAL tar.gz holding one file at the given path —
// makeGzTarball only gzips a marker, which is enough for transport tests and not
// for one that unpacks.
func makeGzTarballAt(path, body string) []byte {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	_ = tw.WriteHeader(&tar.Header{Name: path, Mode: 0o755, Size: int64(len(body)), Typeflag: tar.TypeReg})
	_, _ = tw.Write([]byte(body))
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

// TestInstallForArtifactPublishedUnderAnotherSpelling: the directory INSIDE a
// artifact is named after the tag it was published under, which is not always how
// we spell the version. gnu.org/tar is `1.35` for linux and `1.35.0` for darwin,
// so the linux artifact unpacks to v1.35 while the resolved version reads 1.35.0
// and the install died with
//
//	rename /pkgx/.tmp-…/gnu.org/tar/v1.35.0 …: no such file or directory
//
// after PickVersionFor had correctly found the linux tag.
func TestInstallForArtifactPublishedUnderAnotherSpelling(t *testing.T) {
	fr := newFakeRegistry(t, false)
	base := fr.base("go-zpkg/artifacts")
	old := DistBase
	DistBase = base
	resetOCICache()
	t.Setenv("ZPKG_VERIFY", "0")
	t.Cleanup(func() { DistBase = old; resetOCICache() })

	c, err := NewOCIClient(base)
	if err != nil {
		t.Fatal(err)
	}
	// An artifact whose payload is spelled v1.35, published under tag 1.35.
	if _, err := c.PushWithReferrers("t.test", "1.35", "linux", "x86-64",
		makeGzTarballAt("t.test/v1.35/bin/t", "x"), ".tar.gz", nil); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	r := Resolved{Project: "t.test", Version: ParseVer("1.35.0")}
	r.Version.Tag = "1.35"
	if _, err := InstallFor(r, dir, "linux", "x86-64"); err != nil {
		t.Fatalf("install: %v", err)
	}
	// ⛔ INSTALLED UNDER THE RESOLVED VERSION, NOT THE ARCHIVE'S SPELLING.
	// gnu.org/tar is published as `1.35` for linux and `1.35.0` for darwin,
	// so the tarball's internal directory and the version a caller asked for
	// can disagree. The install used to keep the artifact's own spelling as
	// the real directory and link the canonical one to it — two paths, both
	// naming a version.
	//
	// There is one path now, and it is the resolved version with the build's
	// hash. The archive's internal spelling is not preserved, and for a
	// artifact whose own rpaths name it that would matter — but an artifact built
	// with a hashed prefix names the hashed prefix, and those are the only
	// ones installed from here on.
	p := StorePrefix(dir, "t.test", ParseVer("1.35.0"))
	if !strings.Contains(filepath.Base(p), "v1.35.0"+variantSep) {
		t.Fatalf("installed at %q, want the resolved version with a hash", p)
	}
	if st, err := os.Stat(filepath.Join(p, "bin", "t")); err != nil || st.IsDir() {
		t.Errorf("payload not installed: %v", err)
	}
	// And the archive's spelling is NOT left beside it as a second path.
	if _, err := os.Lstat(filepath.Join(dir, "t.test", "v1.35")); err == nil {
		t.Error("the archive's own spelling survives as a version-named path")
	}
}

// TestFetchRuntimeEnvDropsUnresolvable: a value whose placeholder we cannot
// resolve is DROPPED, not truncated.
//
// rust-lang.org/cargo declares
//
//	CARGO_INSTALL_ROOT: ${{home}}/.local
//	CARGO_HTTP_CAINFO: ${{deps.curl.se/ca-certs.prefix}}/ssl/cert.pem
//
// and deleting the unknown placeholder exported `CARGO_INSTALL_ROOT=/.local`
// and `CARGO_HTTP_CAINFO=/ssl/cert.pem` — two absolute paths that exist nowhere,
// one of them the TLS trust store, with no error raised anywhere.
//
// libpkgx's useMoustaches only substitutes tokens it has, so an unknown one
// survives verbatim. Absent is a condition a caller can notice; wrong is not.
func TestFetchRuntimeEnvDropsUnresolvable(t *testing.T) {
	yml := "runtime:\n  env:\n" +
		"    GOOD: \"{{prefix}}/lib\"\n" +
		"    HOMEISH: \"${{home}}/.local\"\n" +
		"    DEPPY: \"${{deps.curl.se/ca-certs.prefix}}/ssl/cert.pem\"\n" +
		"    LISTY:\n      - \"{{prefix}}/a\"\n      - \"${{home}}/b\"\n" +
		"provides:\n  - bin/x\n"
	defer fakeServer(t, map[string]fakePkg{
		"drop.test": {versions: []string{"1.0.0"}, yaml: yml},
	})()

	env, err := FetchRuntimeEnv("drop.test", "/opt/d", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if env["GOOD"] != "/opt/d/lib" {
		t.Errorf("GOOD = %q", env["GOOD"])
	}
	for _, k := range []string{"HOMEISH", "DEPPY", "LISTY"} {
		if v, ok := env[k]; ok {
			t.Errorf("%s should have been dropped, got %q", k, v)
		}
	}
}

// TestFetchRuntimeEnvInResolvesDepTokens: `deps.<project>.prefix` and the dep
// version tokens, which libpkgx's useMoustaches has and we did not.
//
// rust-lang.org/cargo declares
//
//	CARGO_HTTP_CAINFO: ${{deps.curl.se/ca-certs.prefix}}/ssl/cert.pem
//
// and without the token cargo built with no CA bundle:
//
//	[77] Problem with the SSL CA cert … error setting certificate file: /ssl/cert.pem
//
// A project name carries dots and slashes, so the token is matched literally —
// `curl.se/ca-certs` must not be read as a pattern.
func TestFetchRuntimeEnvInResolvesDepTokens(t *testing.T) {
	yml := "runtime:\n  env:\n" +
		"    CAINFO: \"${{deps.curl.se/ca-certs.prefix}}/ssl/cert.pem\"\n" +
		"    DEPVER: \"{{deps.curl.se/ca-certs.version.marketing}}\"\n" +
		"    OWN: \"{{prefix}}/bin\"\n" +
		"provides:\n  - bin/x\n"
	defer fakeServer(t, map[string]fakePkg{
		"dep.test": {versions: []string{"2.0.0"}, yaml: yml},
	})()

	closure := []Resolved{
		{Project: "dep.test", Version: ParseVer("2.0.0")},
		{Project: "curl.se/ca-certs", Version: ParseVer("2026.8.13")},
	}
	env, err := FetchRuntimeEnvIn("dep.test", closure, "/pkgx")
	if err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]string{
		"CAINFO": "/pkgx/curl.se/ca-certs/v2026.8.13/ssl/cert.pem",
		"DEPVER": "2026.8",
		"OWN":    "/pkgx/dep.test/v2.0.0/bin",
	} {
		if env[k] != want {
			t.Errorf("%s = %q, want %q", k, env[k], want)
		}
	}

	// Without the closure the value is still DROPPED rather than truncated.
	env2, err := FetchRuntimeEnv("dep.test", "/pkgx/dep.test/v2.0.0", "2.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := env2["CAINFO"]; ok {
		t.Errorf("without deps CAINFO should be dropped, got %q", v)
	}
}

// TestFakeServerNeutralisesAmbientOverlay: PantryOverlay is a package-level
// variable pointing at the live overlay by default, and fetchRecipe asks it
// FIRST. A fixture served by fakeServer must win over whatever the ambient
// overlay holds, or a test measures another repository's content instead of
// its own — which is how TestFetchRuntimeEnv came to read the real
// gnu.org/help2man recipe and lose the key it had invented.
func TestFakeServerNeutralisesAmbientOverlay(t *testing.T) {
	ambient := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "runtime:\n  env:\n    FROM: \"the ambient overlay\"\n")
	}))
	defer ambient.Close()

	saved := PantryOverlay
	PantryOverlay = ambient.URL
	defer func() { PantryOverlay = saved }()

	done := fakeServer(t, map[string]fakePkg{
		"acme.org/tool": {
			versions: []string{"1.0.0"},
			yaml:     "runtime:\n  env:\n    FROM: \"the fixture\"\n",
		},
	})
	env, err := FetchRuntimeEnv("acme.org/tool", "/p", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if env["FROM"] != "the fixture" {
		t.Errorf("FROM = %q, want the fixture: the ambient overlay answered", env["FROM"])
	}
	done()
	if PantryOverlay != ambient.URL {
		t.Errorf("PantryOverlay = %q after close, want it restored to %q", PantryOverlay, ambient.URL)
	}
}

// A compound constraint was not refused, it was silently read as a different
// one: ParseVer swallows the second comparator and concatenates what follows.
//
//	ParseVer("3<3.12")    = [3 12]     -> ">=3<3.12"    read as ">=3.12"
//	ParseVer("1.75<1.78") = [1 75 78]  -> ">=1.75<1.78" read as ">=1.75.78"
//
// So a recipe pinning `python.org: '>=3<3.12'` — because it does not work on
// 3.12 and later — was refused 3.11.16, the version it wants, and offered
// 3.14.7, the one it excludes. That is worse than a refusal: it selects a
// version the recipe rules out, and says nothing.
func TestSatisfiesCompoundConstraints(t *testing.T) {
	for _, c := range []struct {
		constraint, version string
		want                bool
	}{
		// conjunction, written without a space, as the pantry writes it
		{">=3<3.12", "3.11.16", true},
		{">=3<3.12", "3.14.7", false}, // above the ceiling the recipe set
		{">=3<3.12", "2.7.18", false}, // below the floor
		{">=3<3.12", "3.12.0", false}, // the ceiling is exclusive
		{">=1.75<1.78", "1.76.0", true},
		{">=1.75<1.78", "1.99.0", false},
		{">=1.75<1.78", "1.70.0", false},
		// the spaced spelling means the same thing
		{">=3 <3.12", "3.11.16", true},
		{">=3 <3.12", "3.14.7", false},
		// alternatives: any one is enough
		{"^16 || ^18 || ^20", "20.11.0", true},
		{"^16 || ^18 || ^20", "18.2.0", true},
		{"^16 || ^18 || ^20", "16.0.0", true},
		{"^16 || ^18 || ^20", "22.0.0", false},
		{"^16 || ^18 || ^20", "14.0.0", false},
		// a single comparator is unchanged
		{">=3", "3.14.7", true},
		{"<3.15", "3.14.7", true},
		{"^3", "3.14.7", true},
		{"~3.12", "3.12.14", true},
		{"~3.12", "3.13.0", false},
		{"*", "9.9.9", true},
		{"", "9.9.9", true},
	} {
		if got := ParseVer(c.version).Satisfies(c.constraint); got != c.want {
			t.Errorf("ParseVer(%q).Satisfies(%q) = %v, want %v", c.version, c.constraint, got, c.want)
		}
	}
}

// splitComparators must leave a single-comparator constraint whole, and must
// not treat the "=" of ">=" as the start of a new part.
func TestSplitComparators(t *testing.T) {
	for _, c := range []struct {
		in   string
		want []string
	}{
		{">=3<3.12", []string{">=3", "<3.12"}},
		{">=3 <3.12", []string{">=3", "<3.12"}},
		{">=1.75<1.78", []string{">=1.75", "<1.78"}},
		{">=3", []string{">=3"}},
		{"^3", []string{"^3"}},
		{"3.12", []string{"3.12"}},
		{">1<2<3", []string{">1", "<2", "<3"}},
	} {
		got := splitComparators(c.in)
		if len(got) != len(c.want) {
			t.Errorf("splitComparators(%q) = %v, want %v", c.in, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("splitComparators(%q) = %v, want %v", c.in, got, c.want)
				break
			}
		}
	}
}

// TestRepoAbsentClassifiesByStatus: "does this registry carry the project?" is
// answered by the registry's STATUS, not by the words in its message. Reading
// prose meant any transient failure whose body happened to contain "not found"
// was taken for "we do not carry this package", and resolution fell back to the
// UPSTREAM dist — silently off our own registry, for as long as the upset
// lasted, with a different answer at the end of it.
func TestRepoAbsentClassifiesByStatus(t *testing.T) {
	resp := func(code int, msg string) error {
		return &errcode.ErrorResponse{
			StatusCode: code,
			Errors:     errcode.Errors{errcode.Error{Code: "UNKNOWN", Message: msg}},
		}
	}
	for _, tc := range []struct {
		name  string
		err   error
		creds map[string]string
		want  bool
	}{
		{name: "404 is an absent repository", err: resp(404, "name unknown"), want: true},
		{name: "403 read anonymously is ghcr's absent repository", err: resp(403, "denied"), want: true},
		{name: "403 with credentials is an access problem",
			err: resp(403, "denied"), creds: map[string]string{"OCI_TOKEN": "t"}, want: false},
		// the one the prose match got wrong
		{name: "500 whose message says not found is not absent",
			err: resp(500, "repository not found in cache"), want: false},
		{name: "502 is not absent", err: resp(502, "bad gateway"), want: false},
		{name: "a plain error still reads as prose", err: errors.New("name unknown"), want: true},
		{name: "a plain transport error is not absent", err: errors.New("connection reset by peer"), want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withGlibcEnv(t, tc.creds)
			if got := repoAbsent(tc.err); got != tc.want {
				t.Errorf("repoAbsent(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// The BSD lanes run this suite on a real FreeBSD, OpenBSD and NetBSD, and
// TestHostSlug is what they exercise first. Simulate each here so the darwin
// and linux lanes fail too when the contract breaks — a rule enforced only on
// the lane that happens to run there is a rule nobody sees break until that
// lane is red for another reason.
func TestHostSlugHoldsOnEveryLaneWeRunOn(t *testing.T) {
	old := goos
	defer func() { goos = old }()
	for _, g := range []string{"linux", "darwin", "windows", "js", "wasip1",
		"freebsd", "openbsd", "netbsd", "dragonfly", "android"} {
		goos = func() string { return osSlug(g) }
		osn, _ := HostSlug()
		if !isPlatformKey(osn) {
			t.Errorf("on %s the os slug is %q, which no recipe can scope a block to", g, osn)
		}
	}
}

// TestUpstreamFallback404SaysWhatItMeans.
//
// The raw error is a URL and reads like a network fault:
//
//	GET https://dist.pkgx.dev/llvm.org/linux/s390x/versions.txt: Not Found
//
// It is not one. Two registries were consulted and neither carries the project
// for that platform — on a new architecture the normal state of the world, not
// a failure to reach anything. It cost a build run to read correctly.
func TestUpstreamFallback404SaysWhatItMeans(t *testing.T) {
	notFound := &httpStatusError{url: "https://dist.pkgx.dev/llvm.org/linux/s390x/versions.txt", status: 404}
	got := bothPlacesLooked(notFound, "llvm.org", "linux", "s390x")
	for _, want := range []string{"llvm.org", "linux/s390x", DistBase, UpstreamDist} {
		if !strings.Contains(got.Error(), want) {
			t.Errorf("message must name %q: %v", want, got)
		}
	}
	// The original survives underneath, so nothing that inspected it stops
	// working.
	if !errors.Is(got, error(notFound)) {
		t.Errorf("the original error must be wrapped: %v", got)
	}

	// A timeout or a 500 IS about reaching the server. Rewriting those would
	// move the lie rather than remove it.
	for _, e := range []error{
		&httpStatusError{url: "u", status: 500},
		errors.New("dial tcp: i/o timeout"),
	} {
		if got := bothPlacesLooked(e, "llvm.org", "linux", "s390x"); got.Error() != e.Error() {
			t.Errorf("a transport failure must pass through unchanged: %v", got)
		}
	}
	if bothPlacesLooked(nil, "p", "linux", "x86-64") != nil {
		t.Error("nil must stay nil")
	}
}

// And the type behind it: the message is unchanged from the fmt.Errorf it
// replaced, so anything reading the text is unaffected, while the status is
// now available without reading the text.
func TestHTTPStatusErrorKeepsItsWording(t *testing.T) {
	e := &httpStatusError{url: "https://x/y", status: 404}
	if e.Error() != "GET https://x/y: Not Found" {
		t.Errorf("wording changed: %q", e.Error())
	}
	if !isNotFound(e) {
		t.Error("isNotFound must see a 404")
	}
	if isNotFound(&httpStatusError{url: "u", status: 503}) || isNotFound(errors.New("boom")) {
		t.Error("isNotFound must not claim anything else")
	}
}

// A dependency declared BOTH at the top level and in a platform block used to
// be decided by Go's map iteration order. qt.io asks for unicode.org ^71 at
// the top and ~71 under linux:, and the client answered ~71 four times in five
// — a different closure, from the same recipe, on the same machine.
//
// The more specific declaration wins, and the two that both match a linux
// host, `linux:` and `linux/x86-64:`, are applied in that order. Run enough
// times that a coin toss would show: a single call cannot tell a fixed choice
// from a lucky one.
func TestReduceDepsPlatformBlockWinsDeterministically(t *testing.T) {
	m := map[string]any{
		"unicode.org": "^71",
		"zlib.net":    "^1",
		"linux": map[string]any{
			"unicode.org": "~71",
			"only.linux":  "*",
		},
		"linux/x86-64": map[string]any{"unicode.org": "=71.1"},
		"darwin":       map[string]any{"unicode.org": "^99", "only.darwin": "*"},
	}
	for i := 0; i < 200; i++ {
		got := reduceDeps(m, "linux", "x86-64")
		if got["unicode.org"] != "=71.1" {
			t.Fatalf("run %d: unicode.org = %q, want the arch block's =71.1", i, got["unicode.org"])
		}
		if got["zlib.net"] != "^1" || got["only.linux"] != "*" {
			t.Fatalf("run %d: %v", i, got)
		}
		if _, leaked := got["only.darwin"]; leaked {
			t.Fatalf("run %d: a darwin-only dependency reached a linux closure", i)
		}
	}
	// Without the arch block, the os block still beats the top level.
	delete(m, "linux/x86-64")
	for i := 0; i < 200; i++ {
		if got := reduceDeps(m, "linux", "x86-64"); got["unicode.org"] != "~71" {
			t.Fatalf("run %d: unicode.org = %q, want the linux block's ~71", i, got["unicode.org"])
		}
	}
	// A platform block that is not a mapping is skipped, not merged.
	if got := reduceDeps(map[string]any{"linux": "nonsense", "a": "1"}, "linux", "x86-64"); len(got) != 1 || got["a"] != "1" {
		t.Errorf("a malformed platform block must be skipped: %v", got)
	}
}

// Two branches of versionsForSourced fall back to the upstream dist, and only
// the second one said what its 404 meant. The FIRST is the one a new
// architecture hits: on a seed registry nothing is published, so a project is
// not a repository at all and the walk arrives there, never at the other. So
// the message written for a new architecture was missing from the case a new
// architecture actually produces —
//
//	resolve deps: GET https://dist.pkgx.dev/llvm.org/linux/s390x/versions.txt: Not Found
//
// which is the exact string bothPlacesLooked exists to stop anyone reading as
// a network fault. Tested here on versionsForSourced rather than on the helper:
// the helper was already tested, and the helper was never the defect.
func TestVersionsForSourcedExplainsBothFallbacks(t *testing.T) {
	// An OCI registry that knows nothing: the tag listing 404s NAME_UNKNOWN,
	// which is repoAbsent — the first branch.
	reg := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"errors":[{"code":"NAME_UNKNOWN"}]}`))
	}))
	defer reg.Close()
	// An upstream dist with no s390x, which is upstream's actual state.
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer up.Close()

	withDist(t, "oci://"+strings.TrimPrefix(reg.URL, "http://")+"/go-zpkg/packages")
	oldUp := UpstreamDist
	UpstreamDist = up.URL
	t.Cleanup(func() { UpstreamDist = oldUp })

	_, _, err := versionsForSourced("llvm.org", "linux", "s390x")
	if err == nil {
		t.Fatal("a project neither registry carries must be an error")
	}
	if !strings.Contains(err.Error(), "neither") {
		t.Errorf("the error must say both places were looked, got: %v", err)
	}
}

// The overlay MERGES over upstream rather than replacing it, so an entry can
// say only the lines it changes instead of forking the whole recipe.
func TestRecipeDocMergesTheOverlayOverThePantry(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/acme.org/package.yml") {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, "dependencies:\n  openssl.org: ^1.1\n  zlib.net: ^1\nprovides:\n  - bin/acme\nbuild:\n  script: make\n")
	}))
	defer up.Close()
	ov := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/acme.org/package.hcl") {
			http.NotFound(w, r)
			return
		}
		// Only what it changes.
		_, _ = io.WriteString(w, "dependencies = { \"openssl.org\" = \"^3\" }\n")
	}))
	defer ov.Close()

	oldBase, oldOver := PantryBase, PantryOverlay
	t.Cleanup(func() { PantryBase, PantryOverlay = oldBase, oldOver })
	PantryBase, PantryOverlay = up.URL, ov.URL

	doc, err := recipeDoc("acme.org")
	if err != nil {
		t.Fatal(err)
	}
	deps, _ := doc["dependencies"].(map[string]any)
	// The overlay's key wins…
	if deps["openssl.org"] != "^3" {
		t.Errorf("openssl = %v", deps["openssl.org"])
	}
	// …and the one it does not mention is INHERITED rather than lost. That is
	// the whole difference between an overlay and a fork.
	if deps["zlib.net"] != "^1" {
		t.Errorf("zlib was dropped: %v", deps)
	}
	if _, ok := doc["build"]; !ok {
		t.Error("a sibling block the overlay does not mention was dropped")
	}
}

// Only one side has it, and neither does.
func TestRecipeDocWithOneSideOrNeither(t *testing.T) {
	only := func(which string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !strings.Contains(r.URL.Path, which) || !strings.HasSuffix(r.URL.Path, "package.yml") {
				http.NotFound(w, r)
				return
			}
			_, _ = io.WriteString(w, "provides:\n  - bin/"+which+"\n")
		}))
	}
	up, ov := only("fromup"), only("fromov")
	defer up.Close()
	defer ov.Close()
	oldBase, oldOver := PantryBase, PantryOverlay
	t.Cleanup(func() { PantryBase, PantryOverlay = oldBase, oldOver })
	PantryBase, PantryOverlay = up.URL, ov.URL

	// Upstream alone.
	if d, err := recipeDoc("fromup"); err != nil || fmt.Sprint(d["provides"]) != "[bin/fromup]" {
		t.Errorf("%v %v", d, err)
	}
	// Ours alone — upstream carries no such project, so the overlay is the
	// whole recipe.
	if d, err := recipeDoc("fromov"); err != nil || fmt.Sprint(d["provides"]) != "[bin/fromov]" {
		t.Errorf("%v %v", d, err)
	}
	// Neither.
	if _, err := recipeDoc("nowhere"); err == nil {
		t.Error("a project in neither pantry must be an error")
	}
}

// A 404 means "this pantry does not carry it". ANYTHING ELSE means we do not
// know, and reading it as "not carried" is how an override stops applying in
// silence: resolution would fall through and hand back the recipe the overlay
// exists to correct, with nothing to show for it.
func TestRecipeDocDoesNotReadAFailureAsAbsence(t *testing.T) {
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "package.yml") {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, "provides:\n  - bin/acme\n")
	}))
	defer good.Close()
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer broken.Close()

	oldBase, oldOver, oldSleep := PantryBase, PantryOverlay, sleep
	t.Cleanup(func() { PantryBase, PantryOverlay, sleep = oldBase, oldOver, oldSleep })
	sleep = func(time.Duration) {}

	// The OVERLAY is unreachable: do not quietly resolve upstream's recipe.
	PantryBase, PantryOverlay = good.URL, broken.URL
	if _, err := recipeDoc("acme.org"); err == nil {
		t.Error("an unreachable overlay must fail, not fall through to upstream")
	}
	// Upstream is unreachable: do not quietly resolve a delta on its own,
	// which would be an incomplete recipe.
	PantryBase, PantryOverlay = broken.URL, good.URL
	if _, err := recipeDoc("acme.org"); err == nil {
		t.Error("an unreachable pantry must fail, not hand back the overlay alone")
	}
}

// A recipe that does not parse is reported, on either side.
func TestFetchSideOnSomethingUnreadable(t *testing.T) {
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "package.hcl") {
			_, _ = io.WriteString(w, "distributable {")
			return
		}
		http.NotFound(w, r)
	}))
	defer bad.Close()
	if _, ok, err := fetchSide(bad.URL, "acme.org"); err == nil || ok {
		t.Errorf("ok=%v err=%v", ok, err)
	}
	badYAML := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "package.yml") {
			_, _ = io.WriteString(w, "a: [\n")
			return
		}
		http.NotFound(w, r)
	}))
	defer badYAML.Close()
	if _, ok, err := fetchSide(badYAML.URL, "acme.org"); err == nil || ok {
		t.Errorf("ok=%v err=%v", ok, err)
	}
	// No base configured is not an error, it is "nothing here".
	if _, ok, err := fetchSide("", "acme.org"); err != nil || ok {
		t.Errorf("ok=%v err=%v", ok, err)
	}
}

// mergeRecipe: a nested block merges, a list REPLACES, and a scalar under a
// block does not become a mapping.
func TestMergeRecipe(t *testing.T) {
	base := map[string]any{
		"build": map[string]any{"script": []any{"make", "make install"}, "env": map[string]any{"A": "1"}},
		"keep":  "me",
	}
	over := map[string]any{
		"build": map[string]any{"script": []any{"gmake"}, "env": map[string]any{"B": "2"}},
	}
	got := mergeRecipe(base, over)
	b := got["build"].(map[string]any)
	if fmt.Sprint(b["script"]) != "[gmake]" {
		t.Errorf("a list must be replaced, got %v", b["script"])
	}
	env := b["env"].(map[string]any)
	if env["A"] != "1" || env["B"] != "2" {
		t.Errorf("a nested block must merge, got %v", env)
	}
	if got["keep"] != "me" {
		t.Error("a key the overlay does not mention must be inherited")
	}
	// A mapping over a scalar replaces it rather than merging into nothing.
	got2 := mergeRecipe(map[string]any{"a": "scalar"}, map[string]any{"a": map[string]any{"b": 1}})
	if _, ok := got2["a"].(map[string]any); !ok {
		t.Errorf("got %v", got2)
	}
}
