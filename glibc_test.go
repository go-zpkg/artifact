package artifact

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// withGlibcEnv points Env at a fixed map (no ~/.zpkg/config.hcl2, no real
// process environment) and clears the memoised glibc constraint.
func withGlibcEnv(t *testing.T, m map[string]string) {
	t.Helper()
	oldLookup, oldPath := lookupEnv, configPathFn
	lookupEnv = func(k string) (string, bool) { v, ok := m[k]; return v, ok }
	configPathFn = func() (string, error) { return filepath.Join(t.TempDir(), "absent.hcl2"), nil }
	reloadConfig()
	resetGlibcConstraint()
	t.Cleanup(func() {
		lookupEnv, configPathFn = oldLookup, oldPath
		reloadConfig()
		resetGlibcConstraint()
	})
}

// withKernel makes the host look like linux running the given kernel release.
func withKernel(t *testing.T, release string) {
	t.Helper()
	setGoos(t, "linux")
	setGoarch(t, "x86-64")
	p := filepath.Join(t.TempDir(), "osrelease")
	if err := os.WriteFile(p, []byte(release+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := osReleasePath
	osReleasePath = p
	t.Cleanup(func() { osReleasePath = old })
}

// withGlibcVersions serves a static pkgx dist listing those glibc versions.
func withGlibcVersions(t *testing.T, versions ...string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/versions.txt") {
			fmt.Fprintln(w, strings.Join(versions, "\n"))
			return
		}
		w.WriteHeader(404)
	}))
	t.Cleanup(srv.Close)
	withDist(t, srv.URL)
}

// withMinKernels stubs the registry annotation lookup: version → floor
// ("" = the artifact records no floor).
func withMinKernels(t *testing.T, floors map[string]string) {
	t.Helper()
	old := glibcMinKernelOf
	glibcMinKernelOf = func(ver, _, _ string) (string, error) {
		mk, ok := floors[ver]
		if !ok {
			return "", errors.New("no such glibc")
		}
		return mk, nil
	}
	t.Cleanup(func() { glibcMinKernelOf = old })
}

func TestSplitFlavor(t *testing.T) {
	for _, tc := range []struct{ tag, version, glibc string }{
		{"8.20.0", "8.20.0", ""},
		{"8.20.0-glibc2.27.0", "8.20.0", "2.27.0"},
		{"1.2.3-rc1-glibc2.44.0", "1.2.3-rc1", "2.44.0"},
		{"-glibc2.27.0", "-glibc2.27.0", ""}, // no version part: not a flavor
		{"", "", ""},
	} {
		v, g := SplitFlavor(tc.tag)
		if v != tc.version || g != tc.glibc {
			t.Errorf("SplitFlavor(%q) = %q, %q; want %q, %q", tc.tag, v, g, tc.version, tc.glibc)
		}
	}
}

func TestHostKernel(t *testing.T) {
	t.Run("linux", func(t *testing.T) {
		withKernel(t, "6.8.0-45-generic")
		got, err := HostKernel()
		if err != nil || got != "6.8.0-45-generic" {
			t.Fatalf("HostKernel = %q, %v", got, err)
		}
	})
	t.Run("not linux", func(t *testing.T) {
		setGoos(t, "darwin")
		got, err := HostKernel()
		if err != nil || got != "" {
			t.Fatalf("HostKernel = %q, %v", got, err)
		}
	})
	t.Run("unreadable", func(t *testing.T) {
		setGoos(t, "linux")
		old := osReleasePath
		osReleasePath = filepath.Join(t.TempDir(), "absent")
		t.Cleanup(func() { osReleasePath = old })
		if _, err := HostKernel(); err == nil {
			t.Fatal("want an error")
		}
	})
}

// TestGlibcConstraintPin: ZPKG_GLIBC pins an exact glibc (with or without the
// leading '='), and the answer is memoised.
func TestGlibcConstraintPin(t *testing.T) {
	for _, pin := range []string{"2.27.0", "=2.27.0", " 2.27.0 "} {
		withGlibcEnv(t, map[string]string{"ZPKG_GLIBC": pin})
		if got := GlibcConstraint(); got != "=2.27.0" {
			t.Fatalf("ZPKG_GLIBC=%q → %q", pin, got)
		}
	}
	// memoised: a later change to the environment does not re-resolve
	withGlibcEnv(t, map[string]string{"ZPKG_GLIBC": "2.27.0"})
	_ = GlibcConstraint()
	lookupEnv = func(string) (string, bool) { return "2.44.0", true }
	if got := GlibcConstraint(); got != "=2.27.0" {
		t.Fatalf("constraint re-resolved: %q", got)
	}
}

// TestGlibcConstraintFallsBackToNewest: with no pin and nothing to compare
// against, resolution is left exactly as it was ("*").
func TestGlibcConstraintFallsBackToNewest(t *testing.T) {
	t.Run("not linux", func(t *testing.T) {
		withGlibcEnv(t, nil)
		setGoos(t, "darwin")
		if got := GlibcConstraint(); got != "*" {
			t.Fatalf("constraint = %q", got)
		}
	})
	t.Run("kernel unreadable", func(t *testing.T) {
		withGlibcEnv(t, nil)
		setGoos(t, "linux")
		old := osReleasePath
		osReleasePath = filepath.Join(t.TempDir(), "absent")
		t.Cleanup(func() { osReleasePath = old })
		if got := GlibcConstraint(); got != "*" {
			t.Fatalf("constraint = %q", got)
		}
	})
}

// TestGlibcSelectionByKernel is the headline behaviour: the newest glibc the
// running kernel can actually run is chosen, and ONLY when the newest one
// cannot run here.
func TestGlibcSelectionByKernel(t *testing.T) {
	for _, tc := range []struct {
		name     string
		kernel   string
		versions []string
		floors   map[string]string
		want     string
	}{
		{
			name:     "newest fits — nothing to change",
			kernel:   "6.8.0-45-generic",
			versions: []string{"2.27.0", "2.44.0"},
			floors:   map[string]string{"2.27.0": "3.2.0", "2.44.0": "3.2.0"},
			want:     "*",
		},
		{
			name:     "old kernel: the newest glibc's floor is too high",
			kernel:   "3.10.0-1160.el7.x86_64",
			versions: []string{"2.27.0", "2.38.0", "2.44.0"},
			floors:   map[string]string{"2.27.0": "3.2.0", "2.38.0": "3.2.0", "2.44.0": "4.19.0"},
			want:     "=2.38.0",
		},
		{
			name:     "nothing published fits — leave it alone",
			kernel:   "2.6.32-696.el6.x86_64",
			versions: []string{"2.38.0", "2.44.0"},
			floors:   map[string]string{"2.38.0": "3.2.0", "2.44.0": "4.19.0"},
			want:     "*",
		},
		{
			name:     "newest records no floor — cannot vouch, so do not downgrade",
			kernel:   "3.10.0-1160.el7.x86_64",
			versions: []string{"2.27.0", "2.44.0"},
			floors:   map[string]string{"2.27.0": "3.2.0", "2.44.0": ""},
			want:     "*",
		},
		{
			name:     "an intermediate with no floor is skipped, not guessed at",
			kernel:   "3.10.0-1160.el7.x86_64",
			versions: []string{"2.27.0", "2.38.0", "2.44.0"},
			floors:   map[string]string{"2.27.0": "3.2.0", "2.38.0": "", "2.44.0": "4.19.0"},
			want:     "=2.27.0",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withGlibcEnv(t, nil)
			withKernel(t, tc.kernel)
			withGlibcVersions(t, tc.versions...)
			withMinKernels(t, tc.floors)
			if got := GlibcConstraint(); got != tc.want {
				t.Fatalf("constraint = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestGlibcSelectionVersionListingFails: an unreachable dist must not break
// closure resolution — it falls back to "*".
func TestGlibcSelectionVersionListingFails(t *testing.T) {
	withGlibcEnv(t, nil)
	withKernel(t, "3.10.0-1160.el7.x86_64")
	withDist(t, "https://127.0.0.1:1/dist")
	if got := GlibcConstraint(); got != "*" {
		t.Fatalf("constraint = %q", got)
	}
}

// TestImplicitRootsUsesGlibcConstraint proves the selector actually reaches
// closure completion (where every dynamic ELF gets its loader + libc).
func TestImplicitRootsUsesGlibcConstraint(t *testing.T) {
	withGlibcEnv(t, map[string]string{"ZPKG_GLIBC": "2.27.0"})
	if got := implicitRoots(nil)[GlibcProject]; got != "=2.27.0" {
		t.Fatalf("glibc root = %q", got)
	}
}

// TestGlibcMinKernelOf covers the real annotation reader against a registry.
func TestGlibcMinKernelOf(t *testing.T) {
	t.Run("static dist has no annotations", func(t *testing.T) {
		withDist(t, "https://dist.example.test")
		mk, err := glibcMinKernelOf("2.44.0", "linux", "x86-64")
		if err != nil || mk != "" {
			t.Fatalf("mk = %q, err = %v", mk, err)
		}
	})
	t.Run("unusable registry", func(t *testing.T) {
		withDist(t, "oci://hostonly")
		if _, err := glibcMinKernelOf("2.44.0", "linux", "x86-64"); err == nil {
			t.Fatal("want an error")
		}
	})
	t.Run("published glibc", func(t *testing.T) {
		fr := newFakeRegistry(t, false)
		defer fr.close()
		withDist(t, fr.base("go-zpkg/artifacts"))
		c, err := NewOCIClient(DistBase)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.PushWithReferrersAnnotated(GlibcProject, "2.44.0", "linux", "x86-64",
			makeGzTarball("libc"), ExtTarGz, nil,
			map[string]string{GlibcMinKernelAnnotation: "3.2.0"}); err != nil {
			t.Fatal(err)
		}
		mk, err := glibcMinKernelOf("2.44.0", "linux", "x86-64")
		if err != nil || mk != "3.2.0" {
			t.Fatalf("mk = %q, err = %v", mk, err)
		}
		// an unpublished version is a real lookup failure, not a silent ""
		if _, err := glibcMinKernelOf("9.9.9", "linux", "x86-64"); err == nil {
			t.Fatal("want an error for an unpublished glibc")
		}
	})
}

// TestOCIClientAnnotations covers the accessor's error paths.
func TestOCIClientAnnotations(t *testing.T) {
	fr := newFakeRegistry(t, false)
	defer fr.close()
	c, err := NewOCIClient(fr.base("go-zpkg/artifacts"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Annotations("BAD..name/../x", "1.0.0", "linux", "x86-64"); err == nil {
		t.Error("want an error for a bad project")
	}
	if _, err := c.Annotations("absent.test", "1.0.0", "linux", "x86-64"); err == nil {
		t.Error("want an error for an unpublished version")
	}
}

// TestOCIVersionsSkipFlavoredTags: a glibc-flavored tag must never be picked as
// a version of its own — it would otherwise outrank the tag it flavors.
func TestOCIVersionsSkipFlavoredTags(t *testing.T) {
	fr := newFakeRegistry(t, false)
	defer fr.close()
	withDist(t, fr.base("go-zpkg/artifacts"))
	c, err := NewOCIClient(DistBase)
	if err != nil {
		t.Fatal(err)
	}
	repo := c.repoName("curl.se")
	for _, tag := range []string{"8.19.0", "8.20.0", "8.20.0-glibc2.27.0"} {
		fr.injectManifest(repo, tag, ocispec.MediaTypeImageManifest, []byte("{}"))
	}
	vs, err := VersionsFor("curl.se", "linux", "x86-64")
	if err != nil {
		t.Fatal(err)
	}
	var raw []string
	for _, v := range vs {
		raw = append(raw, v.Raw)
	}
	if strings.Join(raw, ",") != "8.19.0,8.20.0" {
		t.Fatalf("versions = %v", raw)
	}
	picked, err := PickVersion("curl.se", "*")
	if err != nil || picked.Raw != "8.20.0" {
		t.Fatalf("PickVersion = %q, %v", picked.Raw, err)
	}
}

// TestOCIVersionsSkipReferrerTags: ghcr has no referrers API, so ORAS parks each
// artifact's attestations under a `sha256-<digest>` TAG. Those must never be read
// as versions — they inflated every listing with phantom "0" entries and, by
// making the listing look non-empty, defeated the upstream fallback for a
// project we had published only some versions of (measured live: gnu.org/gcc/
// libstdcxx listed 14 "versions", 13 of them referrer tags).
func TestOCIVersionsSkipReferrerTags(t *testing.T) {
	fr := newFakeRegistry(t, false)
	defer fr.close()
	withDist(t, fr.base("go-zpkg/artifacts"))
	c, err := NewOCIClient(DistBase)
	if err != nil {
		t.Fatal(err)
	}
	repo := c.repoName("gnu.org/gcc/libstdcxx")
	for _, tag := range []string{
		"16.2.0", "v15.1.0",
		"sha256-5e3e8dd10513699116134fe1455e53db8d7d6b575a25d539bac524fc920c12b9",
		"latest",
	} {
		fr.injectManifest(repo, tag, ocispec.MediaTypeImageManifest, []byte("{}"))
	}
	vs, err := VersionsFor("gnu.org/gcc/libstdcxx", "linux", "x86-64")
	if err != nil {
		t.Fatal(err)
	}
	var raw []string
	for _, v := range vs {
		raw = append(raw, v.Raw)
	}
	if strings.Join(raw, ",") != "15.1.0,16.2.0" {
		t.Fatalf("versions = %v", raw)
	}
}

func TestIsVersionTag(t *testing.T) {
	for tag, want := range map[string]bool{
		"1.2.3":         true,
		"v5.8.3":        true,
		"V2":            true,
		"16.2.0":        true,
		"sha256-abc123": false,
		"latest":        false,
		"main":          false,
		"":              false,
		"v":             false,
	} {
		if got := isVersionTag(tag); got != want {
			t.Errorf("isVersionTag(%q) = %v, want %v", tag, got, want)
		}
	}
}

// TestVersionsForGhcrAnonymous403 covers the way ghcr reports a repository that
// does not exist: an ANONYMOUS token request for it is DENIED with 403, never
// 404. Read without credentials that means "we do not carry this package", so
// version listing must fall back to the upstream dist — as it already does for
// an empty listing. With credentials configured, a 403 is a real access problem
// and must surface instead of silently changing where versions come from.
func TestVersionsForGhcrAnonymous403(t *testing.T) {
	up, hits := upstreamVersionsServer(t, "absent.org", "linux", "x86-64", []string{"1.0.0", "2.0.0"})

	for _, tc := range []struct {
		name       string
		env        map[string]string
		wantErr    bool
		wantUpHits int
		wantNewest string
	}{
		{name: "anonymous falls back", env: nil, wantUpHits: 1, wantNewest: "2.0.0"},
		{name: "credentialed surfaces the denial", env: map[string]string{"OCI_USERNAME": "u", "OCI_PASSWORD": "p"}, wantErr: true},
		{name: "token surfaces the denial", env: map[string]string{"OCI_TOKEN": "t"}, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withGlibcEnv(t, tc.env)
			fr := newFakeRegistry(t, false)
			defer fr.close()
			fr.hook = func(r *http.Request) (int, bool) {
				if strings.Contains(r.URL.Path, "/tags/list") {
					return 403, true // ghcr: "denied: requested access to the resource is denied"
				}
				return 0, false
			}
			oldUp := UpstreamDist
			UpstreamDist = up
			t.Cleanup(func() { UpstreamDist = oldUp })
			withDist(t, fr.base("go-zpkg/packages"))

			before := *hits
			vs, err := VersionsFor("absent.org", "linux", "x86-64")
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want the 403 to surface, got %d versions", len(vs))
				}
				if *hits != before {
					t.Fatal("upstream must not be consulted when credentials are configured")
				}
				return
			}
			if err != nil {
				t.Fatalf("err = %v", err)
			}
			if *hits != before+tc.wantUpHits {
				t.Fatalf("upstream hits = %d, want +%d", *hits-before, tc.wantUpHits)
			}
			if len(vs) == 0 || vs[len(vs)-1].Raw != tc.wantNewest {
				t.Fatalf("versions = %v", vs)
			}
		})
	}
}

// TestFlavoredTagSelection: a host that pinned ZPKG_GLIBC takes the build made
// against THAT glibc — the `<version>-glibc<ver>` tag — while the version, the
// constraint matching and the installed prefix all stay the plain version. Any
// other flavor is never a candidate.
func TestFlavoredTagSelection(t *testing.T) {
	tags := []string{
		"8.19.0",
		"8.20.0",
		"8.20.0-glibc2.27.0",
		"8.20.0-glibc2.44.0",
		"8.21.0-glibc2.44.0",
		"sha256-deadbeef",
	}
	for _, tc := range []struct {
		name   string
		pin    string
		want   string // "version@tag" list, oldest first
		newest string
		newTag string
	}{
		{
			name:   "unpinned takes only plain builds",
			pin:    "",
			want:   "8.19.0@8.19.0,8.20.0@8.20.0",
			newest: "8.20.0", newTag: "8.20.0",
		},
		{
			name:   "pinned prefers its own flavor, keeps plain-only versions",
			pin:    "2.27.0",
			want:   "8.19.0@8.19.0,8.20.0@8.20.0-glibc2.27.0",
			newest: "8.20.0", newTag: "8.20.0-glibc2.27.0",
		},
		{
			name:   "a flavor-only version is reachable when pinned to it",
			pin:    "2.44.0",
			want:   "8.19.0@8.19.0,8.20.0@8.20.0-glibc2.44.0,8.21.0@8.21.0-glibc2.44.0",
			newest: "8.21.0", newTag: "8.21.0-glibc2.44.0",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withGlibcEnv(t, map[string]string{"ZPKG_GLIBC": tc.pin})
			fr := newFakeRegistry(t, false)
			defer fr.close()
			withDist(t, fr.base("go-zpkg/artifacts"))
			c, err := NewOCIClient(DistBase)
			if err != nil {
				t.Fatal(err)
			}
			for _, tag := range tags {
				fr.injectManifest(c.repoName("curl.se"), tag, ocispec.MediaTypeImageManifest, []byte("{}"))
			}
			vs, err := VersionsFor("curl.se", "linux", "x86-64")
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, v := range vs {
				got = append(got, v.Raw+"@"+v.tag())
			}
			if strings.Join(got, ",") != tc.want {
				t.Fatalf("versions = %v, want %v", got, tc.want)
			}
			// resolution by constraint still works on the plain version
			picked, err := PickVersion("curl.se", "*")
			if err != nil || picked.Raw != tc.newest || picked.tag() != tc.newTag {
				t.Fatalf("PickVersion = %q (tag %q), %v", picked.Raw, picked.tag(), err)
			}
		})
	}
}

func TestVerTagFallsBackToRaw(t *testing.T) {
	if got := (Ver{Raw: "1.2.3"}).tag(); got != "1.2.3" {
		t.Fatalf("tag() = %q", got)
	}
}

// TestSelectVersionsOrderIndependent: the registry lists tags in whatever order
// it likes (ghcr's listing is not sorted, and a fake registry's map order is
// random), so the flavored-build preference must not depend on it.
func TestSelectVersionsOrderIndependent(t *testing.T) {
	plainFirst := []string{"8.20.0", "8.20.0-glibc2.27.0"}
	flavorFirst := []string{"8.20.0-glibc2.27.0", "8.20.0"}
	for _, tags := range [][]string{plainFirst, flavorFirst} {
		vs := selectVersions(tags, "2.27.0")
		if len(vs) != 1 || vs[0].Raw != "8.20.0" || vs[0].tag() != "8.20.0-glibc2.27.0" {
			t.Fatalf("tags %v → %+v; the flavored build must win either way", tags, vs)
		}
	}
	// duplicate plain tags collapse to one
	if vs := selectVersions([]string{"1.0.0", "v1.0.0"}, ""); len(vs) != 1 {
		t.Fatalf("duplicate plain tags → %+v", vs)
	}
}

// TestStallGuard: a transfer that goes quiet is failed as STALLED, while a slow
// but progressing one is left alone — the old whole-request 5-minute Timeout
// killed the latter, which is how pulling llvm.org (~1 GB) died with "context
// deadline exceeded".
func TestStallGuard(t *testing.T) {
	// no total deadline on the client any more
	if c := NewHTTPClient(); c.Timeout != 0 {
		t.Fatalf("client Timeout = %v, want none (stalls are guarded per-read)", c.Timeout)
	}

	t.Run("silence fails", func(t *testing.T) {
		block := make(chan struct{})
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", "1024")
			w.Write([]byte("start"))
			w.(http.Flusher).Flush()
			<-block // then say nothing at all
		}))
		defer func() { close(block); srv.Close() }()

		old := stallTimeout
		stallTimeout = 150 * time.Millisecond
		defer func() { stallTimeout = old }()

		resp, err := NewHTTPClient().Get(srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		_, err = io.ReadAll(resp.Body)
		if err == nil || !strings.Contains(err.Error(), "stalled") {
			t.Fatalf("read error = %v, want a stall", err)
		}
	})

	t.Run("slow but progressing succeeds", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for i := 0; i < 6; i++ { // keeps trickling, well past one idle window
				w.Write([]byte("x"))
				w.(http.Flusher).Flush()
				time.Sleep(40 * time.Millisecond)
			}
		}))
		defer srv.Close()

		old := stallTimeout
		stallTimeout = 150 * time.Millisecond
		defer func() { stallTimeout = old }()

		resp, err := NewHTTPClient().Get(srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		if err != nil || string(b) != "xxxxxx" {
			t.Fatalf("body = %q, err = %v", b, err)
		}
	})

	t.Run("a bodyless response passes through", func(t *testing.T) {
		tr := &stallTransport{idle: time.Second, base: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 204}, nil
		})}
		resp, err := tr.RoundTrip(&http.Request{})
		if err != nil || resp.Body != nil {
			t.Fatalf("resp = %+v, err = %v", resp, err)
		}
		// and a transport error propagates
		tr.base = roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("boom") })
		if _, err := tr.RoundTrip(&http.Request{}); err == nil {
			t.Fatal("want the transport error")
		}
	})
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// TestSelectVersionsCollapsesEqualSpellings: "2.44" and "2.44.0" ARE the same
// version (cmpVer says so), so keeping both makes the pick depend on the order
// the registry lists its tags. Our own registry carries both for gnu.org/glibc —
// a 2.44 tag from a factory build and a 2.44.0 tag from the upstream mirror —
// and a build ended up with BOTH glibc trees installed, linking against a
// sysroot that was not where its loader came from.
func TestSelectVersionsCollapsesEqualSpellings(t *testing.T) {
	for _, order := range [][]string{{"2.44", "2.44.0"}, {"2.44.0", "2.44"}} {
		vs := selectVersions(order, "")
		if len(vs) != 1 {
			t.Fatalf("%v → %d candidates, want one", order, len(vs))
		}
		if vs[0].Raw != "2.44.0" {
			t.Fatalf("%v → %q, want the more specific spelling either way", order, vs[0].Raw)
		}
	}
	// a flavored build still wins over both spellings
	vs := selectVersions([]string{"2.44", "2.44.0", "2.44-glibc2.27.0"}, "2.27.0")
	if len(vs) != 1 || vs[0].tag() != "2.44-glibc2.27.0" {
		t.Fatalf("→ %+v, want the flavored build", vs)
	}
	// distinct versions are untouched
	if vs := selectVersions([]string{"1.0", "1.0.1", "2.0"}, ""); len(vs) != 3 {
		t.Fatalf("→ %d candidates, want three", len(vs))
	}
}

func TestNumericKey(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"2.44", "2.44"}, {"2.44.0", "2.44"}, {"2.44.0.0", "2.44"},
		{"1.0.1", "1.0.1"}, {"0", "0"}, {"0.0", "0"},
	} {
		if got := numericKey(ParseVer(tc.in)); got != tc.want {
			t.Errorf("numericKey(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
