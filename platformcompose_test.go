package artifact

import (
	"context"
	"net/http"
	"strings"
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// TestIndexComposedFromPlatformTags: the index is rebuilt from the uncontended
// `<ver>--<os>-<arch>` tags, so two publishers racing on one version write the
// same COMPLETE index instead of each dropping the other's platform. 428 index
// entries were lost in a single day of publishing before this.
func TestIndexComposedFromPlatformTags(t *testing.T) {
	t.Setenv("ZPKG_VERIFY", "0")
	fr := newFakeRegistry(t, false)
	defer fr.close()
	c, err := NewOCIClient(fr.base("go-zpkg/artifacts"))
	if err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"x86-64", "aarch64"} {
		if err := c.Push("hello.test", "1.2.3", "linux", arch, makeGzTarball("x"), ".tar.gz"); err != nil {
			t.Fatalf("push %s: %v", arch, err)
		}
	}
	repo, err := c.repository("hello.test")
	if err != nil {
		t.Fatal(err)
	}
	// Both platform tags exist and are NOT versions.
	tags, err := c.ListTags("hello.test")
	if err != nil {
		t.Fatal(err)
	}
	for _, tag := range tags {
		if IsPlatformTag(tag) {
			t.Errorf("ListTags returned a platform tag: %q", tag)
		}
	}
	// Composing sees both, with the OCI arch spelling the index uses.
	got := c.platformManifests(context.Background(), repo, "1.2.3")
	if len(got) != 2 {
		t.Fatalf("composed from %d platform tag(s), want 2", len(got))
	}
	seen := map[string]bool{}
	for _, d := range got {
		seen[d.Platform.OS+"/"+d.Platform.Architecture] = true
	}
	if !seen["linux/amd64"] || !seen["linux/arm64"] {
		t.Errorf("platforms %v, want the OCI spellings linux/amd64 and linux/arm64", seen)
	}
}

// TestPlatformManifestsSurvivesABadTag: a tag that resolves to nothing, and one
// shaped wrong, are skipped rather than failing the composition — which would
// block every later publish of that version.
func TestPlatformManifestsSurvivesABadTag(t *testing.T) {
	t.Setenv("ZPKG_VERIFY", "0")
	fr := newFakeRegistry(t, false)
	defer fr.close()
	c, err := NewOCIClient(fr.base("go-zpkg/artifacts"))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Push("hello.test", "1.2.3", "linux", "x86-64", makeGzTarball("x"), ".tar.gz"); err != nil {
		t.Fatal(err)
	}
	fr.mu.Lock()
	// A platform tag that RESOLVES but whose name carries no arch: it must be
	// skipped on its shape, not on a failed lookup.
	repoKey := "go-zpkg/artifacts/hello.test"
	good := fr.manifests[repoKey+"|1.2.3--linux-x86-64"]
	fr.manifests[repoKey+"|1.2.3--noarch"] = good
	fr.mtypes[repoKey+"|1.2.3--noarch"] = fr.mtypes[repoKey+"|1.2.3--linux-x86-64"]
	fr.tags[repoKey]["1.2.3--noarch"] = true
	fr.mu.Unlock()

	repo, _ := c.repository("hello.test")
	got := c.platformManifests(context.Background(), repo, "1.2.3")
	if len(got) != 1 || got[0].Platform.Architecture != "amd64" {
		t.Fatalf("got %d descriptor(s) %v, want just the real one", len(got), got)
	}
}

// TestPlatformManifestsWhenTagsCannotBeListed: the composition falls back to
// the index's own contents, which is what happened before platform tags — never
// an error, because that would stop a publish that would otherwise succeed.
func TestPlatformManifestsWhenTagsCannotBeListed(t *testing.T) {
	t.Setenv("ZPKG_VERIFY", "0")
	fr := newFakeRegistry(t, false)
	defer fr.close()
	c, err := NewOCIClient(fr.base("go-zpkg/artifacts"))
	if err != nil {
		t.Fatal(err)
	}
	repo, err := c.repository("nothing.test")
	if err != nil {
		t.Fatal(err)
	}
	if got := c.platformManifests(context.Background(), repo, "9.9.9"); got != nil {
		t.Fatalf("got %v, want nothing", got)
	}
}

func TestUpsertPlatformIsIdempotentAcrossComposition(t *testing.T) {
	d := ocispec.Descriptor{Digest: "sha256:a", Platform: &ocispec.Platform{OS: "linux", Architecture: "amd64"}}
	m := upsertPlatform(nil, d)
	m = upsertPlatform(m, d)
	if len(m) != 1 {
		t.Fatalf("composing the same platform twice yielded %d entries", len(m))
	}
	_ = strings.TrimSpace("")
}

// TestPushFailsWhenThePlatformTagCannotBeWritten: the platform tag is what
// makes the index composable, so a push that cannot write it must fail rather
// than fall back to the merge that loses entries.
func TestPushFailsWhenThePlatformTagCannotBeWritten(t *testing.T) {
	t.Setenv("ZPKG_VERIFY", "0")
	fr := newFakeRegistry(t, false)
	defer fr.close()
	fr.hook = func(r *http.Request) (int, bool) {
		if r.Method == http.MethodPut && strings.Contains(r.URL.Path, "--") {
			return http.StatusInternalServerError, true
		}
		return 0, false
	}
	c, err := NewOCIClient(fr.base("go-zpkg/artifacts"))
	if err != nil {
		t.Fatal(err)
	}
	err = c.Push("hello.test", "1.2.3", "linux", "x86-64", makeGzTarball("x"), ".tar.gz")
	if err == nil || !strings.Contains(err.Error(), "tag platform manifest") {
		t.Fatalf("got %v, want the platform-tag write to fail the push", err)
	}
}

// TestPlatformManifestsSkipsATagThatResolvesToNothing: a tag listed but with no
// manifest behind it is skipped, not fatal.
func TestPlatformManifestsSkipsATagThatResolvesToNothing(t *testing.T) {
	t.Setenv("ZPKG_VERIFY", "0")
	fr := newFakeRegistry(t, false)
	defer fr.close()
	c, err := NewOCIClient(fr.base("go-zpkg/artifacts"))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Push("hello.test", "1.2.3", "linux", "x86-64", makeGzTarball("x"), ".tar.gz"); err != nil {
		t.Fatal(err)
	}
	fr.mu.Lock()
	fr.tags["go-zpkg/artifacts/hello.test"]["1.2.3--linux-ppc64le"] = true // listed, never pushed
	fr.mu.Unlock()
	// Resolving it fails the way a registry fails on a dangling tag.
	fr.hook = func(r *http.Request) (int, bool) {
		if strings.Contains(r.URL.Path, "1.2.3--linux-ppc64le") {
			return http.StatusNotFound, true
		}
		return 0, false
	}
	repo, _ := c.repository("hello.test")
	if got := c.platformManifests(context.Background(), repo, "1.2.3"); len(got) != 1 {
		t.Fatalf("got %d, want only the platform that exists", len(got))
	}
}
