package artifact

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// TestFetchAttestations: what a mirror needs to carry an artifact WITH its
// signature — the referrers verbatim, plus the per-platform annotations. A copy
// that drops them turns fail-closed verification into a failure (or, if someone
// then disables verification, into a silent downgrade).
func TestFetchAttestations(t *testing.T) {
	fr := newFakeRegistry(t, false)
	defer fr.close()
	withDist(t, fr.base("go-zpkg/artifacts"))
	c, err := NewOCIClient(DistBase)
	if err != nil {
		t.Fatal(err)
	}

	tarball := makeGzTarball("libc")
	refs := []Referrer{
		{ArtifactType: "application/vnd.cyclonedx+json", MediaType: "application/vnd.cyclonedx+json", Blob: []byte(`{"sbom":true}`)},
		{ArtifactType: ArtifactTypeSignature, MediaType: MediaSimpleSigning, Blob: []byte(`{"sig":true}`),
			Annotations: map[string]string{CosignSignatureAnnotation: "BASE64SIG"}},
	}
	if _, err := c.PushWithReferrersAnnotated(GlibcProject, "2.44.0", "linux", "x86-64", tarball, ExtTarGz,
		refs, map[string]string{GlibcMinKernelAnnotation: "3.10.0"}); err != nil {
		t.Fatal(err)
	}

	got, ann, err := c.FetchAttestations(GlibcProject, "2.44.0", "linux", "x86-64")
	if err != nil {
		t.Fatal(err)
	}
	if ann[GlibcMinKernelAnnotation] != "3.10.0" {
		t.Fatalf("annotations = %v — the min-kernel must survive the copy", ann)
	}
	var kinds []string
	var sig *Referrer
	for i := range got {
		kinds = append(kinds, got[i].ArtifactType)
		if got[i].ArtifactType == ArtifactTypeSignature {
			sig = &got[i]
		}
	}
	if len(got) != 2 {
		t.Fatalf("referrers = %v, want both", kinds)
	}
	if sig == nil || string(sig.Blob) != `{"sig":true}` ||
		sig.Annotations[CosignSignatureAnnotation] != "BASE64SIG" {
		t.Fatalf("the signature did not round-trip: %+v", sig)
	}
}

// TestFetchAttestationsErrors: every failure surfaces rather than yielding an
// unsigned copy.
func TestFetchAttestationsErrors(t *testing.T) {
	fr := newFakeRegistry(t, false)
	defer fr.close()
	withDist(t, fr.base("go-zpkg/artifacts"))
	c, err := NewOCIClient(DistBase)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.FetchAttestations("BAD..name/../x", "1.0", "linux", "x86-64"); err == nil {
		t.Error("want an error for a bad project")
	}
	if _, _, err := c.FetchAttestations("absent.test", "1.0", "linux", "x86-64"); err == nil {
		t.Error("want an error for an unpublished version")
	}
	// an artifact with no attestations at all is not an error — it is simply
	// unsigned, and the caller's verification policy decides.
	if err := c.Push("bare.test", "1.0", "linux", "x86-64", makeGzTarball("x"), ExtTarGz); err != nil {
		t.Fatal(err)
	}
	refs, _, err := c.FetchAttestations("bare.test", "1.0", "linux", "x86-64")
	if err != nil || len(refs) != 0 {
		t.Fatalf("refs = %d, err = %v", len(refs), err)
	}
	_ = strings.TrimSpace
}

// TestReferrerFrom covers the shapes a referrer manifest can take: the normal
// one, a malformed one, one with nothing to carry, and one whose payload cannot
// be read. A mirror must never turn any of these into a silently unsigned copy.
func TestReferrerFrom(t *testing.T) {
	good := `{"schemaVersion":2,"artifactType":"x","layers":[{"mediaType":"application/json","digest":"sha256:aa","size":2}],"annotations":{"dev.cosignproject.cosign/signature":"SIG"}}`
	ref, ok, err := referrerFrom([]byte(good), "application/vnd.dev.cosign.artifact.sig.v1+json",
		func(d ocispec.Descriptor) ([]byte, error) { return []byte(`{"payload":1}`), nil })
	if err != nil || !ok {
		t.Fatalf("ok = %v, err = %v", ok, err)
	}
	if ref.ArtifactType != "application/vnd.dev.cosign.artifact.sig.v1+json" ||
		ref.MediaType != "application/json" ||
		string(ref.Blob) != `{"payload":1}` ||
		ref.Annotations["dev.cosignproject.cosign/signature"] != "SIG" {
		t.Fatalf("referrer = %+v", ref)
	}

	if _, _, err := referrerFrom([]byte("{not json"), "x", nil); err == nil {
		t.Error("a malformed referrer manifest must surface")
	}
	if _, ok, err := referrerFrom([]byte(`{"schemaVersion":2,"layers":[]}`), "x", nil); err != nil || ok {
		t.Errorf("a payload-less referrer must be skipped: ok=%v err=%v", ok, err)
	}
	if _, _, err := referrerFrom([]byte(good), "x", func(ocispec.Descriptor) ([]byte, error) {
		return nil, errors.New("boom")
	}); err == nil {
		t.Error("an unreadable payload must surface")
	}
}

// TestFetchAttestationsRegistryFaults: every step of the walk can fail, and each
// failure must surface. A mirror that swallowed one would publish a copy with
// fewer attestations than the original — an unsigned artifact wearing the same
// name.
func TestFetchAttestationsRegistryFaults(t *testing.T) {
	for _, tc := range []struct {
		name string
		when func(path string) bool
	}{
		{"listing the referrers", func(p string) bool { return strings.Contains(p, "/referrers/") }},
		{"reading a referrer manifest", func() func(string) bool {
			// The walk fetches TWO manifests by digest: the platform manifest
			// first, then the referrer's. Only the second is this case.
			seen := 0
			return func(p string) bool {
				if !strings.Contains(p, "/manifests/sha256") {
					return false
				}
				seen++
				return seen > 1
			}
		}()},
		{"reading the payload", func(p string) bool { return strings.Contains(p, "/blobs/sha256:") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fr := newFakeRegistry(t, false)
			defer fr.close()
			withDist(t, fr.base("go-zpkg/artifacts"))
			c, err := NewOCIClient(DistBase)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := c.PushWithReferrers("fault.test", "1.0", "linux", "x86-64",
				makeGzTarball("x"), ExtTarGz,
				[]Referrer{{ArtifactType: "application/vnd.cyclonedx+json", MediaType: "application/json", Blob: []byte(`{}`)}}); err != nil {
				t.Fatal(err)
			}
			// the fault arms only once the artifact is in place, so the walk starts
			// normally and breaks exactly where the case says.
			fr.hook = func(r *http.Request) (int, bool) {
				return http.StatusInternalServerError, tc.when(r.URL.Path)
			}
			if _, _, err := c.FetchAttestations("fault.test", "1.0", "linux", "x86-64"); err == nil {
				t.Fatalf("%s: want an error", tc.name)
			}
		})
	}
}
