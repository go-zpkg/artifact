package artifact

import (
	"encoding/json"
	"strings"
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// indexWith builds an image index carrying exactly these platform entries.
// A nil entry means a descriptor with no platform at all, which an index is
// allowed to contain.
func indexWith(t *testing.T, plats []*ocispec.Platform) []byte {
	t.Helper()
	idx := ocispec.Index{MediaType: ocispec.MediaTypeImageIndex}
	idx.SchemaVersion = 2
	for _, p := range plats {
		idx.Manifests = append(idx.Manifests, ocispec.Descriptor{
			MediaType: ocispec.MediaTypeImageManifest,
			Digest:    "sha256:0000000000000000000000000000000000000000000000000000000000000000",
			Size:      2,
			Platform:  p,
		})
	}
	b, err := json.Marshal(idx)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func plat(os, arch string) *ocispec.Platform {
	return &ocispec.Platform{OS: os, Architecture: arch}
}

// ⛔ THE QUESTION NOTHING COULD ASK. `HasPlatform` answers "is THIS one
// published", one guess at a time; nothing answered "which are". Measured
// 2026-10-20, go-zpkg/packages' daily CVE lane carried its platform list in
// the workflow file, the list said two, and the registry published six —
// the four nobody asked about were clean, so the cost was coverage rather
// than an exposure, and the mechanism guaranteed the next one would be
// missed too.
func TestPlatformsListsWhatTheIndexPublishes(t *testing.T) {
	fr := newFakeRegistry(t, false)
	defer fr.close()
	c, err := NewOCIClient(fr.base("go-zpkg/packages"))
	if err != nil {
		t.Fatal(err)
	}
	// The six the registry really carries, in a deliberately unsorted order
	// and with one repeated: an index's order is not ours to rely on.
	fr.injectManifest("go-zpkg/packages/go-zpkg.github.io/catalog", "1", ocispec.MediaTypeImageIndex,
		indexWith(t, []*ocispec.Platform{
			plat("linux", "amd64"),
			plat("darwin", "arm64"),
			plat("windows", "amd64"),
			plat("linux", "s390x"),
			plat("darwin", "amd64"),
			plat("linux", "arm64"),
			plat("linux", "amd64"), // the same platform twice
		}))

	got, err := c.Platforms("go-zpkg.github.io/catalog", "1")
	if err != nil {
		t.Fatalf("Platforms: %v", err)
	}
	want := []string{
		"darwin/aarch64", "darwin/x86-64",
		"linux/aarch64", "linux/s390x", "linux/x86-64",
		"windows/x86-64",
	}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("Platforms =\n  %v\nwant (pkgx spelling, sorted, deduplicated)\n  %v", got, want)
	}
}

// ⛔ THE TAG FILTER EVERY ListTags CALLER NEEDS, exported because one could
// not reach it. `pkgs request` filtered a listing with IsPlatformTag alone
// and reported a project with no releases as "2 version(s) tagged": the two
// were `sha256-…` referrer tags, which exist because ghcr implements no
// referrers API and ORAS falls back to tagging attestations by digest.
// Asking Platforms about one of them then returned "the index has 3
// entry(ies) and none of them names a platform" — a true sentence about a
// question nobody meant to ask.
func TestIsVersionTagIsReachableAndKeepsItsRule(t *testing.T) {
	for tag, want := range map[string]bool{
		"1.0.0":           true,
		"v1.0.0":          true,
		"10.4.0":          true,
		"1.0.0+glibc2.28": true,
		"sha256-5e3e8dd10513699116134fe1455e53db8d7d6b575a25d539bac524fc920c12b9": false,
		"sha256-abc123": false,
		"latest":        false,
		"":              false,
	} {
		if got := IsVersionTag(tag); got != want {
			t.Errorf("IsVersionTag(%q) = %v, want %v", tag, got, want)
		}
	}
	// And it is the SAME rule as the unexported one, not a second copy that
	// can drift away from it.
	for _, tag := range []string{"1.2.3", "sha256-deadbeef", "v9", "nonsense"} {
		if IsVersionTag(tag) != isVersionTag(tag) {
			t.Errorf("the exported and unexported forms disagree about %q", tag)
		}
	}
}

// ⛔ THREE SHAPES THAT ARE NOT A PLATFORM, and all three are ordinary. An
// index may hold a descriptor with no platform; buildkit writes attestation
// manifests as the literal `unknown/unknown`. Either, named as one, puts a
// line in this list that no caller can hand back to --platform — and the
// caller here is a CVE scan that would then ask about a platform nobody
// publishes and report whatever that produced.
func TestPlatformsSkipsWhatIsNotAPlatform(t *testing.T) {
	fr := newFakeRegistry(t, false)
	defer fr.close()
	c, _ := NewOCIClient(fr.base("go-zpkg/packages"))
	fr.injectManifest("go-zpkg/packages/p", "1", ocispec.MediaTypeImageIndex,
		indexWith(t, []*ocispec.Platform{
			plat("linux", "amd64"),
			nil,                        // a descriptor with no platform
			plat("unknown", "unknown"), // buildkit's attestation manifest
			plat("linux", ""),          // half a platform
			plat("", "arm64"),          // the other half
		}))
	got, err := c.Platforms("p", "1")
	if err != nil {
		t.Fatalf("Platforms: %v", err)
	}
	if len(got) != 1 || got[0] != "linux/x86-64" {
		t.Errorf("Platforms = %v, want just [linux/x86-64]", got)
	}
}

// A variant distinguishes platforms, so dropping it would merge two entries
// into one name and under-report — the same class of mistake as the list
// this function exists to replace.
func TestPlatformsKeepsAVariant(t *testing.T) {
	fr := newFakeRegistry(t, false)
	defer fr.close()
	c, _ := NewOCIClient(fr.base("go-zpkg/packages"))
	fr.injectManifest("go-zpkg/packages/p", "1", ocispec.MediaTypeImageIndex,
		indexWith(t, []*ocispec.Platform{
			{OS: "linux", Architecture: "arm", Variant: "v7"},
			{OS: "linux", Architecture: "arm", Variant: "v6"},
		}))
	got, err := c.Platforms("p", "1")
	if err != nil {
		t.Fatalf("Platforms: %v", err)
	}
	want := []string{"linux/arm/v6", "linux/arm/v7"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("Platforms = %v, want %v", got, want)
	}
}

// ⛔ AN EMPTY LIST IS AN ERROR, NEVER AN ANSWER.
//
// fetchOrNewIndex — the other reader of this document — turns every failure
// into an empty index on purpose, because it is composing a push and
// "nothing published yet" is its normal case. For a LISTING that is the
// defect: "this version publishes no platform" and "I could not read the
// index" print the same nothing, and this fleet has published that zero
// before.
func TestPlatformsRefusesToReportNothing(t *testing.T) {
	fr := newFakeRegistry(t, false)
	defer fr.close()
	c, _ := NewOCIClient(fr.base("go-zpkg/packages"))

	// An index whose every entry is an attestation: real shape, no platforms.
	fr.injectManifest("go-zpkg/packages/none", "1", ocispec.MediaTypeImageIndex,
		indexWith(t, []*ocispec.Platform{plat("unknown", "unknown"), nil}))
	if got, err := c.Platforms("none", "1"); err == nil {
		t.Errorf("an index naming no platform returned %v and no error", got)
	} else if !strings.Contains(err.Error(), "none of them names a platform") {
		t.Errorf("the error does not say what happened: %v", err)
	}

	// A single manifest cannot answer the question either, and saying so
	// beats returning the host's own platform as if the registry had said it.
	fr.injectManifest("go-zpkg/packages/single", "1", ocispec.MediaTypeImageManifest,
		[]byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.empty.v1+json","digest":"sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a","size":2},"layers":[]}`))
	if got, err := c.Platforms("single", "1"); err == nil {
		t.Errorf("a single manifest returned %v and no error", got)
	} else if !strings.Contains(err.Error(), "not a multi-platform index") {
		t.Errorf("the error does not say what happened: %v", err)
	}

	// And a tag that is not there is an error, not an empty list.
	if got, err := c.Platforms("absent", "1"); err == nil {
		t.Errorf("an absent tag returned %v and no error", got)
	}
}
