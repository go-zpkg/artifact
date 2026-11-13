package artifact

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	orascontent "oras.land/oras-go/v2/content"
)

// The store is addressed by CONTENT: the sha256 the fetcher already computed
// becomes the tag, so the digest an artifact's SBOM records IS the address of the
// bytes it was built from. Nothing has to be named twice or kept in step.
func TestSourceRoundTrip(t *testing.T) {
	fr := newFakeRegistry(t, false)
	defer fr.close()
	c, err := NewOCIClient(fr.base("go-zpkg/sources"))
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("a source tarball, byte for byte as it arrived")
	dg := SourceDigest(data)

	if have, err := c.HasSource("acme.org/thing", dg); err != nil || have {
		t.Fatalf("HasSource before push = %v, %v; want false, nil", have, err)
	}
	if _, err := c.PushSource("acme.org/thing", data, "https://example.invalid/thing-1.2.3.tar.gz"); err != nil {
		t.Fatal(err)
	}
	if have, err := c.HasSource("acme.org/thing", dg); err != nil || !have {
		t.Fatalf("HasSource after push = %v, %v; want true, nil", have, err)
	}
	got, err := c.PullSource("acme.org/thing", dg)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(data) {
		t.Errorf("pulled %q, want %q", got, data)
	}
}

// Pushing the same bytes twice is the same manifest under the same tag, because
// the tag IS the content. A populate step that runs on every build must not
// grow the registry once per build.
func TestSourcePushIsIdempotent(t *testing.T) {
	fr := newFakeRegistry(t, false)
	defer fr.close()
	c, err := NewOCIClient(fr.base("go-zpkg/sources"))
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("same bytes twice")
	first, err := c.PushSource("acme.org/thing", data, "https://example.invalid/a")
	if err != nil {
		t.Fatal(err)
	}
	second, err := c.PushSource("acme.org/thing", data, "https://example.invalid/a")
	if err != nil {
		t.Fatal(err)
	}
	if first.Digest != second.Digest {
		t.Errorf("manifest digests differ: %s vs %s", first.Digest, second.Digest)
	}
}

// A digest the store does not hold is a NAMED absence, not a generic error: the
// caller's next move is to fetch from upstream, and it has to be able to tell
// that case from a broken registry.
func TestPullSourceAbsentIsNamed(t *testing.T) {
	fr := newFakeRegistry(t, false)
	defer fr.close()
	c, err := NewOCIClient(fr.base("go-zpkg/sources"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.PullSource("acme.org/thing", SourceDigest([]byte("never stored")))
	if !errors.Is(err, ErrSourceAbsent) {
		t.Errorf("err = %v, want ErrSourceAbsent", err)
	}
}

// A mirror exists so a rebuild need not trust the upstream host. Trusting the
// mirror instead would move the problem rather than solve it, so what comes
// back is hashed and checked against what was ASKED FOR — a tag pointing at
// the wrong bytes is an error, not a different build.
func TestPullSourceRefusesBytesThatDoNotHash(t *testing.T) {
	fr := newFakeRegistry(t, false)
	defer fr.close()
	c, err := NewOCIClient(fr.base("go-zpkg/sources"))
	if err != nil {
		t.Fatal(err)
	}
	want := SourceDigest([]byte("the bytes the caller asked for"))
	// Store OTHER bytes under that digest's tag, the way a tampered or
	// mis-tagged mirror would.
	ctx := context.Background()
	repo, err := c.repository("acme.org/thing")
	if err != nil {
		t.Fatal(err)
	}
	other := []byte("something else entirely")
	layer := orascontent.NewDescriptorFromBytes(MediaSourceLayer, other)
	if err := pushIfAbsent(ctx, repo, layer, other); err != nil {
		t.Fatal(err)
	}
	man, err := oras.PackManifest(ctx, repo, oras.PackManifestVersion1_1, ArtifactTypeSource,
		oras.PackManifestOptions{Layers: []ocispec.Descriptor{layer}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := oras.Tag(ctx, repo, man.Digest.String(), SourceTag(want)); err != nil {
		t.Fatal(err)
	}
	_, err = c.PullSource("acme.org/thing", want)
	if err == nil || !strings.Contains(err.Error(), "hashing to") {
		t.Errorf("err = %v, want a digest-mismatch refusal", err)
	}
}

// A manifest that is not one layer is not a source archive. Saying so beats
// indexing past the end of a slice.
//
// Note the shape: ORAS packs an EMPTY layer descriptor when given none, so
// "zero layers" is not reachable from here — two is.
func TestPullSourceRefusesAManifestThatIsNotOneLayer(t *testing.T) {
	fr := newFakeRegistry(t, false)
	defer fr.close()
	c, err := NewOCIClient(fr.base("go-zpkg/sources"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	repo, err := c.repository("acme.org/thing")
	if err != nil {
		t.Fatal(err)
	}
	var layers []ocispec.Descriptor
	for _, b := range [][]byte{[]byte("one"), []byte("two")} {
		d := orascontent.NewDescriptorFromBytes(MediaSourceLayer, b)
		if err := pushIfAbsent(ctx, repo, d, b); err != nil {
			t.Fatal(err)
		}
		layers = append(layers, d)
	}
	man, err := oras.PackManifest(ctx, repo, oras.PackManifestVersion1_1, ArtifactTypeSource,
		oras.PackManifestOptions{Layers: layers})
	if err != nil {
		t.Fatal(err)
	}
	dg := SourceDigest([]byte("whatever"))
	if _, err := oras.Tag(ctx, repo, man.Digest.String(), SourceTag(dg)); err != nil {
		t.Fatal(err)
	}
	_, err = c.PullSource("acme.org/thing", dg)
	if err == nil || !strings.Contains(err.Error(), "layers, want 1") {
		t.Errorf("err = %v, want a layer-count refusal", err)
	}
}

// A project name the registry cannot express is an error from every entry
// point, not a panic in one of them.
func TestSourceStoreRejectsAnImpossibleProject(t *testing.T) {
	fr := newFakeRegistry(t, false)
	defer fr.close()
	c, err := NewOCIClient(fr.base("go-zpkg/sources"))
	if err != nil {
		t.Fatal(err)
	}
	const bad = "UPPER/Not A Repo"
	if _, err := c.PushSource(bad, []byte("x"), ""); err == nil {
		t.Error("PushSource accepted an impossible project name")
	}
	if _, err := c.PullSource(bad, SourceDigest([]byte("x"))); err == nil {
		t.Error("PullSource accepted an impossible project name")
	}
	if _, err := c.HasSource(bad, SourceDigest([]byte("x"))); err == nil {
		t.Error("HasSource accepted an impossible project name")
	}
	if _, err := c.PinnedDigest(bad, "https://example.invalid/x.tgz"); err == nil {
		t.Error("PinnedDigest accepted an impossible project name")
	}
}

// OCI tags cannot contain a colon.
func TestSourceTagIsAValidTag(t *testing.T) {
	tag := SourceTag(SourceDigest([]byte("x")))
	if strings.Contains(tag, ":") {
		t.Errorf("tag %q contains a colon", tag)
	}
	if !strings.HasPrefix(tag, "sha256-") {
		t.Errorf("tag %q does not name its algorithm", tag)
	}
}

// The failure paths, driven through the fake registry's hook. A mirror that
// cannot be reached must say so; the caller's fallback is the upstream host and
// it needs an error to know to take it.
func TestSourceStoreRegistryFailures(t *testing.T) {
	data := []byte("some source bytes")
	dg := SourceDigest(data)

	t.Run("layer upload fails", func(t *testing.T) {
		fr := newFakeRegistry(t, false)
		defer fr.close()
		c, _ := NewOCIClient(fr.base("go-zpkg/sources"))
		fr.hook = func(r *http.Request) (int, bool) {
			_, verb, _ := splitV2(r.URL.Path)
			return 500, verb == "uploads"
		}
		if _, err := c.PushSource("acme.org/thing", data, ""); err == nil {
			t.Error("push reported success with every blob upload failing")
		}
	})

	t.Run("resolve fails for a reason that is not absence", func(t *testing.T) {
		fr := newFakeRegistry(t, false)
		defer fr.close()
		c, _ := NewOCIClient(fr.base("go-zpkg/sources"))
		fr.hook = func(r *http.Request) (int, bool) {
			_, verb, _ := splitV2(r.URL.Path)
			return 500, verb == "manifests"
		}
		_, err := c.PullSource("acme.org/thing", dg)
		if err == nil {
			t.Error("pull reported success against a broken registry")
		}
		if errors.Is(err, ErrSourceAbsent) {
			t.Error("a 500 was reported as a missing source, which would send the caller down the wrong path")
		}
		if _, err := c.HasSource("acme.org/thing", dg); err == nil {
			t.Error("HasSource reported an answer against a broken registry")
		}
	})

	t.Run("the manifest does not parse", func(t *testing.T) {
		fr := newFakeRegistry(t, false)
		defer fr.close()
		c, _ := NewOCIClient(fr.base("go-zpkg/sources"))
		if _, err := c.PushSource("acme.org/thing", data, ""); err != nil {
			t.Fatal(err)
		}
		for k := range fr.manifests {
			fr.manifests[k] = []byte("{not json")
		}
		if _, err := c.PullSource("acme.org/thing", dg); err == nil {
			t.Error("pull accepted a manifest that is not JSON")
		}
	})
}

// Trust on first use: the first fetch of a URL records what it served, and
// every later fetch can compare. The pin points at the SAME manifest as the
// content tag, so it cannot claim a digest the stored bytes do not have.
func TestPinnedDigestAnswersWhatTheURLServed(t *testing.T) {
	fr := newFakeRegistry(t, false)
	defer fr.close()
	c, err := NewOCIClient(fr.base("go-zpkg/sources"))
	if err != nil {
		t.Fatal(err)
	}
	const uri = "https://example.invalid/thing-1.2.3.tar.gz"
	data := []byte("the bytes upstream served on the first build")

	// Before anything is stored, the question has no answer — and that is a
	// NAMED absence, not an error that reads like a broken registry.
	if _, err := c.PinnedDigest("acme.org/thing", uri); !errors.Is(err, ErrSourceAbsent) {
		t.Fatalf("PinnedDigest before push = %v; want ErrSourceAbsent", err)
	}
	if _, err := c.PushSource("acme.org/thing", data, uri); err != nil {
		t.Fatal(err)
	}
	got, err := c.PinnedDigest("acme.org/thing", uri)
	if err != nil {
		t.Fatal(err)
	}
	if want := SourceDigest(data); got != want {
		t.Errorf("PinnedDigest = %s; want %s", got, want)
	}
}

// A source stored without a URL gets no pin. The mirror is still
// content-addressed and still useful; there is simply nothing to compare a
// later fetch against, and inventing a key would be worse than saying so.
func TestPushWithNoURIRecordsNoPin(t *testing.T) {
	fr := newFakeRegistry(t, false)
	defer fr.close()
	c, err := NewOCIClient(fr.base("go-zpkg/sources"))
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("bytes from nowhere in particular")
	if _, err := c.PushSource("acme.org/thing", data, ""); err != nil {
		t.Fatal(err)
	}
	if have, err := c.HasSource("acme.org/thing", SourceDigest(data)); err != nil || !have {
		t.Fatalf("the archive itself should still be stored: %v, %v", have, err)
	}
	if _, err := c.PinnedDigest("acme.org/thing", ""); !errors.Is(err, ErrSourceAbsent) {
		t.Errorf("PinnedDigest for an empty URI = %v; want ErrSourceAbsent", err)
	}
}

// The second push MOVES the pin, deliberately. Deciding whether a digest may
// change is the caller's job — it reads PinnedDigest first — and a store that
// refused here would make a legitimate version bump unstorable.
func TestASecondPushMovesThePin(t *testing.T) {
	fr := newFakeRegistry(t, false)
	defer fr.close()
	c, err := NewOCIClient(fr.base("go-zpkg/sources"))
	if err != nil {
		t.Fatal(err)
	}
	const uri = "https://example.invalid/rolling.tar.gz"
	first := []byte("what it served in March")
	second := []byte("what it serves now")
	if _, err := c.PushSource("acme.org/thing", first, uri); err != nil {
		t.Fatal(err)
	}
	if _, err := c.PushSource("acme.org/thing", second, uri); err != nil {
		t.Fatal(err)
	}
	got, err := c.PinnedDigest("acme.org/thing", uri)
	if err != nil {
		t.Fatal(err)
	}
	if got != SourceDigest(second) {
		t.Errorf("pin = %s; want the second push %s", got, SourceDigest(second))
	}
	// And the FIRST bytes are still retrievable by their own digest: moving a
	// pin must not lose history.
	if _, err := c.PullSource("acme.org/thing", SourceDigest(first)); err != nil {
		t.Errorf("the earlier archive became unreachable: %v", err)
	}
}

// An OCI tag may hold only [A-Za-z0-9_.-] and at most 128 characters. A
// distributable URL has slashes, colons and percent-escapes and is routinely
// longer, which is why the URL is hashed rather than escaped.
func TestPinTagIsAValidTagForAnAwkwardURL(t *testing.T) {
	for _, uri := range []string{
		"",
		"http://downloads.sourceforge.net/project/infozip/Zip%203.x%20%28latest%29/3.0/zip30.tar.gz",
		"https://example.invalid/" + strings.Repeat("a", 4096),
	} {
		tag := PinTag(uri)
		if len(tag) > 128 || len(tag) == 0 {
			t.Errorf("PinTag(%.40q) has length %d", uri, len(tag))
		}
		for _, r := range tag {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '.' || r == '-') {
				t.Errorf("PinTag(%.40q) = %q holds %q, which OCI forbids", uri, tag, r)
			}
		}
	}
	// Different URLs must not collide into one pin.
	if PinTag("https://a.invalid/x.tgz") == PinTag("https://b.invalid/x.tgz") {
		t.Error("two URLs share a pin tag")
	}
}

// The pin's failure paths. A mirror that cannot answer must say so rather than
// read as "no pin": a pin that silently reads absent turns trust-on-first-use
// into trust-every-time, which is the state this replaces.
func TestPinnedDigestFailures(t *testing.T) {
	const uri = "https://example.invalid/thing.tar.gz"
	data := []byte("source bytes for the pin failure paths")

	t.Run("a broken registry is not an absent pin", func(t *testing.T) {
		fr := newFakeRegistry(t, false)
		defer fr.close()
		c, _ := NewOCIClient(fr.base("go-zpkg/sources"))
		fr.hook = func(r *http.Request) (int, bool) {
			_, verb, _ := splitV2(r.URL.Path)
			return 500, verb == "manifests"
		}
		_, err := c.PinnedDigest("acme.org/thing", uri)
		if err == nil {
			t.Fatal("PinnedDigest reported an answer against a broken registry")
		}
		if errors.Is(err, ErrSourceAbsent) {
			t.Error("a 500 read as a missing pin, which would let a changed tarball through")
		}
	})

	t.Run("a pinned manifest that does not parse", func(t *testing.T) {
		fr := newFakeRegistry(t, false)
		defer fr.close()
		c, _ := NewOCIClient(fr.base("go-zpkg/sources"))
		if _, err := c.PushSource("acme.org/thing", data, uri); err != nil {
			t.Fatal(err)
		}
		// Corrupt the manifest the PIN resolves to, leaving the content tag
		// alone, so the failure is attributable to the pin.
		setManifest(t, fr, PinTag(uri), []byte("{not json"))
		if _, err := c.PinnedDigest("acme.org/thing", uri); err == nil {
			t.Error("a manifest that does not parse was accepted")
		}
	})

	t.Run("a pinned manifest with the wrong number of layers", func(t *testing.T) {
		fr := newFakeRegistry(t, false)
		defer fr.close()
		c, _ := NewOCIClient(fr.base("go-zpkg/sources"))
		if _, err := c.PushSource("acme.org/thing", data, uri); err != nil {
			t.Fatal(err)
		}
		man := ocispec.Manifest{
			MediaType: ocispec.MediaTypeImageManifest,
			Config:    ocispec.DescriptorEmptyJSON,
			Layers:    []ocispec.Descriptor{},
		}
		b, err := json.Marshal(man)
		if err != nil {
			t.Fatal(err)
		}
		setManifest(t, fr, PinTag(uri), b)
		if _, err := c.PinnedDigest("acme.org/thing", uri); err == nil {
			t.Error("a manifest with no layer was accepted")
		}
	})

	t.Run("a pin whose layer is not sha256", func(t *testing.T) {
		fr := newFakeRegistry(t, false)
		defer fr.close()
		c, _ := NewOCIClient(fr.base("go-zpkg/sources"))
		if _, err := c.PushSource("acme.org/thing", data, uri); err != nil {
			t.Fatal(err)
		}
		man := ocispec.Manifest{
			MediaType: ocispec.MediaTypeImageManifest,
			Config:    ocispec.DescriptorEmptyJSON,
			Layers: []ocispec.Descriptor{{
				MediaType: MediaSourceLayer,
				// A digest bk cannot compare against what fetch computed. It
				// must be refused rather than returned as if it were a sha256.
				Digest: digest.Digest("sha512:" + strings.Repeat("ab", 64)),
				Size:   int64(len(data)),
			}},
		}
		b, err := json.Marshal(man)
		if err != nil {
			t.Fatal(err)
		}
		setManifest(t, fr, PinTag(uri), b)
		if _, err := c.PinnedDigest("acme.org/thing", uri); err == nil {
			t.Error("a non-sha256 layer digest was returned as if it were one")
		}
	})

	t.Run("tagging the url fails", func(t *testing.T) {
		fr := newFakeRegistry(t, false)
		defer fr.close()
		c, _ := NewOCIClient(fr.base("go-zpkg/sources"))
		n := 0
		fr.hook = func(r *http.Request) (int, bool) {
			_, verb, ref := splitV2(r.URL.Path)
			// Let the content tag through and break the URL tag, so the
			// failure is attributable to the pin and not to the push.
			if verb == "manifests" && r.Method == http.MethodPut && strings.HasPrefix(ref, "url-") {
				n++
				return 500, true
			}
			return 0, false
		}
		_, err := c.PushSource("acme.org/thing", data, uri)
		if err == nil {
			t.Fatal("push reported success although the pin could not be written")
		}
		if !strings.Contains(err.Error(), "tag source url") {
			t.Errorf("error = %v; want it to name the url tag", err)
		}
		if n == 0 {
			t.Error("the hook never saw a url- tag, so this proved nothing")
		}
	})
}

// setManifest replaces the bytes the fake registry serves for one tag,
// leaving every other tag alone. The existing failure tests overwrite EVERY
// manifest, which cannot distinguish a broken pin from a broken archive.
func setManifest(t *testing.T, fr *fakeRegistry, tag string, body []byte) {
	t.Helper()
	n := 0
	for k := range fr.manifests {
		if strings.HasSuffix(k, "|"+tag) {
			fr.manifests[k] = body
			n++
		}
	}
	if n != 1 {
		t.Fatalf("replaced %d manifests for tag %s; want exactly 1 — the fixture moved", n, tag)
	}
}
