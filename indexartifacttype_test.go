package artifact

import (
	"context"
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// TestEveryIndexEntryKeepsItsArtifactType: recomposing the index from the
// per-platform tags must not impoverish the entries it recomposes.
//
// `repo.Resolve` returns a BARE descriptor — mediaType, digest, size. The
// composition already knows this and restores Platform from the tag, but
// ArtifactType and the annotations were left empty, and upsertPlatform then
// DROPS the complete entry in favour of the bare one. Every platform except
// the one being pushed lost `artifactType` on every publish, so an index
// stopped saying which of its entries are artifacts.
//
// Measured on the live registry before the fix: lloyd.github.io/yajl and
// gnu.org/wget (two platform tags) had lost it on one entry, nodejs.org
// (three) on two, and libssh.org — which has NO platform tags, so its index is
// never recomposed — had lost it on none.
func TestEveryIndexEntryKeepsItsArtifactType(t *testing.T) {
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
	idx := c.fetchOrNewIndex(context.Background(), repo, "1.2.3")
	if len(idx.Manifests) != 2 {
		t.Fatalf("index lists %d platform(s), want 2", len(idx.Manifests))
	}
	for _, m := range idx.Manifests {
		if m.ArtifactType != ArtifactType {
			t.Errorf("index entry %s/%s: artifactType %q, want %q",
				m.Platform.OS, m.Platform.Architecture, m.ArtifactType, ArtifactType)
		}
		// The created annotation travelled out of the same hole: it is what
		// pins an artifact's timestamp to the epoch, and a recomposed entry that
		// lost it reads as "no reproducible timestamp recorded".
		if got := m.Annotations[ocispec.AnnotationCreated]; got != "1970-01-01T00:00:00Z" {
			t.Errorf("index entry %s/%s: created %q, want %q",
				m.Platform.OS, m.Platform.Architecture, got, "1970-01-01T00:00:00Z")
		}
	}
}
