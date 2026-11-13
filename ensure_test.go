package artifact

import (
	"context"
	"testing"

	"encoding/json"
	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	oras "oras.land/oras-go/v2"
)

// clobberIndexEmpty replaces a version tag's index with an empty one, the way a
// racing publisher that read a stale index does.
func clobberIndexEmpty(t *testing.T, c *OCIClient, project, ver string) {
	t.Helper()
	repo, err := c.repository(project)
	if err != nil {
		t.Fatal(err)
	}
	empty := ocispec.Index{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ocispec.MediaTypeImageIndex}
	b, _ := json.Marshal(empty)
	if _, err := oras.TagBytes(context.Background(), repo, ocispec.MediaTypeImageIndex, b, ver); err != nil {
		t.Fatal(err)
	}
}

// TestEnsureIndexedRepairsALateClobber is the pass that catches what the
// per-push reconcile cannot: a racer that lands after the publisher moved on.
func TestEnsureIndexedRepairsALateClobber(t *testing.T) {
	t.Setenv("ZPKG_VERIFY", "0")
	fr := newFakeRegistry(t, false)
	defer fr.close()
	c, err := NewOCIClient(fr.base("go-zpkg/artifacts"))
	if err != nil {
		t.Fatal(err)
	}
	desc, err := c.PushWithReferrers("late.test", "1.0.0", "linux", "aarch64", makeGzTarball("x"), ".tar.gz", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Everything is fine right after the push...
	if ok, err := c.IndexLists("late.test", "1.0.0", desc); err != nil || !ok {
		t.Fatalf("listed = %v, err = %v", ok, err)
	}
	// ...then a racer clobbers the tag, long after this publisher checked.
	clobberIndexEmpty(t, c, "late.test", "1.0.0")
	if ok, _ := c.IndexLists("late.test", "1.0.0", desc); ok {
		t.Fatal("the clobber did not take, so nothing is being tested")
	}

	repaired, err := c.EnsureIndexed("late.test", "1.0.0", desc)
	if err != nil {
		t.Fatal(err)
	}
	if !repaired {
		t.Fatal("EnsureIndexed did not report the repair")
	}
	if ok, err := c.IndexLists("late.test", "1.0.0", desc); err != nil || !ok {
		t.Fatalf("still missing after repair: %v %v", ok, err)
	}
}

// TestEnsureIndexedIsANoOpWhenIntact: the pass runs over every artifact a batch
// published, so the common case must cost one read and change nothing.
func TestEnsureIndexedIsANoOpWhenIntact(t *testing.T) {
	t.Setenv("ZPKG_VERIFY", "0")
	fr := newFakeRegistry(t, false)
	defer fr.close()
	c, err := NewOCIClient(fr.base("go-zpkg/artifacts"))
	if err != nil {
		t.Fatal(err)
	}
	desc, err := c.PushWithReferrers("intact.test", "1.0.0", "linux", "aarch64", makeGzTarball("y"), ".tar.gz", nil)
	if err != nil {
		t.Fatal(err)
	}

	repaired, err := c.EnsureIndexed("intact.test", "1.0.0", desc)
	if err != nil {
		t.Fatal(err)
	}
	if repaired {
		t.Error("reported a repair on an intact index")
	}
}

// TestEnsureIndexedPreservesAnotherPlatform: repairing must RE-MERGE, not
// re-write. A platform some other publisher added while we were away has to
// survive, or the repair becomes the next clobber.
func TestEnsureIndexedPreservesAnotherPlatform(t *testing.T) {
	t.Setenv("ZPKG_VERIFY", "0")
	fr := newFakeRegistry(t, false)
	defer fr.close()
	c, err := NewOCIClient(fr.base("go-zpkg/artifacts"))
	if err != nil {
		t.Fatal(err)
	}
	mine, err := c.PushWithReferrers("both.test", "1.0.0", "linux", "aarch64", makeGzTarball("a"), ".tar.gz", nil)
	if err != nil {
		t.Fatal(err)
	}
	clobberIndexEmpty(t, c, "both.test", "1.0.0")
	// A peer publishes the other arch into the now-empty index.
	theirs, err := c.PushWithReferrers("both.test", "1.0.0", "linux", "x86-64", makeGzTarball("b"), ".tar.gz", nil)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := c.EnsureIndexed("both.test", "1.0.0", mine); err != nil {
		t.Fatal(err)
	}

	for name, d := range map[string]ocispec.Descriptor{"ours": mine, "theirs": theirs} {
		ok, err := c.IndexLists("both.test", "1.0.0", d)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			t.Errorf("%s platform lost by the repair", name)
		}
	}
}

// TestEnsureIndexedReportsABadRepo: an unusable project name surfaces rather
// than being read as "already indexed".
func TestEnsureIndexedReportsABadRepo(t *testing.T) {
	c, err := NewOCIClient("oci://example.test/x")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.IndexLists("bad\nname", "1.0.0", ocispec.Descriptor{}); err == nil {
		t.Error("IndexLists accepted an unusable repo name")
	}
	if _, err := c.EnsureIndexed("bad\nname", "1.0.0", ocispec.Descriptor{}); err == nil {
		t.Error("EnsureIndexed accepted an unusable repo name")
	}
}

// TestEnsureIndexedSurfacesAFailedRepair: a repair that cannot land must say
// so. Silently returning "not repaired" would turn a corrupt index into a
// clean-looking run.
func TestEnsureIndexedSurfacesAFailedRepair(t *testing.T) {
	t.Setenv("ZPKG_VERIFY", "0")
	fr := newFakeRegistry(t, false)
	defer fr.close()
	c, err := NewOCIClient(fr.base("go-zpkg/artifacts"))
	if err != nil {
		t.Fatal(err)
	}
	desc, err := c.PushWithReferrers("fail.test", "1.0.0", "linux", "aarch64", makeGzTarball("z"), ".tar.gz", nil)
	if err != nil {
		t.Fatal(err)
	}
	clobberIndexEmpty(t, c, "fail.test", "1.0.0")

	oldA := indexRetryAttempts
	indexRetryAttempts = 0 // no attempt can succeed
	defer func() { indexRetryAttempts = oldA }()

	if _, err := c.EnsureIndexed("fail.test", "1.0.0", desc); err == nil {
		t.Fatal("a failed repair was reported as success")
	}
}
