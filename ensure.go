package artifact

import (
	"context"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// IndexLists reports whether the version tag's index carries desc.
//
// An artifact can be pushed, valid and signed — and absent from the index, because
// publishing the index is a read-modify-write on one mutable tag that several
// publishers race on. Nothing about the artifact itself says so; only the index
// does, which is why this takes the descriptor the push returned rather than
// trying to discover it. Discovery would go through the very index in question.
func (c *OCIClient) IndexLists(project, ver string, desc ocispec.Descriptor) (bool, error) {
	repo, err := c.repository(project)
	if err != nil {
		return false, err
	}
	return indexHasManifest(c.fetchOrNewIndex(context.Background(), repo, ver), desc), nil
}

// EnsureIndexed puts desc back into the version tag's index when a racing
// publisher dropped it, and reports whether it had to.
//
// The per-push reconcile in mergePlatformIntoIndex confirms its write twice with
// a settle window between, which catches a racer landing just behind it. It
// cannot catch one that lands later still — after this publisher has moved on to
// the next package, or exited. This is the pass for that: run it once the whole
// batch is done, when the other publishers have finished too and a repair
// sticks.
//
// Re-merging (rather than re-writing) is what keeps the repair safe: it starts
// from the index as it now stands, so a platform some other publisher added in
// the meantime survives.
func (c *OCIClient) EnsureIndexed(project, ver string, desc ocispec.Descriptor) (repaired bool, err error) {
	// One repository lookup for both halves. Calling IndexLists here and then
	// resolving the repository again would add an error path that cannot happen
	// — and an unreachable branch is an untested one.
	repo, err := c.repository(project)
	if err != nil {
		return false, err
	}
	ctx := context.Background()
	if indexHasManifest(c.fetchOrNewIndex(ctx, repo, ver), desc) {
		return false, nil
	}
	if err := c.mergePlatformIntoIndex(ctx, repo, ver, desc); err != nil {
		return false, err
	}
	return true, nil
}
