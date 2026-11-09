package bottle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	oras "oras.land/oras-go/v2"
	orascontent "oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/registry/remote"
)

// ErrSameNamespace means a copy was asked for between one namespace and
// itself. It is not a no-op worth tolerating: a copy that reports success
// without moving anything is exactly how an empty destination passes for a
// full one, which is the failure this whole operation exists to avoid.
var ErrSameNamespace = errors.New("bottle: source and destination are the same namespace")

// CopyPublished copies one published tag of one project from src to dst,
// preserving digests, together with everything that hangs off it: the cosign
// signature manifests and the SBOM / provenance / VEX attestations.
//
// ⛔⛔ THIS EXISTS BECAUSE A REGISTRY NAMESPACE CANNOT BE RENAMED. GitHub's
// container packages are org-scoped and do not follow a repository transfer:
// when every repository moved from go-pkgx to go-zpkg, every bottle stayed.
// DistBase was rewritten to match and v0.64.0 through v0.68.0 shipped a fleet
// pointing at an empty registry (see TestTheDefaultRegistryHoldsBottles, which
// is the gate that came out of it). The bottles have to be PUT in the new
// namespace before anything may name it, and putting them there is this.
//
// ⛔ EXTENDED copy, not Copy, and the difference is the whole point. oras.Copy
// walks a manifest and its blobs — it would move the bottle and leave its
// signature behind, because a signature is not a child of the manifest but a
// REFERRER to it. A bottle that arrives unverifiable is worse than one that
// does not arrive: `zpkgs install` verifies by default, so the first would be
// a silent trust failure at install time and the second is a 404 at copy time.
//
// Digests survive by construction. ExtendedCopy moves content by descriptor,
// so the manifest digest on the far side is the same string, and the signature
// payload commits to exactly that (payloadCommitsTo, verify.go:185 — it checks
// critical.image.docker-manifest-digest and nothing about WHERE the bottle
// lives). That is why this is a copy and not a re-sign.
//
// It streams: ORAS fetches each blob and pushes it, so a 1 GB bottle does not
// become 1 GB of resident memory. Nothing here holds a tarball.
//
// The tag is carried over unchanged, deliberately. A copy that renamed a
// version would make the two namespaces disagree about what is published, and
// the catalogue is built by listing tags.
func CopyPublished(ctx context.Context, src, dst *OCIClient, project, tag string) (ocispec.Descriptor, error) {
	if src == nil || dst == nil {
		return ocispec.Descriptor{}, errors.New("bottle: nil OCI client")
	}
	if tag == "" {
		return ocispec.Descriptor{}, errors.New("bottle: no tag to copy")
	}
	if src.host == dst.host && src.repoBase == dst.repoBase {
		return ocispec.Descriptor{}, fmt.Errorf("%w: %s/%s", ErrSameNamespace, src.host, src.repoBase)
	}

	// repository() validates the project name before it is concatenated into a
	// reference, on both sides — a `..` is nobody's project in either namespace.
	from, err := src.repository(project)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	to, err := dst.repository(project)
	if err != nil {
		return ocispec.Descriptor{}, err
	}

	fail := func(what string, err error) (ocispec.Descriptor, error) {
		return ocispec.Descriptor{}, fmt.Errorf("bottle: copy %s:%s (%s) from %s to %s: %w",
			project, tag, what, src.repoBase, dst.repoBase, err)
	}

	// ⛔⛔ EACH PLATFORM MANIFEST IS COPIED BY DIGEST FIRST, AND THE REASON IS
	// THE DEFECT THIS FUNCTION WAS WRITTEN WITH.
	//
	// ExtendedCopy finds the ROOTS of the graph by walking predecessors up from
	// the node it was given, then copies downward from each root. A version tag
	// resolves to an INDEX, and nothing refers to an index — so the index is
	// already a root, no predecessors are collected, and the walk goes straight
	// down to the platform manifests and their blobs.
	//
	// A signature does not hang off the index. It is a referrer of a PLATFORM
	// manifest, i.e. a predecessor of one of the index's children, and the
	// downward walk never looks for predecessors again. Measured, not reasoned:
	// the first version of this copied the tag alone, and the destination then
	// answered "unsigned (no signature referrer)" to VerifyBottle while holding
	// a byte-identical bottle.
	//
	// Starting from a platform manifest instead makes its signature a root, so
	// it is copied with everything else.
	for _, d := range src.copyablePlatforms(ctx, from, tag) {
		ref := d.Digest.String()
		if _, err := oras.ExtendedCopy(ctx, from, ref, to, ref, oras.DefaultExtendedCopyOptions); err != nil {
			return fail("platform "+ref, err)
		}
	}

	// The `<ver>--<os>-<arch>` tags, which is how platformManifests lists what a
	// version publishes. Without them the destination still HOLDS every bottle
	// and cannot say which platforms it has, so an index repair there would
	// compose from nothing.
	for _, t := range src.platformTags(ctx, from, tag) {
		if _, err := oras.ExtendedCopy(ctx, from, t, to, t, oras.DefaultExtendedCopyOptions); err != nil {
			return fail("tag "+t, err)
		}
	}

	// The version tag last: its children are already present, so this is the
	// step that makes the version resolvable under its own name.
	desc, err := oras.ExtendedCopy(ctx, from, tag, to, tag, oras.DefaultExtendedCopyOptions)
	if err != nil {
		return fail("version tag", err)
	}
	return desc, nil
}

// copyablePlatforms lists the per-platform manifests a version tag points at,
// from the index itself rather than from the platform tags — an older publish
// has entries in the index and no `--` tags at all, and a copy that skipped
// those would move the index and leave the bottles it names behind.
//
// It reports nothing rather than an error when the tag is a plain manifest and
// not an index: there are then no children to copy first, and the version-tag
// copy below already starts at the manifest, so its referrers are roots.
func (c *OCIClient) copyablePlatforms(ctx context.Context, repo *remote.Repository, tag string) []ocispec.Descriptor {
	desc, rc, err := repo.FetchReference(ctx, tag)
	if err != nil {
		return nil
	}
	body, err := orascontent.ReadAll(rc, desc)
	rc.Close()
	if err != nil {
		return nil
	}
	var idx ocispec.Index
	if json.Unmarshal(body, &idx) != nil {
		return nil
	}
	return idx.Manifests
}

// platformTags lists the `<ver>--<os>-<arch>` tags of one version. A registry
// that will not list tags yields nothing rather than an error, matching
// platformManifests: the copy then still moves every manifest, because those
// come from the index.
func (c *OCIClient) platformTags(ctx context.Context, repo *remote.Repository, ver string) []string {
	prefix := ver + "--"
	var out []string
	_ = repo.Tags(ctx, "", func(page []string) error {
		for _, t := range page {
			if strings.HasPrefix(t, prefix) {
				out = append(out, t)
			}
		}
		return nil
	})
	return out
}
