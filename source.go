package artifact

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	orascontent "oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/errdef"
)

// A source mirror: the bytes an artifact was BUILT FROM, stored in a registry so a
// rebuild does not depend on an upstream host answering.
//
// This matters more than "upstream might go away". 57% of the pkgx pantry is
// built from GitHub `/archive/refs/tags/…` tarballs, which are GENERATED on
// request rather than stored: of 165 such URLs probed, not one advertises a
// Content-Length, because the object does not exist until someone asks. The
// compression pipeline behind them has changed before and every checksum in the
// ecosystem changed with it. A mirror of those is not a copy of anything — it is
// the first and only stored artefact those sources have ever had.
//
// Addressed by CONTENT, not by URL. `SourceTag` turns the sha256 the fetcher
// already computed into the tag, so the digest recorded in an artifact's SBOM IS
// the address of the bytes, and nothing has to be named twice or kept in step.
const (
	// MediaSourceLayer marks the stored archive. Deliberately codec-agnostic:
	// what is stored is the upstream bytes exactly as they arrived, whatever
	// they were compressed with, because changing a byte would change the digest
	// that is the whole point.
	//
	// ⛔ `vnd.go-zpkg.*`, not `vnd.pkgx.*`. Upstream pkgx defines no OCI
	// artifacts at all — it serves plain tarballs from dist.pkgx.dev — so
	// these names were minted by us inside a vendor namespace belonging to
	// somebody who never agreed to them. See oci.go for the measurement and
	// the read-compatibility rule.
	MediaSourceLayer = "application/vnd.go-zpkg.source.layer.v1"
	// ArtifactTypeSource marks a source manifest, so a registry listing can tell
	// these from artifacts.
	ArtifactTypeSource = "application/vnd.go-zpkg.source"
)

// AnnotationSourceURI records where the bytes came from. It is provenance,
// not an address: two URLs can serve the same bytes and the digest is what
// identifies them. Declared in annotations.go, read through Annotation().

// ErrSourceAbsent is returned by PullSource when the store has no such digest.
var ErrSourceAbsent = errors.New("artifact: source not in the mirror")

// SourceTag is the registry tag for a source digest. OCI tags cannot contain a
// colon, so `sha256:abcd…` becomes `sha256-abcd…` — the same substitution the
// referrers fallback uses.
func SourceTag(sha256hex string) string { return "sha256-" + sha256hex }

// PinTag is the registry tag recording WHICH digest a URL served.
//
// SourceTag addresses bytes; this addresses a *source*. The mirror is
// content-addressed, which is right for storage and useless for the question
// that matters on a rebuild: "is this the same tarball the last build got?"
// Nothing in the pkgx recipe format answers it — exactly one recipe of 904
// carries a `sha:` at all, and that one points at a `.sha256` served by the
// same host, so it detects corruption and not substitution.
//
// A URL is hashed rather than escaped because an OCI tag may hold only
// [A-Za-z0-9_.-], at most 128 characters, and a distributable URL has slashes,
// colons and percent-escapes and is routinely longer than that.
func PinTag(uri string) string {
	sum := sha256.Sum256([]byte(uri))
	return "url-" + hex.EncodeToString(sum[:])
}

// SourceDigest is the sha256 of data in lowercase hex, the form SourceTag takes
// and the form an artifact's SBOM records.
func SourceDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// PushSource stores one source archive under project:sha256-<digest>.
//
// Idempotent by construction: the tag IS the content, so re-pushing the same
// bytes writes the same manifest. uri is recorded as an annotation for whoever
// later asks where this came from.
func (c *OCIClient) PushSource(project string, data []byte, uri string) (ocispec.Descriptor, error) {
	ctx := context.Background()
	repo, err := c.repository(project)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	layerDesc := orascontent.NewDescriptorFromBytes(MediaSourceLayer, data)
	if err := pushIfAbsent(ctx, repo, layerDesc, data); err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("push source layer: %w", err)
	}
	ann := map[string]string{ocispec.AnnotationCreated: "1970-01-01T00:00:00Z"}
	if uri != "" {
		ann[AnnotationSourceURI] = uri
	}
	manDesc, err := oras.PackManifest(ctx, repo, oras.PackManifestVersion1_1, ArtifactTypeSource,
		oras.PackManifestOptions{
			Layers:              []ocispec.Descriptor{layerDesc},
			ManifestAnnotations: ann,
		})
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("pack source manifest: %w", err)
	}
	if _, err := oras.Tag(ctx, repo, manDesc.Digest.String(), SourceTag(SourceDigest(data))); err != nil {
		return manDesc, fmt.Errorf("tag source manifest: %w", err)
	}
	// A second tag, by URL, so the store can later answer what this URL
	// served. It points at the SAME manifest: no extra blob, and the pin
	// cannot drift from the bytes it describes.
	//
	// This overwrites an existing pin on purpose. The decision about whether
	// the digest MAY change belongs to the caller, which checks PinnedDigest
	// before pushing; a store that refused here would make a legitimate
	// version bump unstorable.
	if uri != "" {
		if _, err := oras.Tag(ctx, repo, manDesc.Digest.String(), PinTag(uri)); err != nil {
			return manDesc, fmt.Errorf("tag source url: %w", err)
		}
	}
	return manDesc, nil
}

// PinnedDigest returns the sha256 the store last recorded for a URL, or
// ErrSourceAbsent when it has never seen it.
//
// This is the read half of trust-on-first-use. The first fetch of a URL
// records what it served; every later fetch compares. It does not make an
// upstream trustworthy — it makes a CHANGE visible, which is the part nobody
// had.
//
// It reads the digest off the manifest's layer rather than parsing it out of
// the tag, so a pin can never claim a digest the stored bytes do not have.
func (c *OCIClient) PinnedDigest(project, uri string) (string, error) {
	ctx := context.Background()
	repo, err := c.repository(project)
	if err != nil {
		return "", err
	}
	manDesc, err := repo.Resolve(ctx, PinTag(uri))
	if err != nil {
		if errors.Is(err, errdef.ErrNotFound) {
			return "", fmt.Errorf("%w: %s %s", ErrSourceAbsent, project, uri)
		}
		return "", err
	}
	manBytes, err := orascontent.FetchAll(ctx, repo, manDesc)
	if err != nil {
		return "", err
	}
	var man ocispec.Manifest
	if err := json.Unmarshal(manBytes, &man); err != nil {
		return "", fmt.Errorf("pinned manifest for %s: %w", uri, err)
	}
	if len(man.Layers) != 1 {
		return "", fmt.Errorf("pinned manifest for %s: %d layers, want 1", uri, len(man.Layers))
	}
	d := man.Layers[0].Digest
	if d.Algorithm() != "sha256" {
		return "", fmt.Errorf("pinned manifest for %s: layer digest is %s, want sha256", uri, d.Algorithm())
	}
	return d.Encoded(), nil
}

// PullSource fetches the archive stored for a sha256 digest, and VERIFIES that
// what came back hashes to it.
//
// The verification is not ceremony. A mirror exists so a rebuild need not trust
// the upstream host; trusting the mirror instead would move the problem rather
// than solve it. The digest is checked against the one the caller asked for, so
// a wrong or tampered blob is an error rather than a different build.
func (c *OCIClient) PullSource(project, sha256hex string) ([]byte, error) {
	ctx := context.Background()
	repo, err := c.repository(project)
	if err != nil {
		return nil, err
	}
	manDesc, err := repo.Resolve(ctx, SourceTag(sha256hex))
	if err != nil {
		if errors.Is(err, errdef.ErrNotFound) {
			return nil, fmt.Errorf("%w: %s %s", ErrSourceAbsent, project, sha256hex)
		}
		return nil, err
	}
	manBytes, err := orascontent.FetchAll(ctx, repo, manDesc)
	if err != nil {
		return nil, err
	}
	var man ocispec.Manifest
	if err := json.Unmarshal(manBytes, &man); err != nil {
		return nil, fmt.Errorf("source manifest %s: %w", sha256hex, err)
	}
	if len(man.Layers) != 1 {
		return nil, fmt.Errorf("source manifest %s: %d layers, want 1", sha256hex, len(man.Layers))
	}
	data, err := orascontent.FetchAll(ctx, repo, man.Layers[0])
	if err != nil {
		return nil, err
	}
	if got := SourceDigest(data); got != sha256hex {
		return nil, fmt.Errorf("source %s: mirror returned bytes hashing to %s", sha256hex, got)
	}
	return data, nil
}

// HasSource reports whether the store already holds a digest, without fetching
// it — what a populate step asks before uploading megabytes for nothing.
func (c *OCIClient) HasSource(project, sha256hex string) (bool, error) {
	ctx := context.Background()
	repo, err := c.repository(project)
	if err != nil {
		return false, err
	}
	if _, err := repo.Resolve(ctx, SourceTag(sha256hex)); err != nil {
		if errors.Is(err, errdef.ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}
