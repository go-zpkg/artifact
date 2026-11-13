package artifact

// attest.go copies a published artifact's attestations between registries.
//
// A mirror that carries the artifact but not its SBOM, provenance and signature
// silently downgrades every consumer behind it: verification is fail-closed by
// default, so the copy is either refused or, worse, run with verification off.
// A local pull-through cache is only useful if what comes out of it is still
// the artefact the factory signed.

import (
	"context"
	"encoding/json"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	orascontent "oras.land/oras-go/v2/content"
)

// FetchAttestations returns a published artifact's attestations, ready to be
// pushed to another registry with PushWithReferrersAnnotated, along with the
// per-platform manifest's annotations (a glibc artifact's minimum kernel, a
// flavored build's glibc version) so those survive the copy too.
func (c *OCIClient) FetchAttestations(project, ver, osn, arch string) ([]Referrer, map[string]string, error) {
	ctx := context.Background()
	repo, err := c.repository(project)
	if err != nil {
		return nil, nil, err
	}
	desc, man, err := c.resolvePlatform(ctx, repo, project, ver, osn, arch)
	if err != nil {
		return nil, nil, err
	}
	descs, err := c.Referrers(project, desc)
	if err != nil {
		return nil, nil, err
	}
	refs := make([]Referrer, 0, len(descs))
	for _, d := range descs {
		// A referrer is itself a MANIFEST: its artifact type identifies the kind,
		// its single layer holds the payload (an SBOM, a provenance statement, a
		// simple-signing document) and its annotations carry the cosign
		// signature. Copying the payload and the annotations is what preserves
		// verifiability — the signature covers the PAYLOAD, so re-packing it into
		// an equivalent manifest at the destination keeps it valid.
		raw, err := orascontent.FetchAll(ctx, repo, d)
		if err != nil {
			return nil, nil, err
		}
		ref, ok, err := referrerFrom(raw, d.ArtifactType, func(l ocispec.Descriptor) ([]byte, error) {
			return orascontent.FetchAll(ctx, repo, l)
		})
		if err != nil {
			return nil, nil, err
		}
		if ok {
			refs = append(refs, ref)
		}
	}
	return refs, man.Annotations, nil
}

// referrerFrom turns a referrer MANIFEST into the Referrer a push needs: its
// single layer is the payload (an SBOM, a provenance statement, a simple-signing
// document) and its annotations carry the cosign signature. The signature covers
// the PAYLOAD, so re-packing these into an equivalent manifest at the
// destination keeps the artifact verifiable there.
//
// It reports ok=false for a referrer with no payload to carry — an empty
// attestation is skipped rather than invented.
func referrerFrom(raw []byte, artifactType string, fetch func(ocispec.Descriptor) ([]byte, error)) (Referrer, bool, error) {
	var rm ocispec.Manifest
	if err := json.Unmarshal(raw, &rm); err != nil {
		return Referrer{}, false, err
	}
	if len(rm.Layers) == 0 {
		return Referrer{}, false, nil
	}
	payload, err := fetch(rm.Layers[0])
	if err != nil {
		return Referrer{}, false, err
	}
	return Referrer{
		ArtifactType: artifactType,
		MediaType:    rm.Layers[0].MediaType,
		Blob:         payload,
		Annotations:  rm.Annotations,
	}, true, nil
}
