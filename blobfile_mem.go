//go:build js

package artifact

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// fetchBlobFile stages a blob IN MEMORY, because a browser has no filesystem.
//
// The disk path exists for a reason that does not apply here: llvm.org is a
// 1.7 GiB artifact, and holding one in a []byte made the largest package in the
// catalogue the memory floor of every install. In a page the constraint is the
// opposite — os.CreateTemp answers "not implemented on js", which is exactly
// how this surfaced:
//
//	blob sha256:4478…: temp file: open /tmp/artifact-blob-…: not implemented on js
//
// and the packages a browser installs are wasm modules of kilobytes to a few
// megabytes, not compilers. Trading disk for memory is the right way round on
// this host, and it is the only way round available.
//
// Retry and resume are deliberately NOT reproduced. They earn their keep on a
// gigabyte over a long connection; here fetch already owns the transfer, and a
// second implementation of resume — one that no test on this host could
// exercise against a real cut — would be more risk than the case is worth. A
// failed fetch is reported as itself.
func (c *OCIClient) fetchBlobFile(ctx context.Context, project string, desc ocispec.Descriptor) (*BlobFile, error) {
	url := c.scheme() + "://" + c.host + "/v2/" + c.repoName(project) + "/blobs/" + desc.Digest.String()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("blob %s: %w", desc.Digest, err)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("blob %s: %w", desc.Digest, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("blob request: unexpected status %s", resp.Status)
	}
	data, err := ioReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("blob %s: %w", desc.Digest, err)
	}
	if desc.Size > 0 && int64(len(data)) != desc.Size {
		return nil, fmt.Errorf("blob %s: got %d of %d bytes: %w", desc.Digest, len(data), desc.Size, io.ErrUnexpectedEOF)
	}
	sum := sha256.Sum256(data)
	got := "sha256:" + hex.EncodeToString(sum[:])
	if got != desc.Digest.String() {
		return nil, fmt.Errorf("blob digest mismatch: got %s, want %s", got, desc.Digest)
	}
	return &BlobFile{
		ReadSeeker: bytes.NewReader(data),
		Digest:     got,
		release:    func() error { return nil },
	}, nil
}
