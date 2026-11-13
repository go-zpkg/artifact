package artifact

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
)

// BlobFile is a staged blob: on disk where there is a filesystem, in memory
// where there is not. Close releases it — on disk that means REMOVING it, since
// the caller owns a temporary and not a cache entry.
type BlobFile struct {
	io.ReadSeeker
	// Digest is the "sha256:…" of the staged bytes, computed as they were
	// written. It is what the signature is checked against, so the tarball
	// never has to be read back — let alone kept — to verify it.
	Digest string

	// release is how this particular staging is undone. A browser has no
	// filesystem, so a blob there is held in memory and there is nothing to
	// delete; the field keeps that difference out of every caller.
	release func() error
}

// Close releases the staged blob.
func (b *BlobFile) Close() error { return b.release() }

// writeBlobFrom requests the blob from byte offset and appends what it manages
// to read to f, returning how many bytes this attempt wrote. restarted reports
// that the registry ignored the Range header (answering 200 with the whole
// blob), in which case f was truncated first and the count replaces — rather
// than adds to — what the caller had.
func (c *OCIClient) writeBlobFrom(ctx context.Context, url string, offset int64, f *os.File) (n int64, restarted bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, false, err
	}
	if offset > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", offset))
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return 0, false, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		restarted = offset > 0
		if err := fTruncate(f, 0); err != nil {
			return 0, restarted, err
		}
		if _, err := fSeek(f, 0, io.SeekStart); err != nil {
			return 0, restarted, err
		}
	case http.StatusPartialContent:
		if _, err := fSeek(f, offset, io.SeekStart); err != nil {
			return 0, false, err
		}
	default:
		return 0, false, fmt.Errorf("blob request: unexpected status %s", resp.Status)
	}
	n, err = ioCopy(f, resp.Body)
	return n, restarted, err
}

// Seams: staging a blob touches the filesystem, and the tests drive these to
// exercise the failure paths a real disk will not produce on demand.
var (
	osCreateTemp = os.CreateTemp
	osMkdirAll   = os.MkdirAll
	osRemove     = os.Remove
	ioCopy       = io.Copy
	ioReadAll    = io.ReadAll

	// Seek and Truncate on a real file fail only when the filesystem is in a
	// state a test cannot arrange (a device error, a revoked fd), and their
	// handling is what keeps a resumed transfer from appending at the wrong
	// offset. Seams, so that handling is exercised rather than assumed.
	fSeek     = (*os.File).Seek
	fTruncate = (*os.File).Truncate
)

// scheme is the URL scheme this client talks.
func (c *OCIClient) scheme() string {
	if c.plainHTTP {
		return "http"
	}
	return "https"
}
