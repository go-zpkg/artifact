//go:build js

package artifact

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// memBlobFixture serves a blob and returns the client and descriptor for it.
func memBlobFixture(t *testing.T, body []byte) (*OCIClient, ocispec.Descriptor) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	t.Cleanup(srv.Close)
	sum := sha256.Sum256(body)
	c, err := NewOCIClient("oci://" + strings.TrimPrefix(srv.URL, "http://") + "/go-zpkg/artifacts")
	if err != nil {
		t.Fatal(err)
	}
	return c, ocispec.Descriptor{
		Digest: digest.Digest("sha256:" + hex.EncodeToString(sum[:])),
		Size:   int64(len(body)),
	}
}

// TestMemoryStagingServesTheBlob: a browser has no filesystem, and the disk
// staging says so plainly — "temp file: open /tmp/artifact-blob-…: not
// implemented on js". Here the blob is held in memory instead, and everything
// downstream (digest, extraction, signature) is unchanged.
func TestMemoryStagingServesTheBlob(t *testing.T) {
	body := []byte(strings.Repeat("artifact-bytes ", 512))
	c, desc := memBlobFixture(t, body)

	f, err := c.fetchBlobFile(context.Background(), "lib.org", desc)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	got, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(body) {
		t.Fatalf("read %d bytes, want %d", len(got), len(body))
	}
	if f.Digest != desc.Digest.String() {
		t.Errorf("Digest = %q, want %q", f.Digest, desc.Digest)
	}
	// Close releases; on this host there is nothing to delete, and it must not
	// pretend otherwise by failing.
	if err := f.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// TestMemoryStagingRejectsAWrongDigest keeps the guarantee that matters: the
// host changed, the verification did not.
func TestMemoryStagingRejectsAWrongDigest(t *testing.T) {
	c, desc := memBlobFixture(t, []byte("the real bytes"))
	desc.Digest = digest.Digest("sha256:" + strings.Repeat("0", 64))

	if _, err := c.fetchBlobFile(context.Background(), "lib.org", desc); err == nil ||
		!strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("err = %v, want a digest mismatch", err)
	}
}

// TestMemoryStagingRejectsAShortBody: a truncated transfer must not become a
// valid-looking artifact.
func TestMemoryStagingRejectsAShortBody(t *testing.T) {
	body := []byte("full body here")
	c, desc := memBlobFixture(t, body)
	desc.Size = int64(len(body)) + 10 // the registry promised more than it sent

	if _, err := c.fetchBlobFile(context.Background(), "lib.org", desc); err == nil ||
		!strings.Contains(err.Error(), "of "+"24"+" bytes") {
		t.Fatalf("err = %v, want a short-body rejection", err)
	}
}
