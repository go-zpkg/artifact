// The resume/retry behaviour under test belongs to the DISK staging; the
// browser build holds a blob in memory and lets fetch own the transfer.
//go:build !js

package artifact

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// blobServer serves payload, cutting each response short after cut bytes for
// the first cuts responses — the way a registry, CDN or container-VM network
// drops a long transfer.
type blobServer struct {
	payload  []byte
	cut      int
	cuts     int
	requests []string // the Range header of each request, "" when absent
	ignore   bool     // answer 200 with the whole blob, ignoring Range
	status   int      // when non-zero, fail with this status
}

func (b *blobServer) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		b.requests = append(b.requests, r.Header.Get("Range"))
		if b.status != 0 {
			w.WriteHeader(b.status)
			return
		}
		start := 0
		partial := false
		if rng := r.Header.Get("Range"); rng != "" && !b.ignore {
			fmt.Sscanf(rng, "bytes=%d-", &start)
			partial = true
		}
		// Content-Length ALWAYS announces the full remainder, so a short write
		// below reads as a cut transfer rather than a complete small response —
		// which is exactly how a real interrupted download presents.
		w.Header().Set("Content-Length", strconv.Itoa(len(b.payload)-start))
		if partial {
			w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, len(b.payload)-1, len(b.payload)))
			w.WriteHeader(http.StatusPartialContent)
		}
		body := b.payload[start:]
		if b.cuts > 0 {
			b.cuts--
			if b.cut < len(body) {
				body = body[:b.cut]
			}
		}
		w.Write(body)
	}
}

func blobClient(t *testing.T, srv *httptest.Server) (*OCIClient, ocispec.Descriptor, []byte) {
	t.Helper()
	payload := []byte(strings.Repeat("artifact-bytes ", 4096))
	sum := sha256.Sum256(payload)
	desc := ocispec.Descriptor{
		Digest: digest.Digest("sha256:" + hex.EncodeToString(sum[:])),
		Size:   int64(len(payload)),
	}
	c, err := NewOCIClient("oci://" + strings.TrimPrefix(srv.URL, "http://") + "/go-zpkg/artifacts")
	if err != nil {
		t.Fatal(err)
	}
	return c, desc, payload
}

// TestFetchBlobResumes is the headline: a transfer cut twice mid-stream is
// RESUMED from where it stopped, not restarted, and the assembled bytes are
// digest-checked.
func TestFetchBlobResumes(t *testing.T) {
	bs := &blobServer{cut: 1000, cuts: 2}
	srv := httptest.NewServer(bs.handler())
	defer srv.Close()
	c, desc, payload := blobClient(t, srv)
	bs.payload = payload

	old := blobBackoff
	blobBackoff = func(int) {}
	defer func() { blobBackoff = old }()

	got, err := c.fetchBlob(context.Background(), "lib.org", desc)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("got %d bytes, want %d", len(got), len(payload))
	}
	if len(bs.requests) != 3 {
		t.Fatalf("requests = %v, want three (initial + two resumes)", bs.requests)
	}
	if bs.requests[0] != "" || bs.requests[1] != "bytes=1000-" || bs.requests[2] != "bytes=2000-" {
		t.Fatalf("ranges = %v — a resume must ask for the REMAINDER", bs.requests)
	}
}

// TestFetchBlobRangeIgnored: a registry that answers 200 with the whole blob
// (no Range support) still yields correct bytes.
func TestFetchBlobRangeIgnored(t *testing.T) {
	bs := &blobServer{cut: 500, cuts: 1, ignore: true}
	srv := httptest.NewServer(bs.handler())
	defer srv.Close()
	c, desc, payload := blobClient(t, srv)
	bs.payload = payload
	blobBackoff = func(int) {}
	defer func() { blobBackoff = func(attempt int) {} }()

	got, err := c.fetchBlob(context.Background(), "lib.org", desc)
	if err != nil || string(got) != string(payload) {
		t.Fatalf("len = %d, err = %v", len(got), err)
	}
}

// TestFetchBlobGivesUp: a failure with no progress at all is not a cut
// transfer, so it is not retried forever; and a truncated result never passes
// the size/digest check.
func TestFetchBlobGivesUp(t *testing.T) {
	blobBackoff = func(int) {}
	defer func() { blobBackoff = func(attempt int) {} }()

	t.Run("hard error", func(t *testing.T) {
		bs := &blobServer{status: http.StatusNotFound}
		srv := httptest.NewServer(bs.handler())
		defer srv.Close()
		c, desc, payload := blobClient(t, srv)
		bs.payload = payload
		if _, err := c.fetchBlob(context.Background(), "lib.org", desc); err == nil {
			t.Fatal("want an error")
		}
		if len(bs.requests) > 2 {
			t.Fatalf("a 404 was retried %d times", len(bs.requests))
		}
	})

	t.Run("never completes", func(t *testing.T) {
		bs := &blobServer{cut: 10, cuts: 99}
		srv := httptest.NewServer(bs.handler())
		defer srv.Close()
		c, desc, payload := blobClient(t, srv)
		bs.payload = payload
		_, err := c.fetchBlob(context.Background(), "lib.org", desc)
		if err == nil || !strings.Contains(err.Error(), "of "+strconv.Itoa(len(payload))+" bytes") {
			t.Fatalf("err = %v, want a short-blob report", err)
		}
	})

	t.Run("digest mismatch", func(t *testing.T) {
		bs := &blobServer{}
		srv := httptest.NewServer(bs.handler())
		defer srv.Close()
		c, desc, payload := blobClient(t, srv)
		bs.payload = append([]byte("tampered"), payload[8:]...) // same size, other bytes
		if _, err := c.fetchBlob(context.Background(), "lib.org", desc); err == nil || !strings.Contains(err.Error(), "digest mismatch") {
			t.Fatalf("err = %v, want a digest mismatch", err)
		}
	})

	t.Run("unusable request", func(t *testing.T) {
		c, desc, _ := blobClient(t, httptest.NewServer(http.NotFoundHandler()))
		if _, _, err := c.writeBlobFrom(context.Background(), "://bad url", 0, nil); err == nil {
			t.Fatal("want a request-construction error")
		}
		if _, err := c.fetchBlob(context.Background(), "lib.org\n", desc); err == nil {
			t.Fatal("want an error for an unusable repo name")
		}
	})
}

func TestOCIClientScheme(t *testing.T) {
	https, err := NewOCIClient("oci://example.test/x")
	if err != nil {
		t.Fatal(err)
	}
	plain, err := NewOCIClient("oci://127.0.0.1:5000/x")
	if err != nil {
		t.Fatal(err)
	}
	if https.scheme() != "https" || plain.scheme() != "http" {
		t.Fatalf("schemes = %q / %q", https.scheme(), plain.scheme())
	}
}

// TestFetchBlobShortWithoutError: a registry that serves FEWER bytes than the
// descriptor claims, without any transport error (a consistent but wrong
// Content-Length), must still be rejected — silence is not success.
func TestFetchBlobShortWithoutError(t *testing.T) {
	bs := &blobServer{}
	srv := httptest.NewServer(bs.handler())
	defer srv.Close()
	c, desc, payload := blobClient(t, srv)
	bs.payload = payload[:len(payload)/2] // honest length, half the blob
	blobBackoff = func(int) {}
	defer func() { blobBackoff = func(attempt int) {} }()

	_, err := c.fetchBlob(context.Background(), "lib.org", desc)
	if err == nil || !strings.Contains(err.Error(), "unexpected EOF") {
		t.Fatalf("err = %v, want a short-blob rejection", err)
	}
}

// TestFetchBlobTransportError: an unreachable registry surfaces its transport
// error rather than looping.
func TestFetchBlobTransportError(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	c, desc, payload := blobClient(t, srv)
	_ = payload
	srv.Close() // nothing is listening any more
	blobBackoff = func(int) {}
	defer func() { blobBackoff = func(attempt int) {} }()

	if _, err := c.fetchBlob(context.Background(), "lib.org", desc); err == nil {
		t.Fatal("want the transport error")
	}
}
