//go:build !js

package artifact

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"strings"
	"testing"
)

// TestFetchBlobFileStagesOnDisk: the bytes land in a FILE, positioned at the
// start, carrying the digest computed on the way past.
func TestFetchBlobFileStagesOnDisk(t *testing.T) {
	bs := &blobServer{}
	srv := httptest.NewServer(bs.handler())
	defer srv.Close()
	c, desc, payload := blobClient(t, srv)
	bs.payload = payload

	f, err := c.fetchBlobFile(context.Background(), "lib.org", desc)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	got, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("read %d bytes, want %d", len(got), len(payload))
	}
	sum := sha256.Sum256(payload)
	if want := "sha256:" + hex.EncodeToString(sum[:]); f.Digest != want {
		t.Errorf("Digest = %q, want %q", f.Digest, want)
	}
}

// TestBlobFileCloseRemoves: the staged blob is a TEMPORARY. Leaving 1.7 GiB
// behind per install would be its own kind of failure.
func TestBlobFileCloseRemoves(t *testing.T) {
	bs := &blobServer{}
	srv := httptest.NewServer(bs.handler())
	defer srv.Close()
	c, desc, payload := blobClient(t, srv)
	bs.payload = payload

	f, err := c.fetchBlobFile(context.Background(), "lib.org", desc)
	if err != nil {
		t.Fatal(err)
	}
	path := f.ReadSeeker.(interface{ Name() string }).Name()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("staged file missing while open: %v", err)
	}

	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("%s survived Close (err = %v)", path, err)
	}
}

// TestFetchBlobFileRangeIgnoredMidTransfer is the file-specific hazard: when a
// registry answers a RESUME with 200 and the whole blob, the partial bytes
// already on disk must be discarded. Appending instead would produce a file
// that is longer than the blob and hashes to nothing.
func TestFetchBlobFileRangeIgnoredMidTransfer(t *testing.T) {
	// Cut the first response, then serve everything ignoring the Range.
	bs := &blobServer{cut: 700, cuts: 1}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Range") != "" {
			bs.ignore = true // second request: pretend Range is unsupported
		}
		bs.handler()(w, r)
	}))
	defer srv.Close()
	c, desc, payload := blobClient(t, srv)
	bs.payload = payload
	old := blobBackoff
	blobBackoff = func(int) {}
	defer func() { blobBackoff = old }()

	f, err := c.fetchBlobFile(context.Background(), "lib.org", desc)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	got, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(payload) {
		t.Fatalf("file holds %d bytes, want %d — a restart must TRUNCATE, not append", len(got), len(payload))
	}
}

// TestPullFileDoesNotBufferTheBlob is the whole point, measured: pulling a
// artifact must not cost the artifact's size in heap. The in-memory Pull is the
// control — it necessarily does.
func TestPullFileDoesNotBufferTheBlob(t *testing.T) {
	t.Setenv("ZPKG_VERIFY", "0")
	const size = 24 << 20 // 24 MiB: big enough to dwarf the fixed overhead
	fr := newFakeRegistry(t, false)
	defer fr.close()
	c, err := NewOCIClient(fr.base("go-zpkg/packages"))
	if err != nil {
		t.Fatal(err)
	}
	blob := make([]byte, size)
	for i := range blob {
		blob[i] = byte(i)
	}
	if err := c.Push("big.org", "1.0.0", "linux", "aarch64", blob, ".tar.gz"); err != nil {
		t.Fatal(err)
	}
	blob = nil

	streamed := heapCost(t, func() {
		f, _, err := c.PullFile("big.org", "1.0.0", "linux", "aarch64")
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
	})
	buffered := heapCost(t, func() {
		data, _, err := c.Pull("big.org", "1.0.0", "linux", "aarch64")
		if err != nil {
			t.Fatal(err)
		}
		runtime.KeepAlive(data)
	})

	if streamed > size/4 {
		t.Errorf("PullFile allocated %d bytes for a %d-byte blob — it is buffering", streamed, size)
	}
	if buffered < size {
		t.Fatalf("control failed: Pull allocated only %d bytes for a %d-byte blob, so the measurement is not measuring", buffered, size)
	}
	t.Logf("peak heap: streamed %d KiB, buffered %d KiB (blob %d KiB)", streamed>>10, buffered>>10, size>>10)
}

// heapCost reports how much the heap grew across fn, at its peak.
func heapCost(t *testing.T, fn func()) int64 {
	t.Helper()
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	fn()
	runtime.ReadMemStats(&after)
	// TotalAlloc never shrinks, so this counts everything allocated during fn
	// whether or not it survived — exactly the pressure that OOM-kills.
	return int64(after.TotalAlloc - before.TotalAlloc)
}

// TestFetchBlobFileErrors drives the staging failures a disk will not produce
// on demand.
func TestFetchBlobFileErrors(t *testing.T) {
	bs := &blobServer{}
	srv := httptest.NewServer(bs.handler())
	defer srv.Close()
	c, desc, payload := blobClient(t, srv)
	bs.payload = payload
	old := blobBackoff
	blobBackoff = func(int) {}
	defer func() { blobBackoff = old }()

	t.Run("no temp file", func(t *testing.T) {
		orig := osCreateTemp
		osCreateTemp = func(string, string) (*os.File, error) { return nil, errors.New("read-only /tmp") }
		defer func() { osCreateTemp = orig }()
		if _, err := c.fetchBlobFile(context.Background(), "lib.org", desc); err == nil ||
			!strings.Contains(err.Error(), "temp file") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("write fails", func(t *testing.T) {
		orig := ioCopy
		ioCopy = func(io.Writer, io.Reader) (int64, error) { return 0, errors.New("disk full") }
		defer func() { ioCopy = orig }()
		if _, err := c.fetchBlobFile(context.Background(), "lib.org", desc); err == nil {
			t.Fatal("want a write error")
		}
	})

	t.Run("hash fails", func(t *testing.T) {
		n := 0
		orig := ioCopy
		ioCopy = func(w io.Writer, r io.Reader) (int64, error) {
			n++
			if n == 1 { // the download itself succeeds
				return orig(w, r)
			}
			return 0, errors.New("read error") // the hashing pass does not
		}
		defer func() { ioCopy = orig }()
		if _, err := c.fetchBlobFile(context.Background(), "lib.org", desc); err == nil ||
			!strings.Contains(err.Error(), "hash") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("staged file is cleaned up on failure", func(t *testing.T) {
		var staged string
		origCreate := osCreateTemp
		osCreateTemp = func(dir, pattern string) (*os.File, error) {
			f, err := origCreate(dir, pattern)
			if f != nil {
				staged = f.Name()
			}
			return f, err
		}
		defer func() { osCreateTemp = origCreate }()
		bad := desc
		bad.Digest = digest.Digest("sha256:" + strings.Repeat("0", 64))
		if _, err := c.fetchBlobFile(context.Background(), "lib.org", bad); err == nil {
			t.Fatal("want a digest mismatch")
		}
		if staged == "" {
			t.Fatal("no file was staged, so nothing was tested")
		}
		if _, err := os.Stat(staged); !os.IsNotExist(err) {
			t.Errorf("%s left behind after a failed pull (err = %v)", staged, err)
		}
	})
}

// TestVerifySignatureDigestMatchesByteForm: the digest form and the bytes form
// must agree, or the streaming install would be verifying something else.
func TestVerifySignatureDigestMatchesByteForm(t *testing.T) {
	tarball := []byte("an artifact")
	sum := sha256.Sum256(tarball)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	payload := []byte(`{"critical":{"image":{"docker-manifest-digest":"` + digest + `"}}}`)

	// Both must reject an unsigned payload for the SAME reason (no valid
	// signature), rather than one of them failing on the digest first.
	byBytes := VerifySignature(tarball, payload, "not-a-signature", "")
	byDigest := VerifySignatureDigest(digest, payload, "not-a-signature", "")
	if (byBytes == nil) != (byDigest == nil) {
		t.Fatalf("bytes → %v, digest → %v", byBytes, byDigest)
	}

	// And a MISMATCHED digest must be rejected by the digest form.
	other := "sha256:" + strings.Repeat("1", 64)
	if err := VerifySignatureDigest(other, payload, "not-a-signature", ""); err == nil {
		t.Error("a foreign digest was accepted")
	}
}

// TestFetchBlobFileSeekFailures: a resumed transfer that cannot position its
// file must FAIL, not append at whatever offset it happens to be at — that
// would produce a file longer than the blob, and only the digest would notice.
func TestFetchBlobFileSeekFailures(t *testing.T) {
	old := blobBackoff
	blobBackoff = func(int) {}
	defer func() { blobBackoff = old }()

	newC := func(t *testing.T, bs *blobServer) (*OCIClient, ocispec.Descriptor) {
		srv := httptest.NewServer(bs.handler())
		t.Cleanup(srv.Close)
		c, desc, payload := blobClient(t, srv)
		bs.payload = payload
		return c, desc
	}

	// The transfer itself seeks once (positioning the very first write), so the
	// pre-hash rewind is the SECOND call and the post-hash one the third.
	failAfter := func(t *testing.T, ok int) {
		n := 0
		orig := fSeek
		fSeek = func(f *os.File, off int64, whence int) (int64, error) {
			n++
			if n <= ok {
				return orig(f, off, whence)
			}
			return 0, errors.New("bad fd")
		}
		t.Cleanup(func() { fSeek = orig })
	}

	t.Run("rewind before hashing", func(t *testing.T) {
		c, desc := newC(t, &blobServer{})
		failAfter(t, 1)
		if _, err := c.fetchBlobFile(context.Background(), "lib.org", desc); err == nil ||
			!strings.Contains(err.Error(), "rewind") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("rewind after hashing", func(t *testing.T) {
		c, desc := newC(t, &blobServer{})
		failAfter(t, 2)
		if _, err := c.fetchBlobFile(context.Background(), "lib.org", desc); err == nil ||
			!strings.Contains(err.Error(), "rewind") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("seek to resume offset", func(t *testing.T) {
		c, desc := newC(t, &blobServer{cut: 700, cuts: 1})
		n := 0
		orig := fSeek
		fSeek = func(f *os.File, off int64, whence int) (int64, error) {
			n++
			if off == 0 {
				return orig(f, off, whence)
			}
			return 0, errors.New("bad fd") // the resume positioning fails
		}
		defer func() { fSeek = orig }()
		if _, err := c.fetchBlobFile(context.Background(), "lib.org", desc); err == nil {
			t.Fatal("want the seek failure to surface")
		}
	})

	// The registry ignores a Range and replays the blob: the file is truncated
	// and rewound. Both steps have to be checked, or the retry writes at the
	// old offset and produces a file that is too long.
	restartServer := func(t *testing.T) (*OCIClient, ocispec.Descriptor) {
		bs := &blobServer{cut: 700, cuts: 1}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Range") != "" {
				bs.ignore = true
			}
			bs.handler()(w, r)
		}))
		t.Cleanup(srv.Close)
		c, desc, payload := blobClient(t, srv)
		bs.payload = payload
		return c, desc
	}

	t.Run("rewind after restart", func(t *testing.T) {
		c, desc := restartServer(t)
		failAfter(t, 1) // the first positioning works; the restart's does not
		if _, err := c.fetchBlobFile(context.Background(), "lib.org", desc); err == nil {
			t.Fatal("want the rewind failure to surface")
		}
	})

	t.Run("truncate on restart", func(t *testing.T) {
		bs := &blobServer{cut: 700, cuts: 1}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Range") != "" {
				bs.ignore = true
			}
			bs.handler()(w, r)
		}))
		defer srv.Close()
		c, desc, payload := blobClient(t, srv)
		bs.payload = payload
		orig := fTruncate
		fTruncate = func(*os.File, int64) error { return errors.New("bad fd") }
		defer func() { fTruncate = orig }()
		if _, err := c.fetchBlobFile(context.Background(), "lib.org", desc); err == nil {
			t.Fatal("want the truncate failure to surface")
		}
	})
}

// TestPullSurfacesFetchFailure: the in-memory wrapper must report the file
// path's error rather than an empty result.
func TestPullSurfacesFetchFailure(t *testing.T) {
	fr := newFakeRegistry(t, false)
	defer fr.close()
	c, err := NewOCIClient(fr.base("go-zpkg/packages"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.Pull("absent.org", "9.9.9", "linux", "aarch64"); err == nil {
		t.Fatal("want an error for an artifact that is not there")
	}
}

// TestPullReportsReadFailure: the in-memory wrapper reads the staged file back,
// and that read can fail too.
func TestPullReportsReadFailure(t *testing.T) {
	t.Setenv("ZPKG_VERIFY", "0")
	fr := newFakeRegistry(t, false)
	defer fr.close()
	c, err := NewOCIClient(fr.base("go-zpkg/packages"))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Push("small.org", "1.0.0", "linux", "aarch64", []byte("payload"), ".tar.gz"); err != nil {
		t.Fatal(err)
	}
	orig := ioReadAll
	ioReadAll = func(io.Reader) ([]byte, error) { return nil, errors.New("read error") }
	defer func() { ioReadAll = orig }()

	if _, _, err := c.Pull("small.org", "1.0.0", "linux", "aarch64"); err == nil {
		t.Fatal("want the read error")
	}
}
