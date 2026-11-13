package artifact

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

// tarPayload is a one-entry tar stream, the shape an artifact actually has.
func tarPayload(t *testing.T) []byte {
	t.Helper()
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	body := []byte("an artifact's worth of bytes")
	if err := tw.WriteHeader(&tar.Header{Name: "prefix/bin/tool", Mode: 0o755, Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return raw.Bytes()
}

// TestDecompressorRoundTripsEveryPublishedCodec: an artifact published in any of
// the three formats must install. gzip and xz are what the catalogue holds
// today; zstd is what it will hold — and a reader that meets an unexpected
// codec fails with "invalid header", which reads like a corrupt download.
func TestDecompressorRoundTripsEveryPublishedCodec(t *testing.T) {
	raw := tarPayload(t)

	for _, tc := range []struct {
		ext  string
		comp func(io.Writer) io.WriteCloser
	}{
		{ExtTarGz, func(w io.Writer) io.WriteCloser { return gzip.NewWriter(w) }},
		{ExtTarXz, func(w io.Writer) io.WriteCloser { x, _ := xz.NewWriter(w); return x }},
		{ExtTarZst, func(w io.Writer) io.WriteCloser { z, _ := zstd.NewWriter(w); return z }},
	} {
		var packed bytes.Buffer
		w := tc.comp(&packed)
		if _, err := w.Write(raw); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}

		dec, closeDec, err := Decompressor(tc.ext, bytes.NewReader(packed.Bytes()))
		if err != nil {
			t.Fatalf("%s: %v", tc.ext, err)
		}
		got, err := io.ReadAll(dec)
		closeDec()
		if err != nil {
			t.Fatalf("%s: %v", tc.ext, err)
		}
		if !bytes.Equal(got, raw) {
			t.Errorf("%s: round trip lost the payload (%d vs %d bytes)", tc.ext, len(got), len(raw))
		}
	}
}

// TestDecompressorEmptyExtIsGzip keeps the historical default: the static-HTTP
// dist path reported no extension when .tar.gz won.
func TestDecompressorEmptyExtIsGzip(t *testing.T) {
	var packed bytes.Buffer
	w := gzip.NewWriter(&packed)
	w.Write([]byte("x"))
	w.Close()

	dec, closeDec, err := Decompressor("", bytes.NewReader(packed.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	defer closeDec()
	if b, _ := io.ReadAll(dec); string(b) != "x" {
		t.Errorf("got %q", b)
	}
}

// TestDecompressorRejectsUnknown: an unknown codec must say so by name rather
// than fail as a corrupt stream three layers down.
func TestDecompressorRejectsUnknown(t *testing.T) {
	if _, _, err := Decompressor(".tar.br", bytes.NewReader(nil)); err == nil ||
		!strings.Contains(err.Error(), ".tar.br") {
		t.Fatalf("err = %v", err)
	}
}

// TestDecompressorReportsBadStreams: a stream that is not what its extension
// claims must fail — but WHERE it fails differs by decoder. gzip and xz parse
// their header when constructed; zstd defers it to the first Read. Both are
// fine for the installer, which streams straight into untar, so the test asks
// the question the installer does: does anything come out?
func TestDecompressorReportsBadStreams(t *testing.T) {
	for _, ext := range []string{ExtTarGz, ExtTarXz, ExtTarZst} {
		dec, closeDec, err := Decompressor(ext, bytes.NewReader([]byte("not compressed at all")))
		if err != nil {
			continue // rejected at construction
		}
		_, err = io.ReadAll(dec)
		closeDec()
		if err == nil {
			t.Errorf("%s accepted a non-%s stream", ext, ext)
		}
	}
}

// TestExtForLayerCoversZstd: the media type is how a puller learns the codec,
// so the mapping has to know +zstd — including the loose form.
func TestExtForLayerCoversZstd(t *testing.T) {
	for _, tc := range []struct{ mt, want string }{
		{MediaLayerZst, ExtTarZst},
		{"application/vnd.oci.image.layer.v1.tar+zstd", ExtTarZst},
		{"application/x-something-zstd", ExtTarZst},
		{MediaLayerGz, ExtTarGz},
		{MediaLayerXz, ExtTarXz},
		{"application/vnd.oci.image.config.v1+json", ""},
	} {
		if got := extForLayer(tc.mt); got != tc.want {
			t.Errorf("extForLayer(%q) = %q, want %q", tc.mt, got, tc.want)
		}
	}
}

// TestZstdArtifactRoundTripsThroughTheRegistry is the migration in one test: a
// artifact PUBLISHED as zstd must come back with the right media type, the right
// extension, and install. Publishing a codec the installed base cannot read
// would brick every consumer, so the reader ships first and this is what says
// it is ready.
func TestZstdArtifactRoundTripsThroughTheRegistry(t *testing.T) {
	t.Setenv("ZPKG_VERIFY", "0")
	fr := newFakeRegistry(t, false)
	defer fr.close()
	base := fr.base("go-zpkg/artifacts")
	c, err := NewOCIClient(base)
	if err != nil {
		t.Fatal(err)
	}

	var packed bytes.Buffer
	zw, err := zstd.NewWriter(&packed, zstd.WithEncoderLevel(zstd.SpeedBestCompression))
	if err != nil {
		t.Fatal(err)
	}
	raw := tarPayload(t)
	if _, err := zw.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	if err := c.Push("zst.test", "1.0.0", "linux", "aarch64", packed.Bytes(), ExtTarZst); err != nil {
		t.Fatalf("push: %v", err)
	}

	old := DistBase
	DistBase = base
	defer func() { DistBase = old; resetOCICache() }()
	resetOCICache()

	got, ext, err := DownloadArtifact("zst.test", "1.0.0", "linux", "aarch64")
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	if ext != ExtTarZst {
		t.Errorf("ext = %q, want %q — the media type must carry the codec", ext, ExtTarZst)
	}
	if !bytes.Equal(got, packed.Bytes()) {
		t.Errorf("bytes differ: %d vs %d", len(got), len(packed.Bytes()))
	}

	// And the installer's own path: decompress what came back.
	dec, closeDec, err := Decompressor(ext, bytes.NewReader(got))
	if err != nil {
		t.Fatal(err)
	}
	defer closeDec()
	back, err := io.ReadAll(dec)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, raw) {
		t.Error("the round trip did not yield the original tar")
	}
}

// TestDecompressorReportsConstructorFailure drives the zstd constructor's error
// path through its seam.
func TestDecompressorReportsConstructorFailure(t *testing.T) {
	orig := zstdNewReader
	zstdNewReader = func(io.Reader) (*zstd.Decoder, error) { return nil, io.ErrUnexpectedEOF }
	defer func() { zstdNewReader = orig }()

	if _, _, err := Decompressor(ExtTarZst, bytes.NewReader(nil)); err == nil {
		t.Fatal("want the constructor error")
	}
}
