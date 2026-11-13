//go:build !js

package artifact

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// `FROM scratch` has no /tmp, and this package's own first paragraph
// promises it works on an image whose only file is the binary. Nothing
// noticed, because every machine a test ever ran on had a /tmp.
//
// Found by building that image and running it:
//
//	pkgx: catalog update: blob sha256:6fc3caf…: temp file:
//	      open /tmp/artifact-blob-1245446855: no such file or directory
func TestABlobIsStagedInsideTheStore(t *testing.T) {
	store := t.TempDir()
	t.Setenv("ZPKG_DIR", store)

	got := blobStagingDir()
	want := filepath.Join(store, ".local", "tmp")
	if got != want {
		t.Fatalf("blobStagingDir = %q, want %q", got, want)
	}
	if fi, err := os.Stat(got); err != nil || !fi.IsDir() {
		t.Fatalf("it did not create the directory: %v", err)
	}

	// And it is USED: the staging directory is where the file lands, not
	// merely a path the function can compute.
	prev := osCreateTemp
	var where string
	osCreateTemp = func(dir, pattern string) (*os.File, error) {
		where = dir
		return prev(dir, pattern)
	}
	t.Cleanup(func() { osCreateTemp = prev })

	fr := newFakeRegistry(t, false)
	defer fr.close()
	c, err := NewOCIClient(fr.base("go-zpkg/packages"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("ZPKG_VERIFY", "0")
	if err := c.Push("zlib.net", "1.3.2", "linux", "x86-64", makeGzTarball("body"), ExtTarGz); err != nil {
		t.Fatal(err)
	}
	f, _, err := c.PullFile("zlib.net", "1.3.2", "linux", "x86-64")
	if err != nil {
		t.Fatalf("PullFile: %v", err)
	}
	f.Close()
	if where != want {
		t.Errorf("the blob was staged in %q, not in the store", where)
	}
}

// A read-only $ZPKG_DIR is somebody's deliberate arrangement. Refusing to
// fetch at all would be a worse answer than the behaviour every release
// until now had, so it falls back to the system temp directory.
func TestStagingFallsBackWhenTheStoreCannotBeMade(t *testing.T) {
	prev := osMkdirAll
	osMkdirAll = func(string, os.FileMode) error { return errors.New("read-only file system") }
	t.Cleanup(func() { osMkdirAll = prev })

	if got := blobStagingDir(); got != "" {
		t.Errorf("blobStagingDir = %q, want \"\" (the system temp dir)", got)
	}
	// "" is what os.CreateTemp takes to mean the system temp directory,
	// which is the point: the fallback is the OLD behaviour exactly.
	f, err := os.CreateTemp("", "probe-*")
	if err != nil {
		t.Skip("no system temp directory here either")
	}
	name := f.Name()
	f.Close()
	os.Remove(name)
	if strings.TrimSpace(name) == "" {
		t.Error("the fallback produced no path")
	}
}
