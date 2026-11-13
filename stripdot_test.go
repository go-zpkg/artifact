package artifact

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// tarOf writes a tar whose members are exactly the given names (regular files
// named after themselves), so a test can reproduce an archive's SHAPE.
func tarOf(t *testing.T, names ...string) *tar.Reader {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, n := range names {
		body := []byte(n)
		h := &tar.Header{Name: n, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}
		if strings.HasSuffix(n, "/") {
			h = &tar.Header{Name: n, Mode: 0o755, Typeflag: tar.TypeDir}
			body = nil
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return tar.NewReader(bytes.NewReader(buf.Bytes()))
}

func extractedNames(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		out = append(out, filepath.ToSlash(rel))
		return nil
	})
	sort.Strings(out)
	return out
}

// TestStripCountsALeadingDotLikeTarDoes: `tar --strip-components` counts a
// leading "." as a component. path.Clean removed it before the count, so N
// components off a "./"-prefixed archive stripped N+1 — which does not fail,
// it FLATTENS: the real root file is dropped and a subdirectory's namesake
// lands in its place.
//
// The expectations below were measured against GNU tar on this exact archive,
// not derived from the documentation.
func TestStripCountsALeadingDotLikeTarDoes(t *testing.T) {
	names := []string{"./top/", "./top/CMakeLists.txt", "./top/sub/", "./top/sub/CMakeLists.txt"}
	for _, tc := range []struct {
		strip int
		want  []string
	}{
		{0, []string{"top/CMakeLists.txt", "top/sub/CMakeLists.txt"}},
		{1, []string{"top/CMakeLists.txt", "top/sub/CMakeLists.txt"}},
		{2, []string{"CMakeLists.txt", "sub/CMakeLists.txt"}},
		{3, []string{"CMakeLists.txt"}},
	} {
		dir := t.TempDir()
		if err := Extract(tarOf(t, names...), dir, tc.strip); err != nil {
			t.Fatalf("strip %d: %v", tc.strip, err)
		}
		got := extractedNames(t, dir)
		if strings.Join(got, " ") != strings.Join(tc.want, " ") {
			t.Errorf("strip %d: %v, want %v", tc.strip, got, tc.want)
		}
	}
}

// TestStripIsUnchangedWithoutALeadingDot is the other half of the control: an
// archive with no "./" must strip exactly as it always did.
func TestStripIsUnchangedWithoutALeadingDot(t *testing.T) {
	names := []string{"top/", "top/CMakeLists.txt", "top/sub/", "top/sub/CMakeLists.txt"}
	for _, tc := range []struct {
		strip int
		want  []string
	}{
		{0, []string{"top/CMakeLists.txt", "top/sub/CMakeLists.txt"}},
		{1, []string{"CMakeLists.txt", "sub/CMakeLists.txt"}},
		{2, []string{"CMakeLists.txt"}},
	} {
		dir := t.TempDir()
		if err := Extract(tarOf(t, names...), dir, tc.strip); err != nil {
			t.Fatalf("strip %d: %v", tc.strip, err)
		}
		got := extractedNames(t, dir)
		if strings.Join(got, " ") != strings.Join(tc.want, " ") {
			t.Errorf("strip %d: %v, want %v", tc.strip, got, tc.want)
		}
	}
}

// TestStripComponentsDropsEmptySegments: "//" and a trailing "/" are not
// components — only tar's "." is.
func TestStripComponentsDropsEmptySegments(t *testing.T) {
	for _, tc := range []struct {
		name string
		want []string
	}{
		{"./a/b", []string{".", "a", "b"}},
		{"a//b/", []string{"a", "b"}},
		{"a", []string{"a"}},
		{"", nil},
		{"./", []string{"."}},
	} {
		got := stripComponents(tc.name)
		if strings.Join(got, "|") != strings.Join(tc.want, "|") {
			t.Errorf("%q -> %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestStripStillRefusesToEscape: counting "." as a component must not weaken
// the traversal check — ".." after stripping still has to be refused.
func TestStripStillRefusesToEscape(t *testing.T) {
	dir := t.TempDir()
	err := Extract(tarOf(t, "./a/../../escaped"), dir, 1)
	if err == nil {
		t.Fatal("a member escaping the root was accepted")
	}
	if got := extractedNames(t, dir); len(got) != 0 {
		t.Errorf("it wrote %v", got)
	}
}
