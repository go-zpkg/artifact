// Copyright (c) 2026, the go-zpkg/artifact authors
// All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package artifact

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// tarEntry is a single archive entry for buildExtractTar.
type tarEntry struct {
	name  string
	typ   byte
	mode  int64
	body  string
	link  string
	mtime time.Time
}

// buildExtractTar assembles an in-memory tar from entries.
func buildExtractTar(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		hdr := &tar.Header{Name: e.name, Typeflag: e.typ, Mode: e.mode, Linkname: e.link}
		if !e.mtime.IsZero() {
			hdr.ModTime = e.mtime
		}
		if e.typ == tar.TypeReg {
			hdr.Size = int64(len(e.body))
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write header %q: %v", e.name, err)
		}
		if e.typ == tar.TypeReg {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatalf("write body %q: %v", e.name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	return buf.Bytes()
}

func extract(data []byte, dest string, strip int) error {
	return Extract(tar.NewReader(bytes.NewReader(data)), dest, strip)
}

// TestExtractHappyPath covers dir, regular file, symlink and hard link, with
// permission fallback and mtime restoration.
func TestExtractHappyPath(t *testing.T) {
	skipOnWASI(t, wasiNoChmod)
	dest := t.TempDir()
	mt := time.Unix(1_600_000_000, 0)
	data := buildExtractTar(t, []tarEntry{
		{name: "d", typ: tar.TypeDir, mode: 0o755},
		{name: "d/f", typ: tar.TypeReg, mode: 0o640, body: "hello", mtime: mt},
		{name: "d/z", typ: tar.TypeDir, mode: 0}, // perm 0 -> fallback 0o755
		{name: "d/s", typ: tar.TypeSymlink, link: "f"},
		{name: "d/h", typ: tar.TypeLink, link: "d/f"},
	})
	if err := extract(data, dest, 0); err != nil {
		t.Fatalf("extract: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dest, "d/f"))
	if err != nil || string(got) != "hello" {
		t.Fatalf("file content = %q, %v", got, err)
	}
	fi, err := os.Stat(filepath.Join(dest, "d/f"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o640 {
		t.Errorf("perm = %o; want 640", fi.Mode().Perm())
	}
	if !fi.ModTime().Equal(mt) {
		t.Errorf("mtime = %v; want %v (mtime not restored)", fi.ModTime(), mt)
	}
	// Directory with mode 0 fell back to a usable perm.
	zi, err := os.Stat(filepath.Join(dest, "d/z"))
	if err != nil || !zi.IsDir() {
		t.Fatalf("dir d/z: %v", err)
	}
	if zi.Mode().Perm() == 0 {
		t.Error("dir perm fell through to 0")
	}
	link, err := os.Readlink(filepath.Join(dest, "d/s"))
	if err != nil || link != "f" {
		t.Fatalf("symlink = %q, %v", link, err)
	}
	// Hard link shares the file identity of d/f.
	hi, err := os.Stat(filepath.Join(dest, "d/h"))
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(fi, hi) {
		t.Error("hard link d/h is not the same file as d/f")
	}
}

// TestExtractMtimeNonRegression is the libexpat-2.8.3 guard: a "generated" file
// archived with a NEWER mtime than the "source" it derives from must keep that
// ordering after extraction, so make does not try to regenerate it. Stamping
// files with "now" would invert or flatten the order.
func TestExtractMtimeNonRegression(t *testing.T) {
	dest := t.TempDir()
	srcTime := time.Unix(1_600_000_000, 0) // older: the source
	genTime := time.Unix(1_600_000_100, 0) // newer: the generated artifact
	data := buildExtractTar(t, []tarEntry{
		// archive order deliberately puts the generated file FIRST, so a
		// "stamp with now" extractor would make it the OLDER of the two.
		{name: "doc/xmlwf.1", typ: tar.TypeReg, mode: 0o644, body: "man", mtime: genTime},
		{name: "doc/xmlwf.xml", typ: tar.TypeReg, mode: 0o644, body: "src", mtime: srcTime},
	})
	if err := extract(data, dest, 0); err != nil {
		t.Fatalf("extract: %v", err)
	}
	gen, err := os.Stat(filepath.Join(dest, "doc/xmlwf.1"))
	if err != nil {
		t.Fatal(err)
	}
	src, err := os.Stat(filepath.Join(dest, "doc/xmlwf.xml"))
	if err != nil {
		t.Fatal(err)
	}
	if !gen.ModTime().Equal(genTime) || !src.ModTime().Equal(srcTime) {
		t.Fatalf("mtimes not restored: gen=%v src=%v", gen.ModTime(), src.ModTime())
	}
	if !gen.ModTime().After(src.ModTime()) {
		t.Errorf("generated file (%v) is not newer than source (%v); make would regenerate it",
			gen.ModTime(), src.ModTime())
	}
}

// TestExtractStrip covers leading-component stripping and the two skip cases:
// an entry fully consumed by stripping, and an entry that is exactly the
// stripped prefix (rel == ".").
func TestExtractStrip(t *testing.T) {
	dest := t.TempDir()
	data := buildExtractTar(t, []tarEntry{
		{name: "top", typ: tar.TypeDir, mode: 0o755},  // == prefix -> rel "." skip
		{name: "top/", typ: tar.TypeDir, mode: 0o755}, // len(parts) <= strip skip
		{name: "top/inner/f", typ: tar.TypeReg, mode: 0o644, body: "x"},
	})
	if err := extract(data, dest, 1); err != nil {
		t.Fatalf("extract: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "inner", "f")); err != nil {
		t.Fatalf("stripped file missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "top")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("prefix component should have been stripped, got %v", err)
	}
}

// TestExtractInsecurePaths covers ErrInsecurePath for absolute and escaping
// entry names and hard-link sources, and the tolerate-tar.ErrInsecurePath
// branch (tr.Next itself flags an absolute name).
func TestExtractInsecurePaths(t *testing.T) {
	cases := []struct {
		name    string
		entries []tarEntry
	}{
		{"absolute name", []tarEntry{{name: "/etc/passwd", typ: tar.TypeReg, mode: 0o644, body: "x"}}},
		{"escaping name", []tarEntry{{name: "../evil", typ: tar.TypeReg, mode: 0o644, body: "x"}}},
		{"absolute hardlink source", []tarEntry{{name: "h", typ: tar.TypeLink, link: "/etc/passwd"}}},
		{"escaping hardlink source", []tarEntry{{name: "h", typ: tar.TypeLink, link: "../../etc/passwd"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := extract(buildExtractTar(t, c.entries), t.TempDir(), 0)
			if !errors.Is(err, ErrInsecurePath) {
				t.Fatalf("err = %v; want ErrInsecurePath", err)
			}
		})
	}
}

// TestExtractNextParseError covers a non-EOF, non-insecure tar.Next error.
func TestExtractNextParseError(t *testing.T) {
	err := Extract(tar.NewReader(bytes.NewReader([]byte("not a tar archive whatsoever"))), t.TempDir(), 0)
	if err == nil {
		t.Fatal("expected a tar parse error")
	}
	if errors.Is(err, ErrInsecurePath) {
		t.Fatalf("did not expect ErrInsecurePath, got %v", err)
	}
}

// TestExtractSkipsUnsupported covers the default switch arm (fifos/devices).
func TestExtractSkipsUnsupported(t *testing.T) {
	dest := t.TempDir()
	data := buildExtractTar(t, []tarEntry{{name: "fifo", typ: tar.TypeFifo, mode: 0o644}})
	if err := extract(data, dest, 0); err != nil {
		t.Fatalf("extract: %v", err)
	}
	if entries, _ := os.ReadDir(dest); len(entries) != 0 {
		t.Errorf("unsupported entry produced output: %v", entries)
	}
}

// withSeam swaps a seam variable for the duration of fn and restores it.
func swap[T any](p *T, v T) func() { old := *p; *p = v; return func() { *p = old } }

// TestExtractSeamErrors drives every os-operation error branch via the seams.
func TestExtractSeamErrors(t *testing.T) {
	boom := errors.New("boom")
	regTar := buildExtractTar(t, []tarEntry{{name: "f", typ: tar.TypeReg, mode: 0o644, body: "x", mtime: time.Unix(1_600_000_000, 0)}})
	dirTar := buildExtractTar(t, []tarEntry{{name: "d", typ: tar.TypeDir, mode: 0o755}})
	symTar := buildExtractTar(t, []tarEntry{{name: "s", typ: tar.TypeSymlink, link: "t"}})
	// hard link needs a real source first, then the link entry.
	linkTar := buildExtractTar(t, []tarEntry{
		{name: "a", typ: tar.TypeReg, mode: 0o644, body: "x"},
		{name: "b", typ: tar.TypeLink, link: "a"},
	})
	// same, but the link lives under a subdir so its parent mkdir is a distinct
	// path from the source's parent — lets us fail ONLY the link's parent.
	linkSubTar := buildExtractTar(t, []tarEntry{
		{name: "a", typ: tar.TypeReg, mode: 0o644, body: "x"},
		{name: "sub/b", typ: tar.TypeLink, link: "a"},
	})

	cases := []struct {
		name  string
		tar   []byte
		setup func() func()
	}{
		{"dir mkdir", dirTar, func() func() { return swap(&extMkdirAll, func(string, os.FileMode) error { return boom }) }},
		{"symlink parent mkdir", symTar, func() func() { return swap(&extMkdirAll, func(string, os.FileMode) error { return boom }) }},
		{"symlink create", symTar, func() func() { return swap(&extSymlink, func(string, string) error { return boom }) }},
		{"reg parent mkdir", regTar, func() func() { return swap(&extMkdirAll, func(string, os.FileMode) error { return boom }) }},
		{"reg openfile", regTar, func() func() {
			return swap(&extOpenFile, func(string, int, os.FileMode) (*os.File, error) { return nil, boom })
		}},
		{"reg copy", regTar, func() func() { return swap(&extCopy, func(io.Writer, io.Reader) (int64, error) { return 0, boom }) }},
		{"reg chtimes", regTar, func() func() { return swap(&extChtimes, func(string, time.Time, time.Time) error { return boom }) }},
		{"hardlink parent mkdir", linkSubTar, func() func() {
			return swap(&extMkdirAll, func(p string, m os.FileMode) error {
				if filepath.Base(p) == "sub" {
					return boom
				}
				return os.MkdirAll(p, m)
			})
		}},
		{"hardlink create", linkTar, func() func() { return swap(&extLink, func(string, string) error { return boom }) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			restore := c.setup()
			defer restore()
			err := extract(c.tar, t.TempDir(), 0)
			if err == nil {
				t.Fatalf("%s: expected an error", c.name)
			}
		})
	}
}

// TestExtractHelpers covers helper branches not reachable from a full tar:
// a zero mtime is a no-op, and a real chtimes succeeds.
func TestExtractHelpers(t *testing.T) {
	// zero time -> no-op, no error even for a missing path.
	if err := extRestoreTime(filepath.Join(t.TempDir(), "nope"), time.Time{}); err != nil {
		t.Fatalf("zero-time restore should be a no-op, got %v", err)
	}
	// real time on a real file.
	f := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	mt := time.Unix(1_500_000_000, 0)
	if err := extRestoreTime(f, mt); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(f)
	if !fi.ModTime().Equal(mt) {
		t.Errorf("mtime = %v; want %v", fi.ModTime(), mt)
	}
	// extPermOr: non-zero perm is kept.
	if got := extPermOr(0o600, 0o644); got != 0o600 {
		t.Errorf("permOr kept = %o; want 600", got)
	}
	// extSafeTarget: a name cleaning to "." is skipped (ok == false, no error).
	if _, ok, err := extSafeTarget(t.TempDir(), "./", 0); ok || err != nil {
		t.Errorf(`extSafeTarget("./") = ok=%v err=%v; want ok=false err=nil`, ok, err)
	}
}

// TestExtractStripsTheHardLinkTargetToo is graphviz.org 16.0.0's shape: a
// release tarball whose entries all sit under one top directory, carrying a
// hard link whose target is spelled the same way.
//
// The entry's own name was stripped and the link target was not, so the link
// pointed at a path that was never created and the whole fetch failed before a
// line was compiled:
//
//	fetch: link .../build/graphviz-16.0.0/redhat/graphviz.spec.fedora.in
//	            .../build/redhat/graphviz.spec.fedora.in
func TestExtractStripsTheHardLinkTargetToo(t *testing.T) {
	skipOnWASI(t, wasiNoChmod)
	dest := t.TempDir()
	data := buildExtractTar(t, []tarEntry{
		{name: "graphviz-16.0.0", typ: tar.TypeDir, mode: 0o755},
		{name: "graphviz-16.0.0/redhat", typ: tar.TypeDir, mode: 0o755},
		{name: "graphviz-16.0.0/redhat/spec.in", typ: tar.TypeReg, mode: 0o644, body: "spec"},
		{name: "graphviz-16.0.0/redhat/spec.fedora.in", typ: tar.TypeLink, link: "graphviz-16.0.0/redhat/spec.in"},
	})
	if err := extract(data, dest, 1); err != nil {
		t.Fatalf("extract with strip=1: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dest, "redhat/spec.fedora.in"))
	if err != nil {
		t.Fatalf("hard link not created: %v", err)
	}
	if string(got) != "spec" {
		t.Errorf("link content = %q, want %q", got, "spec")
	}
	// It is a LINK, not a copy: same inode as its source.
	a, err := os.Stat(filepath.Join(dest, "redhat/spec.in"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.Stat(filepath.Join(dest, "redhat/spec.fedora.in"))
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(a, b) {
		t.Error("extracted a copy rather than a hard link")
	}
}

// TestExtractRefusesALinkAboveTheStrippedRoot: a target that strips away
// entirely names a file outside the extracted tree. Refusing says so; os.Link
// would fail on a path nobody wrote.
func TestExtractRefusesALinkAboveTheStrippedRoot(t *testing.T) {
	dest := t.TempDir()
	data := buildExtractTar(t, []tarEntry{
		{name: "top/d", typ: tar.TypeDir, mode: 0o755},
		{name: "top/d/h", typ: tar.TypeLink, link: "top"},
	})
	err := extract(data, dest, 1)
	if err == nil {
		t.Fatal("want a refusal for a link target above the stripped root")
	}
	if !strings.Contains(err.Error(), "stripped component") {
		t.Errorf("error does not explain itself: %v", err)
	}
}

// A regular entry whose path is ALREADY a symlink must replace the link, not
// write through it. extSafeTarget keeps an entry's own name inside dest; it
// cannot see a link an earlier entry put there.
//
// This is the classic tar symlink traversal, and the test writes the escape
// it would perform: without the unlink, `outside` gains the body.
func TestExtractDoesNotWriteThroughAnEarlierSymlink(t *testing.T) {
	// The escape this guards against needs a symlink to exist, and WASI
	// refuses to make one — so the traversal is not reachable there either.
	skipOnWASI(t, wasiNoSymlink)
	outDir := t.TempDir()
	outside := filepath.Join(outDir, "outside")
	if err := os.WriteFile(outside, []byte("untouched"), 0o644); err != nil {
		t.Fatal(err)
	}

	dest := t.TempDir()
	data := buildExtractTar(t, []tarEntry{
		{name: "x", typ: tar.TypeSymlink, link: outside},
		{name: "x", typ: tar.TypeReg, mode: 0o644, body: "payload"},
	})
	if err := extract(data, dest, 0); err != nil {
		t.Fatalf("extract: %v", err)
	}

	got, err := os.ReadFile(outside)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "untouched" {
		t.Errorf("the archive wrote OUTSIDE dest: %q", got)
	}
	// And the entry landed where it belongs, as a regular file.
	fi, err := os.Lstat(filepath.Join(dest, "x"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		t.Error("the symlink survived; the regular entry did not replace it")
	}
	b, err := os.ReadFile(filepath.Join(dest, "x"))
	if err != nil || string(b) != "payload" {
		t.Errorf("dest/x = %q, %v", b, err)
	}
}

// The benign shape that found it: a symlink that loops, then a regular entry
// at the same name. Opening the path ELOOPs; unlinking first does not.
//
// Measured on real artefacts — invisible-island.net/ncurses 6.6.0 for
// linux/x86-64 would not unpack at all, while the aarch64 artifact of the same
// version did.
func TestExtractReplacesALoopingSymlink(t *testing.T) {
	skipOnWASI(t, wasiNoSymlink)
	dest := t.TempDir()
	data := buildExtractTar(t, []tarEntry{
		{name: "n/loop", typ: tar.TypeSymlink, link: "loop"},
		{name: "n/loop", typ: tar.TypeReg, mode: 0o644, body: "terminfo"},
	})
	if err := extract(data, dest, 0); err != nil {
		t.Fatalf("a looping symlink stopped the extraction: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(dest, "n", "loop"))
	if err != nil || string(b) != "terminfo" {
		t.Errorf("n/loop = %q, %v", b, err)
	}
}

// TestExtractRefusesASymlinkedParent is the contre-épreuve for extSafeParents.
//
// It is written to FAIL without the fix, which is the only way to know it
// measures anything: the probe that found this reported
//
//	extract err=<nil> ; file outside dest = "ESCAPED"
//
// A name check is lexical and a write is not. Four entry kinds take the same
// path through filepath.Dir + MkdirAll, so each is asserted separately rather
// than trusting that one branch stands for the others.
func TestExtractRefusesASymlinkedParent(t *testing.T) {
	// The attack IS a symlink entry, so a platform that cannot make one
	// cannot be vulnerable to it either — there is nothing here to measure.
	skipOnWASI(t, wasiNoSymlink)

	outside := func(t *testing.T) (dest, out string) {
		t.Helper()
		root := t.TempDir()
		dest = filepath.Join(root, "dest")
		out = filepath.Join(root, "outside")
		for _, d := range []string{dest, out} {
			if err := os.MkdirAll(d, 0o755); err != nil {
				t.Fatalf("mkdir %s: %v", d, err)
			}
		}
		return dest, out
	}

	for _, tc := range []struct {
		name  string
		entry tarEntry
	}{
		{"regular", tarEntry{name: "a/b", typ: tar.TypeReg, mode: 0o644, body: "ESCAPED"}},
		{"dir", tarEntry{name: "a/b", typ: tar.TypeDir, mode: 0o755}},
		{"symlink", tarEntry{name: "a/b", typ: tar.TypeSymlink, link: "elsewhere"}},
		{"hardlink", tarEntry{name: "a/b", typ: tar.TypeLink, link: "seed"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dest, out := outside(t)
			data := buildExtractTar(t, []tarEntry{
				{name: "seed", typ: tar.TypeReg, mode: 0o644, body: "x"},
				{name: "a", typ: tar.TypeSymlink, link: out},
				tc.entry,
			})
			err := extract(data, dest, 0)
			if !errors.Is(err, ErrInsecurePath) {
				t.Fatalf("extract: got %v, want ErrInsecurePath", err)
			}
			// The error is the claim; the empty directory is the proof. An
			// extractor can refuse an entry AFTER having written it.
			ents, rerr := os.ReadDir(out)
			if rerr != nil {
				t.Fatalf("read outside dir: %v", rerr)
			}
			if len(ents) != 0 {
				t.Fatalf("archive wrote %d entries outside dest: %v", len(ents), ents[0].Name())
			}
		})
	}
}

// TestExtractStillNestsThroughRealDirectories is the positive control for the
// test above. Tightening a check can make it refuse everything, and a refusal
// of the attack is worth nothing without the proof that ordinary archives —
// which are nested several levels deep, every one of them — still land.
func TestExtractStillNestsThroughRealDirectories(t *testing.T) {
	dest := t.TempDir()
	data := buildExtractTar(t, []tarEntry{
		{name: "a", typ: tar.TypeDir, mode: 0o755},
		{name: "a/b", typ: tar.TypeDir, mode: 0o755},
		{name: "a/b/c/d.txt", typ: tar.TypeReg, mode: 0o644, body: "deep"},
	})
	if err := extract(data, dest, 0); err != nil {
		t.Fatalf("extract: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dest, "a", "b", "c", "d.txt"))
	if err != nil || string(got) != "deep" {
		t.Fatalf("nested file: %q, %v", got, err)
	}
}

// TestExtractDropsSetuidAndSetgid pins a guarantee that was accidental.
//
// extPermOr returns m.Perm(), which is the low nine bits, so the setuid,
// setgid and sticky bits a tar header can carry never reach the filesystem.
// Nothing said so and nothing checked it, and "returns the permission bits"
// is one refactor away from "returns the mode" — in an extractor that bk
// points at upstream source tarballs and that the sovereign lane runs as
// root inside a chroot.
//
// Verified by mutation, surgically — a broader one (`return m`) is caught by
// TestExtractHappyPath for an unrelated reason and would prove nothing. Adding
// just the three bits back,
//
//	m.Perm() | (m & (fs.ModeSetuid | fs.ModeSetgid | fs.ModeSticky))
//
// fails THIS test and leaves every other test in the package green. That is
// the whole argument for it existing.
//
// What a given lane actually witnesses differs. On macOS as an unprivileged
// user the kernel refuses setuid/setgid on a file that user writes, so only
// the sticky bit demonstrates the mutation here; a lane running as root sees
// all three. The assertion covers all three either way, because the place
// this matters is the sovereign build, which runs as root in a chroot and is
// exactly where the kernel would NOT be a second line of defence.
func TestExtractDropsSetuidAndSetgid(t *testing.T) {
	skipOnWASI(t, wasiNoChmod)
	if runtime.GOOS == "windows" {
		t.Skip("windows has no setuid bit to drop")
	}
	dest := t.TempDir()
	// tar carries these in the header's mode; archive/tar maps them onto
	// fs.ModeSetuid and friends in FileInfo().Mode(), which is what Extract
	// reads.
	const dangerous = 0o4000 | 0o2000 | 0o1000 | 0o755
	data := buildExtractTar(t, []tarEntry{
		{name: "s", typ: tar.TypeReg, mode: dangerous, body: "x"},
		{name: "d", typ: tar.TypeDir, mode: dangerous},
	})
	if err := extract(data, dest, 0); err != nil {
		t.Fatalf("extract: %v", err)
	}
	for _, name := range []string{"s", "d"} {
		fi, err := os.Stat(filepath.Join(dest, name))
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		if bad := fi.Mode() & (fs.ModeSetuid | fs.ModeSetgid | fs.ModeSticky); bad != 0 {
			t.Errorf("%s kept %v from the archive (mode %v)", name, bad, fi.Mode())
		}
	}
}
