// Copyright (c) 2026, the go-zpkg/artifact authors
// All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package artifact

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// ErrInsecurePath is returned by Extract when an archive entry (or a hard-link
// source) names an absolute path, or one that after component-stripping would
// escape the destination directory. It is wrapped with the offending name so
// callers can test for it with errors.Is.
var ErrInsecurePath = errors.New("artifact: insecure path in archive")

// osWriteFlags is how extracted regular files are opened.
const osWriteFlags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC

// Injectable seams over the os operations whose error branches are otherwise
// unreachable in a test (a syscall that succeeds and only later fails is not
// reproducible with real files). Tests override these to exercise every
// error-handling path; production uses the real functions verbatim.
var (
	extMkdirAll = os.MkdirAll
	extSymlink  = os.Symlink
	extLink     = os.Link
	extOpenFile = os.OpenFile
	extChtimes  = os.Chtimes
	extCopy     = io.Copy
)

// Extract unpacks every entry of tr into dest, stripping strip leading path
// components from each entry name (strip == 0 keeps the archive layout). It is
// the shared archive extractor for the pkgx ecosystem — both artifact's artifact
// installer and bk's source fetcher route through it, so a single implementation
// carries the invariants both rely on:
//
//   - Regular files keep the modification time the archive recorded (tar(1)
//     semantics). Recipes DEPEND on this: a release tarball ships generated
//     files NEWER than the sources they derive from so make leaves them alone;
//     stamping every file "now" re-orders them by archive position and make then
//     tries to regenerate — libexpat 2.8.3 dies that way (doc/xmlwf.1 is archived
//     before, hence would be stamped older than, doc/xmlwf.xml → make runs the
//     docbook rule with no docbook2x-man installed → Error 1). A zero recorded
//     time is left as written.
//   - Absolute names, and names that escape dest after stripping, are rejected
//     with ErrInsecurePath; a hard-link source is vetted the same way.
//   - An entry whose path crosses a symlink an EARLIER entry created is
//     rejected with ErrInsecurePath. A name check is lexical and a write is
//     not: `dest/a/b` is inside dest even when `a` is a link out of it.
//   - setuid, setgid and sticky are dropped: an entry gets its permission bits
//     and nothing else.
//   - Directories, regular files, symlinks and hard links are reproduced;
//     unsupported entry types (fifos, devices, ...) are skipped.
//
// What it does NOT promise: a symlink ENTRY may point anywhere, including out
// of dest, which is what tar(1) does and what an artifact's relative links need.
// Nothing Extract writes afterwards follows such a link — that is the
// ErrInsecurePath rule above — but a caller that walks the result and resolves
// symlinks itself can still leave dest, and must say whether it means to.
//
// tar.ErrInsecurePath from tr.Next is tolerated because Extract performs its own
// stricter vetting on every entry name.
func Extract(tr *tar.Reader, dest string, strip int) error {
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil && !errors.Is(err, tar.ErrInsecurePath) {
			return err
		}
		target, ok, err := extSafeTarget(dest, hdr.Name, strip)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		mode := hdr.FileInfo().Mode()
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := extSafeParents(dest, target); err != nil {
				return err
			}
			if err := extMkdirAll(target, extPermOr(mode, 0o755)); err != nil {
				return err
			}
		case tar.TypeSymlink:
			if err := extSafeParents(dest, target); err != nil {
				return err
			}
			if err := extMkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			_ = os.Remove(target)
			if err := extSymlink(hdr.Linkname, target); err != nil {
				return err
			}
		case tar.TypeLink:
			if err := extSafeParents(dest, target); err != nil {
				return err
			}
			if err := extMkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			source, err := extLinkSource(dest, hdr.Linkname, strip)
			if err != nil {
				return err
			}
			_ = os.Remove(target)
			if err := extLink(source, target); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := extSafeParents(dest, target); err != nil {
				return err
			}
			if err := extMkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			// Unlink first, like the symlink and hardlink branches above
			// already do, and for a reason they do not share.
			//
			// Writing to a path that is ALREADY a symlink writes through it.
			// extSafeTarget keeps an entry's own NAME inside dest; it cannot
			// see a link an EARLIER entry put there. So an archive holding
			//
			//	x -> /somewhere/else      (symlink entry)
			//	x                         (regular entry)
			//
			// reaches outside the destination on the second entry, which is
			// the classic tar symlink traversal. Nothing in this factory
			// ships such an archive, and "our artifacts are signed" is not the
			// property an extractor should rely on — ZPKG_VERIFY=0 is a
			// supported mode for a loopback registry, and an extractor is
			// exactly where defence in depth belongs.
			//
			// Found from the benign end: invisible-island.net/ncurses 6.6.0
			// for linux/x86-64 and 6.6 for linux/s390x carry a terminfo entry
			// whose symlink loops, and unpacking either died with
			//
			//	open …/share/terminfo/n/ncr260vt300wpp: too many levels of
			//	symbolic links
			//
			// while the aarch64 artifact of the same version unpacked fine. A
			// published artifact that cannot be unpacked is its own defect; it
			// is also the only reason this line was ever looked at.
			//
			// A SYMLINK only. An existing regular file is handled by the
			// O_TRUNC in extWriteFile, and an existing DIRECTORY must keep
			// erroring — TestUntarErrorBranches asserts that, and a blanket
			// Remove silently replaced an empty one with a file. The fix is
			// the size of the defect.
			if fi, err := os.Lstat(target); err == nil && fi.Mode()&os.ModeSymlink != 0 {
				_ = os.Remove(target)
			}
			if err := extWriteFile(target, extPermOr(mode, 0o644), tr); err != nil {
				return err
			}
			if err := extRestoreTime(target, hdr.ModTime); err != nil {
				return err
			}
		}
	}
}

// extSafeTarget resolves an archive entry name to a path under dest after
// stripping strip leading components. ok is false when the entry is fully
// consumed by stripping (nothing to write). An absolute name, or one that
// escapes dest, yields ErrInsecurePath.
func extSafeTarget(dest, name string, strip int) (target string, ok bool, err error) {
	if path.IsAbs(name) || filepath.IsAbs(filepath.FromSlash(name)) {
		return "", false, fmt.Errorf("%w: %q", ErrInsecurePath, name)
	}
	parts := stripComponents(name)
	if len(parts) <= strip {
		return "", false, nil
	}
	rel := path.Join(parts[strip:]...)
	if rel == "." {
		return "", false, nil
	}
	target = filepath.Join(dest, filepath.FromSlash(rel))
	prefix := filepath.Clean(dest) + string(filepath.Separator)
	if !strings.HasPrefix(target+string(filepath.Separator), prefix) {
		return "", false, fmt.Errorf("%w: %q", ErrInsecurePath, name)
	}
	return target, true, nil
}

// extLinkSource resolves a hard-link source name to a path under dest, applying
// the same component STRIPPING and the same safety vetting as extSafeTarget.
//
// It used to apply only the vetting, and the comment saying "the same safety
// vetting" is what made that look complete. A tar entry's link target names the
// file as the ARCHIVE spells it, so with --strip-components it has to be
// stripped exactly like the entry's own name — otherwise the link points at a
// path that was never created:
//
//	fetch: link .../build/graphviz-16.0.0/redhat/graphviz.spec.fedora.in   <- source, unstripped
//	            .../build/redhat/graphviz.spec.fedora.in                   <- target, stripped
//
// graphviz.org 16.0.0 failed its whole rebuild on that, before compiling a
// line. Every archive that carries a hard link and needs stripping hits it; the
// reason it is not more visible is that hard links in source tarballs are rare.
func extLinkSource(dest, linkname string, strip int) (string, error) {
	if path.IsAbs(linkname) || filepath.IsAbs(filepath.FromSlash(linkname)) {
		return "", fmt.Errorf("%w: link %q", ErrInsecurePath, linkname)
	}
	parts := stripComponents(linkname)
	if len(parts) <= strip {
		// The target is above the stripped root, so the file it names is not in
		// the extracted tree at all. Refusing names it; os.Link would fail with
		// a path nobody asked for.
		return "", fmt.Errorf("link target %q is above the %d stripped component(s)", linkname, strip)
	}
	source := filepath.Join(dest, filepath.FromSlash(path.Join(parts[strip:]...)))
	prefix := filepath.Clean(dest) + string(filepath.Separator)
	if !strings.HasPrefix(source+string(filepath.Separator), prefix) {
		return "", fmt.Errorf("%w: link %q", ErrInsecurePath, linkname)
	}
	return source, nil
}

// extSafeParents refuses a target whose path crosses an existing SYMLINK.
//
// extSafeTarget keeps an entry's NAME inside dest, lexically. That is not the
// same as keeping the WRITE inside dest: an earlier entry can make a
// directory component a symlink, and every later entry under it resolves
// through that link. The name passes, the write escapes.
//
//	a   -> /somewhere/else     (symlink entry)
//	a/b                        (regular entry)
//
// `dest/a/b` is lexically inside dest, MkdirAll FOLLOWS `a`, and the body
// lands in /somewhere/else/b. Measured before this existed: the probe found
// the payload outside dest, with Extract returning nil.
//
// This is the sibling of the leaf case fixed one release earlier, which
// unlinked a symlink standing where a regular file goes. That fix covered the
// LAST component only. A defect in an extractor rarely has just one.
//
// Refused rather than unlinked. A leaf can be replaced, because the archive
// says what belongs there; a directory component that is ALREADY a symlink
// says the archive contradicts itself, and rebuilding the path silently would
// discard whatever the link pointed at.
//
// target is always filepath.Join(dest, …) — extSafeTarget built it and
// checked the containment — so the prefix below is exact and there is no
// error to handle here.
func extSafeParents(dest, target string) error {
	rel := strings.TrimPrefix(target, dest+string(filepath.Separator))
	parts := strings.Split(rel, string(filepath.Separator))
	cur := dest
	// Every component EXCEPT the last: the leaf is the caller's business, and
	// the regular-file branch replaces a symlink there on purpose.
	for _, p := range parts[:len(parts)-1] {
		cur = filepath.Join(cur, p)
		fi, err := os.Lstat(cur)
		if err != nil {
			// Not there yet: MkdirAll will create a real directory, and the
			// next entry under it sees that.
			return nil
		}
		if fi.Mode()&fs.ModeSymlink != 0 {
			return fmt.Errorf("%w: %q crosses the symlink %q", ErrInsecurePath, target, cur)
		}
	}
	return nil
}

// extPermOr returns the permission bits of m, or fallback when m carries none
// (e.g. archive entries written without Unix modes).
func extPermOr(m, fallback fs.FileMode) fs.FileMode {
	if p := m.Perm(); p != 0 {
		return p
	}
	return fallback
}

// extWriteFile creates target with perm and copies r into it.
func extWriteFile(target string, perm fs.FileMode, r io.Reader) error {
	f, err := extOpenFile(target, osWriteFlags, perm)
	if err != nil {
		return err
	}
	if _, err := extCopy(f, r); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// extRestoreTime stamps path with the archive's recorded modification time; a
// zero time (no record) is left as written.
func extRestoreTime(path string, mt time.Time) error {
	if mt.IsZero() {
		return nil
	}
	return extChtimes(path, mt, mt)
}

// stripComponents splits an archive member name the way `tar --strip-components`
// counts it: a leading "." IS a component.
//
// `path.Clean` removes it before the count, so N components off a `./`-prefixed
// archive strips N+1. That does not fail — it FLATTENS. `hdf5-2.2.0.tar.gz`
// ships `./hdf5-2.2.0/…` and its recipe says `strip-components: 2`; the
// top-level `CMakeLists.txt` was dropped and a subdirectory's namesake landed
// in its place, which cmake reported as
//
//	CMake Error at CMakeLists.txt:152 (TARGET_C_PROPERTIES):
//	  Unknown CMake command "TARGET_C_PROPERTIES".
//
// — line 152 of `testpar/CMakeLists.txt`, configured as if it were the root.
// Measured against GNU tar on a `./top/sub/f` archive: `--strip-components=2`
// yields `sub/f`, and this yielded `f`.
//
// Empty segments (from "//" or a trailing "/") are not components and are
// dropped; "." is kept.
func stripComponents(name string) []string {
	raw := strings.Split(name, "/")
	out := raw[:0]
	for _, p := range raw {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
