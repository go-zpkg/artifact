package artifact

import (
	"debug/macho"
	"encoding/binary"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// The three load commands that make a file DEPEND on another. Not LC_ID_DYLIB
// (0x0d), which says where this file expects to live: counting it makes every
// library look like it depends on its own home.
const (
	lcLoadDylib     = 0x0c
	lcLoadWeakDylib = 0x18 | 0x80000000
	lcReexportDylib = 0x1f | 0x80000000
)

// MachoNeeded is what a Mach-O file loads. It is the darwin counterpart of
// ELF's DT_NEEDED, and it lives here rather than in a build tool because the
// closure needs it too: bk reads it to rewrite a reference, artifact reads it to
// find out whether that reference resolves.
//
// A file that is not a Mach-O is not an error worth propagating — a store is
// mostly text — so the caller gets an empty list and the walk continues.
// ⛔ A UNIVERSAL ("fat") file is read too, through every one of its slices.
//
// `macho.Open` handles only a thin file, and a universal one made the closure
// check say it could not read a library at all. Reported from the field on
// 2026-10-12, installing python-openstackclient on darwin/aarch64:
//
//	charset_normalizer/*.so looks like a Mach-O (universal) but cannot be read
//
// which is the warning five lines down in unresolvedRefs — so the file was
// correctly identified as a Mach-O, correctly flagged as unreadable, and its
// references were simply unknown. An unknown reference is how a closure gets
// declared complete while it is not, which is the one failure this file exists
// to prevent.
//
// The UNION of the slices, not the slice matching this host, and the choice is
// deliberate — the report suggested selecting the arm64 slice. Two reasons
// against it:
//
//   - On macOS an x86-64 slice still runs, under Rosetta. "No slice for this
//     architecture" therefore does not mean "will not run here", so picking by
//     host arch can under-report for a binary that executes perfectly well.
//   - Under-reporting is the dangerous direction. A universal binary's slices
//     name the same dylib PATHS in practice, since the libraries are universal
//     too, so the union is almost always identical to any single slice — and
//     where it is not, the extra reference is a real thing something loads.
//
// Deduplicated and sorted, because a union across slices has no natural order.
// The thin path keeps its load order untouched: there it is the file's own.
func MachoNeeded(p string) ([]string, error) {
	f, thinErr := macho.Open(p)
	if thinErr == nil {
		defer f.Close()
		return dylibRefs(f), nil
	}
	fat, fatErr := macho.OpenFat(p)
	if fatErr != nil {
		// BOTH errors. For an ordinary text file the thin error is the one
		// that says so; for a corrupt universal file it is the fat one, and
		// returning only the first made the second unsayable.
		return nil, errors.Join(thinErr, fatErr)
	}
	defer fat.Close()
	seen := map[string]bool{}
	var out []string
	for i := range fat.Arches {
		for _, ref := range dylibRefs(fat.Arches[i].File) {
			if !seen[ref] {
				seen[ref] = true
				out = append(out, ref)
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

// dylibRefs is the load-command walk, over one thin image. Split out so a
// universal file's slices go through exactly the same reader rather than a
// second copy of it.
func dylibRefs(f *macho.File) []string {
	var out []string
	for _, l := range f.Loads {
		b := l.Raw()
		if len(b) < 12 {
			continue
		}
		switch f.ByteOrder.Uint32(b[0:4]) {
		case lcLoadDylib, lcLoadWeakDylib, lcReexportDylib:
		default:
			continue
		}
		off := f.ByteOrder.Uint32(b[8:12])
		if int(off) >= len(b) {
			continue
		}
		s := b[off:]
		if i := indexZero(s); i >= 0 {
			s = s[:i]
		}
		out = append(out, string(s))
	}
	return out
}

func indexZero(b []byte) int {
	for i, c := range b {
		if c == 0 {
			return i
		}
	}
	return -1
}

// storeRefRE splits an @rpath reference into the project and the directory it
// binds through: either an ABI line (abi-libxml2.16.dylib) or a version
// directory (v2). The project name has slashes in it — gnupg.org/gpgme — so
// that second segment is the only reliable terminator.
var storeRefRE = regexp.MustCompile(`^@rpath/(.+?)/(abi-([^/]+)|v[0-9][^/]*)/(.+)$`)

// storeRel is the store-relative path an @rpath reference names, and false if
// the reference does not stay inside the store.
//
// ⛔ THE REFERENCE IS UNTRUSTED. It is read from the load commands of a
// downloaded Mach-O, so `@rpath/../../../../etc/passwd` is a thing an artifact
// can carry. The caller stats <dir>/<rel> and treats an existing file as
// "already satisfied" — so without this, an artifact could point at any path the
// process can see and have its closure declared complete on the strength of a
// file that is not a library and is not in the store.
//
// filepath.IsLocal is the stdlib predicate for exactly this: it is false for
// an absolute path, for one that escapes with .., and for a Windows reserved
// name. An allowlist, like ValidateProjectName beside it, because a denylist
// of dangerous shapes inherits the blind spots of whoever wrote it.
func storeRel(ref string) (string, bool) {
	rel := filepath.FromSlash(strings.TrimPrefix(ref, "@rpath/"))
	if !filepath.IsLocal(rel) {
		return "", false
	}
	return rel, true
}

// Seams: the three things below that need a network, so the repair loop is
// testable without one.
var (
	machoProvider = provideMachoSoname
	machoVersions = FetchVersions
	machoInstall  = InstallFor
)

// want is one reference that does not resolve, reduced to what would fix it.
type want struct {
	project string
	soname  string
	ref     string // the reference as the binary records it
	abiLine bool   // it binds through abi-<soname>, not through v<major>
}

func (w want) key() string { return w.project + "\x00" + w.soname }

// unresolvedRefs is every @rpath reference in the store that names a file the
// store does not have.
//
// This is the whole darwin question, and it is simpler than the ELF one: a
// Mach-O reference is a path, so "is it satisfied" is a stat, not a search
// through a library path. It is also stricter — ELF would find a compatible
// soname anywhere on LD_LIBRARY_PATH; here the one named path either exists or
// the program does not start.
func unresolvedRefs(prefixes []string, dir string) []want {
	seen := map[string]bool{}
	var out []want
	for _, prefix := range prefixes {
		_ = filepath.WalkDir(prefix, func(p string, d fs.DirEntry, err error) error {
			if err != nil || !d.Type().IsRegular() {
				return nil
			}
			// Sniff first. A store is mostly text, and asking the Mach-O
			// parser about every file was both the slow way round and a blind
			// spot: a file it declined looked exactly like a README. Now a
			// file that CLAIMS to be a Mach-O and cannot be read is said out
			// loud, because what it loads is then unknown rather than absent
			// — and an unknown reference is how a closure gets declared
			// complete while it is not.
			kind := machoMagic(p)
			if kind == notMachO {
				return nil
			}
			refs, rerr := MachoNeeded(p)
			if rerr != nil {
				warn("%s looks like a Mach-O (%s) but cannot be read, so what it loads is unknown: %v", p, kind, rerr)
				return nil
			}
			for _, ref := range refs {
				if !strings.HasPrefix(ref, "@rpath/") {
					continue // /usr/lib and the system frameworks are the host's
				}
				rel, inStore := storeRel(ref)
				if !inStore {
					warn("%s is NEEDED and names a path OUTSIDE the store, so it is not "+
						"something a closure can satisfy; ignoring it", ref)
					continue
				}
				if _, serr := os.Stat(filepath.Join(dir, rel)); serr == nil {
					continue
				}
				m := storeRefRE.FindStringSubmatch(ref)
				if m == nil {
					// ⛔ REACHED ONLY WHEN THE FILE IS ALSO ABSENT: the two
					// checks above have already let through everything that
					// is the host's (not @rpath) and everything the store
					// already satisfies. So this is a reference that will
					// NOT resolve and that this function cannot even try to
					// resolve — and until now it said nothing at all.
					//
					// What that silence hid, measured 2026-10-26 on the
					// first full darwin/aarch64 sweep: of 3003 unresolvable
					// references, 1266 are shaped
					//
					//	@rpath/libabsl_base.2608.0.0.dylib
					//
					// with no project directory, so storeRefRE cannot match
					// and no want is built. `bk unresolved` COUNTS those —
					// it stats every @rpath reference — while this skipped
					// them, so the auditor and the resolver disagreed about
					// 42% of a platform's backlog and the log carried not
					// one line about it.
					//
					// This does not resolve them; naming a project from a
					// bare soname needs the index provideMachoSoname reads
					// (go-zpkg/artifact#166). It stops the gap being silent,
					// which is the part that let it reach 1266.
					warn("%s is NEEDED, is not in the store, and names no project directory — "+
						"this cannot look for a provider, so it will not resolve", ref)
					continue
				}
				// ⛔ THE PROJECT COMES OUT OF A DOWNLOADED BINARY. m[1] is
				// whatever the load command happened to say, and it goes on to
				// name a registry repository (FetchVersions) and a store path
				// (InstallFor builds <dir>/<project>/v<version>). projectname.go
				// says the check "lives where the name is USED, not where a
				// person typed it" — and this use site did not have it.
				if err := ValidateProjectName(m[1]); err != nil {
					warn("%s names %q as its project, which cannot be used as one (%v), "+
						"so this will not look for a provider", ref, m[1], err)
					continue
				}
				w := want{project: m[1], soname: m[3], ref: ref, abiLine: m[3] != ""}
				if w.soname == "" {
					w.soname = path.Base(m[4])
				}
				if seen[w.key()] {
					continue
				}
				seen[w.key()] = true
				out = append(out, w)
			}
			return nil
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].key() < out[j].key() })
	return out
}

// completeMachO pulls the artifact that provides each soname the store is asked
// for and does not have, so a closure runs on a FROM-scratch image.
//
// Two versions of one project can be installed at once, which is the point: a
// reference through abi-<soname> names an ABI LINE rather than a major, and
// two lines coexist as two symlinks beside the version directories. hwloc
// needs libxml2.16.dylib in the same closure where gettext holds libxml2 at
// the 2.13 line, and on darwin that is safe — the two-level namespace binds
// each symbol to the library that defined it, so nothing is interposed.
//
// A reference through v<major> cannot be repaired that way: v2 is one symlink
// and one version owns it. That case is reported rather than papered over,
// because the fix is to rebuild the consumer against the ABI line, and a
// warning at install time is a diagnosis where dyld's is a crash.
func completeMachO(closure []Resolved, dir, osn, arch string) ([]Resolved, error) {
	installedVer := map[string]bool{}
	for _, r := range closure {
		installedVer[r.Project+"@"+r.Version.Raw] = true
	}
	tried := map[string]bool{}
	for round := 0; round < 8; round++ {
		changed := false
		for _, w := range unresolvedRefs(prefixesOf(closure, dir), dir) {
			if tried[w.key()] {
				continue
			}
			tried[w.key()] = true
			if !w.abiLine {
				warn("%s names %s through a major directory, which one version owns; "+
					"rebuild it against the ABI line to hold both", w.project, w.soname)
				continue
			}
			r, ok := machoProvider(w, dir)
			if !ok {
				continue
			}
			if installedVer[r.Project+"@"+r.Version.Raw] {
				continue
			}
			installedVer[r.Project+"@"+r.Version.Raw] = true
			closure = append(closure, r)
			changed = true
		}
		if !changed {
			break
		}
	}
	return closure, nil
}

// provideMachoSoname installs the newest published version of w.project whose
// artifact declares w.soname, or says why it could not.
//
// It asks the MANIFEST, not the artifact: publish records the sonames an artifact
// ships as an annotation, so choosing between forty versions costs forty small
// reads instead of forty downloads. An artifact published before that annotation
// existed answers nothing, and is skipped rather than downloaded on the chance
// — an old artifact is also one that predates the ABI links this depends on.
func provideMachoSoname(w want, dir string) (Resolved, bool) {
	vs, err := machoVersions(w.project)
	if err != nil {
		warn("cannot provide %s from %s: %v", w.soname, w.project, err)
		return Resolved{}, false
	}
	osn, arch := HostSlug()
	// FetchVersions answers ascending; the newest artifact that declares the
	// soname is the one to hold the line.
	const maxTry = 40
	for i, n := len(vs)-1, 0; i >= 0 && n < maxTry; i, n = i-1, n+1 {
		v := vs[i]
		r := Resolved{w.project, v}
		if !strings.Contains(","+Annotation(abiAnnotations(w.project, v.tag(), osn, arch), ABIProvidesAnnotation)+",", ","+w.soname+",") {
			continue
		}
		if _, err := machoInstall(r, dir, osn, arch); err != nil {
			warn("cannot install %s %s for %s: %v", w.project, v.Raw, w.soname, err)
			continue
		}
		return r, true
	}
	warn("no published %s declares %s, so %s will not resolve", w.project, w.soname, w.ref)
	return Resolved{}, false
}

// The Mach-O magics, in both byte orders. A universal ("fat") file holds
// several architectures and debug/macho.Open declines it — which is why it is
// named here rather than lumped in with everything else: our own artifacts are
// built one architecture at a time and carry none (measured: 770 executables
// across 29 closures, zero fat), but an artifact mirrored from elsewhere could,
// and its references would otherwise be silently invisible.
type machoKind string

const (
	notMachO  machoKind = ""
	thinMachO machoKind = "thin"
	fatMachO  machoKind = "universal"
)

func machoMagic(p string) machoKind {
	f, err := os.Open(p)
	if err != nil {
		return notMachO
	}
	defer f.Close()
	var b [8]byte
	n, _ := io.ReadFull(f, b[:])
	if n < 4 {
		return notMachO
	}
	switch binary.BigEndian.Uint32(b[:4]) {
	case 0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe:
		return thinMachO
	case 0xcafebabe, 0xbebafeca, 0xcafebabf, 0xbfbafeca:
		// 0xcafebabe is ALSO a Java class file, and a store that packages a
		// JVM tool is full of them. The word after the magic tells them
		// apart: in a universal file it is nfat_arch, a handful of
		// architectures; in a class file it is the minor and major version,
		// and every major since Java 1.1 is at least 45. `file` draws the
		// same line in the same place.
		if n == 8 && binary.BigEndian.Uint32(b[4:]) >= 30 {
			return notMachO
		}
		return fatMachO
	}
	return notMachO
}
