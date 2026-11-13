package artifact

import (
	"debug/elf"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// The "implicit system" shared libraries: artifacts link them but never declare
// them as pkgx dependencies, because pkgx historically assumes the host libc /
// toolchain runtime. On a `FROM scratch` image there is no host, so the
// installer must supply them from pkgx artifacts too. Each group maps to the
// artifact that provides it.
var (
	glibcSonames = []string{
		"libc.so", "libm.so", "libpthread.so", "libdl.so", "librt.so",
		"libresolv.so", "libutil.so", "libnsl.so", "libanl.so", "ld-linux",
	}
	libstdcxxSonames = []string{"libgcc_s.so", "libstdc++.so"}
	gccSonames       = []string{"libatomic.so", "libgomp.so", "libquadmath.so", "libitm.so"}
	// The OTHER C++ runtime. libstdc++ above is gcc's; this is llvm's, and the
	// sovereign toolchain links it — zbk's own driver flags say
	// `-stdlib=libc++ … --unwindlib=libunwind` out of ${ZBK_LIBCXX_PREFIX}.
	// So anything zbk builds under `--libc=zpkx` that touches C++ NEEDs these
	// three, and nothing supplied them at install time:
	//
	//	ninja: error while loading shared libraries: libc++.so.1
	//	pzstd: error while loading shared libraries: libc++.so.1
	//
	// Implicit rather than an entry in sonameProject below, for the reason
	// that map's comment gives: these are not a library a recipe forgot to
	// declare, they are the toolchain's runtime — the same thing
	// libstdcxxSonames is, from the other compiler.
	//
	// libunwind.so.1 is ambiguous ELSEWHERE — nongnu.org/libunwind ships one
	// too — and is not ambiguous here: the pantry has no such project (its
	// nongnu.org directory holds lzip and nothing else), and our binaries are
	// linked against llvm's by the flags above.
	libcxxSonames = []string{"libc++.so", "libc++abi.so", "libunwind.so"}
)

// sonameProject maps a shared-library soname stem to the pkgx project that
// provides it, for the common libraries that packages link but frequently do
// NOT declare in their package.yml dependencies (compression, text, tls…).
// package.yml runtime graphs are incomplete; on FROM scratch the closure must
// be complete, so we resolve the gap from the artifacts' own DT_NEEDED.
var sonameProject = map[string]string{
	"libz":         "zlib.net",
	"libbz2":       "sourceware.org/bzip2",
	"liblzma":      "tukaani.org/xz",
	"libzstd":      "facebook.com/zstd",
	"liblz4":       "lz4.org",
	"libssl":       "openssl.org",
	"libcrypto":    "openssl.org",
	"libcurl":      "curl.se",
	"libncurses":   "invisible-island.net/ncurses",
	"libncursesw":  "invisible-island.net/ncurses",
	"libtinfo":     "invisible-island.net/ncurses",
	"libreadline":  "gnu.org/readline",
	"libffi":       "sourceware.org/libffi",
	"libpcre2-8":   "pcre.org/v2",
	"libintl":      "gnu.org/gettext",
	"libiconv":     "gnu.org/libiconv",
	"libidn2":      "gnu.org/libidn2",
	"libunistring": "gnu.org/libunistring",
	"libpsl":       "rockdaboot.github.io/libpsl",
	"libnghttp2":   "nghttp2.org",
	"libexpat":     "libexpat.github.io",
	"libxml2":      "gnome.org/libxml2",
	"libsqlite3":   "sqlite.org",
	"libgmp":       "gnu.org/gmp",
	"libmpfr":      "gnu.org/mpfr",
	"libcrypt":     "github.com/besser82/libxcrypt", // glibc 2.38+ dropped libcrypt
	"libtinfow":    "invisible-island.net/ncurses",  // wide-char ncurses terminfo
	"libFLAC":      "xiph.org/flac",
	"libtheora":    "theora.org",
	"libgit2":      "libgit2.org",
	"libcbor":      "github.com/PJK/libcbor",
	"libavro":      "apache.org/avro",
	"libprotoc":    "protobuf.dev", // protoc lib; libprotobuf is prefix-mapped below
	"libclang":     "llvm.org",
	"libgflags":    "gflags.github.io",
	"libcap":       "kernel.org/libcap",
	// eudev is the lightweight standalone libudev provider (a few files) vs
	// pulling all of systemd (200+ binaries) just for libudev.so.1.
	"libudev": "github.com/eudev-project/eudev",
	// From the second sovereign generation, and each one CHECKED against an
	// installed artifact rather than recalled: `ls ~/.zpkg/gnu.org/gettext/*/lib`
	// lists libtextstyle in five versions, and ncurses' ships libpanel and
	// libpanelw beside libncurses. gnu.org/bison died on the first of them —
	//   bison: error while loading shared libraries: libtextstyle.so.0
	// after a build that had succeeded.
	"libtextstyle": "gnu.org/gettext",
	"libpanel":     "invisible-island.net/ncurses",
	"libpanelw":    "invisible-island.net/ncurses",
}

// sonamePrefixProject maps a soname PREFIX to its provider, for libraries that
// ship many differently-named sonames from one project (e.g. abseil's dozens
// of libabsl_*.so). Consulted when the exact-stem map misses.
var sonamePrefixProject = map[string]string{
	"libabsl":     "abseil.io",
	"libprotobuf": "protobuf.dev",
	"libre2":      "github.com/google/re2",
	"libboost":    "boost.org", // libboost_regex/system/… all ship from boost.org
}

// projectForSoname resolves a NEEDED soname to its providing pkgx project via
// the exact-stem map first, then the prefix map. Returns "" if unknown.
func projectForSoname(soname string) string {
	if p := sonameProject[sonameBase(soname)]; p != "" {
		return p
	}
	for pfx, p := range sonamePrefixProject {
		if strings.HasPrefix(soname, pfx) {
			return p
		}
	}
	return ""
}

// sonameBase reduces a soname like "libz.so.1" to its stem "libz".
func sonameBase(soname string) string {
	if i := strings.Index(soname, ".so"); i >= 0 {
		return soname[:i]
	}
	return soname
}

// scanNeeded walks every ELF under the given installed prefixes and returns the
// set of DT_NEEDED sonames across all of them (pure Go, via debug/elf).
func scanNeeded(prefixes []string) map[string]bool {
	needed := map[string]bool{}
	for _, prefix := range prefixes {
		_ = filepath.Walk(prefix, func(p string, info os.FileInfo, err error) error {
			if err != nil || info == nil || !info.Mode().IsRegular() {
				return nil
			}
			f, err := elf.Open(p)
			if err != nil {
				return nil // not an ELF
			}
			defer f.Close()
			libs, err := f.ImportedLibraries()
			if err != nil {
				return nil
			}
			for _, l := range libs {
				needed[l] = true
			}
			return nil
		})
	}
	return needed
}

// SonameProviders is every project the soname maps can pull into a closure:
// the bounded set of dependencies a RECIPE never mentions.
//
// A dependency discovered this way exists only in the compiled artefact. perl
// declares nothing about libcrypt, glibc 2.38+ stopped providing it, and the
// map above supplies github.com/besser82/libxcrypt when a perl binary turns
// out to need it. Anything planning a build order from recipes alone is blind
// to that channel, and finds out one failed build at a time.
//
// Sorted and deduplicated, so a caller can diff it against an order it
// computed and see what that order cannot have known.
func SonameProviders() []string {
	seen := map[string]bool{}
	for _, m := range []map[string]string{sonameProject, sonamePrefixProject} {
		for _, p := range m {
			seen[p] = true
		}
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// implicitRoots inspects a set of NEEDED sonames and returns the extra pkgx
// artifacts required to satisfy the implicit system libraries on a scratch image.
// glibc is always included on linux (every dynamic ELF needs the loader+libc).
//
// ImplicitRootsOff turns the whole thing off, for the one case where the
// premise in that sentence is false: a BOOTSTRAP host, where the machine has a
// libc and the registry has no artifact of one yet. On linux/s390x the effect is
// total rather than partial -- glibc is added unconditionally, so installing
// ANY artifact fails before it starts, including one this factory has just built
// and published:
//
//	pkgx: GET .../gnu.org/glibc/linux/s390x/versions.txt: Not Found
//	bk: the tool environment failed: pkgx +gnu.org/m4@1
//
// It is off by default and must stay a deliberate act. A closure assembled
// this way is complete only against THIS machine: the whole point of pulling
// glibc is that a scratch image has none, and an artifact built under it owes its
// libc to the host.
func implicitRoots(needed map[string]bool) map[string]string {
	if ImplicitRootsOff {
		return nil
	}
	// glibc is the one implicit root whose newest is not always the right one:
	// its loader refuses to run below the kernel floor it was built against, so
	// the constraint is kernel-aware (and ZPKG_GLIBC-pinnable). See glibc.go.
	roots := map[string]string{GlibcProject: GlibcConstraint()}
	if matchesAny(needed, libstdcxxSonames) {
		roots["gnu.org/gcc/libstdcxx"] = "*"
	}
	if matchesAny(needed, gccSonames) {
		roots["gnu.org/gcc"] = "*"
	}
	if matchesAny(needed, libcxxSonames) {
		roots["libcxx.llvm.org"] = "*"
	}
	return roots
}

// hostProvidedSonames are libraries that come from the MACHINE and never from a
// artifact.
//
// A GPU driver's userspace half is versioned in lockstep with the kernel module
// it talks to, and is installed by whoever installed the driver. Shipping a copy
// would be wrong even where it is allowed — a mismatched libcuda and kernel
// module do not work together — and NVIDIA's is not redistributable anyway. The
// cudart artifact carries lib/stubs/libcuda.so purely so that a LINK succeeds; the
// real library is resolved at run time, and on a machine with no GPU the module
// that needs it declines to load, which is the correct outcome rather than a
// failure.
//
// Without this list such a soname reads as a hole in the packaging — "no pkgx
// project is mapped to that soname" — on every install of anything that links a
// GPU transport. It is not a hole. It is the boundary.
var hostProvidedSonames = []string{
	"libcuda.so",      // NVIDIA driver API (the stub in cuda-cudart is link-time only)
	"libnvidia-ml.so", // NVML, shipped with the same driver
}

// isHostProvidedSoname reports whether a soname is one the machine provides.
func isHostProvidedSoname(soname string) bool {
	return matchesAny(map[string]bool{soname: true}, hostProvidedSonames)
}

// isImplicitSoname reports whether a soname belongs to one of the implicit
// system groups — glibc, the libstdc++/libgcc pair, the gcc runtime libs. Those
// are the implicit block's business, and it installs them from their project
// groups rather than from the soname map. The soname loop must not treat one as
// unprovided: `provided` is sampled at the top of a round, BEFORE the implicit
// install of that same round, so libstdc++.so.6 still looks missing there.
func isImplicitSoname(soname string) bool {
	one := map[string]bool{soname: true}
	return matchesAny(one, glibcSonames) || matchesAny(one, libstdcxxSonames) ||
		matchesAny(one, gccSonames) || matchesAny(one, libcxxSonames)
}

// matchesAny reports whether any needed soname starts with one of the prefixes.
func matchesAny(needed map[string]bool, prefixes []string) bool {
	for soname := range needed {
		for _, p := range prefixes {
			if strings.HasPrefix(soname, p) {
				return true
			}
		}
	}
	return false
}

// prefixesOf returns the installed prefix directories of a closure.
func prefixesOf(closure []Resolved, dir string) []string {
	var out []string
	for _, r := range closure {
		out = append(out, StorePrefix(dir, r.Project, r.Version))
	}
	return out
}

// availableSonames returns the set of shared-library sonames present in the
// installed closure's lib dirs (what the closure already provides).
//
// # AT ANY DEPTH, BECAUSE A FIXED ONE WAS WRONG BY EXACTLY ONE LEVEL
//
// This used to glob `lib/*.so*` and `lib/*/*.so*`: the top of the lib dir and
// one level under it, which covers the usual `lib/gconv/` plugin layout. Our
// glibc does not have the usual layout. Its recipe sets
//
//	LIBDIR="{{prefix}}/lib/glibc-{{version.marketing}}"
//
// and says why in its own comment — "--libdir alone only affects gconv/audit
// plugins" — so the gconv modules land at
//
//	lib/glibc-2.44/gconv/libCNS.so
//
// three levels down, one past where the glob looked. The second sovereign
// generation reported the result on every test that touched iconv:
//
//	pkgx: libCNS.so is NEEDED but no pkgx project is mapped to that soname
//	pkgx: libGB.so is NEEDED but no pkgx project is mapped to that soname
//	pkgx: libJIS.so  … libKSC.so … libISOIR165.so … libJISX0213.so
//
// Six warnings, on a closure that already held every one of those files. The
// map was never the problem — these are glibc's own modules and no entry
// could name a better provider than the artifact already installed.
//
// A walk, not a deeper glob. The depth that was wrong here would be wrong
// again at the next project that nests its libs, and a number chosen to fit
// today's layouts is the same mistake with a larger constant.
func availableSonames(prefixes []string) map[string]bool {
	have := map[string]bool{}
	for _, prefix := range prefixes {
		for _, sub := range []string{"lib", "lib64"} {
			root := filepath.Join(prefix, sub)
			_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
				if err != nil || d.IsDir() {
					return nil
				}
				if base := filepath.Base(p); strings.Contains(base, ".so") {
					have[base] = true
				}
				return nil
			})
		}
	}
	return have
}

// CompleteClosure resolves a package's declared closure, installs it, then
// iteratively reads the artifacts' ELF DT_NEEDED and pulls whatever artifact
// provides each unsatisfied soname — the implicit glibc/gcc system libraries
// and the common undeclared libraries (libz, libbz2, ncurses…) that
// package.yml graphs omit — until every NEEDED soname is satisfied. This makes
// the closure complete enough to run on a `FROM scratch` image.
func CompleteClosure(roots map[string]string, dir string) ([]Resolved, error) {
	osn, arch := HostSlug()
	return CompleteClosureFor(roots, dir, osn, arch)
}

// CompleteClosureFor is CompleteClosure for an EXPLICIT pkgx os/arch slug:
// the version pick, the dependency read, every install and the choice of
// binary format all happen in the TARGET platform's terms.
//
// # WHY IT HAD TO EXIST
//
// ⛔ AN AUDIT THAT CAN ONLY ASK ABOUT ITS OWN MACHINE COVERS ONE PLATFORM
// OF SIX. `bk unresolved` reads every reference in an installed closure
// and reports the ones the store cannot answer; wired into CI as
// sonames.yml it found 967 unresolvable references over 259 of the 1407
// packaged projects on linux/x86-64 (2026-10-24). The other five platforms
// had never been asked, because this function resolved and installed for
// the host and nothing else could be said honestly.
//
// That is the shape vulnscan.yml spent two months in: a coverage gap
// living in a comment. ResolveClosureFor and InstallFor were already
// platform-explicit — this is the piece between them that was not.
//
// ⛔ CompleteClosure IS NOW THIS FUNCTION AT HostSlug(), so the host path
// is identical BY CONSTRUCTION rather than by a second reading of the
// same logic. The existing closure tests passing unchanged is the
// evidence, including the ones that swap the `goos` seam: HostSlug reads
// it, so a test pretending to be Windows still reaches the Windows path.
func CompleteClosureFor(roots map[string]string, dir, osn, arch string) ([]Resolved, error) {
	closure, err := ResolveClosureFor(roots, osn, arch)
	if err != nil {
		return nil, err
	}
	for _, r := range closure {
		if _, err := InstallFor(r, dir, osn, arch); err != nil {
			return nil, err
		}
	}
	// ⛔ THE TARGET'S OS, NOT THE HOST'S. This is the one line here that is
	// a behaviour change rather than a pass-through: reading a linux
	// closure from a mac has to take the ELF path, and taking the host's
	// would silently complete nothing and report a clean closure.
	switch osn {
	case "linux":
		return completeELF(closure, dir, osn, arch)
	case "darwin":
		return completeMachO(closure, dir, osn, arch)
	}
	return closure, nil
}

// completeELF is the repair for a format that binds by SONAME: read every
// DT_NEEDED, and pull whatever artifact provides a soname nothing in the closure
// offers. Two versions of one project may both be installed — the dedup below
// is on project@version, not project — because each ships a different soname
// and both lib directories sit on LD_LIBRARY_PATH.
//
// Mach-O cannot work this way: a reference is a PATH, not a name to search
// for, so the darwin half is completeMachO and the two share only the shape.
func completeELF(closure []Resolved, dir, osn, arch string) ([]Resolved, error) {
	have := map[string]bool{}
	installedVer := map[string]bool{} // "project@version" already in the closure
	for _, r := range closure {
		have[r.Project] = true
		installedVer[r.Project+"@"+r.Version.Raw] = true
	}
	triedSoname := map[string]bool{} // sonames we've already attempted to provide
	// Fixpoint: keep pulling providers of unsatisfied sonames until none remain.
	for round := 0; round < 8; round++ {
		prefixes := prefixesOf(closure, dir)
		needed := scanNeeded(prefixes)
		provided := availableSonames(prefixes)
		changed := false

		// Implicit system libraries (glibc always; gcc runtime when linked).
		// These have one obvious latest version, so resolve them as "*".
		implicit := map[string]string{}
		for p, c := range implicitRoots(needed) {
			if !have[p] {
				implicit[p] = c
			}
		}
		if len(implicit) > 0 {
			more, err := ResolveClosureFor(implicit, osn, arch)
			if err != nil {
				return nil, err
			}
			for _, r := range more {
				if have[r.Project] {
					continue
				}
				if _, err := InstallFor(r, dir, osn, arch); err != nil {
					return nil, err
				}
				have[r.Project] = true
				closure = append(closure, r)
				changed = true
			}
		}

		// Undeclared regular-package libraries, mapped by soname. Pull the
		// NEWEST version of the provider that actually ships the exact soname —
		// NOT just the latest release, because a soname carries an ABI version
		// and a newer release may have bumped it (e.g. libxml2 2.15 ships
		// libxml2.so.16, but a binary linked against libxml2.so.2 needs a 2.x
		// artifact; likewise openssl 3 ships libssl.so.3, not libssl.so.1.1).
		for soname := range needed {
			if provided[soname] || triedSoname[soname] || isImplicitSoname(soname) {
				continue
			}
			// NB: do NOT skip when have[proj] — the provider may already be in
			// the closure at a version that ships a DIFFERENT abi soname (e.g.
			// libxml2 2.15 pulled as a declared dep ships libxml2.so.16, yet a
			// binary needs libxml2.so.2). Pull the exact-soname version too;
			// both lib dirs sit on LD_LIBRARY_PATH and each soname resolves.
			triedSoname[soname] = true // once per soname, so a warning is said once
			if isHostProvidedSoname(soname) {
				// Said once, and said as what it is: a fact about where this
				// library comes from, not a gap in the closure.
				warn("%s comes from the machine's GPU driver rather than from an artifact; "+
					"what needs it will load only where a driver is installed", soname)
				continue
			}
			r, ok := provideSoname(soname, dir, osn, arch)
			if !ok {
				continue
			}
			proj := r.Project
			key := r.Project + "@" + r.Version.Raw
			if installedVer[key] {
				continue
			}
			installedVer[key] = true
			have[proj] = true
			closure = append(closure, r)
			changed = true
		}

		if !changed {
			break
		}
	}
	return closure, nil
}

// provideSoname installs the artifact that provides soname, or says why it could
// not. ok=false means the closure stays INCOMPLETE — and an incomplete closure
// does not fail here: it fails later, when the binary starts and reports
// "<soname>: cannot open shared object file" with nothing pointing back at the
// resolution that gave up. Each of the three ways to give up is distinct, and
// distinguishing them is the whole point: an unmapped soname needs an entry in
// sonameProject, a lookup error usually means the registry in use does not
// carry the provider at all (perl's libcrypt.so.1 was simply absent from a
// local cache, and the silence cost an hour), and "no version provides it"
// means the provider moved past that ABI.
func provideSoname(soname, dir, osn, arch string) (Resolved, bool) {
	proj := projectForSoname(soname)
	if proj == "" {
		warn("%s is NEEDED but no pkgx project is mapped to that soname", soname)
		return Resolved{}, false
	}
	r, ok, err := installProvidingSoname(proj, soname, dir, osn, arch)
	switch {
	case err != nil:
		warn("cannot provide %s from %s: %v", soname, proj, err)
		return Resolved{}, false
	case !ok:
		warn("no published %s version provides %s", proj, soname)
		return Resolved{}, false
	}
	return r, true
}

// installProvidingSoname installs the newest available version of project whose
// artifact actually provides the exact soname, trying newest→oldest, and returns
// that matching artifact. ok is false if no examined version ships the soname.
// Sonames carry an ABI version a project's latest release may have moved past,
// so "latest" is not always the right artifact for a specific soname.
func installProvidingSoname(project, soname, dir, osn, arch string) (Resolved, bool, error) {
	vs, err := FetchVersions(project)
	if err != nil {
		return Resolved{}, false, err
	}
	const maxTry = 40 // bound the walk for a soname no examined version provides
	tried := 0
	for _, v := range candidateOrder(vs, soname) {
		if tried >= maxTry {
			break
		}
		tried++
		r := Resolved{project, v}
		if _, err := InstallFor(r, dir, osn, arch); err != nil {
			continue // no artifact for this version/platform — try the next one
		}
		prefix := StorePrefix(dir, r.Project, r.Version)
		if availableSonames([]string{prefix})[soname] {
			return r, true, nil
		}
	}
	return Resolved{}, false, nil
}

// candidateOrder returns versions newest-first, but floats versions whose
// leading number equals the soname's ABI tail to the front — so a version that
// drifted its soname (e.g. libssl.so.1.1 is openssl 1.1.x, not the latest 3.x;
// libprotoc.so.25.x is protobuf 25.x) is found without walking every release.
func candidateOrder(vs []Ver, soname string) []Ver {
	hint := sonameABI(soname)
	var match, rest []Ver
	for i := len(vs) - 1; i >= 0; i-- { // newest first
		v := vs[i]
		if hint != "" && len(v.Nums) > 0 && strconv.Itoa(v.Nums[0]) == hint {
			match = append(match, v)
		} else {
			rest = append(rest, v)
		}
	}
	return append(match, rest...)
}

// sonameABI extracts the first numeric component after ".so." in a soname,
// e.g. "libssl.so.1.1" -> "1", "libprotoc.so.25.7.0" -> "25", "libz.so" -> "".
func sonameABI(soname string) string {
	i := strings.Index(soname, ".so.")
	if i < 0 {
		return ""
	}
	tail := soname[i+len(".so."):]
	j := 0
	for j < len(tail) && tail[j] >= '0' && tail[j] <= '9' {
		j++
	}
	return tail[:j]
}
