package artifact

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMatchesAny(t *testing.T) {
	needed := map[string]bool{"libc.so.6": true, "libgcc_s.so.1": true}
	if !matchesAny(needed, libstdcxxSonames) {
		t.Error("libgcc_s should match libstdcxx group")
	}
	if matchesAny(needed, gccSonames) {
		t.Error("no libatomic present")
	}
	if !matchesAny(needed, glibcSonames) {
		t.Error("libc should match glibc group")
	}
}

func TestImplicitRoots(t *testing.T) {
	// bare glibc only
	r := implicitRoots(map[string]bool{"libc.so.6": true})
	if _, ok := r["gnu.org/glibc"]; !ok {
		t.Error("glibc always included")
	}
	if _, ok := r["gnu.org/gcc/libstdcxx"]; ok {
		t.Error("no libstdcxx for pure C")
	}
	// C++ needs libstdcxx
	r = implicitRoots(map[string]bool{"libstdc++.so.6": true, "libgcc_s.so.1": true})
	if _, ok := r["gnu.org/gcc/libstdcxx"]; !ok {
		t.Error("libstdcxx expected for C++")
	}
	// libatomic pulls gnu.org/gcc
	r = implicitRoots(map[string]bool{"libatomic.so.1": true})
	if _, ok := r["gnu.org/gcc"]; !ok {
		t.Error("gcc expected for libatomic")
	}
}

func TestProjectForSoname(t *testing.T) {
	// exact-stem map
	if projectForSoname("libz.so.1") != "zlib.net" {
		t.Error("libz exact stem")
	}
	// prefix map (abseil ships many differently-named libabsl_*.so)
	if projectForSoname("libabsl_die_if_null.so.2505.0.0") != "abseil.io" {
		t.Error("libabsl prefix")
	}
	if projectForSoname("libprotobuf-lite.so.32") != "protobuf.dev" {
		t.Error("libprotobuf prefix")
	}
	// unknown
	if projectForSoname("libwhatever.so.9") != "" {
		t.Error("unknown should be empty")
	}
}

func TestPrefixesOf(t *testing.T) {
	closure := []Resolved{{"acme.org/tool", ParseVer("1.2.3")}}
	got := prefixesOf(closure, "/pkgx")
	if len(got) != 1 || got[0] != filepath.Join("/pkgx", "acme.org/tool", "v1.2.3") {
		t.Errorf("prefixesOf = %v", got)
	}
}

func TestSonameBase(t *testing.T) {
	cases := map[string]string{
		"libz.so.1":     "libz",
		"libpcre2-8.so": "libpcre2-8",
		"libc.so.6":     "libc",
		"weird":         "weird",
	}
	for in, want := range cases {
		if got := sonameBase(in); got != want {
			t.Errorf("sonameBase(%q)=%q want %q", in, got, want)
		}
	}
	if sonameProject["libz"] != "zlib.net" {
		t.Error("libz should map to zlib.net")
	}
}

func TestAvailableSonames(t *testing.T) {
	dir := t.TempDir()
	prefix := filepath.Join(dir, "p", "v1")
	_ = os.MkdirAll(filepath.Join(prefix, "lib", "glibc-2.44"), 0o755)
	_ = os.WriteFile(filepath.Join(prefix, "lib", "libfoo.so.1"), []byte("x"), 0o644)
	_ = os.WriteFile(filepath.Join(prefix, "lib", "glibc-2.44", "libc.so.6"), []byte("x"), 0o644)
	got := availableSonames([]string{prefix})
	if !got["libfoo.so.1"] || !got["libc.so.6"] {
		t.Errorf("availableSonames = %v", got)
	}
}

func TestScanNeededNonELF(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "not-an-elf"), []byte("hello"), 0o644)
	if n := scanNeeded([]string{dir}); len(n) != 0 {
		t.Errorf("expected empty for non-ELF, got %v", n)
	}
}

func TestSonameABI(t *testing.T) {
	cases := map[string]string{
		"libssl.so.1.1":       "1",
		"libprotoc.so.25.7.0": "25",
		"libfoo.so.2":         "2",
		"libz.so":             "", // ".so" but no ".so.<n>"
		"weird":               "",
	}
	for in, want := range cases {
		if got := sonameABI(in); got != want {
			t.Errorf("sonameABI(%q)=%q want %q", in, got, want)
		}
	}
}

func TestCandidateOrder(t *testing.T) {
	vs := []Ver{ParseVer("1.1.1w"), ParseVer("3.0.0"), ParseVer("3.5.0")} // ascending
	// libssl.so.1.1 -> hint "1" floats openssl 1.x ahead of the newer 3.x.
	got := candidateOrder(vs, "libssl.so.1.1")
	if got[0].Raw != "1.1.1w" {
		t.Errorf("hint match should lead, got %q", got[0].Raw)
	}
	if got[1].Raw != "3.5.0" || got[2].Raw != "3.0.0" {
		t.Errorf("rest should be newest-first, got %v", []string{got[1].Raw, got[2].Raw})
	}
	// no ABI hint -> pure newest-first.
	if got = candidateOrder(vs, "libz.so"); got[0].Raw != "3.5.0" {
		t.Errorf("no-hint newest-first, got %q", got[0].Raw)
	}
}

func TestInstallProvidingSoname(t *testing.T) {
	defer fakeServer(t, map[string]fakePkg{
		"xml.org/libxml2": {
			versions: []string{"2.13.9", "2.15.3"},
			yaml:     "provides:\n  - bin/xml\n",
			// the newer release bumped the soname; the older one still ships .so.2
			filesByVer: map[string]map[string]string{
				"2.15.3": {"lib/libxml2.so.16": "x"},
				"2.13.9": {"lib/libxml2.so.2": "x"},
			},
		},
	})()
	dir := t.TempDir()
	osn, arch := HostSlug()
	// The walk must skip 2.15.3 (ships .so.16) and fall back to 2.13.9 (.so.2).
	r, ok, err := installProvidingSoname("xml.org/libxml2", "libxml2.so.2", dir, osn, arch)
	if err != nil || !ok {
		t.Fatalf("expected libxml2.so.2 provider, ok=%v err=%v", ok, err)
	}
	if r.Version.Raw != "2.13.9" {
		t.Errorf("picked v%s, want 2.13.9", r.Version.Raw)
	}
	// a soname no version provides -> ok=false, no error.
	if _, ok, err := installProvidingSoname("xml.org/libxml2", "libnope.so.9", dir, osn, arch); ok || err != nil {
		t.Errorf("absent soname: ok=%v err=%v, want false/nil", ok, err)
	}
	// unknown project -> fetchVersions error surfaces.
	if _, _, err := installProvidingSoname("no.org/x", "libx.so.1", dir, osn, arch); err == nil {
		t.Error("expected error for unknown project")
	}
}

func TestProjectForSonameAddedMappings(t *testing.T) {
	cases := map[string]string{
		"libFLAC.so.12":            "xiph.org/flac",
		"libtheora.so.0":           "theora.org",
		"libgit2.so.1.7":           "libgit2.org",
		"libboost_regex.so.1.82.0": "boost.org", // prefix map
		"libgflags.so.2.2":         "gflags.github.io",
		"libtinfow.so.6":           "invisible-island.net/ncurses",
		"libprotoc.so.25.7.0":      "protobuf.dev",
		"libcap.so.2":              "kernel.org/libcap",
		"libudev.so.1":             "github.com/eudev-project/eudev",
	}
	for in, want := range cases {
		if got := projectForSoname(in); got != want {
			t.Errorf("projectForSoname(%q)=%q want %q", in, got, want)
		}
	}
}

// TestProvideSonameWarns pins each of the three ways the resolver gives up on a
// soname. None of them fails the install, so the ONLY thing standing between
// them and a runtime "cannot open shared object file" hours later is this
// warning — perl's libcrypt.so.1 went missing exactly this way.
func TestProvideSonameWarns(t *testing.T) {
	defer fakeServer(t, map[string]fakePkg{
		// zlib.net is published, but no version ships libz.so.1 in this fixture.
		"zlib.net": {versions: []string{"1.3.2"}, yaml: "provides:\n  - bin/z\n", files: map[string]string{"bin/z": "x"}},
	})()
	var said []string
	Warn = func(msg string) { said = append(said, msg) }
	defer func() { Warn = nil }()

	osn, arch := HostSlug()
	// 1. no project is mapped to the soname at all
	if _, ok := provideSoname("libwhatever.so.9", t.TempDir(), osn, arch); ok {
		t.Error("unmapped soname must not resolve")
	}
	// 2. the provider is mapped but the registry in use does not carry it
	if _, ok := provideSoname("libcrypt.so.1", t.TempDir(), osn, arch); ok {
		t.Error("absent provider must not resolve")
	}
	// 3. the provider is carried but no version ships that soname
	if _, ok := provideSoname("libz.so.1", t.TempDir(), osn, arch); ok {
		t.Error("soname absent from every version must not resolve")
	}
	for i, want := range []string{
		"libwhatever.so.9 is NEEDED but no pkgx project is mapped to that soname",
		"cannot provide libcrypt.so.1 from github.com/besser82/libxcrypt",
		"no published zlib.net version provides libz.so.1",
	} {
		if i >= len(said) || !strings.Contains(said[i], want) {
			t.Fatalf("warning %d = %q, want it to contain %q (all: %v)", i, said, want, said)
		}
	}
	// A nil Warn is the library default and must stay silent, not panic.
	Warn = nil
	if _, ok := provideSoname("libwhatever.so.9", t.TempDir(), osn, arch); ok {
		t.Error("unmapped soname must not resolve without a Warn either")
	}
}

func TestCompleteClosure(t *testing.T) {
	defer fakeServer(t, map[string]fakePkg{
		"acme.org/tool": {versions: []string{"1.0.0"}, yaml: "provides:\n  - bin/tool\n", files: map[string]string{"bin/tool": "x"}},
		"gnu.org/glibc": {versions: []string{"2.44.0"}, yaml: "provides:\n  - bin/ldd\n", files: map[string]string{"lib/glibc-2.44/libc.so.6": "x"}},
	})()
	dir := t.TempDir()
	closure, err := CompleteClosure(map[string]string{"acme.org/tool": "*"}, dir)
	if err != nil {
		t.Fatal(err)
	}
	// The fake artifacts contain no real ELFs, so scanNeeded finds nothing; on
	// linux glibc is still added unconditionally, on darwin nothing is.
	if GOOS() == "linux" {
		if len(closure) != 2 {
			t.Errorf("linux closure = %d, want 2 (tool+glibc)", len(closure))
		}
	} else if len(closure) != 1 {
		t.Errorf("darwin closure = %d, want 1", len(closure))
	}
}

// ⛔ THE TARGET'S OS DECIDES, NOT THE HOST'S — and that is the one line of
// CompleteClosureFor that is a behaviour change rather than a pass-through.
//
// Everything else there is ResolveClosureFor and InstallFor in place of
// their host-bound siblings, so the host path is identical by
// construction and the rest of this file passing says so. This is the
// part that needs its own evidence.
//
// It matters because an audit that reads a linux closure from a mac must
// take the ELF path. Taking the host's would complete nothing, find every
// soname satisfied — because it never looked — and report a clean
// closure. A wrong answer that looks like good news.
//
// The host here claims to be darwin while the target is linux, so the
// glibc that only the ELF completer adds is the witness: 2 entries means
// the ELF path ran, 1 means the host's choice won.
func TestTheTargetsFormatDecidesNotTheHosts(t *testing.T) {
	// linux FIRST, so the fake registry serves linux paths and the target's
	// installs resolve; the host identity is changed afterwards.
	setGoos(t, "linux")
	_, arch := HostSlug()
	defer fakeServer(t, map[string]fakePkg{
		"acme.org/tool": {versions: []string{"1.0.0"}, yaml: "provides:\n  - bin/tool\n", files: map[string]string{"bin/tool": "x"}},
		"gnu.org/glibc": {versions: []string{"2.44.0"}, yaml: "provides:\n  - bin/ldd\n", files: map[string]string{"lib/glibc-2.44/libc.so.6": "x"}},
	})()
	setGoos(t, "darwin") // the host is now something else entirely

	closure, err := CompleteClosureFor(map[string]string{"acme.org/tool": "*"}, t.TempDir(), "linux", arch)
	if err != nil {
		t.Fatal(err)
	}
	if len(closure) != 2 {
		t.Fatalf("closure = %d entry(ies), want 2 (tool+glibc): the host's darwin chose the format, so the ELF completer never ran: %+v", len(closure), closure)
	}
}

// And the other direction, which is the quiet one: a platform with no
// completer at all returns the declared closure untouched rather than
// erroring. `CompleteClosureFor(..., "windows", ...)` is a real call —
// the registry publishes windows/x86-64 — and it must not take the host's
// ELF path and start pulling glibc into a windows closure.
func TestAPlatformWithNoCompleterIsLeftAlone(t *testing.T) {
	setGoos(t, "windows")
	_, arch := HostSlug()
	defer fakeServer(t, map[string]fakePkg{
		"acme.org/tool": {versions: []string{"1.0.0"}, yaml: "provides:\n  - bin/tool\n", files: map[string]string{"bin/tool": "x"}},
		"gnu.org/glibc": {versions: []string{"2.44.0"}, yaml: "provides:\n  - bin/ldd\n", files: map[string]string{"lib/glibc-2.44/libc.so.6": "x"}},
	})()
	setGoos(t, "linux") // a linux host asking about windows

	closure, err := CompleteClosureFor(map[string]string{"acme.org/tool": "*"}, t.TempDir(), "windows", arch)
	if err != nil {
		t.Fatal(err)
	}
	if len(closure) != 1 {
		t.Errorf("closure = %d entry(ies), want 1: the host's linux pulled glibc into a windows closure: %+v", len(closure), closure)
	}
}

// TestIsImplicitSoname pins the boundary between the two providers. The soname
// loop samples `provided` at the top of a round, BEFORE the implicit block of
// that same round installs glibc/libstdcxx — so without this test libstdc++.so.6
// looks unprovided and the closure warns about a library it is installing.
func TestIsImplicitSoname(t *testing.T) {
	for _, s := range []string{"libc.so.6", "libm.so.6", "ld-linux-aarch64.so.1", "libstdc++.so.6", "libgcc_s.so.1", "libatomic.so.1"} {
		if !isImplicitSoname(s) {
			t.Errorf("%s belongs to an implicit group", s)
		}
	}
	for _, s := range []string{"libz.so.1", "libcrypt.so.1", "libJIS.so"} {
		if isImplicitSoname(s) {
			t.Errorf("%s is NOT implicit — it must go through the soname map", s)
		}
	}
}

// TestHostProvidedSoname: a GPU driver's userspace half is not a hole in the
// packaging, and must not be reported as one. UCX built --with-cuda links its
// cuda module against the stub in the cudart artifact; the real libcuda.so.1
// belongs to whoever installed the driver, and must match the kernel module it
// talks to, so no artifact can or should provide it.
func TestHostProvidedSoname(t *testing.T) {
	for _, s := range []string{"libcuda.so.1", "libcuda.so", "libnvidia-ml.so.1"} {
		if !isHostProvidedSoname(s) {
			t.Errorf("%s should be host-provided", s)
		}
	}
	// Not a licence to swallow anything cuda-shaped: cudart IS an artifact, and a
	// missing one is a real gap that must still be reported.
	for _, s := range []string{"libcudart.so.13", "libz.so.1", "libhsa-runtime64.so.1"} {
		if isHostProvidedSoname(s) {
			t.Errorf("%s must not be treated as host-provided", s)
		}
	}
}

// TestImplicitRootsOff: the escape for a bootstrap host, where the machine has
// a libc and the registry has no artifact of one.
//
// The default is the one that matters here, so it is asserted in the same test
// as the override: a variable that silently defaulted to "off" would turn every
// scratch-image closure into one that only works where it was assembled, and
// nothing would say so.
func TestImplicitRootsOff(t *testing.T) {
	// C++ sonames, so all three roots are in play at once.
	needed := map[string]bool{"libc.so.6": true, "libstdc++.so.6": true, "libatomic.so.1": true}
	if len(implicitRoots(needed)) != 3 {
		t.Fatalf("premise wrong: want glibc + libstdcxx + gcc, got %v", implicitRoots(needed))
	}
	t.Cleanup(func() { ImplicitRootsOff = false })
	ImplicitRootsOff = true
	if got := implicitRoots(needed); len(got) != 0 {
		t.Errorf("implicitRoots = %v; want none when the host supplies them", got)
	}
}

// And the variable that sets it, through the same reader every other knob goes
// through — including the values that must NOT turn it on, since anything but
// "none" leaving it off is what keeps a typo from quietly producing a closure
// that works on one machine.
func TestImplicitRootsEnv(t *testing.T) {
	t.Cleanup(func() { ImplicitRootsOff = false })
	for _, c := range []struct {
		val  string
		want bool
	}{
		{"none", true},
		{"", false},
		{"1", false},
		{"true", false},
		{"NONE", false},
	} {
		ImplicitRootsOff = false
		applyEnv(func(k string) string {
			if k == "ZPKG_IMPLICIT_ROOTS" {
				return c.val
			}
			return ""
		})
		if ImplicitRootsOff != c.want {
			t.Errorf("ZPKG_IMPLICIT_ROOTS=%q → off=%v, want %v", c.val, ImplicitRootsOff, c.want)
		}
	}
}

// TestSonameProviders: the bounded set of dependencies a recipe never
// mentions. A seed order computed from recipes alone cannot see any of them —
// perl declares nothing about libcrypt, and a perl build stopped dead on
// github.com/besser82/libxcrypt because of it.
func TestSonameProviders(t *testing.T) {
	got := SonameProviders()
	if len(got) < 10 {
		t.Fatalf("suspiciously few providers: %v", got)
	}
	idx := map[string]bool{}
	for _, p := range got {
		idx[p] = true
	}
	// The case that prompted this, and one from the PREFIX map, so a future
	// refactor cannot quietly drop half the answer.
	for _, want := range []string{"github.com/besser82/libxcrypt", "zlib.net", "openssl.org"} {
		if !idx[want] {
			t.Errorf("missing %q from %v", want, got)
		}
	}
	// Sorted and deduplicated: openssl.org answers both libssl and libcrypto,
	// and a caller diffing this against its own list needs it to appear once.
	for i := 1; i < len(got); i++ {
		if got[i] <= got[i-1] {
			t.Errorf("not sorted/deduplicated at %d: %q then %q", i, got[i-1], got[i])
		}
	}
}

// The gconv modules live THREE levels under the prefix, because our glibc's
// libdir is `lib/glibc-<marketing>` and its plugins go under that. A scan
// that stopped at two reported six sonames as unprovided on a closure that
// already held every one of their files:
//
//	pkgx: libCNS.so is NEEDED but no pkgx project is mapped to that soname
//
// The two-level case above still passes; this is the one that did not.
func TestASonameThreeLevelsDownIsProvided(t *testing.T) {
	prefix := filepath.Join(t.TempDir(), "gnu.org", "glibc", "v2.44")
	gconv := filepath.Join(prefix, "lib", "glibc-2.44", "gconv")
	if err := os.MkdirAll(gconv, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"libCNS.so", "libGB.so", "libJIS.so", "libKSC.so"} {
		if err := os.WriteFile(filepath.Join(gconv, n), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got := availableSonames([]string{prefix})
	for _, n := range []string{"libCNS.so", "libGB.so", "libJIS.so", "libKSC.so"} {
		if !got[n] {
			t.Errorf("%s sits in the closure and is not counted as provided: %v", n, got)
		}
	}
}

// And a lib dir that is not there at all must be silence, not a walk error
// leaking out: an artifact with no lib/ is ordinary.
func TestAPrefixWithNoLibDir(t *testing.T) {
	prefix := t.TempDir()
	if got := availableSonames([]string{prefix}); len(got) != 0 {
		t.Errorf("a prefix with no lib dir provided %v", got)
	}
}

// The two entries added from the second sovereign generation, each checked
// against an installed artifact rather than recalled. gnu.org/bison died on
// libtextstyle.so.0 AFTER a successful build.
func TestTheSonamesGen1Named(t *testing.T) {
	for soname, want := range map[string]string{
		"libtextstyle.so.0": "gnu.org/gettext",
		"libpanelw.so.6":    "invisible-island.net/ncurses",
		"libpanel.so.6":     "invisible-island.net/ncurses",
	} {
		if got := projectForSoname(soname); got != want {
			t.Errorf("projectForSoname(%q) = %q, want %q", soname, got, want)
		}
	}
}

// The toolchain's OTHER C++ runtime. bk's sovereign driver flags link libc++,
// not libstdc++, and the second sovereign generation showed what happens when
// nothing supplies it at install time:
//
//	ninja: error while loading shared libraries: libc++.so.1
//	pzstd: error while loading shared libraries: libc++.so.1
func TestLibcxxIsAnImplicitRoot(t *testing.T) {
	for _, soname := range []string{"libc++.so.1", "libc++abi.so.1", "libunwind.so.1"} {
		got := implicitRoots(map[string]bool{soname: true})
		if got["libcxx.llvm.org"] == "" {
			t.Errorf("%s does not pull libcxx.llvm.org: %v", soname, got)
		}
	}
	// And a closure that touches no C++ must not grow one.
	if got := implicitRoots(map[string]bool{"libz.so.1": true}); got["libcxx.llvm.org"] != "" {
		t.Errorf("libcxx was pulled for a C-only closure: %v", got)
	}
	// gcc's runtime is still gcc's: the two must not be confused.
	if got := implicitRoots(map[string]bool{"libstdc++.so.6": true}); got["libcxx.llvm.org"] != "" {
		t.Errorf("a libstdc++ consumer pulled llvm's runtime too: %v", got)
	}
}

// The two lists have to agree. #114 added libc++ to implicitRoots, so the
// closure PULLS it — and left isImplicitSoname alone, so every install that
// touched C++ still printed
//
//	pkgx: libc++.so.1 is NEEDED but no pkgx project is mapped to that soname
//
// about a soname that now has one. A warning that contradicts what the
// resolver just did is worse than no warning: it sends its reader looking
// for a gap that was closed.
func TestEveryImplicitRootIsAlsoAnImplicitSoname(t *testing.T) {
	for _, group := range [][]string{glibcSonames, libstdcxxSonames, gccSonames, libcxxSonames} {
		for _, stem := range group {
			soname := stem
			if !strings.HasSuffix(soname, ".so") {
				soname += ".so"
			}
			soname += ".1"
			if !isImplicitSoname(soname) {
				t.Errorf("%s pulls an implicit root and is not an implicit soname — it will warn about itself", soname)
			}
		}
	}
	// And the inverse: an ordinary library is NOT implicit, or nothing would
	// ever be resolved through the map.
	if isImplicitSoname("libz.so.1") {
		t.Error("libz.so.1 reads as implicit; the soname map would never be consulted")
	}
}
