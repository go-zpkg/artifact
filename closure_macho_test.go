package artifact

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	lcIDDylib = 0x0d
	lcRpath   = 0x1c | 0x80000000
)

type mcmd struct {
	cmd uint32
	str string
}

// writeMachO builds a Mach-O by hand rather than compiling one, so these tests
// run on every lane. A darwin-only fixture is how the coverage gate on linux
// went short once before.
func writeMachO(t *testing.T, p string, cmds ...mcmd) {
	t.Helper()
	writeFile(t, p, machoBytes(cpuArm64, cmds...))
}

// CPU types, as a fat_arch records them.
const (
	cpuArm64 = 0x0100000c
	cpuAmd64 = 0x01000007
)

func writeFile(t *testing.T, p string, b []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b, 0o755); err != nil {
		t.Fatal(err)
	}
}

// fatSlice is one architecture's image inside a universal file.
type fatSlice struct {
	cpu  uint32
	cmds []mcmd
}

// writeFatMachO wraps thin images in a fat_header, by hand for the same reason
// writeMachO builds one by hand: `lipo` exists only on darwin, and a
// darwin-only fixture is how the coverage gate on linux went short once before.
//
// Every field of fat_header and fat_arch is BIG endian, whatever the slices
// are — that is the format, not an oversight.
func writeFatMachO(t *testing.T, p string, slices ...fatSlice) {
	t.Helper()
	be := binary.BigEndian
	const hdr, arch = 8, 20
	// Slices are page-aligned, which is what align=12 (2^12) promises. A
	// reader that trusted the alignment and not the offset would read
	// garbage otherwise.
	const algn, page = 12, 1 << 12

	bodies := make([][]byte, len(slices))
	for i, s := range slices {
		bodies[i] = machoBytes(s.cpu, s.cmds...)
	}
	off := hdr + arch*len(slices)
	if r := off % page; r != 0 {
		off += page - r
	}
	var out []byte
	head := make([]byte, hdr+arch*len(slices))
	be.PutUint32(head[0:], 0xcafebabe)          // FAT_MAGIC
	be.PutUint32(head[4:], uint32(len(slices))) // nfat_arch
	for i, b := range bodies {
		a := head[hdr+arch*i:]
		be.PutUint32(a[0:], slices[i].cpu) // cputype
		be.PutUint32(a[4:], 0)             // cpusubtype
		be.PutUint32(a[8:], uint32(off))   // offset
		be.PutUint32(a[12:], uint32(len(b)))
		be.PutUint32(a[16:], algn)
		off += len(b)
		if r := off % page; r != 0 {
			off += page - r
		}
	}
	out = append(out, head...)
	for i, b := range bodies {
		a := head[hdr+arch*i:]
		for len(out) < int(be.Uint32(a[8:])) {
			out = append(out, 0)
		}
		out = append(out, b...)
	}
	writeFile(t, p, out)
}

func machoBytes(cpu uint32, cmds ...mcmd) []byte {
	le := binary.LittleEndian
	var body []byte
	for _, c := range cmds {
		strOff := 24
		if c.cmd == lcRpath {
			strOff = 12
		}
		size := strOff + len(c.str) + 1
		for size%8 != 0 {
			size++
		}
		cb := make([]byte, size)
		le.PutUint32(cb[0:], c.cmd)
		le.PutUint32(cb[4:], uint32(size))
		le.PutUint32(cb[8:], uint32(strOff))
		copy(cb[strOff:], c.str)
		body = append(body, cb...)
	}
	buf := make([]byte, 32+len(body))
	le.PutUint32(buf[0:], 0xfeedfacf) // MH_MAGIC_64
	le.PutUint32(buf[4:], cpu)
	le.PutUint32(buf[12:], 6) // MH_DYLIB
	le.PutUint32(buf[16:], uint32(len(cmds)))
	le.PutUint32(buf[20:], uint32(len(body)))
	copy(buf[32:], body)
	return buf
}

// What a file LOADS, and nothing else. LC_ID_DYLIB says where the file expects
// to live: counting it makes every library depend on its own home, and an
// rpath is a search path, not a dependency.
func TestMachoNeededReadsOnlyTheLoads(t *testing.T) {
	p := filepath.Join(t.TempDir(), "libx.dylib")
	writeMachO(t, p,
		mcmd{lcIDDylib, "@rpath/me.org/v1/lib/libx.1.dylib"},
		mcmd{lcLoadDylib, "@rpath/a.org/v1/lib/liba.1.dylib"},
		mcmd{lcLoadWeakDylib, "@rpath/b.org/v2/lib/libb.2.dylib"},
		mcmd{lcReexportDylib, "@rpath/c.org/v3/lib/libc.3.dylib"},
		mcmd{lcRpath, "@loader_path/../.."},
	)
	got, err := MachoNeeded(p)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"@rpath/a.org/v1/lib/liba.1.dylib",
		"@rpath/b.org/v2/lib/libb.2.dylib",
		"@rpath/c.org/v3/lib/libc.3.dylib",
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("MachoNeeded = %v, want %v", got, want)
	}
}

// Anything that is not a Mach-O is not a finding: a store is mostly text.
func TestMachoNeededOnSomethingElse(t *testing.T) {
	p := filepath.Join(t.TempDir(), "readme")
	if err := os.WriteFile(p, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := MachoNeeded(p); err == nil {
		t.Error("a text file was read as a Mach-O")
	}
}

// A reference is satisfied when the path it names EXISTS. That is the whole
// darwin test, and it is stricter than ELF's: there is no search.
func TestUnresolvedRefsIsAStatNotASearch(t *testing.T) {
	dir := t.TempDir()
	// The provider that IS there, at the ABI line the consumer asks for.
	writeMachO(t, filepath.Join(dir, "a.org/v1.2.3/lib/liba.1.dylib"))
	if err := os.Symlink("v1.2.3", filepath.Join(dir, "a.org/abi-liba.1.dylib")); err != nil {
		t.Fatal(err)
	}
	writeMachO(t, filepath.Join(dir, "top.org/v9.0/bin/tool"),
		mcmd{lcLoadDylib, "@rpath/a.org/abi-liba.1.dylib/lib/liba.1.dylib"},
		mcmd{lcLoadDylib, "@rpath/gnome.org/libxml2/abi-libxml2.16.dylib/lib/libxml2.16.dylib"},
		mcmd{lcLoadDylib, "/usr/lib/libSystem.B.dylib"},
	)

	got := unresolvedRefs([]string{filepath.Join(dir, "top.org/v9.0")}, dir)
	if len(got) != 1 {
		t.Fatalf("unresolvedRefs = %+v, want only the missing one", got)
	}
	if got[0].project != "gnome.org/libxml2" || got[0].soname != "libxml2.16.dylib" || !got[0].abiLine {
		t.Errorf("got %+v", got[0])
	}
}

// A project name has slashes in it, and the reference comes in two shapes. The
// soname is explicit in one and the filename in the other; both must give the
// same answer, because the repair keys on it.
func TestUnresolvedRefsReadsBothShapes(t *testing.T) {
	dir := t.TempDir()
	writeMachO(t, filepath.Join(dir, "top.org/v1/bin/tool"),
		mcmd{lcLoadDylib, "@rpath/gnome.org/libxml2/v2/lib/libxml2.2.dylib"},
		mcmd{lcLoadDylib, "@rpath/gnupg.org/gpgme/abi-libgpgme.11.dylib/lib/libgpgme.11.dylib"},
	)
	got := unresolvedRefs([]string{filepath.Join(dir, "top.org/v1")}, dir)
	if len(got) != 2 {
		t.Fatalf("unresolvedRefs = %+v", got)
	}
	// Sorted by project, so libxml2 comes first.
	if got[0].project != "gnome.org/libxml2" || got[0].soname != "libxml2.2.dylib" || got[0].abiLine {
		t.Errorf("the major-directory shape read as %+v", got[0])
	}
	if got[1].project != "gnupg.org/gpgme" || got[1].soname != "libgpgme.11.dylib" || !got[1].abiLine {
		t.Errorf("the ABI-line shape read as %+v", got[1])
	}
}

// The point of the whole chain: a closure that already holds one ABI line of a
// project installs the OTHER one when something asks for it. This is what a
// resolver keyed on project cannot do, and what hwloc needs in a closure where
// gettext holds libxml2 at 2.13.
func TestCompleteMachOHoldsBothABILines(t *testing.T) {
	old := machoProvider
	defer func() { machoProvider = old }()

	dir := t.TempDir()
	writeMachO(t, filepath.Join(dir, "gnome.org/libxml2/v2.13.9/lib/libxml2.2.dylib"))
	writeMachO(t, filepath.Join(dir, "open-mpi.org/hwloc/v2.15.0/lib/libhwloc.15.dylib"),
		mcmd{lcLoadDylib, "@rpath/gnome.org/libxml2/abi-libxml2.16.dylib/lib/libxml2.16.dylib"},
	)
	closure := []Resolved{
		{"gnome.org/libxml2", Ver{Raw: "2.13.9"}},
		{"open-mpi.org/hwloc", Ver{Raw: "2.15.0"}},
	}

	var asked []string
	machoProvider = func(w want, d string) (Resolved, bool) {
		asked = append(asked, w.project+" "+w.soname)
		// Install it, as the real provider would, so the loop converges.
		writeMachO(t, filepath.Join(d, "gnome.org/libxml2/v2.15.4/lib/libxml2.16.dylib"))
		if err := os.Symlink("v2.15.4", filepath.Join(d, "gnome.org/libxml2/abi-libxml2.16.dylib")); err != nil {
			t.Fatal(err)
		}
		return Resolved{"gnome.org/libxml2", Ver{Raw: "2.15.4"}}, true
	}

	// darwin/aarch64 explicitly, not the host: this exercises the Mach-O
	// completer, and naming its platform is what lets the test say the
	// same thing on a linux runner as on a mac.
	got, err := completeMachO(closure, dir, "darwin", "aarch64")
	if err != nil {
		t.Fatal(err)
	}
	if len(asked) != 1 || asked[0] != "gnome.org/libxml2 libxml2.16.dylib" {
		t.Fatalf("asked for %v", asked)
	}
	if len(got) != 3 {
		t.Fatalf("closure = %+v, want the second line added", got)
	}
	// Both lines, one project: the dedup is on project@version.
	var vers []string
	for _, r := range got {
		if r.Project == "gnome.org/libxml2" {
			vers = append(vers, r.Version.Raw)
		}
	}
	if len(vers) != 2 {
		t.Errorf("libxml2 versions in the closure: %v, want both lines", vers)
	}
}

// A reference through v<major> cannot be repaired: one symlink, one owner. Say
// so, naming the rebuild that would fix it — dyld's version of this message
// arrives as a crash with nothing pointing back here.
func TestCompleteMachODiagnosesTheMajorDirectory(t *testing.T) {
	oldW, oldP := Warn, machoProvider
	defer func() { Warn, machoProvider = oldW, oldP }()
	var said []string
	Warn = func(m string) { said = append(said, m) }
	machoProvider = func(want, string) (Resolved, bool) {
		t.Error("a major-directory reference was sent to the provider")
		return Resolved{}, false
	}

	dir := t.TempDir()
	writeMachO(t, filepath.Join(dir, "open-mpi.org/hwloc/v2.15.0/bin/lstopo"),
		mcmd{lcLoadDylib, "@rpath/gnome.org/libxml2/v2/lib/libxml2.16.dylib"},
	)
	if _, err := completeMachO([]Resolved{{"open-mpi.org/hwloc", Ver{Raw: "2.15.0"}}}, dir, "darwin", "aarch64"); err != nil {
		t.Fatal(err)
	}
	if len(said) != 1 || !strings.Contains(said[0], "libxml2.16.dylib") ||
		!strings.Contains(said[0], "major directory") {
		t.Errorf("diagnostics: %v", said)
	}
}

// The provider asks the MANIFEST which version ships the soname, and stops at
// the newest that does — forty small reads instead of forty downloads.
func TestProvideMachoSonameAsksTheManifest(t *testing.T) {
	oldV, oldI, oldA := machoVersions, machoInstall, abiAnnotations
	defer func() { machoVersions, machoInstall, abiAnnotations = oldV, oldI, oldA }()

	machoVersions = func(string) ([]Ver, error) { // ascending, as the real one answers
		return []Ver{{Raw: "2.12.0"}, {Raw: "2.13.9"}, {Raw: "2.15.4"}, {Raw: "2.16.0"}}, nil
	}
	abiAnnotations = func(_, tag, _, _ string) map[string]string {
		switch tag {
		case "2.13.9":
			return map[string]string{ABIProvidesAnnotation: "libxml2.2.dylib"}
		case "2.15.4", "2.16.0":
			return map[string]string{ABIProvidesAnnotation: "libxml2.16.dylib,libxml2mod.dylib"}
		}
		return nil // published before the annotation existed
	}
	var installed []string
	machoInstall = func(r Resolved, _, _, _ string) (bool, error) {
		installed = append(installed, r.Version.Raw)
		return true, nil
	}

	r, ok := provideMachoSoname(want{project: "gnome.org/libxml2", soname: "libxml2.16.dylib"}, t.TempDir())
	if !ok || r.Version.Raw != "2.16.0" {
		t.Fatalf("provideMachoSoname = %+v, %v; want the newest that declares it", r, ok)
	}
	if len(installed) != 1 {
		t.Errorf("downloaded %d artifacts to answer a manifest question: %v", len(installed), installed)
	}
}

// Nothing declares it: say which reference will not resolve, rather than
// leaving dyld to say it later with no way back to here.
func TestProvideMachoSonameWhenNothingDeclaresIt(t *testing.T) {
	oldV, oldA, oldW := machoVersions, abiAnnotations, Warn
	defer func() { machoVersions, abiAnnotations, Warn = oldV, oldA, oldW }()
	machoVersions = func(string) ([]Ver, error) { return []Ver{{Raw: "1.0"}}, nil }
	abiAnnotations = func(string, string, string, string) map[string]string { return nil }
	var said []string
	Warn = func(m string) { said = append(said, m) }

	if _, ok := provideMachoSoname(want{project: "a.org", soname: "liba.9.dylib", ref: "@rpath/a.org/abi-liba.9.dylib/lib/liba.9.dylib"}, t.TempDir()); ok {
		t.Fatal("claimed to provide a soname nothing declares")
	}
	if len(said) != 1 || !strings.Contains(said[0], "@rpath/a.org/abi-liba.9.dylib") {
		t.Errorf("diagnostics: %v", said)
	}
}

// A lookup that fails is not the same answer as a project whose versions all
// lack the soname: the first is a broken registry, the second is a fact.
func TestProvideMachoSonameWhenTheLookupFails(t *testing.T) {
	oldV, oldW := machoVersions, Warn
	defer func() { machoVersions, Warn = oldV, oldW }()
	machoVersions = func(string) ([]Ver, error) { return nil, errors.New("no such project") }
	var said []string
	Warn = func(m string) { said = append(said, m) }

	if _, ok := provideMachoSoname(want{project: "a.org", soname: "liba.9.dylib"}, t.TempDir()); ok {
		t.Fatal("claimed to provide from a project it could not list")
	}
	if len(said) != 1 || !strings.Contains(said[0], "no such project") {
		t.Errorf("diagnostics: %v", said)
	}
}

// A file that CLAIMS to be a Mach-O and cannot be read is said out loud: what
// it loads is then unknown rather than absent, and an unknown reference is how
// a closure gets declared complete while it is not. A README is not a finding.
// ⛔ A REFERENCE THIS CANNOT MODEL USED TO BE SKIPPED IN SILENCE, and the
// silence is what let it reach 1266. Measured 2026-10-26 on the first
// full darwin/aarch64 sweep: of 3003 unresolvable references, 1266 are
//
//	@rpath/libabsl_base.2608.0.0.dylib
//
// with no project directory, so storeRefRE cannot match and no want is
// built. `bk unresolved` counts them — it stats every @rpath reference —
// while this skipped them, so the auditor and the resolver disagreed
// about 42% of a platform's backlog with not one line in the log.
//
// The warning does not resolve them (go-zpkg/artifact#166). It stops the
// gap being invisible.
func TestABareReferenceIsNamedRatherThanSkippedInSilence(t *testing.T) {
	oldW := Warn
	defer func() { Warn = oldW }()
	var said []string
	Warn = func(m string) { said = append(said, m) }

	dir := t.TempDir()
	prefix := filepath.Join(dir, "top.org", "v1")
	if err := os.MkdirAll(filepath.Join(prefix, "lib"), 0o755); err != nil {
		t.Fatal(err)
	}
	// The one that must be named: @rpath, absent from the store, and no
	// project directory to look a provider up by.
	//
	// Beside it, the two that must stay quiet — a system library, which is
	// the host's business, and a store-shaped reference, which becomes a
	// want and is reported by the machinery that handles it.
	writeMachO(t, filepath.Join(prefix, "bin", "tool"),
		mcmd{lcLoadDylib, "@rpath/libabsl_base.2608.0.0.dylib"},
		mcmd{lcLoadDylib, "/usr/lib/libSystem.B.dylib"},
		mcmd{lcLoadDylib, "@rpath/other.org/v2/lib/libother.dylib"},
	)

	wants := unresolvedRefs([]string{prefix}, dir)

	if len(said) != 1 {
		t.Fatalf("want exactly one diagnostic, got %d: %v", len(said), said)
	}
	for _, s := range []string{"libabsl_base.2608.0.0.dylib", "names no project directory"} {
		if !strings.Contains(said[0], s) {
			t.Errorf("the diagnostic does not say %q: %s", s, said[0])
		}
	}
	// ⛔ AND IT IS STILL NOT A WANT. Naming it must not quietly turn it
	// into something provideMachoSoname will be asked about with an empty
	// project — that would trade a silent skip for a confident wrong
	// lookup.
	for _, w := range wants {
		if strings.Contains(w.ref, "libabsl_base") {
			t.Errorf("a bare reference became a want: %+v", w)
		}
	}
	// The store-shaped one did become a want, so the quiet above is the
	// quiet of being handled, not of being dropped too.
	if len(wants) != 1 || wants[0].project != "other.org" {
		t.Errorf("the store-shaped reference did not become a want: %+v", wants)
	}
}

// A satisfied bare reference says nothing: the file is there, so there is
// no gap to name. Without this the warning would fire on every closure
// that happens to resolve its siblings by bare name.
func TestABareReferenceThatResolvesIsSilent(t *testing.T) {
	oldW := Warn
	defer func() { Warn = oldW }()
	var said []string
	Warn = func(m string) { said = append(said, m) }

	dir := t.TempDir()
	prefix := filepath.Join(dir, "top.org", "v1")
	if err := os.MkdirAll(filepath.Join(prefix, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	// @rpath is the store root here, so this is the file the reference
	// names — present, therefore nothing to report.
	if err := os.WriteFile(filepath.Join(dir, "libthere.1.dylib"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	writeMachO(t, filepath.Join(prefix, "bin", "tool"),
		mcmd{lcLoadDylib, "@rpath/libthere.1.dylib"},
	)

	if wants := unresolvedRefs([]string{prefix}, dir); len(wants) != 0 {
		t.Errorf("wants = %+v, want none", wants)
	}
	if len(said) != 0 {
		t.Errorf("a satisfied reference was reported: %v", said)
	}
}

// ⛔ A LOAD COMMAND IS INPUT FROM A STRANGER, and these two go somewhere.
//
// The reference decides the path that is stat'd to call it "already
// satisfied", and the project it names becomes a registry repository
// (FetchVersions) and a store path written to (InstallFor builds
// <dir>/<project>/v<version>). Neither was checked.
//
// This drives unresolvedRefs itself rather than the two helpers, because the
// question is not "does the rule work" but "is the rule CALLED" — the fuzz
// target next door asserts the rule and would pass with both guards deleted.
func TestUnresolvedRefsRefusesWhatLeavesTheStore(t *testing.T) {
	oldW := Warn
	defer func() { Warn = oldW }()
	var said []string
	Warn = func(m string) { said = append(said, m) }

	dir := t.TempDir()
	prefix := filepath.Join(dir, "top.org", "v1")
	if err := os.MkdirAll(filepath.Join(prefix, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	// A file outside the store that the escaping reference would find. Its
	// existence is the point: without the guard the stat succeeds and the
	// reference is passed over as "satisfied" by a file that is neither a
	// library nor in the store.
	outside := filepath.Join(dir, "..", "outside.dylib")
	if err := os.WriteFile(outside, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(outside)

	writeMachO(t, filepath.Join(prefix, "bin", "tool"),
		mcmd{lcLoadDylib, "@rpath/../outside.dylib"},
		mcmd{lcLoadDylib, "@rpath/../../../../etc/passwd"},
		// Local, and the regex matches, but "evil project" is not a usable
		// project name — a space is not a project rune.
		mcmd{lcLoadDylib, "@rpath/evil project/v1/lib/libx.dylib"},
		// The control: ordinary, and must still become a want, or a guard
		// that refuses everything would pass this test just as quietly.
		mcmd{lcLoadDylib, "@rpath/good.org/v2/lib/libgood.dylib"},
	)

	wants := unresolvedRefs([]string{prefix}, dir)

	if len(wants) != 1 || wants[0].project != "good.org" {
		t.Fatalf("want exactly the good.org want, got %+v", wants)
	}
	for _, w := range wants {
		if err := ValidateProjectName(w.project); err != nil {
			t.Errorf("a want carries project %q: %v", w.project, err)
		}
	}
	// Each refusal is SAID. A silent skip is the failure mode this family
	// already paid for once, at 1266 references.
	joined := strings.Join(said, "\n")
	for _, want := range []string{
		"outside.dylib", "etc/passwd", "OUTSIDE the store",
		"evil project", "cannot be used as one",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("the diagnostics do not mention %q:\n%s", want, joined)
		}
	}
}

func TestUnresolvedRefsNamesAMachoItCannotRead(t *testing.T) {
	oldW := Warn
	defer func() { Warn = oldW }()
	var said []string
	Warn = func(m string) { said = append(said, m) }

	dir := t.TempDir()
	prefix := filepath.Join(dir, "a.org", "v1")
	if err := os.MkdirAll(prefix, 0o755); err != nil {
		t.Fatal(err)
	}
	// Truncated after the magic: a Mach-O by its own claim, unreadable in fact.
	if err := os.WriteFile(filepath.Join(prefix, "broken"), []byte{0xcf, 0xfa, 0xed, 0xfe, 1, 2}, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(prefix, "README"), []byte("not a binary"), 0o644); err != nil {
		t.Fatal(err)
	}

	unresolvedRefs([]string{prefix}, dir)
	if len(said) != 1 || !strings.Contains(said[0], "broken") {
		t.Errorf("diagnostics: %v", said)
	}
}

// 0xcafebabe is a universal Mach-O AND a Java class file, and a store carrying
// a JVM tool is full of the latter. Warning about every one of them would be
// noise, and a warning that cries wolf is worse than none.
func TestMachoMagicTellsAClassFileApart(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		name string
		head []byte
		want machoKind
	}{
		{"universal", []byte{0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 2}, fatMachO},   // nfat_arch = 2
		{"java class", []byte{0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 65}, notMachO}, // major 65 = Java 21
		{"thin", []byte{0xcf, 0xfa, 0xed, 0xfe, 0, 0, 0, 0}, thinMachO},
		{"text", []byte("hello wo"), notMachO},
		{"too short", []byte{0xca}, notMachO},
	} {
		p := filepath.Join(dir, tc.name)
		if err := os.WriteFile(p, tc.head, 0o644); err != nil {
			t.Fatal(err)
		}
		if got := machoMagic(p); got != tc.want {
			t.Errorf("%s: machoMagic = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// A universal file is read through every slice. Before this, `macho.Open`
// refused it and the closure check printed "looks like a Mach-O (universal)
// but cannot be read" — the field report that prompted it, installing
// python-openstackclient on darwin/aarch64.
//
// The two slices name DIFFERENT libraries on purpose: with both naming the
// same one, reading a single slice would pass this test and the union would be
// untested.
func TestMachoNeededReadsEverySliceOfAUniversalFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "fat.so")
	writeFatMachO(t, p,
		fatSlice{cpu: cpuArm64, cmds: []mcmd{{lcLoadDylib, "@rpath/only.org/v1/lib/libarm.1.dylib"}}},
		fatSlice{cpu: cpuAmd64, cmds: []mcmd{{lcLoadDylib, "@rpath/only.org/v1/lib/libamd.1.dylib"}}},
	)
	got, err := MachoNeeded(p)
	if err != nil {
		t.Fatalf("MachoNeeded on a universal file: %v", err)
	}
	want := []string{"@rpath/only.org/v1/lib/libamd.1.dylib", "@rpath/only.org/v1/lib/libarm.1.dylib"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want both slices' references %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d] = %q, want %q (sorted)", i, got[i], want[i])
		}
	}
}

// The same reference in two slices is one reference. A universal binary's
// slices normally name the SAME dylib paths, so without this the common case
// would report everything twice.
func TestMachoNeededDeduplicatesAcrossSlices(t *testing.T) {
	p := filepath.Join(t.TempDir(), "same.dylib")
	ref := "@rpath/both.org/v2/lib/libboth.2.dylib"
	writeFatMachO(t, p,
		fatSlice{cpu: cpuArm64, cmds: []mcmd{{lcLoadDylib, ref}}},
		fatSlice{cpu: cpuAmd64, cmds: []mcmd{{lcLoadDylib, ref}}},
	)
	got, err := MachoNeeded(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != ref {
		t.Errorf("got %v, want exactly [%s]", got, ref)
	}
}

// A thin file still goes through the thin reader, in its own load order. The
// positive control: without it, every test here could be passing because
// MachoNeeded now reads everything as a union.
func TestMachoNeededStillReadsAThinFileInLoadOrder(t *testing.T) {
	p := filepath.Join(t.TempDir(), "thin.dylib")
	writeMachO(t, p,
		mcmd{lcLoadDylib, "@rpath/z.org/v1/lib/libz.1.dylib"},
		mcmd{lcLoadDylib, "@rpath/a.org/v1/lib/liba.1.dylib"},
	)
	got, err := MachoNeeded(p)
	if err != nil {
		t.Fatal(err)
	}
	// z before a: the FILE's order, not sorted. A thin file's load order is
	// its own and this must not start sorting it.
	if len(got) != 2 || got[0] != "@rpath/z.org/v1/lib/libz.1.dylib" {
		t.Errorf("got %v, want the file's load order with libz first", got)
	}
}

// Neither reader can open it: both failures are reported. Returning only the
// thin error made "this is a corrupt universal file" unsayable.
func TestMachoNeededReportsBothFailures(t *testing.T) {
	p := filepath.Join(t.TempDir(), "truncated")
	// FAT_MAGIC and a plausible nfat_arch, then nothing: the magic says
	// universal, so the thin reader's "not a Mach-O" is the less useful half.
	writeFile(t, p, []byte{0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 2})
	got, err := MachoNeeded(p)
	if err == nil {
		t.Fatalf("a truncated universal file read as %v, want an error", got)
	}
	if !strings.Contains(err.Error(), "fat") && !strings.Contains(err.Error(), "Mach-O") {
		t.Errorf("the error names neither attempt: %v", err)
	}
}
