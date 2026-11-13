package artifact

import (
	"debug/elf"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// writeDynELF builds a tiny 64-bit little-endian shared object with a .dynamic
// section carrying the given DT_NEEDED names and DT_SONAME. Built by hand
// rather than compiled, so this runs on every lane — including the darwin one,
// where no linker would produce an ELF at all.
func writeDynELF(t *testing.T, path, soname string, needed ...string) {
	t.Helper()
	writeDynELFPaths(t, path, soname, nil, nil, needed...)
}

// writeDynELFPaths is writeDynELF plus DT_RUNPATH and DT_RPATH. They are
// ordinary dynamic entries pointing into .dynstr, exactly like DT_NEEDED, so
// the only thing that changes is which tag they carry.
func writeDynELFPaths(t *testing.T, path, soname string, runpath, rpath []string, needed ...string) {
	t.Helper()
	le := binary.LittleEndian

	// .dynstr: a leading NUL, then each name NUL-terminated.
	strtab := []byte{0}
	off := func(s string) uint64 {
		o := uint64(len(strtab))
		strtab = append(strtab, s...)
		strtab = append(strtab, 0)
		return o
	}
	var dyn []byte
	ent := func(tag elf.DynTag, val uint64) {
		var b [16]byte
		le.PutUint64(b[0:], uint64(tag))
		le.PutUint64(b[8:], val)
		dyn = append(dyn, b[:]...)
	}
	for _, n := range needed {
		ent(elf.DT_NEEDED, off(n))
	}
	if soname != "" {
		ent(elf.DT_SONAME, off(soname))
	}
	for _, r := range runpath {
		ent(elf.DT_RUNPATH, off(r))
	}
	for _, r := range rpath {
		ent(elf.DT_RPATH, off(r))
	}
	// DT_STRTAB/DT_STRSZ are what debug/elf follows to read the names.
	const (
		ehSize  = 64
		shEntSz = 64
		numSec  = 4 // null, .dynstr, .dynamic, .shstrtab
		dynAddr = 0x1000
		strAddr = 0x2000
	)
	shstr := []byte{0}
	nameOff := func(s string) uint32 {
		o := uint32(len(shstr))
		shstr = append(shstr, s...)
		shstr = append(shstr, 0)
		return o
	}
	nDynstr, nDynamic, nShstrtab := nameOff(".dynstr"), nameOff(".dynamic"), nameOff(".shstrtab")

	dynOff := uint64(ehSize)
	strOff := dynOff + uint64(len(dyn))
	shstrOff := strOff + uint64(len(strtab))
	shOff := shstrOff + uint64(len(shstr))

	ent(elf.DT_NULL, 0) // must come last, after the offsets above are fixed
	buf := make([]byte, shOff+numSec*shEntSz)
	copy(buf, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0})
	le.PutUint16(buf[16:], uint16(elf.ET_DYN))
	le.PutUint16(buf[18:], uint16(elf.EM_X86_64))
	le.PutUint32(buf[20:], 1)
	le.PutUint64(buf[40:], shOff)
	le.PutUint16(buf[52:], ehSize)
	le.PutUint16(buf[58:], shEntSz)
	le.PutUint16(buf[60:], numSec)
	le.PutUint16(buf[62:], 3) // .shstrtab index
	copy(buf[dynOff:], dyn)
	copy(buf[strOff:], strtab)
	copy(buf[shstrOff:], shstr)

	sh := func(i int, name uint32, typ elf.SectionType, addr, off, size, link, entsize uint64) {
		b := buf[shOff+uint64(i)*shEntSz:]
		le.PutUint32(b[0:], name)
		le.PutUint32(b[4:], uint32(typ))
		le.PutUint64(b[16:], addr)
		le.PutUint64(b[24:], off)
		le.PutUint64(b[32:], size)
		le.PutUint32(b[40:], uint32(link))
		le.PutUint64(b[56:], entsize)
	}
	sh(1, nDynstr, elf.SHT_STRTAB, strAddr, strOff, uint64(len(strtab)), 0, 0)
	sh(2, nDynamic, elf.SHT_DYNAMIC, dynAddr, dynOff, uint64(len(dyn)), 1, 16)
	sh(3, nShstrtab, elf.SHT_STRTAB, 0, shstrOff, uint64(len(shstr)), 0, 0)

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf, 0o755); err != nil {
		t.Fatal(err)
	}
}

// What an ELF LOADS is its DT_NEEDED, and not its own DT_SONAME — the name it
// calls itself by is not a dependency, and counting it makes every library
// depend on itself.
func TestELFNeeded(t *testing.T) {
	p := filepath.Join(t.TempDir(), "libx.so.1")
	writeDynELF(t, p, "libx.so.1", "libz.so.1", "libc.so.6")
	got, err := ELFNeeded(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "libz.so.1" || got[1] != "libc.so.6" {
		t.Errorf("ELFNeeded = %v", got)
	}
}

// Anything that is not an ELF is not a finding: a store is mostly text.
func TestELFNeededOnSomethingElse(t *testing.T) {
	p := filepath.Join(t.TempDir(), "readme")
	if err := os.WriteFile(p, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ELFNeeded(p); err == nil {
		t.Error("a text file was read as an ELF")
	}
}

// On linux a DT_NEEDED entry is satisfied by any file of that name anywhere in
// the closure, because the loader searches a path rather than following one.
func TestSonamesUnder(t *testing.T) {
	dir := t.TempDir()
	for _, p := range []string{"a/lib/libz.so.1", "b/lib64/libssl.so.3", "c/lib/pkgconfig/z.pc"} {
		full := filepath.Join(dir, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got := SonamesUnder([]string{filepath.Join(dir, "a"), filepath.Join(dir, "b"), filepath.Join(dir, "c")})
	if !got["libz.so.1"] || !got["libssl.so.3"] {
		t.Errorf("SonamesUnder = %v", got)
	}
	if got["z.pc"] {
		t.Errorf("a pkg-config file was counted as a library: %v", got)
	}
}

// Two different kinds of outside, and an audit that called either a defect
// would report a hole in every closure on the fleet.
func TestSonameComesFromOutside(t *testing.T) {
	for _, s := range []string{"libc.so.6", "ld-linux-x86-64.so.2", "libstdc++.so.6", "libgomp.so.1", "libcuda.so.1"} {
		if !SonameComesFromOutside(s) {
			t.Errorf("%s is not recognised as coming from outside the closure", s)
		}
	}
	for _, s := range []string{"libz.so.1", "libxml2.so.2", "libssl.so.3"} {
		if SonameComesFromOutside(s) {
			t.Errorf("%s was excused, and it is a closure's own business", s)
		}
	}
}

// writeInterpELF builds a 64-bit little-endian ELF whose only program header
// is PT_INTERP. debug/elf reads Progs from the program-header table alone, so
// no sections are needed — and a file nothing will ever exec does not have to
// be loadable to be readable.
func writeInterpELF(t *testing.T, path, interp string) {
	t.Helper()
	writeInterpELFAs(t, path, interp, false, 0)
}

// writeInterpELFAs adds the two shapes the happy path never produces: a
// leading PT_LOAD, so the scan has something to skip, and an oversized
// p_filesz, so the segment read runs off the end of the file.
func writeInterpELFAs(t *testing.T, path, interp string, leadingLoad bool, extraFilesz uint64) {
	t.Helper()
	le := binary.LittleEndian
	const ehSize, phEntSz = 64, 56
	str := append([]byte(interp), 0)
	nph := uint16(1)
	if leadingLoad {
		nph = 2
	}
	phOff := uint64(ehSize)
	strOff := phOff + uint64(nph)*phEntSz

	buf := make([]byte, strOff+uint64(len(str)))
	copy(buf, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0})
	le.PutUint16(buf[16:], uint16(elf.ET_EXEC))
	le.PutUint16(buf[18:], uint16(elf.EM_X86_64))
	le.PutUint32(buf[20:], 1)
	le.PutUint64(buf[32:], phOff) // e_phoff
	le.PutUint16(buf[52:], ehSize)
	le.PutUint16(buf[54:], phEntSz) // e_phentsize
	le.PutUint16(buf[56:], nph)     // e_phnum

	ph := buf[phOff:]
	if leadingLoad {
		le.PutUint32(ph[0:], uint32(elf.PT_LOAD))
		ph = buf[phOff+phEntSz:]
	}
	le.PutUint32(ph[0:], uint32(elf.PT_INTERP))
	le.PutUint64(ph[8:], strOff)                        // p_offset
	le.PutUint64(ph[32:], uint64(len(str))+extraFilesz) // p_filesz
	copy(buf[strOff:], str)

	if err := os.WriteFile(path, buf, 0o755); err != nil {
		t.Fatal(err)
	}
}

// TestELFInterp: the loader path an artifact names is the first of Nix's three
// bootstrap invariants — the final environment must not REFERENCE the seed.
// A PT_INTERP under /lib64 says the MACHINE has the loader, not the store.
func TestELFInterp(t *testing.T) {
	dir := t.TempDir()
	want := "/pkgx/gnu.org/glibc/v2.44.0/lib/glibc-2.44/ld-linux-x86-64.so.2"
	p := filepath.Join(dir, "sovereign")
	writeInterpELF(t, p, want)
	got, err := ELFInterp(p)
	if err != nil || got != want {
		t.Errorf("ELFInterp = %q, %v; want %q", got, err, want)
	}

	// A file with no PT_INTERP is static, not broken. Reusing the dynamic
	// fixture, which builds sections and no program headers at all.
	q := filepath.Join(dir, "static.so")
	writeDynELF(t, q, "libx.so.1", "libc.so.6")
	if got, err := ELFInterp(q); err != nil || got != "" {
		t.Errorf("ELFInterp on a file with no PT_INTERP = %q, %v; want \"\", nil", got, err)
	}

	// Something that is not an ELF must FAIL, not answer "". "Could not read"
	// is not "names no interpreter", and a purity check that conflated them
	// would pass every file it could not open.
	r := filepath.Join(dir, "script")
	if err := os.WriteFile(r, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := ELFInterp(r); err == nil {
		t.Error("ELFInterp must refuse a non-ELF rather than report no interpreter")
	}
}

// TestELFRunpath: the two tags are returned SEPARATELY because they are
// consulted on opposite sides of LD_LIBRARY_PATH, and a file carrying both is
// answering two different questions.
func TestELFRunpath(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "both.so")
	writeDynELFPaths(t, p, "libx.so.1",
		[]string{"$ORIGIN/../lib"},
		[]string{"/usr/lib/x86_64-linux-gnu"},
		"libc.so.6")
	run, rp, err := ELFRunpath(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(run) != 1 || run[0] != "$ORIGIN/../lib" {
		t.Errorf("DT_RUNPATH = %v", run)
	}
	if len(rp) != 1 || rp[0] != "/usr/lib/x86_64-linux-gnu" {
		t.Errorf("DT_RPATH = %v", rp)
	}

	// Neither tag is absence, not failure.
	q := filepath.Join(dir, "none.so")
	writeDynELF(t, q, "libx.so.1", "libc.so.6")
	if run, rp, err := ELFRunpath(q); err != nil || len(run) != 0 || len(rp) != 0 {
		t.Errorf("ELFRunpath with neither tag = %v, %v, %v", run, rp, err)
	}

	// And a non-ELF fails, for the reason ELFInterp's does.
	r := filepath.Join(dir, "script")
	if err := os.WriteFile(r, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ELFRunpath(r); err == nil {
		t.Error("ELFRunpath must refuse a non-ELF")
	}
}

// The two shapes the happy path cannot reach: a program header table whose
// PT_INTERP is not first, and a segment whose declared size runs past the end
// of the file.
func TestELFInterpSkipsAndRefuses(t *testing.T) {
	dir := t.TempDir()

	behind := filepath.Join(dir, "behind-a-load")
	writeInterpELFAs(t, behind, "/pkgx/loader", true, 0)
	if got, err := ELFInterp(behind); err != nil || got != "/pkgx/loader" {
		t.Errorf("a PT_INTERP behind a PT_LOAD = %q, %v", got, err)
	}

	// A truncated segment must be an error, not a short string: silently
	// returning what fitted would let a purity check pass on a path it only
	// read half of.
	short := filepath.Join(dir, "truncated")
	writeInterpELFAs(t, short, "/pkgx/loader", false, 4096)
	if got, err := ELFInterp(short); err == nil {
		t.Errorf("ELFInterp on a segment past EOF = %q, nil; want an error", got)
	}
}
