package artifact

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// abiNote builds a GNU note section body: namesz|descsz|type | name(pad4) | desc.
func abiNote(name string, typ uint32, desc []byte) []byte {
	le := binary.LittleEndian
	nb := append([]byte(name), 0)
	for len(nb)%4 != 0 {
		nb = append(nb, 0)
	}
	var b bytes.Buffer
	var h [12]byte
	le.PutUint32(h[0:], uint32(len(name)+1)) // namesz includes the NUL
	le.PutUint32(h[4:], uint32(len(desc)))
	le.PutUint32(h[8:], typ)
	b.Write(h[:])
	b.Write(nb)
	b.Write(desc)
	return b.Bytes()
}

// abiDesc builds the 4-word ABI-tag descriptor [os, major, minor, sub].
func abiDesc(os, maj, min, sub uint32) []byte {
	le := binary.LittleEndian
	d := make([]byte, 16)
	le.PutUint32(d[0:], os)
	le.PutUint32(d[4:], maj)
	le.PutUint32(d[8:], min)
	le.PutUint32(d[12:], sub)
	return d
}

// elfWithNote crafts a minimal ELF64 carrying `note` in a .note.ABI-tag section.
// declaredSize, when non-zero, overrides the section header's sh_size (used to
// make Section.Data() fail by pointing past the file).
func elfWithNote(note []byte, declaredSize uint64) []byte {
	le := binary.LittleEndian
	var shstr bytes.Buffer
	shstr.WriteByte(0)
	nameOff := func(s string) uint32 { o := uint32(shstr.Len()); shstr.WriteString(s); shstr.WriteByte(0); return o }
	nNote := nameOff(".note.ABI-tag")
	nShstr := nameOff(".shstrtab")

	ehsize := uint64(64)
	noteOff := ehsize
	shstrOff := noteOff + uint64(len(note))
	shoff := shstrOff + uint64(shstr.Len())

	buf := &bytes.Buffer{}
	hdr := make([]byte, 64)
	copy(hdr[0:], []byte{0x7f, 'E', 'L', 'F'})
	hdr[4], hdr[5], hdr[6] = 2, 1, 1 // class64, LSB, current
	le.PutUint16(hdr[16:], 3)        // ET_DYN
	le.PutUint16(hdr[18:], 62)       // EM_X86_64
	le.PutUint32(hdr[20:], 1)
	le.PutUint64(hdr[40:], shoff)
	le.PutUint16(hdr[52:], 64)
	le.PutUint16(hdr[58:], 64)
	le.PutUint16(hdr[60:], 3) // shnum
	le.PutUint16(hdr[62:], 2) // shstrndx
	buf.Write(hdr)
	buf.Write(note)
	buf.Write(shstr.Bytes())

	sz := uint64(len(note))
	if declaredSize != 0 {
		sz = declaredSize
	}
	sh := func(name, typ uint32, offset, size uint64, align uint64) []byte {
		b := make([]byte, 64)
		le.PutUint32(b[0:], name)
		le.PutUint32(b[4:], typ)
		le.PutUint64(b[24:], offset)
		le.PutUint64(b[32:], size)
		le.PutUint64(b[48:], align)
		return b
	}
	buf.Write(sh(0, 0, 0, 0, 0))            // SHT_NULL
	buf.Write(sh(nNote, 7, noteOff, sz, 4)) // .note.ABI-tag (SHT_NOTE)
	buf.Write(sh(nShstr, 3, shstrOff, uint64(shstr.Len()), 1))
	return buf.Bytes()
}

func writeELF(t *testing.T, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "libc.so.6")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestGlibcMinKernel(t *testing.T) {
	p := writeELF(t, elfWithNote(abiNote("GNU", 1, abiDesc(0, 3, 2, 0)), 0))
	got, err := GlibcMinKernel(p)
	if err != nil || got != "3.2.0" {
		t.Fatalf("GlibcMinKernel = %q, %v (want 3.2.0)", got, err)
	}
}

func TestGlibcMinKernelErrors(t *testing.T) {
	// not an ELF at all
	if _, err := GlibcMinKernel(writeELF(t, []byte("not elf"))); err == nil {
		t.Error("non-ELF should error")
	}
	// nonexistent path
	if _, err := GlibcMinKernel(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Error("missing file should error")
	}
	// ELF with no .note.ABI-tag section — reuse buildELF (only .dynamic/.dynstr)
	if _, err := GlibcMinKernel(writeELF(t, buildELF(nil, 1))); err == nil {
		t.Error("missing .note.ABI-tag should error")
	}
	// wrong note type
	if _, err := GlibcMinKernel(writeELF(t, elfWithNote(abiNote("GNU", 3 /*build-id*/, abiDesc(0, 3, 2, 0)), 0))); err == nil {
		t.Error("wrong note type should error")
	}
	// truncated note (< 12 bytes)
	if _, err := GlibcMinKernel(writeELF(t, elfWithNote([]byte{1, 2, 3}, 0))); err == nil {
		t.Error("truncated note should error")
	}
	// descsz too small
	if _, err := GlibcMinKernel(writeELF(t, elfWithNote(abiNote("GNU", 1, []byte{0, 0, 0, 0}), 0))); err == nil {
		t.Error("short desc should error")
	}
	// non-Linux OS
	if _, err := GlibcMinKernel(writeELF(t, elfWithNote(abiNote("GNU", 1, abiDesc(1 /*not linux*/, 3, 2, 0)), 0))); err == nil {
		t.Error("non-Linux OS should error")
	}
	// section header claims a size past EOF -> Section.Data() fails
	if _, err := GlibcMinKernel(writeELF(t, elfWithNote(abiNote("GNU", 1, abiDesc(0, 3, 2, 0)), 1<<20))); err == nil {
		t.Error("oversized section should error on Data()")
	}
}
