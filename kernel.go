package artifact

import (
	"debug/elf"
	"fmt"
)

// GlibcMinKernel reads the minimum supported Linux kernel version baked into a
// glibc's libc.so.6 (or any glibc-linked ELF) via the GNU `.note.ABI-tag` note,
// returned as "major.minor.subminor" (e.g. "3.2.0").
//
// glibc records its `--enable-kernel` floor here: the loader+libc refuse to run
// on an older kernel. So this is exactly the datum a glibc-by-kernel selector
// needs — pick the newest glibc whose min-kernel <= the host's `uname -r`. Pure
// Go (debug/elf); no external readelf.
//
// The note layout (ELF spec + GNU ABI tag): namesz(u32) descsz(u32) type(u32),
// then the name ("GNU\0", padded to 4 bytes), then desc = 4 u32 words
// [OS, major, minor, subminor] with OS==0 for Linux. type is NT_GNU_ABI_TAG(1).
func GlibcMinKernel(path string) (string, error) {
	f, err := elf.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	sec := f.Section(".note.ABI-tag")
	if sec == nil {
		return "", fmt.Errorf("%s: no .note.ABI-tag", path)
	}
	data, err := sec.Data()
	if err != nil {
		return "", err
	}
	bo := f.ByteOrder
	if len(data) < 12 {
		return "", fmt.Errorf("%s: truncated .note.ABI-tag", path)
	}
	namesz := bo.Uint32(data[0:])
	descsz := bo.Uint32(data[4:])
	typ := bo.Uint32(data[8:])
	if typ != 1 { // NT_GNU_ABI_TAG
		return "", fmt.Errorf("%s: not an ABI-tag note (type %d)", path, typ)
	}
	descOff := 12 + (namesz+3)&^uint32(3) // name padded to 4 bytes
	if descsz < 16 || uint64(descOff)+uint64(descsz) > uint64(len(data)) {
		return "", fmt.Errorf("%s: bad ABI-tag desc", path)
	}
	desc := data[descOff:]
	if os := bo.Uint32(desc[0:]); os != 0 { // 0 == ELF_NOTE_OS_LINUX
		return "", fmt.Errorf("%s: ABI-tag OS %d is not Linux", path, os)
	}
	return fmt.Sprintf("%d.%d.%d", bo.Uint32(desc[4:]), bo.Uint32(desc[8:]), bo.Uint32(desc[12:])), nil
}
