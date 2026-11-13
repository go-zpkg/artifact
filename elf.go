package artifact

import (
	"bytes"
	"debug/elf"
)

// ELFNeeded is what an ELF file loads: its DT_NEEDED entries.
//
// It is the linux counterpart of MachoNeeded, and the two answer differently
// shaped questions. A Mach-O names a PATH, so "is it satisfied" is a stat. An
// ELF names a SONAME and the loader searches for it, so the question is
// whether ANYTHING in the closure provides that name — which is a comparison
// against the whole store, not against one path.
//
// Both readers live here because an audit that runs on one platform and not
// the other measures half a fleet. This one is exported for `bk unresolved`;
// CompleteClosure has used the same reading to repair a closure for a while.
func ELFNeeded(p string) ([]string, error) {
	f, err := elf.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	libs, err := f.ImportedLibraries()
	if err != nil {
		return nil, err
	}
	return libs, nil
}

// SonamesUnder is every shared-library file name the given installed prefixes
// offer. On linux a DT_NEEDED entry is satisfied by any of them, wherever it
// sits, because the loader searches a path rather than following one.
func SonamesUnder(prefixes []string) map[string]bool {
	return availableSonames(prefixes)
}

// SonameComesFromOutside reports whether a soname is one the CLOSURE is not
// expected to carry.
//
// Two groups, and they are different kinds of outside. The implicit system
// libraries — glibc, the libstdc++/libgcc pair, the gcc runtime — are supplied
// by the installer from their own project groups rather than by the soname
// map, so a closure that has not run that step yet looks short of them without
// being wrong. The host-provided ones are a boundary rather than a gap: a GPU
// driver's userspace half is versioned in lockstep with a kernel module and
// belongs to whoever installed the driver.
//
// An audit that counted either as a defect would report a hole in every
// closure on the fleet.
func SonameComesFromOutside(soname string) bool {
	return isImplicitSoname(soname) || isHostProvidedSoname(soname)
}

// ELFInterp is the program interpreter an ELF names in its PT_INTERP header —
// the absolute path the kernel execs to load it.
//
// It is the first of the three things Nix requires of a bootstrapped
// toolchain: the final environment must not REFERENCE the seed it came from.
// An artifact whose PT_INTERP is /lib64/ld-linux-x86-64.so.2 runs because the
// MACHINE has that file, and says nothing about whether the store does. Our
// own builder README states the same property in prose and measured it once,
// by hand, on one recipe:
//
//	PT_INTERP  /pkgx/gnu.org/glibc/v2.44.0/lib/glibc-2.44/ld-linux-aarch64.so.1
//
// An invariant nothing checks is a hope.
//
// A statically linked file has no PT_INTERP, and that is not an error: it
// returns "" with a nil error. Only a file that cannot be read as an ELF at
// all fails.
func ELFInterp(p string) (string, error) {
	f, err := elf.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	for _, prog := range f.Progs {
		if prog.Type != elf.PT_INTERP {
			continue
		}
		b := make([]byte, prog.Filesz)
		if _, err := prog.ReadAt(b, 0); err != nil {
			return "", err
		}
		// The segment is a NUL-terminated string, and its Filesz includes the
		// NUL. Trimming at the first one rather than the last keeps a padded
		// segment from carrying trailing bytes into the path.
		if i := bytes.IndexByte(b, 0); i >= 0 {
			b = b[:i]
		}
		return string(b), nil
	}
	return "", nil
}

// ELFRunpath is where an ELF tells the loader to look: DT_RUNPATH, and the
// older DT_RPATH, in that order.
//
// Both are returned, and NOT merged, because they do not mean the same thing
// to the loader: DT_RPATH is consulted before LD_LIBRARY_PATH and DT_RUNPATH
// after it, and a file carrying both is answering two different questions. A
// caller auditing for paths that escape the store cares about every entry; one
// reasoning about resolution order needs to know which list an entry came
// from, so the two are returned separately rather than concatenated.
//
// Absent entries are not an error: a file with neither returns two nil slices.
func ELFRunpath(p string) (runpath, rpath []string, err error) {
	f, err := elf.Open(p)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	// DynString returns an error for a file with no .dynamic at all, which a
	// static binary legitimately is. That is absence, not failure.
	if v, e := f.DynString(elf.DT_RUNPATH); e == nil {
		runpath = v
	}
	if v, e := f.DynString(elf.DT_RPATH); e == nil {
		rpath = v
	}
	return runpath, rpath, nil
}
