package artifact

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// StorePlatformFile is the name of the marker a store carries saying which
// platform its artifacts were built for.
// ⛔ `.zpkg-platform`: this file is OURS, written by our installer into our
// store, and upstream pkgx writes nothing of the kind. Named after upstream
// it would claim a convention that is not theirs — and a store shared with
// them is exactly what moving to ~/.zpkg stops.
const StorePlatformFile = ".zpkg-platform"

// MarkStorePlatform records, once, which platform a store holds.
//
// ⛔ IT NEVER FAILS A CALLER. A read-only $ZPKG_DIR is somebody's deliberate
// arrangement — a materialised squashfs image on a compute node is exactly
// that — and refusing to run because a note could not be left would break the
// case this was written to help. An unwritable marker means the store simply
// cannot say what it holds, which is where everything was before.
func MarkStorePlatform(dir, osn, arch string) {
	path := filepath.Join(dir, StorePlatformFile)
	if _, err := os.Stat(path); err == nil {
		return // already said, and it is not this function's job to argue
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return
	}
	// ⛔ WRITTEN VIA A TEMPORARY AND RENAMED, because on a cluster this runs
	// in thousands of ranks at once against one NFS export. A half-written
	// marker read by a neighbour is a mismatch that is not real, and a
	// refusal nobody can explain is worse than no marker at all.
	tmp, err := os.CreateTemp(dir, StorePlatformFile+".*")
	if err != nil {
		return
	}
	name := tmp.Name()
	_, werr := fmt.Fprintf(tmp, "%s/%s\n", osn, arch)
	cerr := tmp.Close()
	if werr != nil || cerr != nil {
		_ = os.Remove(name)
		return
	}
	if err := os.Rename(name, path); err != nil {
		_ = os.Remove(name)
	}
}

// StorePlatform reads a store's marker. It reports ok=false when the store
// does not say, which every store written before this existed does not.
func StorePlatform(dir string) (osn, arch string, ok bool) {
	b, err := os.ReadFile(filepath.Join(dir, StorePlatformFile))
	if err != nil {
		return "", "", false
	}
	o, a, found := strings.Cut(strings.TrimSpace(string(b)), "/")
	if !found || o == "" || a == "" {
		return "", "", false
	}
	return o, a, true
}

// CheckStorePlatform says whether a store holds artifacts for the platform about
// to use it.
//
// ⛔ THE FAILURE IT REPLACES IS `Exec format error`, WITH NO EXPLANATION. A
// prefix is `$ZPKG_DIR/<project>/v<version>/…` with no platform in it, so a
// store shared over NFS between linux/x86-64 and linux/aarch64 holds whichever
// architecture was installed last — `lib/libssl.so.3` is the same file name on
// both — and the other architecture gets a kernel error naming nothing anybody
// can act on.
//
// ⛔ A STORE THAT DOES NOT SAY IS NOT A MISMATCH. Every store written before
// the marker existed is silent, and treating silence as disagreement would
// refuse to run on the installed base. Silence is reported as agreement here
// and the question is closed the first time somebody installs into it.
func CheckStorePlatform(dir, osn, arch string) error {
	have, haveArch, ok := StorePlatform(dir)
	if !ok || (have == osn && haveArch == arch) {
		return nil
	}
	return fmt.Errorf("store %s holds %s/%s artifacts and this is %s/%s — one store cannot hold two architectures; give the platform a place in the path, e.g. ZPKG_DIR=%s/{platform}",
		dir, have, haveArch, osn, arch, filepath.Dir(dir))
}
