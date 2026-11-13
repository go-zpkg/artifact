package artifact

// glibc.go decides WHICH glibc a linux closure gets, and keeps glibc-flavored
// registry tags out of ordinary version resolution.
//
// Every dynamically linked ELF in a pkgx closure needs the loader + libc, so
// CompleteClosure always pulls gnu.org/glibc. Taking the newest one is wrong on
// an old kernel: glibc bakes its `--enable-kernel` floor into libc.so.6's
// .note.ABI-tag and the loader REFUSES to run below it — the HPC case, where a
// login node still runs a 3.10 kernel. Our factory stamps that floor as the
// org.go-zpkg.glibc.min-kernel annotation when it publishes a glibc artifact, so
// a client can read it from the registry without downloading anything: pick the
// newest published glibc the running kernel can actually run.
//
// The selector only ENGAGES when the newest glibc does not fit this host — if it
// fits (every modern machine), or if the registry carries no floor to compare
// against, resolution is left exactly as it was.
//
// ZPKG_GLIBC=<version> pins one explicitly instead. That is the consumer side of
// `bk factory --glibc <version>`, which builds a whole stack against one glibc.

import (
	"context"
	"os"
	"strings"
	"sync"
)

// osReleasePath holds the running kernel release — `uname -r` without a syscall,
// and identical on every Linux arch. A var so tests can point it elsewhere.
var osReleasePath = "/proc/sys/kernel/osrelease"

// osReadFile is os.ReadFile, swappable in tests.
var osReadFile = os.ReadFile

// glibcFlavorSep separates an artifact's version from the glibc it was built
// against in a registry tag: <version>-glibc<glibcVersion>.
const glibcFlavorSep = "-glibc"

// SplitFlavor splits a registry tag into the software version and the glibc
// flavor it was built against; the flavor is "" for an ordinary tag.
//
//	"8.20.0"             → "8.20.0", ""
//	"8.20.0-glibc2.27.0" → "8.20.0", "2.27.0"
func SplitFlavor(tag string) (version, glibc string) {
	i := strings.LastIndex(tag, glibcFlavorSep)
	if i <= 0 {
		return tag, ""
	}
	return tag[:i], tag[i+len(glibcFlavorSep):]
}

// HostKernel returns the running Linux kernel release (e.g. "6.8.0-45-generic"),
// or "" on a non-Linux host.
func HostKernel() (string, error) {
	if goos() != "linux" {
		return "", nil
	}
	b, err := osReadFile(osReleasePath)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// glibcOnce caches the resolved constraint: it costs a registry round-trip, and
// CompleteClosure asks for it inside a fixpoint loop.
var (
	glibcOnce sync.Once
	glibcPin  string
)

// GlibcConstraint is the constraint gnu.org/glibc is resolved with when a
// closure needs the C library: an exact "=<version>" when a glibc has been
// pinned (ZPKG_GLIBC) or chosen for this host's kernel, else "*" (newest).
func GlibcConstraint() string {
	glibcOnce.Do(func() { glibcPin = resolveGlibcConstraint() })
	return glibcPin
}

// resetGlibcConstraint clears the cache; for tests and for a consumer that
// re-points ZPKG_DIST at runtime.
func resetGlibcConstraint() {
	glibcOnce = sync.Once{}
	glibcPin = ""
}

// GlibcFlavor is the glibc build variant this host asks for: the ZPKG_GLIBC
// pin, or "" for ordinary builds. A pinned host wants BOTH that exact glibc
// artifact AND, wherever the factory published one, the tool built against it —
// the `<version>-glibc<ver>` tag.
func GlibcFlavor() string {
	return strings.TrimPrefix(strings.TrimSpace(Env("ZPKG_GLIBC")), "=")
}

func resolveGlibcConstraint() string {
	if v := GlibcFlavor(); v != "" {
		return "=" + v
	}
	kernel, err := HostKernel()
	if err != nil || kernel == "" {
		return "*"
	}
	v := newestGlibcForKernel(kernel)
	if v == "" {
		return "*"
	}
	return "=" + v
}

// newestGlibcForKernel returns the newest published glibc this kernel can run,
// or "" to mean "nothing to change".
//
// It is deliberately conservative: if the newest published glibc has no recorded
// floor (an artifact published before the annotation existed, or a dist with no
// annotations at all) or already fits, it returns "" — so this only ever changes
// what gets installed on a host that genuinely cannot run the newest glibc.
func newestGlibcForKernel(kernel string) string {
	vs, err := FetchVersions(GlibcProject)
	if err != nil || len(vs) == 0 {
		return ""
	}
	osn, arch := HostSlug()
	kv := ParseVer(kernel)
	fits := func(v Ver) (ok, known bool) {
		mk, err := glibcMinKernelOf(v.Raw, osn, arch)
		if err != nil || mk == "" {
			return false, false
		}
		return cmpVer(ParseVer(mk), kv) <= 0, true
	}
	// Newest first: unknown floor or a fitting one → leave resolution alone.
	if ok, known := fits(vs[len(vs)-1]); !known || ok {
		return ""
	}
	for i := len(vs) - 2; i >= 0; i-- {
		if ok, known := fits(vs[i]); known && ok {
			return vs[i].Raw
		}
	}
	return ""
}

// glibcMinKernelOf reads a published glibc artifact's minimum-kernel floor from
// its registry annotation. A static HTTP dist carries no annotations, so it
// reports "unknown" (empty) rather than an error.
var glibcMinKernelOf = func(ver, osn, arch string) (string, error) {
	if !IsOCI(DistBase) {
		return "", nil
	}
	c, err := ociClientForDist()
	if err != nil {
		return "", err
	}
	ann, err := c.Annotations(GlibcProject, ver, osn, arch)
	if err != nil {
		return "", err
	}
	return Annotation(ann, GlibcMinKernelAnnotation), nil
}

// Annotations returns the OCI annotations of a published artifact's per-platform
// manifest — how a client reads an artifact's self-description (a glibc's minimum
// kernel, a tool's glibc flavor) without downloading the artifact itself.
func (c *OCIClient) Annotations(project, ver, osn, arch string) (map[string]string, error) {
	repo, err := c.repository(project)
	if err != nil {
		return nil, err
	}
	_, man, err := c.resolvePlatform(context.Background(), repo, project, ver, osn, arch)
	if err != nil {
		return nil, err
	}
	return man.Annotations, nil
}
