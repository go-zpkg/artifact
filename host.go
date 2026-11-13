// Package artifact is the reusable pkgx "artifact backend": it resolves a package's
// runtime dependency closure from the pkgx pantry, downloads the artifacts from
// the configured ZPKG_DIST (default: the signed oci://ghcr.io/go-zpkg/packages
// registry; ZPKG_DIST=https://dist.pkgx.dev for the unsigned upstream), and
// installs them — with no runtime dependencies of its own (pure Go,
// CGO_ENABLED=0, runnable on a `FROM scratch` image). It is imported by the
// pkgm CLI and by sibling tools so there is one source of truth.
package artifact

import "runtime"

// osSlug maps a Go GOOS value to the pkgx OS slug. Everything that is not
// named here is treated as linux (pkgx artifacts those three families, and an
// exotic unix is closer to linux than to nothing). It is a pure function so
// every branch is unit-testable without needing to be built for that OS.
//
// js and wasip1 are named because the linux default is WRONG for them, not
// merely approximate. This package compiles and passes for both, so it runs in
// a browser and under a WASI runtime — and there it used to report
//
//	HostSlug() = "linux" / "wasm"
//
// a platform that does not exist and never will. A consumer asking the registry
// for linux/wasm artifacts gets nothing, forever, with no hint as to why. They
// stay distinct from each other too: a WASI guest and a browser are different
// hosts (different imports, different capabilities), so a module built for one
// is not an artifact for the other.
// osSlug maps Go's GOOS onto the OS name pkgx uses for a platform.
//
// The BSDs are named explicitly because the fallback below is the dangerous
// kind of default: it does not refuse, it ANSWERS, and the answer was "linux".
// A FreeBSD or OpenBSD host running this therefore called itself linux and
// resolved linux artifacts — ELF files it cannot load, discovered at the first
// exec rather than at the resolution that chose them. Nothing said no.
//
// Naming them turns that into "no artifact for <project> (freebsd/aarch64)",
// which is true, actionable, and arrives before anything is installed. There
// are no freebsd artifacts yet; saying so is the point.
//
// What still falls through is honest to state rather than paper over: android
// is linux-like and the fallback suits it, while illumos, solaris, aix and
// plan9 would be answered wrongly in the same silent way. They are not targets
// today, and widening the list for a platform with no witness is how a guess
// gets mistaken for support.
func osSlug(g string) string {
	switch g {
	case "darwin":
		return "darwin"
	case "windows":
		return "windows"
	case "js":
		return "js"
	case "wasip1":
		return "wasip1"
	case "freebsd", "openbsd", "netbsd", "dragonfly":
		return g
	default:
		return "linux"
	}
}

// archSlug maps a Go GOARCH value to the pkgx architecture slug (the pass-through
// default keeps arches pkgx spells the same as Go, e.g. riscv64). Pure, for the
// same testability reason as osSlug.
func archSlug(a string) string {
	switch a {
	case "arm64":
		return "aarch64"
	case "amd64":
		return "x86-64"
	default:
		return a
	}
}

// goos / goarch return the pkgx OS / architecture slug for the running machine.
// They are function vars (defaulting to the real runtime detection, always
// routed through osSlug/archSlug so they can never disagree with it) so a test
// can exercise the OS/arch-specific code paths — Windows binary resolution, the
// linux scratch-rootfs and DT_NEEDED closure completion — that are otherwise
// unreachable on the host running the suite.
var (
	goos   = func() string { return osSlug(runtime.GOOS) }
	goarch = func() string { return archSlug(runtime.GOARCH) }
)

// GOOS returns the pkgx OS slug ("linux", "darwin", or "windows") for the
// running machine.
func GOOS() string { return goos() }

// GOARCH returns the pkgx architecture slug (e.g. "x86-64", "aarch64") for the
// running machine.
func GOARCH() string { return goarch() }
