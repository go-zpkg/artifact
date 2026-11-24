// Package artifact is the reusable package-artifact backend: it resolves a
// project's runtime dependency closure from the pantry, downloads the
// artifacts from the configured ZPKG_DIST and installs them — with no runtime
// dependencies of its own (pure Go, CGO_ENABLED=0, runnable on a `FROM
// scratch` image). It is imported by zpkm, zpkx and zpkb so there is one
// source of truth.
//
// ⛔ THE DEFAULT REGISTRY IS oci://ghcr.io/go-zpkg/packages (since 2026-11-24),
// and this sentence has been wrong before. DefaultDistBase (zpkg.go) is the
// authority; readmedefault_test.go asserts the README agrees with it and does
// NOT name go-pkgx/packages as a default. ZPKG_DIST is an ORDERED list of
// sources (see dist.go); any source under go-pkgx is refused.
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
//
// ⭐ AND ANDROID NOW HAS ITS WITNESS, so that sentence is a measurement rather
// than a reasonable guess. On a Pixel 11 Pro Fold running Android 17
// (arm64-v8a), 2026-11-14: `zpkm` built CGO_ENABLED=0 GOOS=linux GOARCH=arm64
// resolved linux/aarch64, installed lz4.org v1.10.0 with the gnu.org/glibc
// closure, and ran it — `zpkm run lz4.org -- --version` exit 0. The linux
// artifacts work there, so answering "linux" is CORRECT and not a silent
// wrong answer.
//
// ⛔ WHICH IS WHY ANDROID MUST NOT BE ADDED TO THE LIST ABOVE. It looks like
// the same tidy-up the BSDs got, and it is the opposite: naming it would make
// a GOOS=android build resolve android/aarch64, for which nothing is
// published, so a platform that works today would start refusing. The BSDs
// were named because the fallback's answer was WRONG for them; here it is
// right. (go-zpkg/artifact#235 was filed proposing exactly that change, by me,
// before any of this was measured.)
//
// Note also that the fallback is unreachable from the binary people actually
// run: runtime.GOOS is a property of the BUILD, and the published zpkm is a
// linux/arm64 binary, so it reports "linux" on a phone and never reaches the
// android case at all. Two probes of one source, built for the two GOOS
// values and run on the same device, reported "linux" and "android"
// respectively.
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
