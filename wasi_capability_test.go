package artifact

import (
	"runtime"
	"testing"
)

// WASI preview 1 cannot do two things this package's staging tests assert, and
// both were established by reading Go's own implementation rather than by
// inferring them from a failure:
//
//   - CHMOD IS A NO-OP. $GOROOT/src/syscall/fs_wasip1.go:
//
//     func Chmod(path string, mode uint32) error {
//     var stat Stat_t
//     return Stat(path, &stat)
//     }
//
//     It stats the path and returns that error. The mode is not passed
//     anywhere, because WASI p1 has no call that takes one. So a file keeps
//     whatever mode the runtime gave it, and a directory made "read-only" is
//     not read-only.
//
//   - SYMLINKS ARE REFUSED BY THE HOST. Go does implement Symlink there — it
//     calls path_symlink — but under wasmtime's preopen it comes back EPERM:
//
//     symlink /pkgx/…/ld-linux-x86-64.so.2 /tmp/…/lib/ld-linux-x86-64.so.2:
//     Operation not permitted
//
// These are limits of the sandbox, not defects here, so the tests that need
// them SKIP with the capability named. What they must not do is weaken the
// assertion for every other platform: the mode of an extracted file and the
// loader symlink in a scratch rootfs are both load-bearing, and a test that
// stopped checking them everywhere to stay green in one place would be worse
// than no wasip1 lane at all.
//
// Everything else in this package — OCI resolution, semver, closure
// completion, decompression — runs under wasip1 and is exactly what a wasm
// consumer executes, which is why the lane is worth having.
const (
	wasiNoChmod   = "WASI preview 1 has no chmod: syscall.Chmod stats the path and ignores the mode"
	wasiNoSymlink = "WASI preview 1 symlinks are refused by the host sandbox (path_symlink → EPERM)"
)

// skipOnWASI skips a test that needs a filesystem capability WASI does not
// offer, naming it. A skip nobody can read is indistinguishable from a test
// that was quietly deleted.
func skipOnWASI(t *testing.T, capability string) {
	t.Helper()
	if runtime.GOOS == "wasip1" || runtime.GOOS == "js" {
		t.Skip("not available under " + runtime.GOOS + ": " + capability)
	}
}
