//go:build !windows && !js && !wasip1

package artifact

import "syscall"

// On UNIX, Exec replaces the current process image via execve(2): on success it
// never returns, so the child inherits our pid and its exit status becomes ours
// for free. This is the historical pkgx behavior.
func init() { Exec = syscall.Exec }
