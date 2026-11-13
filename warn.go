package artifact

import "fmt"

// Warn receives diagnostics a caller should SEE but that are not fatal: a
// closure the resolver could not complete, a soname nothing provides. It is nil
// by default — a library must not write to a process's stderr uninvited — so a
// command-line tool sets it once at startup:
//
//	artifact.Warn = func(msg string) { fmt.Fprintln(os.Stderr, "pkgx: "+msg) }
//
// Silence here is expensive: an unprovided soname does not fail the install, it
// fails LATER, when the binary starts and reports "cannot open shared object
// file" with nothing pointing back at the resolution that gave up.
var Warn func(msg string)

// warn formats a diagnostic and hands it to Warn, if a caller installed one.
func warn(format string, args ...any) {
	if Warn == nil {
		return
	}
	Warn(fmt.Sprintf(format, args...))
}
