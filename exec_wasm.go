//go:build js || wasip1

package artifact

import "fmt"

// A wasm host cannot replace its process image: there is no execve(2), and
// unlike Windows there is no child process to spawn as an analogue either — a
// browser tab and a WASI guest both have exactly one program in them, the one
// already running.
//
// So Exec fails, loudly and early, instead of being absent. Everything else in
// this package — resolving versions, pulling artifacts, verifying signatures,
// extracting into a store — has no such obstacle and works unchanged; only the
// "become the target program" step has no meaning here. A wasm host runs a
// module it fetched, it does not hand its own identity over to it.
func init() { Exec = execWasm }

func execWasm(argv0 string, _ []string, _ []string) error {
	return fmt.Errorf("exec %s: a wasm host cannot replace its process image — run the module instead", argv0)
}
