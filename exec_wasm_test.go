//go:build js || wasip1

package artifact

import (
	"strings"
	"testing"
)

// TestExecWasmRefusesWithAReason: this file exists only for wasm builds, so the
// native lane never runs it — and an error path no lane executes is a message
// nobody has read. A wasm host cannot replace its process image; saying so by
// name beats a nil-func panic.
func TestExecWasmRefusesWithAReason(t *testing.T) {
	err := Exec("/usr/bin/tool", []string{"tool", "--help"}, nil)
	if err == nil {
		t.Fatal("a wasm host has no execve; Exec must fail")
	}
	if !strings.Contains(err.Error(), "/usr/bin/tool") {
		t.Errorf("the message does not name what it refused to exec: %v", err)
	}
	if !strings.Contains(err.Error(), "wasm host") {
		t.Errorf("the message does not say why: %v", err)
	}
}
