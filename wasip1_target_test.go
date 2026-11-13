package artifact

import (
	"os"
	"path/filepath"
	"testing"
)

// TestPlatformBlockNamesEveryPlatform pins the fix: before it, platformBlock
// listed only linux/darwin and x86-64/aarch64, so on a linux host a recipe's
// `wasip1:`, `windows:` or `js:` map was not "another platform's block" and
// fell through to be read as a plain value.
func TestPlatformBlockNamesEveryPlatform(t *testing.T) {
	blk := map[string]any{"K": "v"}
	for _, key := range []string{
		"wasip1", "wasip1/wasm", "windows", "windows/x86-64", "windows/aarch64",
		"js", "js/wasm", "freebsd", "freebsd/x86-64", "darwin/aarch64", "wasm",
	} {
		got, isPlatform := platformBlock(blk, key, "linux", "x86-64")
		if !isPlatform || got != nil {
			t.Errorf("linux/x86-64 host, key %q: got (%v, %v), want (nil, true)", key, got, isPlatform)
		}
	}
	// On the wasip1 host the matching block applies, the others do not.
	for _, key := range []string{"wasip1", "wasip1/wasm", "wasm"} {
		if got, ok := platformBlock(blk, key, "wasip1", "wasm"); !ok || got == nil {
			t.Errorf("wasip1/wasm host, key %q must apply", key)
		}
	}
	if got, ok := platformBlock(blk, "linux", "wasip1", "wasm"); !ok || got != nil {
		t.Error("linux block must be inert on wasip1/wasm")
	}
	// A real variable name stays a value.
	if _, ok := platformBlock(blk, "PATH", "linux", "x86-64"); ok {
		t.Error("PATH is not a platform")
	}
}

// TestFlattenEnvIgnoresAWasip1Block: the user-visible effect.
func TestFlattenEnvIgnoresAWasip1Block(t *testing.T) {
	in := map[string]any{"A": "1", "wasip1": map[string]any{"B": "2"}, "windows": map[string]any{"C": "3"}}
	out := map[string]string{}
	flattenEnv(in, out, "linux", "x86-64", "/p", "1.0", nil)
	if len(out) != 1 || out["A"] != "1" {
		t.Errorf("linux host: got %v, want only A=1", out)
	}
	out = map[string]string{}
	flattenEnv(in, out, "wasip1", "wasm", "/p", "1.0", nil)
	if out["A"] != "1" || out["B"] != "2" || len(out) != 2 {
		t.Errorf("wasip1 host: got %v, want A=1 B=2", out)
	}
}

// TestResolveBinPathWasm: a wasip1/wasm artifact ships bin/<name>.wasm while the
// recipe's `provides: bin/<name>` stays extension-free, as with windows .exe.
func TestResolveBinPathWasm(t *testing.T) {
	for _, host := range []string{"wasip1", "js"} {
		setGoos(t, host)
		dir := t.TempDir()
		bin := filepath.Join(dir, "tool")
		if err := os.WriteFile(bin+".wasm", []byte("\x00asm\x01\x00\x00\x00"), 0o644); err != nil {
			t.Fatal(err)
		}
		if got := ResolveBinPath(bin); got != bin+".wasm" {
			t.Errorf("%s: ResolveBinPath = %q, want %q", host, got, bin+".wasm")
		}
		if got := ResolveBinPath(bin + ".wasm"); got != bin+".wasm" {
			t.Errorf("%s: already-suffixed path changed: %q", host, got)
		}
		bare := filepath.Join(dir, "other")
		if got := ResolveBinPath(bare); got != bare {
			t.Errorf("%s: missing module = %q, want bare name", host, got)
		}
	}
	// a unix host never goes looking for .wasm
	setGoos(t, "linux")
	dir := t.TempDir()
	bin := filepath.Join(dir, "tool")
	if err := os.WriteFile(bin+".wasm", []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := ResolveBinPath(bin); got != bin {
		t.Errorf("linux: ResolveBinPath = %q, want identity", got)
	}
}

// TestOCIPlatformForWasip1 pins the registry-side spelling: a wasip1/wasm
// artifact is published with OCI platform os=wasip1, architecture=wasm, the
// convention Docker+Wasm and the CNCF wasm-oci-artifact use. wasm is not
// renamed in either direction (only x86-64/aarch64 are).
func TestOCIPlatformForWasip1(t *testing.T) {
	if got := ociArch("wasm"); got != "wasm" {
		t.Errorf("ociArch(wasm) = %q, want wasm", got)
	}
	if got := pkgxArch("wasm"); got != "wasm" {
		t.Errorf("pkgxArch(wasm) = %q, want wasm", got)
	}
}
