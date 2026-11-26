//go:build !js && !wasip1

// Pipes do not exist on the wasm targets.

package artifact

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A descriptor handed over is written with no path lookup: the entry is on the
// pipe, and a ledger file that was also named is not touched.
func TestASeedIsWrittenToTheLedgerDescriptor(t *testing.T) {
	seedBase, r := seedFixture(t)
	file := filepath.Join(t.TempDir(), "ledger.jsonl")
	SetSeedLedgerFile(file)
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pr.Close()
	SetSeedLedgerFD(pw)
	t.Cleanup(func() { SetSeedLedgerFD(nil) })
	if err := fetchSeed(seedBase, r); err != nil {
		t.Fatal(err)
	}
	pw.Close()
	b, _ := io.ReadAll(pr)
	if n := strings.Count(string(b), "\n"); n != 1 || !strings.Contains(string(b), `"project":"f.test"`) {
		t.Fatalf("the pipe holds %q", b)
	}
	if _, err := os.Stat(file); err == nil {
		t.Fatal("the descriptor was named and the ledger file was written anyway")
	}
}

// The descriptor alone is a ledger: WithSeedSource needs no file.
func TestADescriptorAloneIsALedger(t *testing.T) {
	seedBase, r := seedFixture(t)
	SetSeedLedgerFile("")
	pr, pw, _ := os.Pipe()
	defer pr.Close()
	defer pw.Close()
	SetSeedLedgerFD(pw)
	t.Cleanup(func() { SetSeedLedgerFD(nil) })
	if err := fetchSeed(seedBase, r); err != nil {
		t.Fatal(err)
	}
	SetSeedLedgerFD(nil)
	if err := fetchSeed(seedBase, r); err == nil {
		t.Fatal("a seed ran with no ledger at all")
	}
}

// A file named after the descriptor replaces it: one ledger at a time.
func TestNamingAFileReplacesTheDescriptor(t *testing.T) {
	seedBase, r := seedFixture(t)
	pr, pw, _ := os.Pipe()
	defer pr.Close()
	defer pw.Close()
	SetSeedLedgerFD(pw)
	t.Cleanup(func() { SetSeedLedgerFD(nil) })
	file := filepath.Join(t.TempDir(), "ledger.jsonl")
	SetSeedLedgerFile(file)
	if err := fetchSeed(seedBase, r); err != nil {
		t.Fatal(err)
	}
	if es, err := ReadSeedLedger(file); err != nil || len(es) != 1 {
		t.Fatalf("file ledger = %v, %v", es, err)
	}
}

// A seed that cannot be written to the descriptor is not installed.
func TestASeedIsNotInstalledWhenTheLedgerDescriptorCannotBeWritten(t *testing.T) {
	seedBase, r := seedFixture(t)
	pr, pw, _ := os.Pipe()
	pr.Close() // a pipe with no reader: the write fails
	pw.Close()
	SetSeedLedgerFD(pw)
	t.Cleanup(func() { SetSeedLedgerFD(nil) })
	if err := fetchSeed(seedBase, r); err == nil {
		t.Fatal("a seed was installed although the ledger descriptor could not be written")
	}
}
