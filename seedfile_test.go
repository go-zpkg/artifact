package artifact

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-attest/sign"
)

func seedFixture(t *testing.T) (seedBase string, r Resolved) {
	t.Helper()
	resetSeedState(t)
	reg := newFakeRegistry(t, false)
	seedBase = reg.base("go-pkgx/packages")
	kp, err := sign.Generate()
	if err != nil {
		t.Fatal(err)
	}
	oldKey := SigningPublicKey
	SigningPublicKey = kp.PublicKeyString()
	t.Cleanup(func() { SigningPublicKey = oldKey; SetSeedLedgerFile("") })
	c, err := NewOCIClient(seedBase)
	if err != nil {
		t.Fatal(err)
	}
	pushSignedArtifact(t, c, "f.test", kp, makeGzTarball("f"), true)
	return seedBase, Resolved{Project: "f.test", Version: ParseVer("1.0.0")}
}

func fetchSeed(seedBase string, r Resolved) error {
	return WithSeedSource(seedBase, func() error {
		f, _, _, err := fetchArtifact(r, "linux", "x86-64")
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.ReadAll(f)
		return err
	})
}

// The ledger FILE is what survives a process that replaces itself with the
// build command: every verified seed is on it before the install returns.
func TestASeedIsAppendedToTheLedgerFile(t *testing.T) {
	seedBase, r := seedFixture(t)
	path := filepath.Join(t.TempDir(), "ledger.jsonl")
	SetSeedLedgerFile(path)
	if err := fetchSeed(seedBase, r); err != nil {
		t.Fatal(err)
	}
	if err := fetchSeed(seedBase, r); err != nil { // a second process asking again
		t.Fatal(err)
	}
	es, err := ReadSeedLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(es) != 1 || es[0].Project != "f.test" || es[0].Version != "1.0.0" || es[0].Source != seedBase ||
		!strings.HasPrefix(es[0].Digest, "sha256:") || len(es[0].Signers) == 0 {
		t.Fatalf("entries = %+v", es)
	}
	raw, _ := os.ReadFile(path)
	if n := strings.Count(string(raw), "\n"); n != 2 {
		t.Fatalf("the file holds %d lines, want one per install (2)", n)
	}
}

// A seed that cannot be written down is not installed.
func TestASeedIsNotInstalledWhenTheLedgerFileCannotBeWritten(t *testing.T) {
	seedBase, r := seedFixture(t)
	SetSeedLedgerFile(t.TempDir()) // a directory: opening it for append fails
	if err := fetchSeed(seedBase, r); err == nil {
		t.Fatal("a seed was installed although the ledger file could not be written")
	}
}

// The canonical form does not depend on the order of installation, repeats, or
// the order of signers; a line that is not an entry is an error.
func TestTheSeedLedgerHasOneCanonicalForm(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	a := `{"project":"a.test","version":"1","digest":"sha256:aa","signers":["y","x"],"source":"s"}`
	b := `{"project":"b.test","version":"2","digest":"sha256:bb","signers":["x"],"source":"s"}`
	a2 := `{"project":"a.test","version":"1","digest":"sha256:aa","signers":["x","y"],"source":"s"}`
	e1, err := ReadSeedLedger(write("1", a+"\n"+b+"\n"))
	if err != nil {
		t.Fatal(err)
	}
	e2, err := ReadSeedLedger(write("2", b+"\n\n"+a2+"\n"+a+"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if SeedLedgerDigest(e1) != SeedLedgerDigest(e2) || len(e1) != 2 || len(e2) != 2 {
		t.Fatalf("digests differ: %d %d entries", len(e1), len(e2))
	}
	// The order is project, then version, then digest.
	mix := strings.Join([]string{
		`{"project":"b.test","version":"1","digest":"sha256:b1","signers":[],"source":"s"}`,
		`{"project":"a.test","version":"2","digest":"sha256:a0","signers":[],"source":"s"}`,
		`{"project":"a.test","version":"1","digest":"sha256:a1y","signers":[],"source":"s"}`,
		`{"project":"a.test","version":"1","digest":"sha256:a1x","signers":[],"source":"s"}`,
	}, "\n")
	em, err := ReadSeedLedger(write("mix", mix))
	if err != nil {
		t.Fatal(err)
	}
	var order []string
	for _, e := range em {
		order = append(order, e.Project+" "+e.Version+" "+e.Digest)
	}
	if got := strings.Join(order, ","); got != "a.test 1 sha256:a1x,a.test 1 sha256:a1y,a.test 2 sha256:a0,b.test 1 sha256:b1" {
		t.Fatalf("order = %s", got)
	}
	e3, _ := ReadSeedLedger(write("3", a+"\n"))
	if SeedLedgerDigest(e3) == SeedLedgerDigest(e1) {
		t.Fatal("a smaller seed has the same digest")
	}
	for name, body := range map[string]string{
		"not json":      "nope\n",
		"unknown field": `{"project":"a","version":"1","digest":"d","extra":1}` + "\n",
		"no digest":     `{"project":"a","version":"1"}` + "\n",
		"truncated":     a[:20] + "\n",
	} {
		if _, err := ReadSeedLedger(write("bad", body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := ReadSeedLedger(filepath.Join(dir, "absent")); err == nil {
		t.Error("an absent ledger was read as an empty one")
	}
}
