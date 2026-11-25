package artifact

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-attest/sign"
)

// The seed has ONE source. Anything else, whatever it looks like, is refused
// before fn runs: a seed chosen by the caller is chosen by whoever reaches it.
func TestASeedHasOneSource(t *testing.T) {
	for _, from := range []string{
		"oci://attacker.example/anything",
		"oci://ghcr.io/go-pkgx/some-other-repo",
		"oci://ghcr.io/GO-PKGX/packages",
		"oci://ghcr.io/go-pkgx/packages/sub",
		"oci://ghcr.io/go-zpkg/packages",
	} {
		resetSeedState(t)
		ran := false
		err := WithSeedSource(from, func() error { ran = true; return nil })
		if !errors.Is(err, ErrSeedSource) || ran {
			t.Errorf("%s: err=%v ran=%v", from, err, ran)
		}
	}
	resetSeedState(t)
	ran := false
	if err := WithSeedSource(SeedRegistry+"/", func() error { ran = true; return nil }); err != nil || !ran {
		t.Errorf("the pinned seed registry: err=%v ran=%v", err, ran)
	}
}

// A seed that has nowhere to be recorded is not installed.
func TestASeedWithoutALedgerFileIsRefused(t *testing.T) {
	resetSeedState(t)
	SetSeedLedgerFile("")
	ran := false
	err := WithSeedSource(SeedRegistry, func() error { ran = true; return nil })
	if !errors.Is(err, ErrSeedSource) || ran {
		t.Fatalf("err=%v ran=%v", err, ran)
	}
}

// Who may vouch for a seed is compiled in: a key that the environment adds, or
// that replaces the set, does not make a seed installable.
func TestASeedIsVerifiedAgainstTheCompiledInKeysOnly(t *testing.T) {
	for _, env := range []string{ExtraTrustedKeysEnv, TrustedKeysEnv} {
		t.Run(env, func(t *testing.T) {
			seedBase, _ := seedFixture(t) // SigningPublicKey is a throwaway key
			other, err := sign.Generate()
			if err != nil {
				t.Fatal(err)
			}
			c, err := NewOCIClient(seedBase)
			if err != nil {
				t.Fatal(err)
			}
			pushSignedArtifact(t, c, "x.test", other, makeGzTarball("x"), true)
			t.Setenv(env, "attacker:"+other.PublicKeyString())
			err = fetchSeed(seedBase, Resolved{Project: "x.test", Version: ParseVer("1.0.0")})
			if err == nil {
				t.Fatal("a seed signed by a key from the environment was installed")
			}
			if len(SeedLedger()) != 0 {
				t.Fatalf("ledger = %+v", SeedLedger())
			}
		})
	}
}

// The ledger names the KEYS that vouched, not only the labels the local trust
// set gives them.
func TestTheSeedLedgerNamesKeyIDs(t *testing.T) {
	seedBase, r := seedFixture(t)
	if err := fetchSeed(seedBase, r); err != nil {
		t.Fatal(err)
	}
	want := (Signer{Key: SigningPublicKey}).KeyID()
	l := SeedLedger()
	if len(l) != 1 || len(l[0].Keys) != 1 || l[0].Keys[0] != want {
		t.Fatalf("ledger = %+v, want key id %s", l, want)
	}
}

// A ledger is bounded before it is read, not after.
func TestASeedLedgerFileIsBoundedBeforeItIsRead(t *testing.T) {
	p := filepath.Join(t.TempDir(), "big.jsonl")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(MaxSeedLedgerBytes + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := ReadSeedLedger(p); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("err = %v", err)
	}
	if err := os.WriteFile(p, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if es, err := ReadSeedLedger(p); err != nil || len(es) != 0 {
		t.Fatalf("an empty ledger: %v %v", es, err)
	}
	// Exactly the cap is accepted: the limit is on what is larger.
	if err := os.WriteFile(p, []byte(strings.Repeat("\n", MaxSeedLedgerBytes)), 0o644); err != nil {
		t.Fatal(err)
	}
	if es, err := ReadSeedLedger(p); err != nil || len(es) != 0 {
		t.Fatalf("a ledger of exactly the cap: %v %v", es, err)
	}
}

// A ledger that cannot be opened or read is an error, never an empty ledger.
func TestAnUnreadableSeedLedgerIsAnError(t *testing.T) {
	dir := t.TempDir()
	if _, err := ReadSeedLedger(filepath.Join(dir, "absent")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a missing ledger: %v, want the open error", err)
	}
	if _, err := ReadSeedLedger(dir); err == nil {
		t.Error("a directory read as a ledger")
	}
}

// A seed with no ledger file fails to record, it does not skip recording.
func TestANoteWithoutALedgerFileFails(t *testing.T) {
	resetSeedState(t)
	SetSeedLedgerFile("")
	seedMu.Lock()
	seedSource = SeedRegistry
	seedMu.Unlock()
	t.Cleanup(func() { seedMu.Lock(); seedSource = ""; seedMu.Unlock() })
	if err := appendSeedEntry("", SeedEntry{Project: "p", Version: "1", Digest: "d"}); err == nil {
		t.Error("an entry was recorded nowhere without an error")
	}
}
