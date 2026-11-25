package artifact

import (
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-attest/sign"
)

func resetSeedState(t *testing.T) {
	t.Helper()
	oldB, oldX, oldP := DistBase, DistExtra, promotionSource
	seedMu.Lock()
	oldS, oldL := seedSource, seedLedger
	seedSource, seedLedger = "", nil
	seedMu.Unlock()
	oldPin := seedRegistryPin
	SetSeedLedgerFile(filepath.Join(t.TempDir(), "ledger.jsonl"))
	t.Cleanup(func() {
		DistBase, DistExtra, promotionSource = oldB, oldX, oldP
		seedMu.Lock()
		seedSource, seedLedger = oldS, oldL
		seedMu.Unlock()
		seedRegistryPin = oldPin
		SetSeedLedgerFile("")
		resetOCICache()
	})
	promotionSource = ""
}

// pinSeed points the seed pin at a registry on 127.0.0.1, which is what a test
// can serve; the pin itself is a constant outside the package.
func pinSeed(base string) { seedRegistryPin = strings.TrimRight(base, "/") }

// Half one: the seed IS accepted, as the build environment, inside the call.
func TestASeedSourceInGoPkgxIsAcceptedAsABuildEnvironment(t *testing.T) {
	resetSeedState(t)
	DistBase, DistExtra = "oci://ghcr.io/go-zpkg/packages", nil
	err := WithSeedSource(goPkgxReg+"/", func() error {
		if DistBase != goPkgxReg || len(DistExtra) != 0 {
			t.Errorf("DistBase=%q DistExtra=%q", DistBase, DistExtra)
		}
		if _, err := distSources(); err != nil {
			t.Errorf("the seed source is refused as a build environment: %v", err)
		}
		if _, err := ociClientForDist(); errors.Is(err, ErrClosedDistRegistry) {
			t.Errorf("the client for the seed source is refused: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// ...and the previous configuration is back, with the exception gone.
	if DistBase != "oci://ghcr.io/go-zpkg/packages" {
		t.Fatalf("DistBase not restored: %q", DistBase)
	}
	DistBase = goPkgxReg
	if _, err := distSources(); !errors.Is(err, ErrClosedDistRegistry) {
		t.Fatalf("go-pkgx accepted after the seed call returned: %v", err)
	}
}

// Half two: go-pkgx stays refused as a DEPENDENCY source, whatever the seed says.
func TestGoPkgxStaysRefusedAsADependencySourceDuringASeed(t *testing.T) {
	for name, set := range map[string]func(){
		"ZPKG_DIST inside the seed call": func() {
			applyEnv(func(k string) string {
				if k == "ZPKG_DIST" {
					return goPkgxReg
				}
				return ""
			})
		},
		"go-pkgx as a second source": func() { DistExtra = []string{goPkgxReg} },
		"a different go-pkgx repository": func() {
			DistBase = "oci://ghcr.io/go-pkgx/other"
		},
		"go-pkgx behind another base": func() {
			DistBase, DistExtra = "oci://ghcr.io/go-zpkg/packages", []string{goPkgxReg}
		},
	} {
		t.Run(name, func(t *testing.T) {
			resetSeedState(t)
			_ = WithSeedSource(goPkgxReg, func() error {
				set()
				if _, err := distSources(); !errors.Is(err, ErrClosedDistRegistry) {
					t.Errorf("distSources: %v, want the closed-registry refusal", err)
				}
				return nil
			})
		})
	}
}

// The rule for a dependency source never learns the exception.
func TestCheckDistSourceIgnoresTheSeedSource(t *testing.T) {
	resetSeedState(t)
	_ = WithSeedSource(goPkgxReg, func() error {
		if err := CheckDistSource(goPkgxReg); !errors.Is(err, ErrClosedDistRegistry) {
			t.Errorf("CheckDistSource accepted go-pkgx inside a seed call: %v", err)
		}
		return nil
	})
}

// A seed is only ever verified: verification off, or a transport with no
// signatures, is a refusal and fn never runs.
func TestASeedIsRefusedUnverified(t *testing.T) {
	t.Run("ZPKG_VERIFY=0", func(t *testing.T) {
		resetSeedState(t)
		t.Setenv("ZPKG_VERIFY", "0")
		ran := false
		err := WithSeedSource(goPkgxReg, func() error { ran = true; return nil })
		if !errors.Is(err, ErrSeedUnverified) || ran {
			t.Fatalf("err=%v ran=%v", err, ran)
		}
	})
	t.Run("HTTP dist", func(t *testing.T) {
		resetSeedState(t)
		ran := false
		err := WithSeedSource("https://dist.pkgx.dev", func() error { ran = true; return nil })
		if !errors.Is(err, ErrSeedUnverified) || ran {
			t.Fatalf("err=%v ran=%v", err, ran)
		}
	})
}

// The seed is recorded, with the digest and the signer, and not hidden: an
// artifact fetched from the seed source lands in the ledger, one fetched from
// anywhere else does not.
func TestASeedArtifactIsRecordedInTheLedger(t *testing.T) {
	resetSeedState(t)
	reg := newFakeRegistry(t, false)
	seedBase := reg.base("go-pkgx/packages")
	pinSeed(seedBase)
	kp, err := sign.Generate()
	if err != nil {
		t.Fatal(err)
	}
	oldKey := SigningPublicKey
	SigningPublicKey = kp.PublicKeyString()
	t.Cleanup(func() { SigningPublicKey = oldKey })

	c, err := NewOCIClient(seedBase)
	if err != nil {
		t.Fatal(err)
	}
	body := makeGzTarball("seed payload")
	pushSignedArtifact(t, c, "s.test", kp, body, true)

	r := Resolved{Project: "s.test", Version: ParseVer("1.0.0")}
	err = WithSeedSource(seedBase, func() error {
		f, _, digest, err := fetchArtifact(r, "linux", "x86-64")
		if err != nil {
			return err
		}
		defer f.Close()
		if _, err := io.ReadAll(f); err != nil {
			return err
		}
		l := SeedLedger()
		if len(l) != 1 {
			t.Fatalf("ledger = %+v", l)
		}
		e := l[0]
		if e.Project != "s.test" || e.Version != "1.0.0" || e.Digest != digest || e.Source != seedBase || len(e.Signers) == 0 {
			t.Errorf("entry = %+v (digest %s)", e, digest)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// Outside a seed call the same registry is go-pkgx again, and nothing is recorded.
	DistBase, DistExtra = seedBase, nil
	if _, err := distSources(); !errors.Is(err, ErrClosedDistRegistry) {
		t.Fatalf("outside the seed call: %v", err)
	}
}

// An artifact whose signature does not verify is not installed as a seed.
func TestAnUnsignedSeedIsNotInstalled(t *testing.T) {
	resetSeedState(t)
	reg := newFakeRegistry(t, false)
	seedBase := reg.base("go-pkgx/packages")
	pinSeed(seedBase)
	c, err := NewOCIClient(seedBase)
	if err != nil {
		t.Fatal(err)
	}
	kp, err := sign.Generate()
	if err != nil {
		t.Fatal(err)
	}
	// Signed by a key the trust set does not hold.
	pushSignedArtifact(t, c, "u.test", kp, makeGzTarball("x"), true)
	r := Resolved{Project: "u.test", Version: ParseVer("1.0.0")}
	err = WithSeedSource(seedBase, func() error {
		f, _, _, err := fetchArtifact(r, "linux", "x86-64")
		if err == nil {
			f.Close()
		}
		return err
	})
	if err == nil {
		t.Fatal("an artifact signed by an untrusted key was accepted as a seed")
	}
	if len(SeedLedger()) != 0 {
		t.Fatalf("ledger = %+v", SeedLedger())
	}
}
