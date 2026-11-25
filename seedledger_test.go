package artifact

import (
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/go-attest/sign"
)

// noteSeed is a second, independent account of the seed: it refuses what it
// cannot account for, whether the registry will not answer or the signature
// does not commit to the bytes that were fetched.
func TestNoteSeedRefusesWhatItCannotAccountFor(t *testing.T) {
	resetSeedState(t)
	reg := newFakeRegistry(t, false)
	seedBase := reg.base("go-pkgx/packages")
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
	pushSignedArtifact(t, c, "n.test", kp, makeGzTarball("n"), true)
	seedMu.Lock()
	seedSource = seedBase
	seedMu.Unlock()

	v := ParseVer("1.0.0")
	if err := noteSeed(c, seedBase, "absent.test", v, "1.0.0", "linux", "x86-64", "sha256:00"); err == nil {
		t.Error("an artifact the registry does not hold was recorded")
	}
	if err := noteSeed(c, seedBase, "n.test", v, "1.0.0", "linux", "x86-64", "sha256:"+strings.Repeat("0", 64)); err == nil {
		t.Error("a digest the signature does not commit to was recorded")
	}
	if len(SeedLedger()) != 0 {
		t.Errorf("ledger = %+v", SeedLedger())
	}
}

// The ledger check is not the verification's shadow: when the registry stops
// answering the signature question AFTER the install check passed, the seed is
// not installed, on the cache path and the direct path alike.
func TestASeedIsNotInstalledWhenTheLedgerCannotBeWritten(t *testing.T) {
	for _, viaCache := range []bool{false, true} {
		name := "direct"
		if viaCache {
			name = "cache"
		}
		t.Run(name, func(t *testing.T) {
			resetSeedState(t)
			reg := newFakeRegistry(t, false)
			seedBase := reg.base("go-pkgx/packages")
			pinSeed(seedBase)
			kp, err := sign.Generate()
			if err != nil {
				t.Fatal(err)
			}
			oldKey, oldCache := SigningPublicKey, CacheBase
			SigningPublicKey = kp.PublicKeyString()
			t.Cleanup(func() { SigningPublicKey, CacheBase = oldKey, oldCache })
			c, err := NewOCIClient(seedBase)
			if err != nil {
				t.Fatal(err)
			}
			body := makeGzTarball("l")
			pushSignedArtifact(t, c, "l.test", kp, body, true)
			if viaCache {
				cache := newFakeRegistry(t, false)
				cc, err := NewOCIClient(cache.base("go-pkgx/packages"))
				if err != nil {
					t.Fatal(err)
				}
				pushSignedArtifact(t, cc, "l.test", kp, body, true)
				CacheBase = cache.base("go-pkgx/packages")
				resetOCICache()
			}
			r := Resolved{Project: "l.test", Version: ParseVer("1.0.0")}

			var mu sync.Mutex
			var n, failFrom int
			reg.hook = func(rq *http.Request) (int, bool) {
				mu.Lock()
				defer mu.Unlock()
				n++
				return 500, failFrom > 0 && n >= failFrom
			}
			fetch := func() error {
				return WithSeedSource(seedBase, func() error {
					f, _, _, err := fetchArtifact(r, "linux", "x86-64")
					if err == nil {
						f.Close()
					}
					return err
				})
			}
			if err := fetch(); err != nil {
				t.Fatalf("good install: %v", err)
			}
			mu.Lock()
			perInstall := n
			n = 0
			// Let the install's own check through and fail from the second
			// account of the signers on: the last third of the requests.
			failFrom = perInstall*2/3 + 1
			mu.Unlock()
			if err := fetch(); err == nil {
				t.Fatal("a seed was installed although its signers could not be recorded")
			}
		})
	}
}
