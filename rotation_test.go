package artifact

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/go-attest/sign"
)

// ⛔⛔ THE TWO CONSTANTS A ROTATION TOUCHES ARE PINNED HERE, because getting
// either wrong is a fleet-wide outage that compiles.
//
// `SigningPublicKey` is believed, never re-derived: one wrong character and
// every artifact fails verification with a message that reads as tampering.
// And dropping the retired entry would refuse the whole published registry,
// which is the failure mode rotation exists to avoid.
//
// These are literals on purpose. A test that recomputed them from the same
// variables would assert that a equals a.
const (
	keyIDNow     = "df35c3a46931d3e6" // in service from 2026-11-06
	keyIDRetired = "3eae61fe7d7cb689" // signed everything before it
)

func TestTheRotationOf2026_11(t *testing.T) {
	id, _, err := sign.ParsePublicKey(SigningPublicKey)
	if err != nil {
		t.Fatalf("the compiled-in signing key does not parse: %v", err)
	}
	if got := hex.EncodeToString(id[:]); got != keyIDNow {
		t.Errorf("current key id = %s, want %s — SigningPublicKey changed without this test", got, keyIDNow)
	}

	// ⛔ THE RETIRED KEY IS STILL THERE AND STILL TRUSTED. Everything in the
	// registry up to 2026-11-06 is signed by it; a trust set without it
	// refuses the lot.
	var found bool
	for _, entry := range RetiredSigningPublicKeys {
		s, err := ParseSigner(entry)
		if err != nil {
			t.Errorf("retired entry %q does not parse: %v", entry, err)
			continue
		}
		if s.KeyID() == keyIDRetired {
			found = true
			if !strings.HasPrefix(s.Name, "go-zpkg-") {
				t.Errorf("the retired key is named %q; a name is what a verdict prints", s.Name)
			}
		}
	}
	if !found {
		t.Fatalf("the key that signed the published registry (%s) is not in RetiredSigningPublicKeys", keyIDRetired)
	}

	// Both must be in the default trust set, and the old one must not be
	// the current one.
	ts := DefaultTrustSet()
	if len(ts.Signers) != 2 {
		t.Fatalf("default trust set holds %d key(s): %v", len(ts.Signers), ts.Names())
	}
	if SigningPublicKey == RetiredSigningPublicKeys[0] {
		t.Error("the current key is also the retired one — the rotation changed nothing")
	}

	// ⛔ AND IT IS NOT REVOKED. Lost is not compromised: the private half
	// could not be found, and nothing suggests anybody else holds it. If
	// that ever changes this test should fail, loudly, rather than the
	// distinction being quietly erased.
	for _, r := range RevokedSigningKeys {
		if (Signer{Key: r.Key}).KeyID() == keyIDRetired {
			t.Errorf("the retired key is listed as REVOKED (%s) — if that is deliberate, "+
				"everything it signed must be rebuilt and this test updated to say so", r.Because)
		}
	}
}
