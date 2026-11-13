package artifact

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/go-attest/sign"
)

func digestOf(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

func TestVerifySignature(t *testing.T) {
	kp, err := sign.Generate()
	if err != nil {
		t.Fatal(err)
	}
	tarball := []byte("artifact tarball bytes")
	payload, err := sign.SimpleSigningPayload("pkg:pkgx/x@1", digestOf(tarball))
	if err != nil {
		t.Fatal(err)
	}
	sig := kp.SignPayload(payload)
	pub := kp.PublicKeyString()

	// happy path
	if err := VerifySignature(tarball, payload, sig, pub); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
	// bad public key
	if err := VerifySignature(tarball, payload, sig, "!!!"); err == nil {
		t.Error("bad pubkey accepted")
	}
	// tampered signature
	if err := VerifySignature(tarball, payload, "AAAA", pub); err == nil {
		t.Error("bad signature accepted")
	}
	// signed but non-JSON payload → sig verifies, unmarshal fails
	notJSON := []byte("not json")
	if err := VerifySignature(tarball, notJSON, kp.SignPayload(notJSON), pub); err == nil {
		t.Error("non-JSON payload accepted")
	}
	// digest mismatch: payload commits to a different tarball
	other, _ := sign.SimpleSigningPayload("pkg:pkgx/x@1", digestOf([]byte("different")))
	if err := VerifySignature(tarball, other, kp.SignPayload(other), pub); err == nil {
		t.Error("digest mismatch accepted")
	}
	// default (pinned) key path: empty pubkey uses SigningPublicKey, which our
	// test signature is not from → fail-closed
	if err := VerifySignature(tarball, payload, sig, ""); err == nil {
		t.Error("signature not from the pinned key was accepted")
	}
}
