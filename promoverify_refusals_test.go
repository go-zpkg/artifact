package artifact

import (
	"strings"
	"testing"

	"github.com/go-attest/sign"
)

func TestVerifiedPayloadsRefusalsNameTheirCause(t *testing.T) {
	fr := newFakeRegistry(t, false)
	defer fr.close()
	c, _ := NewOCIClient(fr.base("go-zpkg/artifacts"))
	kp, err := sign.Generate()
	if err != nil {
		t.Fatal(err)
	}
	old := SigningPublicKey
	SigningPublicKey = kp.PublicKeyString()
	defer func() { SigningPublicKey = old }()
	tarball := makeGzTarball("refusals-body")
	digest := digestOf(tarball)
	pushClaiming(t, c, "vr.pkg", "1.0.0", "pkg:generic/vr.pkg@1.0.0", kp, tarball)

	if _, err := c.VerifiedPayloads("vr.pkg", "1.0.0", "linux", "x86-64", digest); err != nil {
		t.Fatalf("control: %v", err)
	}
	t.Run("a malformed trust threshold", func(t *testing.T) {
		t.Setenv(TrustThresholdEnv, "zero")
		_, err := c.VerifiedPayloads("vr.pkg", "1.0.0", "linux", "x86-64", digest)
		if err == nil || !strings.Contains(err.Error(), TrustThresholdEnv) {
			t.Errorf("err = %v; want one naming %s", err, TrustThresholdEnv)
		}
	})
	t.Run("an invalid project name", func(t *testing.T) {
		_, err := c.VerifiedPayloads("../vr.pkg", "1.0.0", "linux", "x86-64", digest)
		if err == nil || strings.Contains(err.Error(), "signature") {
			t.Errorf("err = %v; want a project-name refusal", err)
		}
	})
	t.Run("a flood of signature referrers", func(t *testing.T) {
		stranger, err := sign.Generate()
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < MaxSignatures; i++ {
			body := []byte(strings.Repeat("x", i+1))
			if err := c.AttachReferrer("vr.pkg", "1.0.0", "linux", "x86-64", Referrer{
				ArtifactType: ArtifactTypeSignature, MediaType: MediaSimpleSigning, Blob: body,
				Annotations: map[string]string{CosignSignatureAnnotation: stranger.SignPayload(body)},
			}); err != nil {
				t.Fatal(err)
			}
		}
		_, err = c.VerifiedPayloads("vr.pkg", "1.0.0", "linux", "x86-64", digest)
		if err == nil || !strings.Contains(err.Error(), "refusing") {
			t.Errorf("err = %v; want the flood refused by name", err)
		}
	})
	t.Run("a tag nothing published", func(t *testing.T) {
		_, err := c.VerifiedPayloads("vr.pkg", "9.9.9", "linux", "x86-64", digest)
		if err == nil || strings.Contains(err.Error(), "signature") {
			t.Errorf("err = %v; want a resolution refusal, not a signature one", err)
		}
	})
}
