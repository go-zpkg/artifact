package artifact

import (
	"strings"
	"testing"

	"github.com/go-attest/sign"
)

// A catalogue is a list of names, and a list of names is what a person then
// TYPES. That is the whole reason this test exists.
//
// FetchCatalog was the one path that brought artifact bytes onto a machine
// without the fail-closed check — under a comment, at verifyPulled, saying
// that EVERY such path went through it. Someone able to serve a forged
// catalogue cannot make the install path accept an unsigned artifact; what
// they can do is decide what `<TAB>` offers, and a near-miss name at the
// prompt is the whole of a typosquat.
//
// Three arms, because two of them would pass for the wrong reason: a test
// that only shows the refusal also passes when FetchCatalog is broken
// outright, and one that only shows the signed fetch also passes when
// nothing is checked at all.
func TestACatalogueIsVerifiedLikeAnyOtherArtifact(t *testing.T) {
	kp, err := sign.Generate()
	if err != nil {
		t.Fatal(err)
	}
	oldKey := SigningPublicKey
	SigningPublicKey = kp.PublicKeyString()
	defer func() { SigningPublicKey = oldKey }()

	fr := newFakeRegistry(t, false)
	defer fr.close()
	c, err := NewOCIClient(fr.base("go-zpkg/artifacts"))
	if err != nil {
		t.Fatal(err)
	}
	osn, arch := HostSlug()

	// 1. Unsigned, verification on: refused.
	t.Setenv("ZPKG_VERIFY", "1")
	if err := PublishCatalog(c, sampleCatalog(), osn, arch); err != nil {
		t.Fatal(err)
	}
	if _, err := FetchCatalog(c, osn, arch); err == nil {
		t.Error("an unsigned catalogue was accepted — a mirror decides what <TAB> offers")
	} else if !strings.Contains(err.Error(), CatalogProjectName) {
		t.Errorf("the refusal does not name the catalogue: %v", err)
	}

	// 2. The same bytes with the factory's signature beside them: accepted,
	//    and it is really the catalogue that comes back.
	tgz, err := CatalogTarball(sampleCatalog())
	if err != nil {
		t.Fatal(err)
	}
	payload, err := sign.SimpleSigningPayload("pkg:pkgx/"+CatalogProjectName, digestOf(tgz))
	if err != nil {
		t.Fatal(err)
	}
	refs := []Referrer{{
		ArtifactType: ArtifactTypeSignature,
		MediaType:    MediaSimpleSigning,
		Blob:         payload,
		Annotations:  map[string]string{CosignSignatureAnnotation: kp.SignPayload(payload)},
	}}
	if _, err := c.PushWithReferrers(CatalogProjectName, CatalogVersion, osn, arch, tgz, ExtTarGz, refs); err != nil {
		t.Fatal(err)
	}
	got, err := FetchCatalog(c, osn, arch)
	if err != nil {
		t.Fatalf("a signed catalogue was refused: %v", err)
	}
	if len(got.Projects) != len(sampleCatalog().Projects) {
		t.Errorf("fetched %d projects, want %d", len(got.Projects), len(sampleCatalog().Projects))
	}

	// 3. And the opt-out still works, because the seed registry a sovereign
	//    build runs against signs nothing and must stay usable.
	t.Setenv("ZPKG_VERIFY", "0")
	if err := PublishCatalog(c, sampleCatalog(), osn, arch); err != nil {
		t.Fatal(err)
	}
	if _, err := FetchCatalog(c, osn, arch); err != nil {
		t.Errorf("ZPKG_VERIFY=0 still refused: %v", err)
	}
}
