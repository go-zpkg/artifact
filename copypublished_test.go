package bottle

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/go-attest/sign"
)

// ⛔⛔ THE ASSERTION IS THAT THE COPY STILL VERIFIES, NOT THAT BYTES ARRIVED.
//
// "The bottle is in the new namespace" is what the broken release of
// v0.64.0–v0.68.0 would also have reported, had anything reported anything: a
// manifest can copy perfectly and leave its signature behind, because a cosign
// signature is a REFERRER and not a child of the manifest. A copy checked by
// pulling the tarball back would pass on a bottle that `zpkgs install` then
// refuses, and refusing at install time is the expensive place to find out.
//
// So the destination is checked with VerifyBottle — the same call the install
// path makes — and only after that is the digest compared.
func TestCopyPublishedCarriesTheSignature(t *testing.T) {
	fr := newFakeRegistry(t, false)
	defer fr.close()

	// One host, two namespaces: exactly the real case, where ghcr.io serves
	// both go-pkgx and go-zpkg and only the namespace differs.
	src, err := NewOCIClient(fr.base("go-pkgx/packages"))
	if err != nil {
		t.Fatal(err)
	}
	dst, err := NewOCIClient(fr.base("go-zpkg/packages"))
	if err != nil {
		t.Fatal(err)
	}

	kp, err := sign.Generate()
	if err != nil {
		t.Fatal(err)
	}
	old := SigningPublicKey
	SigningPublicKey = kp.PublicKeyString()
	defer func() { SigningPublicKey = old }()

	tarball := makeGzTarball("bottle-body")
	pushSignedBottle(t, src, "zlib.net", kp, tarball, true)

	// The destination holds nothing yet. Asserted, because a test that cannot
	// tell an empty destination from a full one is the defect it is here for.
	if err := dst.VerifyBottle("zlib.net", "1.0.0", "linux", "x86-64", tarball); err == nil {
		t.Fatal("the destination namespace verified a bottle before anything was copied")
	}

	desc, err := CopyPublished(context.Background(), src, dst, "zlib.net", "1.0.0")
	if err != nil {
		t.Fatalf("CopyPublished: %v", err)
	}

	// The install path's own check, against the destination.
	if err := dst.VerifyBottle("zlib.net", "1.0.0", "linux", "x86-64", tarball); err != nil {
		t.Fatalf("copied bottle does not verify in the new namespace: %v", err)
	}

	// And the digest is the SAME string on both sides — which is why the
	// signature still commits to it (payloadCommitsTo reads
	// critical.image.docker-manifest-digest and nothing about the namespace).
	from, err := src.BottleDigest("zlib.net", "1.0.0", "linux", "x86-64")
	if err != nil {
		t.Fatal(err)
	}
	to, err := dst.BottleDigest("zlib.net", "1.0.0", "linux", "x86-64")
	if err != nil {
		t.Fatal(err)
	}
	if from != to {
		t.Errorf("digest changed across the copy: %s then %s", from, to)
	}
	if desc.Digest == "" {
		t.Error("CopyPublished returned a descriptor with no digest")
	}
}

// A copy into the namespace it came from is refused rather than quietly
// succeeding: it is the shape a mistyped flag takes, and "copied, 0 bytes
// moved" reads as success.
func TestCopyPublishedRefusesTheSameNamespace(t *testing.T) {
	fr := newFakeRegistry(t, false)
	defer fr.close()

	a, err := NewOCIClient(fr.base("go-zpkg/packages"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewOCIClient(fr.base("go-zpkg/packages"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = CopyPublished(context.Background(), a, b, "zlib.net", "1.0.0")
	if !errors.Is(err, ErrSameNamespace) {
		t.Fatalf("same namespace: want ErrSameNamespace, got %v", err)
	}
}

// The arguments that cannot produce a copy are refused before any request is
// made, so a bad call costs nothing and names itself.
func TestCopyPublishedRejectsBadArguments(t *testing.T) {
	fr := newFakeRegistry(t, false)
	defer fr.close()
	src, err := NewOCIClient(fr.base("go-pkgx/packages"))
	if err != nil {
		t.Fatal(err)
	}
	dst, err := NewOCIClient(fr.base("go-zpkg/packages"))
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name     string
		src, dst *OCIClient
		project  string
		tag      string
		want     string
	}{
		{"nil source", nil, dst, "zlib.net", "1.0.0", "nil OCI client"},
		{"nil destination", src, nil, "zlib.net", "1.0.0", "nil OCI client"},
		{"no tag", src, dst, "zlib.net", "", "no tag to copy"},
		// ValidateProjectName, reached through repository(): a traversal is
		// nobody's project in either namespace.
		{"traversal", src, dst, "../etc", "1.0.0", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CopyPublished(context.Background(), tc.src, tc.dst, tc.project, tc.tag)
			if err == nil {
				t.Fatal("accepted")
			}
			if tc.want != "" && !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// A tag that is not published is a 404 at copy time, which is the cheap place
// for it. The point of asserting it is that the error names the pair, so a
// bulk run says WHICH package it could not move.
func TestCopyPublishedAbsentTag(t *testing.T) {
	fr := newFakeRegistry(t, false)
	defer fr.close()
	src, err := NewOCIClient(fr.base("go-pkgx/packages"))
	if err != nil {
		t.Fatal(err)
	}
	dst, err := NewOCIClient(fr.base("go-zpkg/packages"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = CopyPublished(context.Background(), src, dst, "absent.test", "9.9.9")
	if err == nil {
		t.Fatal("copied a tag that was never published")
	}
	for _, want := range []string{"absent.test", "9.9.9", "go-pkgx/packages", "go-zpkg/packages"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %q", err, want)
		}
	}
}
