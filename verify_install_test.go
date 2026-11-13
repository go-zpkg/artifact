package artifact

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-attest/sign"
)

// pushSignedArtifact pushes an artifact whose signature referrer is signed by kp, and
// points the pinned key at kp for the duration of the test.
func pushSignedArtifact(t *testing.T, c *OCIClient, project string, kp *sign.Keypair, tarball []byte, withSig bool) {
	t.Helper()
	refs := []Referrer{
		{ArtifactType: "application/vnd.cyclonedx+json", MediaType: "application/vnd.cyclonedx+json", Blob: []byte(`{}`)},
	}
	if withSig {
		payload, err := sign.SimpleSigningPayload("pkg:pkgx/"+project, digestOf(tarball))
		if err != nil {
			t.Fatal(err)
		}
		refs = append(refs, Referrer{
			ArtifactType: ArtifactTypeSignature,
			MediaType:    MediaSimpleSigning,
			Blob:         payload,
			Annotations:  map[string]string{CosignSignatureAnnotation: kp.SignPayload(payload)},
		})
	}
	if _, err := c.PushWithReferrers(project, "1.0.0", "linux", "x86-64", tarball, ".tar.gz", refs); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyRequired(t *testing.T) {
	// Empty config so only the injected env drives the decision.
	setConfigPath(t, filepath.Join(t.TempDir(), "absent.hcl2"))
	set := func(v string, present bool) {
		lookupEnv = func(k string) (string, bool) {
			if k == "ZPKG_VERIFY" {
				return v, present
			}
			return "", false
		}
	}
	// On by default: the truthy words and any unrecognised value all verify.
	for _, v := range []string{"1", "true", "TRUE", "yes", "on", "maybe"} {
		set(v, true)
		if !VerifyRequired() {
			t.Errorf("ZPKG_VERIFY=%q should require verify", v)
		}
	}
	// Unset (absent) also verifies.
	set("", false)
	if !VerifyRequired() {
		t.Error("unset ZPKG_VERIFY should require verify")
	}
	// Only an explicit opt-out disables it.
	for _, v := range []string{"0", "false", "FALSE", "off", "no"} {
		set(v, true)
		if VerifyRequired() {
			t.Errorf("ZPKG_VERIFY=%q should not require verify", v)
		}
	}
}

func TestVerifyRequiredFromConfig(t *testing.T) {
	// With no env var, the config file value disables verification.
	writeConfig(t, `ZPKG_VERIFY = false`)
	setLookup(nil)
	if VerifyRequired() {
		t.Error("config ZPKG_VERIFY=false should disable verification")
	}
}

func TestVerifyArtifact(t *testing.T) {
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

	tarball := makeGzTarball("artifact-body")
	pushSignedArtifact(t, c, "signed.ok", kp, tarball, true)
	if err := c.VerifyArtifact("signed.ok", "1.0.0", "linux", "x86-64", tarball); err != nil {
		t.Fatalf("valid signed artifact rejected: %v", err)
	}
	// tampered tarball → payload digest mismatch
	if err := c.VerifyArtifact("signed.ok", "1.0.0", "linux", "x86-64", makeGzTarball("tampered")); err == nil {
		t.Error("tampered tarball accepted")
	}
	// unsigned artifact → fail closed
	pushSignedArtifact(t, c, "unsigned.pkg", kp, tarball, false)
	if err := c.VerifyArtifact("unsigned.pkg", "1.0.0", "linux", "x86-64", tarball); err == nil ||
		!strings.Contains(err.Error(), "unsigned") {
		t.Errorf("unsigned artifact: expected fail-closed, got %v", err)
	}
	// missing version → resolve error
	if err := c.VerifyArtifact("signed.ok", "9.9.9", "linux", "x86-64", tarball); err == nil {
		t.Error("missing version accepted")
	}
	// bad project → repository() error
	if err := c.VerifyArtifact("BAD..name/../x", "1.0.0", "linux", "x86-64", tarball); err == nil {
		t.Error("bad project accepted")
	}
}

func TestVerifyArtifactMalformedSig(t *testing.T) {
	fr := newFakeRegistry(t, false)
	defer fr.close()
	c, _ := NewOCIClient(fr.base("go-zpkg/artifacts"))
	tarball := makeGzTarball("x")
	// a signature referrer with no cosign annotation → malformed
	_, err := c.PushWithReferrers("malformed.sig", "1.0.0", "linux", "x86-64", tarball, ".tar.gz",
		[]Referrer{{ArtifactType: ArtifactTypeSignature, MediaType: MediaSimpleSigning, Blob: []byte(`{}`)}})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.VerifyArtifact("malformed.sig", "1.0.0", "linux", "x86-64", tarball); err == nil ||
		!strings.Contains(err.Error(), "malformed") {
		t.Errorf("expected malformed error, got %v", err)
	}
}

func TestDownloadArtifactVerify(t *testing.T) {
	fr := newFakeRegistry(t, false)
	defer fr.close()
	c, _ := NewOCIClient(fr.base("go-zpkg/artifacts"))
	kp, err := sign.Generate()
	if err != nil {
		t.Fatal(err)
	}
	oldKey := SigningPublicKey
	SigningPublicKey = kp.PublicKeyString()
	defer func() { SigningPublicKey = oldKey }()

	tarball := makeGzTarball("dl-body")
	pushSignedArtifact(t, c, "dl.signed", kp, tarball, true)
	pushSignedArtifact(t, c, "dl.unsigned", kp, tarball, false)

	oldDist := DistBase
	DistBase = fr.base("go-zpkg/artifacts")
	resetOCICache()
	defer func() { DistBase = oldDist; resetOCICache() }()

	// ZPKG_VERIFY + signed OCI artifact → succeeds
	t.Setenv("ZPKG_VERIFY", "1")
	if _, _, err := DownloadArtifact("dl.signed", "1.0.0", "linux", "x86-64"); err != nil {
		t.Fatalf("signed download+verify: %v", err)
	}
	// ZPKG_VERIFY + unsigned OCI artifact → fail closed
	if _, _, err := DownloadArtifact("dl.unsigned", "1.0.0", "linux", "x86-64"); err == nil {
		t.Error("unsigned artifact passed under ZPKG_VERIFY")
	}
	// with verification explicitly opted out (ZPKG_VERIFY=0), an unsigned artifact
	// downloads fine (verify is on by default, so this needs the opt-out).
	t.Setenv("ZPKG_VERIFY", "0")
	if _, _, err := DownloadArtifact("dl.unsigned", "1.0.0", "linux", "x86-64"); err != nil {
		t.Errorf("unverified download: %v", err)
	}
}

func TestVerifyArtifactFetchFailures(t *testing.T) {
	kp, _ := sign.Generate()
	old := SigningPublicKey
	SigningPublicKey = kp.PublicKeyString()
	defer func() { SigningPublicKey = old }()
	tarball := makeGzTarball("body")

	cases := map[string]func(method, verb, ref string) bool{
		"referrers":    func(method, verb, ref string) bool { return verb == "referrers" },
		"payload-blob": func(method, verb, ref string) bool { return method == "GET" && verb == "blobs" },
		"platform-man": func(method, verb, ref string) bool {
			return method == "GET" && verb == "manifests" && strings.HasPrefix(ref, "sha256:")
		},
	}
	for name, fail := range cases {
		t.Run(name, func(t *testing.T) {
			fr := newFakeRegistry(t, false)
			defer fr.close()
			c, _ := NewOCIClient(fr.base("go-zpkg/artifacts"))
			pushSignedArtifact(t, c, "fetch.fail", kp, tarball, true)
			fr.hook = func(r *http.Request) (int, bool) {
				_, verb, ref := splitV2(r.URL.Path)
				return 500, fail(r.Method, verb, ref)
			}
			if err := c.VerifyArtifact("fetch.fail", "1.0.0", "linux", "x86-64", tarball); err == nil {
				t.Errorf("%s: expected fetch failure", name)
			}
		})
	}
}

func TestDownloadArtifactVerifyHTTP(t *testing.T) {
	oldDist := DistBase
	DistBase = "https://dist.example.test"
	defer func() { DistBase = oldDist }()
	t.Setenv("ZPKG_VERIFY", "1")
	// the HTTP transport has no signatures → fail closed before any fetch
	if _, _, err := DownloadArtifact("p", "1.0.0", "linux", "x86-64"); err == nil ||
		!strings.Contains(err.Error(), "ZPKG_VERIFY") {
		t.Errorf("HTTP under ZPKG_VERIFY should fail closed, got %v", err)
	}
}

// TestInstallVerify pins the hole this file used to leave open: the guarantee
// pkgx and pkgm advertise — "verifying each artifact's signature (fail-closed)" —
// was enforced in DownloadArtifact, which only the MIRROR tooling calls. Every
// actual install went through fetchArtifact, which checked nothing, so
// `ZPKG_VERIFY=1 pkgx +pkg` cheerfully installed an unsigned artifact. Measured on
// a real registry before the fix.
func TestInstallVerify(t *testing.T) {
	// pushSignedArtifact publishes for linux/x86-64; Install resolves for the host.
	setGoos(t, "linux")
	setGoarch(t, "x86-64")
	fr := newFakeRegistry(t, false)
	defer fr.close()
	c, _ := NewOCIClient(fr.base("go-zpkg/artifacts"))
	kp, err := sign.Generate()
	if err != nil {
		t.Fatal(err)
	}
	oldKey := SigningPublicKey
	SigningPublicKey = kp.PublicKeyString()
	defer func() { SigningPublicKey = oldKey }()

	tarball := ociGzArtifact(t, "inst.signed", "1.0.0", map[string]string{"bin/s": "x"})
	pushSignedArtifact(t, c, "inst.signed", kp, tarball, true)
	unsigned := ociGzArtifact(t, "inst.unsigned", "1.0.0", map[string]string{"bin/u": "x"})
	pushSignedArtifact(t, c, "inst.unsigned", kp, unsigned, false)

	oldDist := DistBase
	DistBase = fr.base("go-zpkg/artifacts")
	resetOCICache()
	defer func() { DistBase = oldDist; resetOCICache() }()

	t.Setenv("ZPKG_VERIFY", "1")
	// signed → installs
	if fresh, err := Install(Resolved{"inst.signed", ParseVer("1.0.0")}, t.TempDir()); err != nil || !fresh {
		t.Fatalf("signed install fresh=%v err=%v", fresh, err)
	}
	// unsigned → refused, and nothing is written
	dir := t.TempDir()
	if _, err := Install(Resolved{"inst.unsigned", ParseVer("1.0.0")}, dir); err == nil {
		t.Error("an unsigned artifact installed under ZPKG_VERIFY")
	} else if !strings.Contains(err.Error(), "unsigned") {
		t.Errorf("install error = %v, want it to name the missing signature", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "inst.unsigned")); err == nil {
		t.Error("refused artifact left files behind")
	}
	// explicit opt-out → installs, as documented
	t.Setenv("ZPKG_VERIFY", "0")
	if fresh, err := Install(Resolved{"inst.unsigned", ParseVer("1.0.0")}, t.TempDir()); err != nil || !fresh {
		t.Errorf("opted-out install fresh=%v err=%v", fresh, err)
	}
}

// TestInstallVerifyHTTP: a static-HTTP dist carries no signatures at all, so an
// install through one must fail closed rather than silently skip the check.
func TestInstallVerifyHTTP(t *testing.T) {
	oldDist := DistBase
	DistBase = "https://dist.example.test"
	defer func() { DistBase = oldDist }()
	t.Setenv("ZPKG_VERIFY", "1")
	if _, err := Install(Resolved{"p", ParseVer("1.0.0")}, t.TempDir()); err == nil ||
		!strings.Contains(err.Error(), "ZPKG_VERIFY") {
		t.Errorf("HTTP install under ZPKG_VERIFY should fail closed, got %v", err)
	}
}
