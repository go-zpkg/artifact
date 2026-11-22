package artifact

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-attest/sign"
)

// pushClaiming pushes tarball under project@ver with a signature by kp whose
// signed claim names claim, not necessarily what it is pushed as.
func pushClaiming(t *testing.T, c *OCIClient, project, ver, claim string, kp *sign.Keypair, tarball []byte) {
	t.Helper()
	payload, err := sign.SimpleSigningPayload(claim, digestOf(tarball))
	if err != nil {
		t.Fatal(err)
	}
	refs := []Referrer{{
		ArtifactType: ArtifactTypeSignature,
		MediaType:    MediaSimpleSigning,
		Blob:         payload,
		Annotations:  map[string]string{CosignSignatureAnnotation: kp.SignPayload(payload)},
	}}
	if _, err := c.PushWithReferrers(project, ver, "linux", "x86-64", tarball, ".tar.gz", refs); err != nil {
		t.Fatal(err)
	}
}

// A validly signed tarball served under another project or another version is
// refused; the genuine name and tag pass.
func TestSignatureIsBoundToTheProjectAndVersionInstalled(t *testing.T) {
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
	tarball := makeGzTarball("bound-body")

	pushClaiming(t, c, "real.pkg", "1.0.0", "pkg:generic/real.pkg@1.0.0", kp, tarball)
	pushClaiming(t, c, "other.pkg", "1.0.0", "pkg:generic/real.pkg@1.0.0", kp, tarball) // wrong project
	pushClaiming(t, c, "real.pkg", "2.0.0", "pkg:generic/real.pkg@1.0.0", kp, tarball)  // wrong version
	pushClaiming(t, c, "legacy.pkg", "1.0.0", "pkg:pkgx/legacy.pkg@1.0.0", kp, tarball) // retired spelling
	pushClaiming(t, c, "bare.pkg", "1.0.0", "pkg:generic/bare.pkg", kp, tarball)        // no version
	pushClaiming(t, c, "none.pkg", "1.0.0", "", kp, tarball)                            // no claim

	if err := c.VerifyArtifact("real.pkg", "1.0.0", "linux", "x86-64", tarball); err != nil {
		t.Fatalf("genuine artifact refused: %v", err)
	}
	if err := c.VerifyArtifact("legacy.pkg", "1.0.0", "linux", "x86-64", tarball); err != nil {
		t.Fatalf("artifact signed with the retired spelling refused: %v", err)
	}
	for _, tc := range []struct{ project, ver string }{
		{"other.pkg", "1.0.0"}, {"real.pkg", "2.0.0"}, {"bare.pkg", "1.0.0"}, {"none.pkg", "1.0.0"},
	} {
		err := c.VerifyArtifact(tc.project, tc.ver, "linux", "x86-64", tarball)
		if err == nil {
			t.Errorf("%s %s: a signature for something else was accepted", tc.project, tc.ver)
			continue
		}
		if !strings.Contains(err.Error(), "name a different project or version") {
			t.Errorf("%s %s: refusal does not say why: %v", tc.project, tc.ver, err)
		}
	}
	// The listing path agrees with the install path.
	rep, err := c.SignaturesOfTag("other.pkg", "1.0.0", "linux", "x86-64")
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK() || rep.Misbound != 1 {
		t.Errorf("listing: OK=%v misbound=%d, want refused with 1 misbound", rep.OK(), rep.Misbound)
	}
}

func TestClaimedBy(t *testing.T) {
	mk := func(ref string) []byte {
		p, err := sign.SimpleSigningPayload(ref, "sha256:aa")
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	for _, tc := range []struct {
		name, ref, project, tag string
		ok                      bool
	}{
		{"exact", "pkg:generic/gnu.org/bash@5.2.37", "gnu.org/bash", "5.2.37", true},
		{"retired spelling", "pkg:pkgx/gnu.org/bash@5.2.37", "gnu.org/bash", "5.2.37", true},
		{"repository is lowercased", "pkg:generic/Foo.org/Bar@1", "foo.org/bar", "1", true},
		{"shorter tag", "pkg:generic/x@1.35.0", "x", "1.35", true},
		{"longer tag", "pkg:generic/x@1.35", "x", "1.35.0", true},
		{"flavored tag", "pkg:generic/x@2.40", "x", "2.40-glibc2.39", true},
		{"variant tag", "pkg:generic/x@2.40.1", "x", "2.40.1-h0123abcd", true},
		{"another project", "pkg:generic/y@1", "x", "1", false},
		{"suffix of a project", "pkg:generic/ax@1", "x", "1", false},
		{"another version", "pkg:generic/x@1.0.1", "x", "1.0.2", false},
		{"dropping a non-zero component", "pkg:generic/x@26.8", "x", "26.8.1", false},
		{"prefix is not a flavor", "pkg:generic/x@1.1", "x", "1.10", false},
		{"no version", "pkg:generic/x", "x", "1", false},
		{"empty version", "pkg:generic/x@", "x", "1", false},
		{"not a purl", "docker.io/x:1", "x", "1", false},
		{"empty", "", "x", "1", false},
	} {
		err := Identity{Project: tc.project, Version: tc.tag}.claimedBy(mk(tc.ref))
		if (err == nil) != tc.ok {
			t.Errorf("%s: claim %q for %s %s: err=%v, want ok=%v", tc.name, tc.ref, tc.project, tc.tag, err, tc.ok)
		}
	}
	if err := (Identity{Project: "x", Version: "1"}).claimedBy([]byte("not json")); err == nil {
		t.Error("a payload that is not JSON was accepted")
	}
	if err := (Identity{Project: "x", Version: "1"}).claimedBy([]byte(`{"critical":{"identity":{"docker-reference":["pkg:generic/x@1"]}}}`)); err == nil {
		t.Error("a payload with a non-string reference was accepted")
	}
}

func FuzzClaimedBy(f *testing.F) {
	f.Add([]byte(`{"critical":{"identity":{"docker-reference":"pkg:generic/x@1"}}}`), "x", "1")
	f.Add([]byte(`{}`), "", "")
	f.Add([]byte(`{"critical":{"identity":{"docker-reference":"pkg:pkgx/@@"}}}`), "@", "@")
	f.Fuzz(func(t *testing.T, payload []byte, project, tag string) {
		err := Identity{Project: project, Version: tag}.claimedBy(payload)
		if err == nil {
			// An accepted claim must read back as the identity it was accepted for.
			p, v, ok := claimedIdentity(payload)
			if !ok || !strings.EqualFold(p, project) || !sameVersionTag(v, tag) {
				t.Fatalf("accepted %q for %q %q but it reads %q %q ok=%v", payload, project, tag, p, v, ok)
			}
		}
	})
}

// Registry credentials are offered to the host they were configured for, and
// over plain HTTP only to loopback.
func TestCredentialsGoOnlyToTheirHost(t *testing.T) {
	env := func(k string) string {
		switch k {
		case "OCI_USERNAME":
			return "user"
		case "OCI_PASSWORD":
			return "secret"
		}
		return ""
	}
	ctx := context.Background()
	cases := []struct {
		name, base, asked string
		want              bool
	}{
		{"configured host over https", "oci://ghcr.io/o/r", "ghcr.io", true},
		{"another host", "oci://ghcr.io/o/r", "evil.example", false},
		{"a subdomain", "oci://ghcr.io/o/r", "x.ghcr.io", false},
		{"another port", "oci://reg.example:5000/o/r", "reg.example:5001", false},
		{"plain http to a remote host", "oci://http://10.46.81.1:5111/o/r", "10.46.81.1:5111", false},
		{"plain http, other host", "oci://http://10.46.81.1:5111/o/r", "evil.example", false},
		{"loopback is not remote", "oci://127.0.0.1:5000/o/r", "127.0.0.1:5000", true},
		{"loopback, other host", "oci://127.0.0.1:5000/o/r", "evil.example", false},
	}
	for _, tc := range cases {
		c, err := newOCIClientEnv(tc.base, env)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		cred, err := c.client.Credential(ctx, tc.asked)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		got := cred.Username == "user" && cred.Password == "secret"
		if got != tc.want {
			t.Errorf("%s: credential offered to %s = %v, want %v", tc.name, tc.asked, got, tc.want)
		}
		if !got && (cred.Username != "" || cred.Password != "" || cred.AccessToken != "" || cred.RefreshToken != "") {
			t.Errorf("%s: a partial credential leaked: %+v", tc.name, cred)
		}
	}
	// A bearer token follows the same rule.
	c, err := newOCIClientEnv("oci://http://10.1.2.3:5000/o/r", func(k string) string {
		if k == "OCI_TOKEN" {
			return "tok"
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	if cred, _ := c.client.Credential(ctx, "10.1.2.3:5000"); cred.AccessToken != "" {
		t.Error("a bearer token was offered over plain http")
	}
}

func TestShDQ(t *testing.T) {
	if got, want := shDQ("a\"b$c`d\\e"), "a\\\"b\\$c\\`d\\\\e"; got != want {
		t.Errorf("shDQ = %q, want %q", got, want)
	}
}

// A provided binary whose name could be more than a word is refused, and no
// stub is written for it.
func TestStubBinsRefusesAnUnsafeName(t *testing.T) {
	defer fakeServer(t, map[string]fakePkg{
		"evil.org/tool": {
			versions: []string{"1.0.0"},
			yaml:     "provides:\n  - bin/..\n",
			files:    map[string]string{"bin/ok": "#!x\n"},
		},
	})()
	dir := t.TempDir()
	if _, err := Install(Resolved{"evil.org/tool", ParseVer("1.0.0")}, dir); err != nil {
		t.Fatal(err)
	}
	prefix := filepath.Join(dir, "stubprefix")
	n, err := StubBins([]Resolved{{"evil.org/tool", ParseVer("1.0.0")}}, dir, prefix)
	if err == nil || !strings.Contains(err.Error(), "not a safe command name") || n != 0 {
		t.Fatalf("StubBins = %d, %v; want a refusal and no stub", n, err)
	}
	ents, _ := os.ReadDir(filepath.Join(prefix, "bin"))
	if len(ents) != 0 {
		t.Errorf("stubs written despite the refusal: %v", ents)
	}
}

func TestClaimedIdentityShapes(t *testing.T) {
	ref := func(r string) []byte { return []byte(`{"critical":{"identity":{"docker-reference":"` + r + `"}}}`) }
	for _, r := range []string{"", "pkg:generic/", "pkg:generic/x@", "pkg:generic/@1", "pkg:generic/x", "x@1", "pkg:other/x@1"} {
		if p, v, ok := claimedIdentity(ref(r)); ok {
			t.Errorf("%q read as %q %q", r, p, v)
		}
	}
	if p, v, ok := claimedIdentity(ref("pkg:generic/a@b/c@1.2")); !ok || p != "a@b/c" || v != "1.2" {
		t.Errorf("the LAST @ must split: got %q %q %v", p, v, ok)
	}
}

func TestSameVersionTagNeverMatchesEmpty(t *testing.T) {
	for _, tc := range [][2]string{{"", ""}, {"", "1"}, {"1", ""}, {"v", "v"}} {
		if sameVersionTag(tc[0], tc[1]) {
			t.Errorf("sameVersionTag(%q, %q) = true", tc[0], tc[1])
		}
	}
}

func TestVerifiedPayloadsAreOnlyTheTrustedBoundOnes(t *testing.T) {
	fr := newFakeRegistry(t, false)
	defer fr.close()
	c, _ := NewOCIClient(fr.base("go-zpkg/artifacts"))
	kp, err := sign.Generate()
	if err != nil {
		t.Fatal(err)
	}
	stranger, err := sign.Generate()
	if err != nil {
		t.Fatal(err)
	}
	old := SigningPublicKey
	SigningPublicKey = kp.PublicKeyString()
	defer func() { SigningPublicKey = old }()
	tarball := makeGzTarball("payloads-body")
	digest := digestOf(tarball)

	pushClaiming(t, c, "vp.pkg", "1.0.0", "pkg:generic/vp.pkg@1.0.0", kp, tarball)
	// a stranger's signature is attached too: it must not be returned.
	payload, _ := sign.SimpleSigningPayload("pkg:generic/vp.pkg@1.0.0", digest)
	if err := c.AttachReferrer("vp.pkg", "1.0.0", "linux", "x86-64", Referrer{
		ArtifactType: ArtifactTypeSignature, MediaType: MediaSimpleSigning, Blob: append([]byte(nil), payload...),
		Annotations: map[string]string{CosignSignatureAnnotation: stranger.SignPayload([]byte("other"))},
	}); err != nil {
		t.Fatal(err)
	}
	got, err := c.VerifiedPayloads("vp.pkg", "1.0.0", "linux", "x86-64", digest)
	if err != nil || len(got) != 1 {
		t.Fatalf("VerifiedPayloads = %d payloads, %v; want exactly the trusted one", len(got), err)
	}
	if _, err := c.VerifiedPayloads("vp.pkg", "1.0.0", "linux", "x86-64", "sha256:00"); err == nil {
		t.Error("payloads returned for a digest nothing signed")
	}
	pushClaiming(t, c, "vp.other", "1.0.0", "pkg:generic/vp.pkg@1.0.0", kp, tarball)
	if got, err := c.VerifiedPayloads("vp.other", "1.0.0", "linux", "x86-64", digest); err == nil || len(got) != 0 {
		t.Errorf("payloads returned for a claim about another project: %d, %v", len(got), err)
	}
}
