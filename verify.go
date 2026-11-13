package artifact

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/go-attest/sign"
)

// VerifyRequired reports whether fail-closed signature verification is demanded
// when installing. It is **on by default** (secure by default): only an explicit
// ZPKG_VERIFY=0/false/no/off opts out. Anything else — unset, 1/true/yes/on, or
// an unrecognised value — keeps verification on. The value is read through Env,
// so it may come from a real environment variable or from ~/.zpkg/config.hcl2.
func VerifyRequired() bool {
	switch strings.ToLower(strings.TrimSpace(Env("ZPKG_VERIFY"))) {
	case "0", "false", "no", "off":
		return false
	}
	return true
}

// SigningPublicKey is the go-zpkg artifact signing key (minisign format). A signed
// artifact carries a cosign-style signature referrer whose signature verifies
// against this key; verification is fail-closed. It is a var (not const) only so
// tests can substitute a throwaway key.
//
// ⛔ IT IS THE DEFAULT TRUST SET, NOT THE WHOLE OF IT. What a client will
// accept is a TrustSet — this key unless the operator says otherwise, plus
// whatever ZPKG_EXTRA_TRUSTED_KEYS adds, and a threshold over the lot. See
// trust.go; everything that verifies an artifact goes through LoadTrustSet.
var SigningPublicKey = "RWTfNcOkaTHT5lsudyEtExOI45lQQEHCu+fckxlKljWtzfuFTQtgjLZT"

// RetiredSigningPublicKeys are keys this project HAS signed with and still
// trusts, newest first, as `name:key` entries.
//
// ⛔⛔ RETIRING A KEY MUST NOT INVALIDATE WHAT IT SIGNED. A signature is a
// statement about bytes, made at a moment; replacing the key we sign WITH
// says nothing about the artifacts already signed. A trust set that dropped
// the old key would refuse the whole published registry overnight — and
// since the fix for a lost or compromised key is to rotate, a design where
// rotation breaks everything is a design where nobody rotates.
//
// ⛔ AND THEY ARE NOT EXPIRED BY DATE, BECAUSE THERE IS NO DATE TO EXPIRE
// THEM BY. Every published artifact carries the same pinned timestamp so that
// re-publishing is byte-identical, so "was this signed before the key was
// retired?" is a question nothing on the artefact can answer. Pretending
// otherwise would be a check that cannot fail. A key leaves this list only
// when a human decides its signatures are no longer to be believed — which
// is a withdrawal of trust, a different and louder act than rotation.
//
// ⛔ `go-zpkg-until-2026-11` IS RETIRED, NOT REVOKED, AND THE DISTINCTION IS
// A JUDGEMENT WE MADE RATHER THAN A FACT WE FOUND. Its private half could
// not be located: two scans of the maintainer's workstation covered
// 2,167,120 files and found no key, and what sat in the CI secret turned out
// to be its PUBLIC half. Lost is not compromised — nothing suggests anybody
// else holds it — so everything it signed stays trusted and nothing needs
// rebuilding. If evidence of compromise ever appears, it moves to
// RevokedSigningKeys and that changes.
//
// It signed every artifact in the registry up to 2026-11-06.
var RetiredSigningPublicKeys = []string{
	"go-zpkg-until-2026-11:RWQ+rmH+fXy2iYr+gReQAOQtYWtH0A7UlxcAa2hpr+txNBwGqtpFsR6L",
}

// RevokedKey is a key whose signatures are no longer to be believed.
type RevokedKey struct {
	// Name is how it is spoken of in the verdict.
	Name string
	// Key is the minisign public key.
	Key string
	// Because is why — "CI secret exposed in run 42067525642", an advisory
	// identifier, a date. ⛔ A REVOCATION WITHOUT A REASON IS A RUMOUR. The
	// person reading "this artifact is signed by a revoked key" has to decide
	// what to do about an artefact they may already be running, and "we
	// revoked it" tells them nothing about whether that matters.
	Because string
}

// RevokedSigningKeys are keys that were OURS and are no longer trusted —
// compromised, exfiltrated, or signed something we did not authorise.
//
// ⛔⛔ REVOKING IS NOT RETIRING, AND THE DIFFERENCE IS THE WHOLE POINT OF
// HAVING BOTH. A retired key is one we stopped signing WITH; everything it
// signed is still ours and still true. A revoked key is one somebody else
// may have held, so NOTHING it signed can be distinguished from a forgery —
// including artifacts it signed perfectly legitimately before the compromise.
//
// ⛔ AND WE CANNOT TELL THE TWO APART, BECAUSE THERE IS NO DATE. Every
// published artifact carries the same pinned timestamp, so "was this signed
// before the key leaked?" has no answer on the artefact. A scheme that
// honoured signatures made "before" the revocation would be a check that
// cannot fail, which is worse than no check: it would restore trust in
// exactly the artefacts an attacker would plant.
//
// So a revoked key's signature counts for NOTHING — and is reported, loudly
// and separately from a stranger's. A stranger signing our artifact is noise
// anybody can make; our own revoked key on an artifact is a fact about our
// supply chain that the reader has to act on.
//
// The remedy for a revoked key is to rebuild and re-sign, not to argue. That
// is expensive, which is why it is a different list from the retired one and
// why entries carry a reason.
var RevokedSigningKeys []RevokedKey

// Signature referrer conventions.
const (
	// ArtifactTypeSignature marks a cosign signature referrer manifest.
	ArtifactTypeSignature = "application/vnd.dev.cosign.artifact.sig.v1+json"
	// ArtifactTypeProvenance marks the in-toto SLSA provenance referrer: the
	// statement that says WITH WHAT an artifact was built.
	//
	// ⛔ IT IS THE ONLY PLACE THE BUILDER IS RECORDED. The build's identity
	// (Concrete) deliberately excludes the builder — a zbk release must not
	// re-address every artifact in the registry, which is Nix's and Spack's
	// position too. So "which factory made this?" is answerable ONLY from
	// this attestation, and anything that wants to ask has to read it.
	ArtifactTypeProvenance = "application/vnd.in-toto+json"
	// MediaSimpleSigning is the media type of the simple-signing payload blob.
	MediaSimpleSigning = "application/vnd.dev.cosign.simplesigning.v1+json"
	// CosignSignatureAnnotation carries the base64 signature on the referrer
	// manifest (cosign's convention).
	CosignSignatureAnnotation = "dev.cosignproject.cosign/signature"
	// SignerKeyIDAnnotation names, in hex, the minisign key id that made the
	// signature on this referrer.
	//
	// ⛔ IT IS A HINT AND MUST NEVER BE TRUSTED. A cosign blob signature is a
	// bare Ed25519 signature: it does not say which key made it, so with two
	// signers a verifier would have to try every trusted key against every
	// signature. This annotation turns that product back into a walk — and
	// nothing more. Verify tries the hinted key FIRST and then the others, so
	// an annotation that lies costs time and changes no verdict.
	//
	// There is deliberately no annotation for the signer's NAME. A name on the
	// artefact is written by whoever pushed it; the name a user reads comes
	// from their own trust set, which is the only place it means anything.
	SignerKeyIDAnnotation = "org.go-zpkg.signer.keyid"

	// GlibcVersionAnnotation and GlibcMinKernelAnnotation describe a
	// glibc-flavored artifact on its per-platform manifest: the exact glibc it
	// was built against, and (for the glibc artifact itself) glibc's min
	// supported kernel from .note.ABI-tag. A glibc-aware resolver/selector
	// reads these. They live in annotations.go with the rest, and are read
	// through Annotation() so an artifact published under an older spelling is
	// still understood.
)

// VerifySignature checks a cosign simple-signing signature over an artifact
// tarball: the base64 sig must verify over payload against pubkey (defaulting to
// the pinned SigningPublicKey), and payload must commit to this exact tarball
// (docker-manifest-digest == sha256(tarball)). Every failure returns an error —
// callers treat that as fail-closed.
func VerifySignature(tarball, payload []byte, b64sig, pubkey string) error {
	sum := sha256.Sum256(tarball)
	return VerifySignatureDigest("sha256:"+hex.EncodeToString(sum[:]), payload, b64sig, pubkey)
}

// VerifySignatureDigest is VerifySignature for a tarball identified by its
// DIGEST rather than by its bytes. The bytes are only ever hashed here, so a
// caller that streamed the artifact to disk — computing the digest on the way —
// can verify the signature without reading the tarball back, let alone holding
// it in memory.
func VerifySignatureDigest(digest string, payload []byte, b64sig, pubkey string) error {
	if pubkey == "" {
		pubkey = SigningPublicKey
	}
	_, pub, err := sign.ParsePublicKey(pubkey)
	if err != nil {
		return err
	}
	if err := sign.VerifyBlob(payload, b64sig, pub); err != nil {
		return err
	}
	return payloadCommitsTo(payload, digest)
}

// payloadCommitsTo checks that a simple-signing payload names this exact
// artifact. A valid signature over SOMEBODY ELSE'S payload is the whole attack
// this prevents, so it is kept apart from the key check and both are run on
// every path — TrustSet.Verify reuses it.
func payloadCommitsTo(payload []byte, digest string) error {
	var p struct {
		Critical struct {
			Image struct {
				Digest string `json:"docker-manifest-digest"`
			} `json:"image"`
		} `json:"critical"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return fmt.Errorf("artifact: bad signing payload: %w", err)
	}
	if p.Critical.Image.Digest != digest {
		return errors.New("artifact: signature does not match this artifact")
	}
	return nil
}
