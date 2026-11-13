package artifact

import (
	"strings"
	"testing"
)

// ⛔⛔ THE FACTORY AND THE INSTALLER MUST SHORTEN ALIKE, AND THAT IS THE WHOLE
// REASON THIS IS EXPORTED. go-zpkg/zbk computes a build's identity and has to
// put it in an OCI tag; `artifact` has to find the matching directory. If each
// shortened in its own way the two would address different things, and the
// symptom would be "the artifact is not published" for an artifact that is.
func TestShortHashIsTheShapeATagAndAPathBothAccept(t *testing.T) {
	got := ShortHash("sha256:e47e158cd9d5d25a0fac14c4deaf4877af16d17c8780a14f02f9a6f0e8839894")

	if len(got) != hashLen {
		t.Errorf("ShortHash = %q (%d chars), want %d", got, len(got), hashLen)
	}
	// ⛔ THE ALPHABET IS WHAT MAKES IT A TAG. An OCI tag may hold
	// `[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}` and no `:` or `+`, so neither the
	// raw "sha256:…" nor base64 can be one. isVariantHash is what reads these
	// back out of a tag, so agreeing with it is the actual requirement.
	if !isVariantHash(got) {
		t.Errorf("ShortHash = %q, which SplitVariantHash would not recognise", got)
	}
	if strings.ToLower(got) != got {
		t.Errorf("ShortHash = %q, want lowercase: a registry lowercases a repository and a reader must not be surprised", got)
	}
}

func TestShortHashIsDeterministicAndDistinguishing(t *testing.T) {
	if ShortHash("a") != ShortHash("a") {
		t.Error("the same identity hashed to two different values")
	}
	if ShortHash("a") == ShortHash("b") {
		t.Error("two different identities share a short hash")
	}
	// An empty identity still produces a well-formed hash rather than an
	// empty string: callers put the result straight into a path, and ""
	// there would silently rebuild the unhashed layout.
	if h := ShortHash(""); !isVariantHash(h) {
		t.Errorf("ShortHash(\"\") = %q, want a well-formed hash", h)
	}
}
