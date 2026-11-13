package artifact

import (
	"encoding/json"
	"fmt"
)

// SpecAnnotation carries an artifact's concrete spec on its per-platform OCI
// manifest, as JSON.
//
// ⛔ THE TAG CARRIES THE ADDRESS, THE ANNOTATION CARRIES THE MEANING. An
// identity hash is opaque by construction, and Nix pays for that: a store
// path says WHICH build and never WHAT build, so answering "the one with
// CUDA?" needs a second index. Spack keeps the spec queryable instead
// (`spack find libdwarf +debug`), and conda writes its hash inputs into
// info/hash_input.json beside the hash.
//
// So readability is a TOOLING property here, not a naming one: the tag stays
// a hash, and this annotation is what `pkgx ls` reads to print `+cuda ~mpi`.
// That is the whole reason the `-glibc<X>` suffix could stop being a second
// spelling of identity.
//
// The key is declared in annotations.go and read through AnnotationPresent(),
// which keeps "absent" distinguishable from "present and empty" — an empty
// spec is a malformed artifact and a missing one is simply an older artifact.

// specJSON is the wire form. Field names are short because an OCI annotation
// value travels in every manifest fetch, and explicit because a Go field
// rename must not silently change what published artifacts mean.
// SpecVersion is the payload's format version.
//
// ⛔⛔ A NUMBER, NOT A SCHEMA, AND IT BUYS ONE THING: A LEGIBLE FAILURE.
// Without it, a payload written by a NEWER release is not rejected — it is
// MISREAD. encoding/json drops fields it does not know, silently, so a v2
// spec carrying a new identity-bearing field parses cleanly here as a v1
// spec that happens to lack it.
//
// The artifact is not installed in that case, because VerifySpec recomputes
// the hash and the dropped field moves it. So the outcome is already
// fail-closed — but the message is "the artifact does not match its own
// description", which reads as tampering and sends its reader to look for an
// attacker. The truth is "this artifact was written by a release newer than
// yours", and only a version field can say so.
//
// A JSON Schema would say more and cost more: this value travels in every
// manifest fetch, and a schema is a URL to fetch and a document to keep in
// step for a payload of five fields. The question a reader actually has is
// "can I understand this?", and an integer answers it.
const SpecVersion = 1

type specJSON struct {
	// ⛔ NOT `omitempty`. Every other field here is omitted when empty, so an
	// empty spec is `{}`; if the version were omitted too, "written before
	// versions existed" and "version 0" would be the same bytes.
	V        int                 `json:"v"`
	Platform string              `json:"platform,omitempty"`
	Variants map[string][]string `json:"variants,omitempty"`
	Deps     []depJSON           `json:"deps,omitempty"`
	Recipe   string              `json:"recipe,omitempty"`
	Graft    string              `json:"graft,omitempty"`
}

type depJSON struct {
	Project string `json:"project"`
	Version string `json:"version"`
	Hash    string `json:"hash,omitempty"`
}

// MarshalSpec renders a concrete spec for the SpecAnnotation.
//
// No error: specJSON is strings, string maps and slices of those, and
// encoding/json cannot fail on any of them. Returning one anyway would add a
// branch no caller can reach and no test can exercise — the shape the
// coverage measurement keeps finding and a reader later mistakes for a real
// case. TestMarshalSurvivesAwkwardBytes pins the property instead.
func MarshalSpec(c Concrete) string {
	j := specJSON{V: SpecVersion, Platform: c.Platform, Recipe: c.Recipe, Graft: c.Graft}
	if len(c.Variants) > 0 {
		j.Variants = map[string][]string{}
		for n, v := range c.Variants {
			j.Variants[n] = append([]string(nil), v...)
		}
	}
	for _, d := range c.Deps {
		j.Deps = append(j.Deps, depJSON{Project: d.Project, Version: d.Version, Hash: d.Hash})
	}
	b, _ := json.Marshal(j)
	return string(b)
}

// UnmarshalSpec reads a spec from an annotation value.
//
// ⛔⛔ IT IS NOT TRUSTED. This value comes from a registry, which is to say
// from whoever could push to it, and the canonical form had to be made
// injective for exactly this reason: a validator guards the door it stands
// at, and the annotation arrives through another one. Callers that care
// which artifact they have must use VerifySpec, not this.
func UnmarshalSpec(s string) (Concrete, error) {
	var j specJSON
	if err := json.Unmarshal([]byte(s), &j); err != nil {
		return Concrete{}, fmt.Errorf("%s: %w", SpecAnnotation, err)
	}
	// ⛔ REFUSED BEFORE IT IS READ, and the message is the whole point. A
	// newer payload parses cleanly — encoding/json drops what it does not
	// know — so without this the caller gets a hash mismatch and goes
	// looking for an attacker. Say which version it is instead.
	if j.V > SpecVersion {
		return Concrete{}, fmt.Errorf(
			"%s is format version %d and this build understands %d: the artifact was published by a newer release of go-zpkg",
			SpecAnnotation, j.V, SpecVersion)
	}
	c := Concrete{Platform: j.Platform, Recipe: j.Recipe, Graft: j.Graft}
	if len(j.Variants) > 0 {
		c.Variants = Variants{}
		for n, v := range j.Variants {
			c.Variants[n] = append([]string(nil), v...)
		}
	}
	for _, d := range j.Deps {
		c.Deps = append(c.Deps, Dep{Project: d.Project, Version: d.Version, Hash: d.Hash})
	}
	return c, nil
}

// VerifySpec reads the annotation and checks that it hashes to the hash the
// TAG claims. It returns the spec only when the two agree.
//
// ⛔⛔ A SPEC THAT DOES NOT HASH TO ITS OWN ADDRESS IS NOT DESCRIPTION, IT IS
// A CLAIM. Both halves are supplied by the publisher: the tag says
// `-h<hash>`, the annotation says what that hash is of. Reading the second
// without checking it against the first would let an artifact tagged as the
// plain build describe itself as the CUDA one, or the reverse — and the
// reverse is the one that matters, because the lie is in the direction of
// "this is the build you asked for".
//
// An empty wantHash means the tag made no claim (every artifact published
// before this existed), and then there is nothing to check against: the spec
// is returned as the unverified description it is, and a caller deciding
// anything on it should say so.
func VerifySpec(annotation, wantHash string) (Concrete, error) {
	c, err := UnmarshalSpec(annotation)
	if err != nil {
		return Concrete{}, err
	}
	if wantHash == "" {
		return c, nil
	}
	if got := c.Hash(); got != wantHash {
		return Concrete{}, fmt.Errorf(
			"%s describes a build whose hash is %q, but the tag says %q: the artifact does not match its own description",
			SpecAnnotation, got, wantHash)
	}
	return c, nil
}

// SpecOf reads a published artifact's concrete spec from its manifest and
// verifies it against the hash in its tag.
//
// An artifact published before specs existed carries no annotation; that is
// reported as an absent spec (ok=false) rather than an error, because "we
// do not know what options this was built with" is the truth about every
// artifact in the registry today.
func (c *OCIClient) SpecOf(project, tag, osn, arch string) (Concrete, bool, error) {
	ann, err := c.Annotations(project, tag, osn, arch)
	if err != nil {
		return Concrete{}, false, err
	}
	s, present := AnnotationPresent(ann, SpecAnnotation)
	if !present || s == "" {
		return Concrete{}, false, nil
	}
	_, wantHash := SplitVariantHash(tag)
	spec, err := VerifySpec(s, wantHash)
	if err != nil {
		return Concrete{}, false, fmt.Errorf("%s %s: %w", project, tag, err)
	}
	return spec, true, nil
}
