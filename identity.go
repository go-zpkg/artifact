package artifact

import (
	"encoding/json"
	"errors"
	"strings"
)

// Identity is the project and registry tag an artifact is being installed as.
// A signature commits to bytes AND to a claim about what those bytes are; this
// is the second half of that check.
//
// ⛔ A VALID SIGNATURE OVER THE RIGHT BYTES IS NOT ENOUGH. The tarball digest
// alone lets a registry serve any validly signed artifact under any name or
// tag; the signed docker-reference is the only thing that ties the bytes to
// the project and version a user asked for.
type Identity struct {
	Project string
	Version string // the registry tag being installed
}

// claimPrefixes are the spellings of the signed reference publishers have
// written: the current one and the retired one (read, never written).
var claimPrefixes = []string{"pkg:generic/", "pkg:pkgx/"}

// claimedIdentity reads the docker-reference of a simple-signing payload as
// project and version. ok is false when it is absent or not of that shape.
func claimedIdentity(payload []byte) (project, version string, ok bool) {
	var p struct {
		Critical struct {
			Identity struct {
				Ref string `json:"docker-reference"`
			} `json:"identity"`
		} `json:"critical"`
	}
	if json.Unmarshal(payload, &p) != nil {
		return "", "", false
	}
	ref := p.Critical.Identity.Ref
	rest := ""
	for _, pre := range claimPrefixes {
		if strings.HasPrefix(ref, pre) {
			rest = strings.TrimPrefix(ref, pre)
			break
		}
	}
	i := strings.LastIndex(rest, "@")
	if rest == "" || i <= 0 || i == len(rest)-1 {
		return "", "", false
	}
	return rest[:i], rest[i+1:], true
}

// claimedBy reports nil when the payload's signed claim names this identity.
// A missing, unreadable or different claim is an error: fail closed.
func (id Identity) claimedBy(payload []byte) error {
	project, version, ok := claimedIdentity(payload)
	if !ok || !strings.EqualFold(project, id.Project) || !sameVersionTag(version, id.Version) {
		return errors.New("artifact: signature does not name this project and version")
	}
	return nil
}

// sameVersionTag reports whether the registry tag denotes the signed version:
// the same string, the same release spelled with or without trailing zero
// components ("1.35" and "1.35.0"), or the version followed by a build suffix
// introduced by "-" (a glibc flavor or a variant hash). Anything else is
// another version.
func sameVersionTag(signed, tag string) bool {
	signed = strings.TrimPrefix(signed, "v")
	tag = strings.TrimPrefix(tag, "v")
	if signed == "" || tag == "" {
		return false
	}
	if signed == tag || trimZeroes(signed) == trimZeroes(tag) {
		return true
	}
	return strings.HasPrefix(tag, signed+"-") || strings.HasPrefix(signed, tag+"-")
}

// trimZeroes drops trailing ".0" components of a dotted version.
func trimZeroes(v string) string {
	for strings.HasSuffix(v, ".0") {
		v = strings.TrimSuffix(v, ".0")
	}
	return v
}
