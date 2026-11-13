package artifact

import (
	"errors"
	"fmt"
	"strings"
)

// A project name is a NAME. It is not a path, and it is not a URL fragment.
//
// # WHAT HAPPENED WITHOUT THIS
//
// Every lookup builds a URL by concatenation:
//
//	fmt.Sprintf("%s/%s/%s", base, project, "package.yml")
//
// Go sends the path verbatim — it does not clean `..` out of a request —
// and raw.githubusercontent.com answers a traversing path with a 307 to
// the normalised one, which Go's client follows by default. Measured, not
// reasoned about:
//
//	httpGet(".../pkgxdev/pantry/main/projects/../../../../go-zpkg/pantry-overlay/main/README.md")
//	→ 1270 bytes of ANOTHER REPOSITORY'S file
//
// A recipe is not inert. It declares dependencies, a build script and the
// runtime environment a package exports, so fetching one from a repository
// an attacker chose is the whole game: `bk` would run its build script, and
// `pkgx` would resolve and export whatever it says.
//
// # WHERE THE NAME COMES FROM
//
// Not only from a command line, which is why the command line is not the
// place to check it. A project name arrives in:
//
//	a LOCK file      fetched from a repository and acted on by
//	                 `pkgx --lock` and `bk factory --lock`
//	a CATALOGUE      pulled from a registry, read by `pkgx ls`, `search`
//	                 and every <TAB>
//	a RECIPE's deps  which came from one of the above
//
// All three are things that arrive from elsewhere. The check therefore
// lives where the name is USED, not where a person typed it.
//
// # THE RULE
//
// Segments of [A-Za-z0-9._+-], separated by single slashes, at most
// maxProjectSegments of them. Measured against the 1908 projects of the
// published catalogue: every one fits, nothing uses another character, and
// the deepest is four segments
// (github.com/GoogleContainerTools/container-structure-test).
//
// An allowlist rather than a denylist of dangerous shapes, because a
// denylist inherits the blind spots of whoever wrote it — `..` is obvious,
// `..%2f` is not, and a percent-encoded separator was already reaching a
// different path in the probe.

// ErrBadProjectName is returned for a name that cannot be used as one.
var ErrBadProjectName = errors.New("artifact: not a project name")

// maxProjectSegments bounds the depth. Four is the deepest real one; eight
// leaves room without leaving a name that is really a path.
const maxProjectSegments = 8

// maxProjectName bounds the length, so a name cannot be a payload.
const maxProjectName = 200

// ValidateProjectName reports whether a name may be used to build a URL, a
// registry repository or a store path.
func ValidateProjectName(p string) error {
	switch {
	case p == "":
		return fmt.Errorf("%w: empty", ErrBadProjectName)
	case len(p) > maxProjectName:
		return fmt.Errorf("%w: %d characters, limit %d", ErrBadProjectName, len(p), maxProjectName)
	}
	segs := strings.Split(p, "/")
	if len(segs) > maxProjectSegments {
		return fmt.Errorf("%w: %q has %d segments, limit %d",
			ErrBadProjectName, p, len(segs), maxProjectSegments)
	}
	for _, s := range segs {
		switch {
		case s == "":
			// Catches a leading, trailing or doubled slash in one rule.
			return fmt.Errorf("%w: %q has an empty segment", ErrBadProjectName, p)
		case s == "." || s == "..":
			return fmt.Errorf("%w: %q has a %q segment", ErrBadProjectName, p, s)
		}
		for _, r := range s {
			if !isProjectRune(r) {
				return fmt.Errorf("%w: %q contains %q", ErrBadProjectName, p, r)
			}
		}
	}
	return nil
}

func isProjectRune(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		return true
	case r == '.' || r == '-' || r == '_' || r == '+':
		return true
	}
	return false
}
