package artifact

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// ⛔⛔ ZPKG_DIST IS AN ORDERED LIST OF DIST SOURCES, AND go-pkgx IS NOT ONE.
//
// ZPKG_DIST holds one or more sources separated by whitespace or commas, in
// priority order:
//
//	ZPKG_DIST="oci://10.0.0.1:5111/run/packages oci://ghcr.io/go-zpkg/packages"
//
// The first source is DistBase; the rest are DistExtra. Resolution reads them
// in order:
//
//   - version listing is the UNION across sources, each source consulted in
//     order, a source that does not carry the project contributing nothing;
//   - an artifact is taken from the FIRST source that has it, and every
//     source's artifact is verified against that source's own signature;
//   - the single-value form (one source) behaves exactly as before.
//
// A run that stages artifacts in its own registry lists it first, so the
// dependents of an in-run artifact find it, and then the go-zpkg registry for
// everything already published.
//
// The go-pkgx registry is closed: artifacts are published to go-zpkg only, and
// a dependency resolved from go-pkgx would silently re-introduce what the fleet
// no longer publishes. distSources REFUSES any source whose repository path
// has a go-pkgx component; there is no opt-out.

// DistExtra holds the sources after DistBase, in priority order. It is empty
// for the single-value form of ZPKG_DIST.
var DistExtra []string

// ErrClosedDistRegistry is wrapped by the refusal of a go-pkgx source.
var ErrClosedDistRegistry = fmt.Errorf("go-pkgx is closed")

// SplitDistList splits a ZPKG_DIST value on whitespace and commas, trims
// trailing slashes, and drops empty items and exact duplicates (the first
// occurrence keeps its rank).
func SplitDistList(s string) []string {
	var out []string
	seen := map[string]bool{}
	for _, f := range strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	}) {
		f = strings.TrimRight(f, "/")
		if f == "" || seen[f] {
			continue
		}
		seen[f] = true
		out = append(out, f)
	}
	return out
}

// CheckDistSource refuses a dist source whose repository path is under
// go-pkgx. It looks at path components, case-insensitively, so
// oci://ghcr.io/go-pkgx/packages and https://host/go-pkgx are refused while a
// host merely named like it is a different question.
func CheckDistSource(src string) error {
	rest := src
	if i := strings.Index(rest, "://"); i >= 0 {
		rest = rest[i+3:]
	}
	if i := strings.IndexAny(rest, "?#"); i >= 0 {
		rest = rest[:i]
	}
	if u, err := url.PathUnescape(rest); err == nil {
		rest = u
	}
	parts := strings.Split(rest, "/")
	for _, p := range parts[1:] { // parts[0] is the host
		if strings.EqualFold(p, "go-pkgx") {
			return fmt.Errorf("dist source %q refused: %w: we no longer publish to go-pkgx, "+
				"dependencies resolve from go-zpkg (oci://ghcr.io/go-zpkg/packages) "+
				"and the run's own staging registry only", src, ErrClosedDistRegistry)
		}
	}
	return nil
}

// distSources returns the configured sources in priority order, refusing any
// that CheckDistSource rejects. Every resolution path goes through it, so a
// go-pkgx source fails the call that would have read it.
func distSources() ([]string, error) {
	srcs := make([]string, 0, 1+len(DistExtra))
	srcs = append(srcs, DistBase)
	srcs = append(srcs, DistExtra...)
	for _, s := range srcs {
		if err := CheckDistSource(s); err != nil {
			return nil, err
		}
	}
	return srcs, nil
}

// ValidateDist reports the refusal early, for a CLI that wants to fail before
// it starts resolving.
func ValidateDist() error {
	_, err := distSources()
	return err
}

// distLabel names the configured sources for an error message.
func distLabel() string {
	return strings.Join(append([]string{DistBase}, DistExtra...), " ")
}

// mergeVers returns the union of two ascending lists, ascending, with one
// entry per Raw spelling.
func mergeVers(a, b []Ver) []Ver {
	if len(a) == 0 {
		return b
	}
	seen := make(map[string]bool, len(a))
	out := append([]Ver(nil), a...)
	for _, v := range a {
		seen[v.Raw] = true
	}
	for _, v := range b {
		if !seen[v.Raw] {
			seen[v.Raw] = true
			out = append(out, v)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return cmpVer(out[i], out[j]) < 0 })
	return out
}
