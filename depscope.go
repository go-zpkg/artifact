package artifact

import (
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"
)

// One reduction of a recipe's dependency map, shared by every reader.
//
// A dependency map carries three kinds of key: a project, a platform block
// (`linux:`, `darwin/aarch64:`) and a VERSION SCOPE (`">=9":`), a block that
// holds only for the package's own version. Two programs used to reduce it —
// this package's reduceDeps and zpkb's build.reduceDepMap — and they disagreed
// on the order of the third pass (random against sorted), on a platform block
// nested in a scope (copied through unreduced against reduced), and on which
// version a scope is read against. go-zpkg/artifact#261's review found that divergence.
// The walk is here, in the lowest shared library, and zpkb calls it.
//
// pkgx has no version scope: libpkgx reduces platform keys only. It is zpkg's
// own extension (zpkb schema/package.schema.json), meaning "the version of the
// package whose recipe this is".

// DepKeyMatcher classifies a dependency-map key. isPlatform reports whether the
// key is a platform block at all; matches reports whether that block applies to
// the target being reduced for. Each caller owns its platform grammar (zpkb
// reads bare architecture keys, this package's host walk does not), the walk
// around it is the same.
type DepKeyMatcher func(key string) (isPlatform, matches bool)

// versionScopeKeyRE matches a dependency-map key that scopes its sub-map to the
// package's OWN version (`">=9": {...}`) instead of naming a project or a
// platform. The schema's depKey grammar admits only [A-Za-z0-9._+-] segments, so
// a key carrying any of < > = ^ ~ * cannot be a project name. It is not a
// first-character test: 26 upstream projects begin with `v`.
var versionScopeKeyRE = regexp.MustCompile(`[<>=^~*]`)

// IsVersionScopeKey reports whether a dependency-map key is a version scope.
func IsVersionScopeKey(k string) bool { return versionScopeKeyRE.MatchString(k) }

// ScopeApplies reports whether a version-scope key holds for a package whose
// version is one of candidates.
//
// With no candidates the version is unknown and the scope applies (the union: a
// closure too large builds something, one too small builds a package missing a
// library). With candidates, the scope applies when ANY satisfies it: all of
// them is a certain yes, none a certain no, and a mix is the union again,
// because the candidates genuinely span both sides.
//
// A candidate whose version cannot be parsed is skipped, and a scope nobody can
// evaluate applies: fail-open, as buildscript.matchGuard does.
func ScopeApplies(key string, candidates []Ver) bool {
	parsed := false
	for _, v := range candidates {
		if v.Raw == "" {
			continue
		}
		parsed = true
		if v.Satisfies(key) {
			return true
		}
	}
	return !parsed
}

// ReduceDepKeys flattens a dependency map to project -> raw value for one
// target. Order is the whole correctness argument, and it is deterministic:
//
//  1. plain project keys,
//  2. platform blocks that match, fewest path elements first (`linux` before
//     `linux/x86-64`), then by name,
//  3. version scopes that apply, sorted by key,
//
// each overriding the one before: the more specific statement wins. A platform
// block inside a scope is reduced for the target too, and so is a scope inside
// a platform block. Values are returned as the recipe wrote them; each caller
// renders a constraint its own way.
func ReduceDepKeys(m map[string]any, platform DepKeyMatcher, candidates []Ver) map[string]any {
	out := map[string]any{}
	var plats, scopes []string
	for k := range m {
		isPlat, _ := platform(k)
		switch {
		case isPlat:
			plats = append(plats, k)
		case IsVersionScopeKey(k):
			scopes = append(scopes, k)
		default:
			out[k] = m[k]
		}
	}
	sort.Slice(plats, func(i, j int) bool {
		a, b := strings.Count(plats[i], "/"), strings.Count(plats[j], "/")
		if a != b {
			return a < b
		}
		return plats[i] < plats[j]
	})
	sort.Strings(scopes)
	merge := func(v any) {
		sub, _ := v.(map[string]any) // a block that is not a mapping adds nothing
		for k, v := range ReduceDepKeys(sub, platform, candidates) {
			out[k] = v
		}
	}
	for _, k := range plats {
		if _, matches := platform(k); matches {
			merge(m[k])
		}
	}
	for _, k := range scopes {
		if ScopeApplies(k, candidates) {
			merge(m[k])
		}
	}
	return out
}

// hostPlatformMatcher is this package's platform grammar: an OS name, or
// `<os>/<arch>`.
func hostPlatformMatcher(osn, arch string) DepKeyMatcher {
	return func(k string) (bool, bool) {
		if !isPlatformKey(k) {
			return false, false
		}
		return true, platformMatches(k, osn, arch)
	}
}

func hasScopeKey(m map[string]any) bool {
	for k, v := range m {
		if IsVersionScopeKey(k) {
			return true
		}
		if sub, ok := v.(map[string]any); ok && hasScopeKey(sub) {
			return true
		}
	}
	return false
}

// reduceDeps flattens a dependency map for one os/arch with the version unknown
// (scopes unioned): the form `companions` and the pantry walks use.
func reduceDeps(m map[string]any, osn, arch string) map[string]string {
	return reduceDepsFor(m, osn, arch, nil)
}

func reduceDepsFor(m map[string]any, osn, arch string, candidates []Ver) map[string]string {
	out := map[string]string{}
	for k, v := range ReduceDepKeys(m, hostPlatformMatcher(osn, arch), candidates) {
		out[k] = constraintText(v)
	}
	return out
}

// versionsForScope lists a project's published versions. A variable so a test
// can answer without a registry.
var versionsForScope = func(project, osn, arch string) ([]Ver, error) {
	vs, _, err := versionsForSourced(project, osn, arch)
	return vs, err
}

// fetchMetaGiven is FetchMetaFor for a project whose version is only known to
// satisfy `constraints`: a version scope is read against the published versions
// that do. Nothing is listed unless the recipe has a scope, so the common case
// costs no request.
func fetchMetaGiven(project, osn, arch string, constraints []string) (map[string]string, error) {
	doc, err := recipeDoc(project)
	if err != nil {
		return nil, err
	}
	d, err := mapField(doc, "dependencies")
	if err != nil {
		return nil, fmt.Errorf("%s: %w", project, err)
	}
	var cands []Ver
	if hasScopeKey(d) {
		all, err := versionsForScope(project, osn, arch)
		if err != nil {
			return nil, fmt.Errorf("%s: listing versions to read a version scope: %w", project, err)
		}
		for _, v := range all {
			if satisfiesAll(v, constraints) {
				cands = append(cands, v)
			}
		}
	}
	return reduceDepsFor(d, osn, arch, cands), nil
}

// maxScopePasses bounds the re-walk in collectGraph.
const maxScopePasses = 8

func sameConstraints(a, b map[string][]string) bool {
	norm := func(m map[string][]string) map[string][]string {
		out := make(map[string][]string, len(m))
		for k, v := range m {
			c := append([]string(nil), v...)
			sort.Strings(c)
			out[k] = c
		}
		return out
	}
	return reflect.DeepEqual(norm(a), norm(b))
}
