package bottle

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/registry/remote/errcode"
)

// Base URLs for the pkgx distribution + pantry; overridable in tests, and at
// runtime via $ZPKG_DIST / $ZPKG_PANTRY so a consumer can point pkgm/pkgx at a
// local mirror produced by the `mirror` tool.
//
// DistBase defaults to the **signed** OCI registry so the default install
// path is verifiable end-to-end (pairs with VerifyRequired defaulting on). That
// registry is a growing subset of the pantry; for the full upstream catalogue set
// ZPKG_DIST=https://dist.pkgx.dev (unsigned → also set ZPKG_VERIFY=0).
//
// ⛔⛔ THE ORG IN THIS URL IS A DEPLOYMENT FACT, NOT OUR NAME, AND THE RENAME
// GOT IT WRONG. The go-pkgx → go-zpkg pass rewrote it to
// `ghcr.io/go-zpkg/packages`, which every release from v0.64.0 to v0.68.0
// carries. Measured 2026-11-04 with ghcrprobe, anonymously, against a control:
//
//	ghcr.io/go-pkgx/packages/gnu.org/bash   PRESENT  (tag sha256-64caff4d…)
//	ghcr.io/go-pkgx/packages/zlib.net       PRESENT  (tag sha256-21c9e221…)
//	ghcr.io/go-zpkg/packages/gnu.org/bash   ABSENT
//	ghcr.io/go-zpkg/packages/zlib.net       ABSENT
//
// GitHub's container packages are org-scoped and did NOT follow the repository
// transfer: the repositories all moved, every bottle stayed. So those five
// releases point the whole fleet at an empty registry, and `zpkgx` cannot
// fetch anything with its defaults — which is what the `FROM scratch, offline`
// check was reporting in go-zpkg/zpkgx#141 while I read it as a path problem.
//
// Renaming a URL did not move what it addresses. The bottles move by COPY,
// and this line follows them — not the other way round. Until that copy has
// run and been verified, this is where they are.
// DefaultDistBase is the same value as DistBase's initial one, as a CONSTANT.
//
// ⛔ DistBase IS A VAR THAT TESTS REASSIGN, so it cannot be used to check what
// the documentation claims the default is: the first version of
// readmedefault_test.go compared the README against DistBase, passed under
// `-run`, and failed in the full suite with
//
//	the README does not name the real default "http://127.0.0.1:55863"
//
// — another test had pointed it at an httptest server first. A gate that
// reads mutable global state tests the order the suite happened to run in.
const DefaultDistBase = "oci://ghcr.io/go-pkgx/packages"

var (
	DistBase   = DefaultDistBase
	PantryBase = "https://raw.githubusercontent.com/pkgxdev/pantry/main/projects"

	// PantryOverlay is MERGED OVER PantryBase for a project's package.yml: a
	// key the overlay states replaces that key, a key it omits is inherited
	// from upstream, and a list replaces rather than merges. A small curated
	// overlay can then carry corrected recipes (e.g. a stale
	// `openssl.org: ^1.1` bumped to a constraint that matches the published
	// bottles) without forking the whole pantry.
	//
	// This said "consulted BEFORE PantryBase, falling back when the overlay
	// has no recipe" until #103, and that description outlived the code by
	// long enough to matter. Preferring the overlay WHOLE was right while every
	// entry was a full copy of an upstream recipe; go-zpkg/pantry-overlay#50
	// then reduced all 183 to the keys they change, so an entry read whole is a
	// FRAGMENT — under the old rule curl.se would resolve to `dependencies` and
	// nothing else, with no distributable and no build. bk read one that way
	// and its closure collapsed from 54 projects to 8 (go-zpkg/bk#232).
	//
	// A comment that describes a superseded rule is worse than none, because it
	// is believed: this is the second one found today.
	//
	// It defaults to OUR overlay because DistBase defaults to OUR registry, and
	// the two have to agree. They did not, and the disagreement was silent:
	//
	//	$ pkgm install rust-lang.org/cargo      # defaults, darwin/aarch64
	//	$ cargo --version
	//	$ echo $?
	//	137
	//
	// The published cargo links openssl 3, and says so — `@rpath/openssl.org/
	// v3.6.4/lib/libssl.3.dylib`. Upstream's recipe does not mention openssl at
	// all, so the resolver installed 1.1.1w (pulled in by libssh2) and the
	// binary died on a library nothing had installed. The corrected recipe was
	// in the overlay the whole time, and nothing consulted it.
	//
	// ZPKG_PANTRY_OVERLAY overrides it; "none" turns it off and resolves
	// everything upstream.
	PantryOverlay = "https://raw.githubusercontent.com/go-zpkg/pantry-overlay/main/projects"

	// UpstreamDist is a SECOND distribution consulted for the versions of a
	// project our own DistBase does not carry. Empty means there is none, and
	// that is the default.
	//
	// ⛔⛔ THE MECHANISM IS KEPT, THE VALUE IS NOT. This was
	// `https://dist.pkgx.dev` — upstream pkgx's distribution — compiled in and
	// always on, so every lookup our registry could not answer silently became
	// a question asked of another project. That was right while this was a
	// mirror with a gap-filler. It is wrong for a distribution: a project we
	// do not carry should SAY SO, not resolve to somebody else's bottle.
	//
	// Measured 2026-11-04 on a one-in-forty sample of the 1907 recipes: of the
	// bottles published and read, 0% were built here and 100% were mirrored,
	// on darwin/aarch64 and linux/x86-64 alike, toolchain included. So the
	// fallback is not a corner case today — which is exactly why it has to
	// become a stated choice rather than a built-in assumption.
	//
	// Set ZPKG_UPSTREAM_DIST to point at one; "none" is the explicit off, as
	// with ZPKG_PANTRY_OVERLAY. Our own factory sets it while the rebuild is
	// in flight, which puts the dependency in a workflow where it can be read
	// instead of in a constant where it cannot.
	UpstreamDist = ""

	// ImplicitRootsOff drops the implicit system-library roots from closure
	// completion. See implicitRoots; set from ZPKG_IMPLICIT_ROOTS=none.
	ImplicitRootsOff = false

	// CacheBase is an OCI registry consulted for the BOTTLE ITSELF before
	// DistBase — a pull-through cache next to the builders, so a job does not
	// fetch llvm.org's ~1.7 GiB across the network again.
	//
	// It deliberately takes NO part in resolution. A pull-through cache cannot
	// list the tags of a repository it has not synced yet, so listing against it
	// falls back to the upstream dist, which yields a VERSION where our registry
	// wants a TAG — gnu.org/bash is published as `5.3`, not `5.3.0` — and the
	// pull then 404s on a tag that never existed. Measured; it is why this is a
	// separate variable and not simply ZPKG_DIST pointed elsewhere.
	//
	// What the cache serves is still verified against the signature DistBase
	// advertises, so a cache that returns the wrong bytes is rejected rather
	// than trusted.
	CacheBase = ""
)

func init() { applyEnv(Env) }

// ociClientCache memoises OCIClients by dist base so the bearer-token cache is
// reused across calls (and rebuilds automatically when DistBase changes, e.g. in
// tests or when a consumer re-points ZPKG_DIST).
var (
	ociClientCache = map[string]*OCIClient{}
	ociClientMu    sync.Mutex
)

// ociClientForDist returns the OCIClient for the current DistBase, cached.
func ociClientForDist() (*OCIClient, error) { return ociClientFor(DistBase) }

// ociCacheClient returns the client for CacheBase, or nil when no cache is
// configured or it is not an OCI registry. A cache that cannot be reached is
// not an error: the caller falls back to DistBase.
func ociCacheClient() *OCIClient {
	if CacheBase == "" || !IsOCI(CacheBase) {
		return nil
	}
	c, err := ociClientFor(CacheBase)
	if err != nil {
		return nil
	}
	return c
}

func ociClientFor(base string) (*OCIClient, error) {
	ociClientMu.Lock()
	defer ociClientMu.Unlock()
	if c, ok := ociClientCache[base]; ok {
		return c, nil
	}
	c, err := NewOCIClient(base)
	if err != nil {
		return nil, err
	}
	ociClientCache[base] = c
	return c, nil
}

// applyEnv overrides DistBase/PantryBase from ZPKG_DIST/ZPKG_PANTRY (testable).
func applyEnv(get func(string) string) {
	if d := get("ZPKG_DIST"); d != "" {
		DistBase = strings.TrimRight(d, "/")
	}
	if p := get("ZPKG_PANTRY"); p != "" {
		PantryBase = strings.TrimRight(p, "/")
	}
	// ZPKG_IMPLICIT_ROOTS=none says the MACHINE supplies the implicit system
	// libraries -- libc, and the gcc runtime when something links it -- so a
	// closure must not reach for bottles of them. It is named after the
	// function it disables rather than after glibc, because it governs all
	// three roots and a glibc-shaped name would under-describe two of them.
	//
	// "none" rather than an empty value, for the reason the overlay below
	// gives, and "none" rather than a boolean so the two knobs read alike.
	if r := get("ZPKG_IMPLICIT_ROOTS"); r == "none" {
		ImplicitRootsOff = true
	}
	// "none" is how a caller says "no overlay": an empty value cannot mean it,
	// because an unset variable and one set to nothing are the same string here,
	// and defaulting on an unset variable is the whole point.
	// A second distribution is opt-in: the default is that we are the only
	// one. See UpstreamDist for why it stopped being compiled in.
	if u := get("ZPKG_UPSTREAM_DIST"); u != "" {
		UpstreamDist = strings.TrimRight(u, "/")
	}
	if p := get("ZPKG_PANTRY_OVERLAY"); p != "" {
		if p == "none" {
			PantryOverlay = ""
		} else {
			PantryOverlay = strings.TrimRight(p, "/")
		}
	}
	if c := get("ZPKG_CACHE"); c != "" {
		CacheBase = strings.TrimRight(c, "/")
	}
}

// fetchRecipe returns a project's recipe as HCL bytes, trying PantryOverlay
// first (when set) and falling back to PantryBase when the overlay lacks that
// project.
//
// HCL is the format this client speaks. Our own overlay is written in it, and
// an upstream package.yml is converted HERE, on the way in — so this function
// is the last place in the tree that knows two formats exist. Nothing is
// written to disk and upstream is not forked; the conversion is a step in a
// fetch.
//
// It used to run the other way, converting HCL to YAML so the readers below
// could keep their yaml.Node fields. That put a YAML emitter on the path of
// every recipe, and yaml.v3 can emit a block scalar it cannot re-read —
// priver.dev/geni is the one that does. Going this direction, nothing on the
// recipe path emits YAML at all.
func fetchRecipe(project string) ([]byte, error) {
	doc, err := recipeDoc(project)
	if err != nil {
		return nil, err
	}
	return []byte(EmitHCL(doc)), nil
}

// fetchSide reads ONE pantry's copy of a recipe, reporting separately whether
// it is there and whether asking failed.
//
// The two are not the same answer and conflating them is how an override stops
// applying in silence: a 404 means this pantry does not carry the project, and
// anything else means we do not know. Reading "not found" out of a timeout
// would resolve the recipe the overlay exists to replace, and nothing would
// say so — the same shape the comment on `repoAbsent` warns about, that
// classifying a transport failure by the words in its message turns a
// transient error into a different, silent answer.
func fetchSide(base, project string) (map[string]any, bool, error) {
	if base == "" {
		return nil, false, nil
	}
	// THE NAME GOES INTO A URL BY CONCATENATION, so it is checked here
	// rather than wherever it was typed: it mostly was not typed at all,
	// but read out of a lock or a catalogue. See ValidateProjectName.
	if err := ValidateProjectName(project); err != nil {
		return nil, false, err
	}
	// HCL first, and only then YAML. Our own overlay is written in HCL;
	// upstream's pantry is YAML.
	for _, name := range []string{"package.hcl", "package.yml"} {
		body, err := httpGet(fmt.Sprintf("%s/%s/%s", base, project, name))
		switch {
		case err == nil:
			src := body
			if name == "package.yml" {
				if src, err = YAMLToHCL(body, project+"/package.yml"); err != nil {
					return nil, false, err
				}
			}
			doc, err := HCLToMap(src, project+"/"+name)
			return doc, err == nil, err
		case !isNotFound(err):
			return nil, false, err
		}
	}
	return nil, false, nil
}

// mergeRecipe deep-merges the overlay's document over the pantry's.
//
// A key the overlay states replaces that key; a key it does not mention is
// INHERITED. That is what makes an overlay an overlay rather than a fork: an
// entry can say only the two lines it changes, and everything else follows
// upstream instead of drifting from a copy taken once.
//
// LISTS ARE REPLACED, not merged — the same rule the build-side overrides
// follow (go-zpkg/bk's `logical` package). Kustomize merges some lists by a
// "merge key" and replaces others and needs OpenAPI metadata to know which;
// there is no merge key for the lines of a shell script.
//
// Omission stopping to mean removal is the one semantic change, and it was
// measured before it was made: of the 175 overlay projects upstream also
// carries, 8 omit a key the built recipe has, all of them under `build` and
// `test`, and NONE under a key a consumer reads.
func mergeRecipe(base, over map[string]any) map[string]any {
	out := make(map[string]any, len(base)+len(over))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range over {
		if om, ok := v.(map[string]any); ok {
			if bm, ok2 := out[k].(map[string]any); ok2 {
				out[k] = mergeRecipe(bm, om)
				continue
			}
		}
		out[k] = v
	}
	return out
}

// recipeDoc fetches a recipe and reads it as a document.
//
// One place parses, so the three readers below differ only in what they look
// for. Each of them used to unmarshal the bytes into a struct of its own with
// its own error wording, and two of those said "package.yml" about a recipe
// that may well be HCL.
func recipeDoc(project string) (map[string]any, error) {
	base, hasBase, err := fetchSide(PantryBase, project)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", project, err)
	}
	over, hasOver, err := fetchSide(PantryOverlay, project)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", project, err)
	}
	switch {
	case hasBase && hasOver:
		return mergeRecipe(base, over), nil
	case hasOver:
		// Upstream does not carry this project at all, so the overlay's copy
		// is the whole recipe — for a consumer here and for the builder, which
		// reads it the same way (go-zpkg/bk#231).
		return over, nil
	case hasBase:
		return base, nil
	}
	return nil, fmt.Errorf("no recipe for %s in %s or %s", project, PantryOverlay, PantryBase)
}

// Dir resolves the bottle store (ZPKG_DIR, default ~/.zpkg), expanding the
// platform placeholders described by [ExpandStorePath].
//
// ⛔⛔ `~/.zpkg`, AND IT IS UPSTREAM'S DIRECTORY WE ARE GETTING OUT OF. pkgx
// documents its own store as `~/.pkgx/<project>/v<version>/` — upstream's own
// corpus, read 2026-11-04 — and upstream's `pkgx` can now sit on the same
// PATH as ours, which is the entire reason the binaries were renamed. Two
// implementations writing one directory, under two different layouts (ours
// carries a variant hash; see storepath.go), is the collision the rename
// existed to remove, left in the one place it does the most damage.
//
// It is also what every command PRINTS. The landing page's transcripts said
//
//	1965 project(s) → ~/.pkgx/catalog/linux-x86-64.json
//
// after the rename, and the page was right — that is what the code returned.
// A product that answers with somebody else's directory has not been renamed,
// it has been relabelled.
//
// ⛔ NOTHING IS MIGRATED, ON PURPOSE. An existing `~/.pkgx` is pkgx's as much
// as ours and we cannot tell which bottles in it are whose; moving it would
// be taking somebody else's files. A user who wants the old store keeps it
// with ZPKG_DIR=~/.pkgx, which is one line and says what it means.
func Dir() string {
	if d := Env("ZPKG_DIR"); d != "" {
		return ExpandStorePath(d)
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".zpkg")
}

// storePlaceholders are the names [ExpandStorePath] knows.
var storePlaceholders = []string{"{platform}", "{os}", "{arch}"}

// ExpandStorePath replaces the platform placeholders in a store path:
// `{platform}` becomes `linux-x86-64`, `{os}` becomes `linux` and `{arch}`
// becomes `x86-64`, all for the RUNNING machine.
//
// ⛔ ONE STORE CANNOT HOLD TWO ARCHITECTURES, and nothing said so. A prefix is
// `$ZPKG_DIR/<project>/v<version>/…` with no platform anywhere in it.
// Measured 2026-10-29 on one machine, the same project and version staged
// twice:
//
//	…/openssl.org/v3.6.4/lib/libssl.so.3     ELF 64-bit x86-64
//	…/openssl.org/v3.6.4/lib/libssl.3.dylib  Mach-O arm64
//
// Those two were kept apart only by being under different ZPKG_DIRs. Here the
// FILE NAMES differ because the operating systems do; between linux/x86-64 and
// linux/aarch64 they are identical — `lib/libssl.so.3` both times — so a store
// shared over NFS holds whichever architecture was installed last, and the
// other one gets `Exec format error` from the kernel with no explanation.
//
// ⛔ WHY THIS MATTERS ON A CLUSTER, specifically. srun's `--export` defaults to
// ALL — Slurm's own documentation: "All of the user's environment will be
// loaded from the caller's environment" — so the PATH composed on the head node
// arrives unchanged on every compute node. A head of one architecture and nodes
// of another is then two failures at once: the PATH names the head's binaries,
// and the store they point into cannot contain the node's.
//
// Giving the platform a place IN the path is what Spack does (its prefixes
// carry platform, os and target) and it costs nothing here: a path with no
// placeholder is returned unchanged, so every existing store keeps working.
//
//	ZPKG_DIR=/shared/pkgx/{platform}     one tree per architecture, one NFS export
//	ZPKG_DIR=/shared/pkgx/{os}/{arch}    the same, split
//
// ⛔ BRACES, NOT `$`: the shell expands `$PLATFORM` before pkgx ever sees it,
// and a value the shell has already eaten cannot be resolved per node. `{…}`
// survives quoting and reaches the program, which is the point — the SAME
// exported string has to mean a different directory on each node.
func ExpandStorePath(p string) string {
	if !strings.ContainsRune(p, '{') {
		return p
	}
	osn, arch := HostSlug()
	return strings.NewReplacer(
		"{platform}", osn+"-"+arch,
		"{os}", osn,
		"{arch}", arch,
	).Replace(p)
}

// UnknownStorePlaceholders lists the `{…}` names left in a store path that
// [ExpandStorePath] does not know.
//
// ⛔ A MISSPELT PLACEHOLDER IS WORSE THAN NO PLACEHOLDER. `{platfrom}` expands
// to nothing, so the store becomes a directory literally called `{platfrom}` —
// which works, silently, as a single-architecture store, and the cluster it was
// meant to fix fails the same way it did before. Dir cannot return an error
// without changing every caller, so the question is asked separately and the
// commands report it.
func UnknownStorePlaceholders(p string) []string {
	var out []string
	for rest := p; ; {
		open := strings.IndexRune(rest, '{')
		if open < 0 {
			return out
		}
		rest = rest[open:]
		end := strings.IndexRune(rest, '}')
		if end < 0 {
			return out // an unclosed brace is not a placeholder
		}
		name := rest[:end+1]
		if !slices.Contains(storePlaceholders, name) {
			out = append(out, name)
		}
		rest = rest[end+1:]
	}
}

// HostSlug returns the pkgx (os, arch) slug for the running machine.
func HostSlug() (string, string) {
	return goos(), goarch()
}

// --- version type + constraint matching ------------------------------------

// Ver is a parsed pkgx version: its numeric components plus the raw string.
//
// Tag is the registry tag the version was found under, when that differs from
// Raw — a glibc-flavored build lives at `<version>-glibc<ver>` while remaining
// version <version>. Everything version-shaped (comparison, constraints, the
// installed v<version> prefix) uses Raw; only the registry pull uses the tag.
type Ver struct {
	Raw  string
	Nums []int
	Tag  string
	// Rebuild is the N in `1.8.2_N`: the SAME upstream software, built again
	// — for a compiler security release, say, where nothing about the recipe
	// or the version changes and the binary does.
	//
	// Absent means 0, which is Debian's rule for its own revision ("the
	// absence of a debian_revision is equivalent to a debian_revision of 0")
	// and, here, the literal state of the registry: measured 2026-10-10, 0
	// of 1371 published version strings carry one.
	Rebuild int
	// Variant is the concrete spec's hash from the tag's `-h<hash>` suffix:
	// WHICH BUILD of this version, when several were published.
	//
	// It is not ordered and never will be. A rebuild counter says "newer than";
	// a variant hash says "different from", and two builds of one version are
	// siblings rather than a sequence. That is why cmpVer ignores it and
	// numericKey does not: ordering by it would invent a preference the
	// registry never expressed, and dropping it from the identity would
	// collapse two bottles into one — the defect numericKey already carries a
	// comment about.
	Variant string
}

// tag is the registry tag to pull this version from.
func (v Ver) tag() string {
	if v.Tag != "" {
		return v.Tag
	}
	return v.Raw
}

// ParseVer parses a pkgx version string into a Ver, stopping each component at
// the first non-numeric character (e.g. "1w" in openssl 1.1.1w).
func ParseVer(s string) Ver {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	v := Ver{Raw: s}
	body, rebuild := splitRebuild(s)
	v.Rebuild = rebuild
	parts := strings.Split(body, ".")
	for _, p := range parts {
		// stop at first non-numeric segment (e.g. "1w" in openssl 1.1.1w)
		n := 0
		i := 0
		for i < len(p) && p[i] >= '0' && p[i] <= '9' {
			n = n*10 + int(p[i]-'0')
			i++
		}
		v.Nums = append(v.Nums, n)
	}
	return v
}

// splitRebuild cuts a trailing `_N` rebuild counter off a version.
//
// ⛔ WHY IT NEEDS A DISCRIMINATOR. `_` is admitted by ValidateVersionString
// because it is ordinary in versions elsewhere, so `2026_09_25` is a shape
// this parser could meet — and reading its `_25` as a rebuild would turn one
// release into the 25th build of another.
//
// The rule is therefore: the part BEFORE the underscore must be dotted. A
// rebuild counter is something bk appends to a version it already resolved,
// and every version this registry carries is dotted — measured 2026-10-10,
// 1371 published version strings, the only non-alphanumeric rune among them
// being `.`, not one underscore. A date-like `2026_09_25` has no dot before
// its underscore and is left whole.
//
// `_beta` is not a rebuild either: what follows must be all digits.
func splitRebuild(s string) (body string, rebuild int) {
	i := strings.LastIndexByte(s, '_')
	if i <= 0 || i == len(s)-1 {
		return s, 0
	}
	head, tail := s[:i], s[i+1:]
	if !strings.Contains(head, ".") {
		return s, 0
	}
	n := 0
	for k := 0; k < len(tail); k++ {
		if tail[k] < '0' || tail[k] > '9' {
			return s, 0
		}
		n = n*10 + int(tail[k]-'0')
	}
	return head, n
}

// cmpVer orders two versions: the numeric components first, then the REBUILD
// counter.
//
// ⛔ WITHOUT THE SECOND HALF, A REBUILD IS INVISIBLE AND AN EXACT PIN LIES.
// ParseVer stops each component at the first non-digit, so `1.8.2_1` and
// `1.8.2` both yielded Nums [1 8 2] and compared EQUAL. Measured 2026-10-10,
// before this existed:
//
//	1.8.2 satisfies "=1.8.2_1" ? true
//	1.8.2_1 satisfies "=1.8.2" ? true
//
// A lock pinning the rebuilt bottle would therefore have installed the
// un-rebuilt one — the vulnerable one — and said nothing. `satisfies` routes
// every operator through here, so ordering and exactness are the same fix.
func cmpVer(a, b Ver) int {
	for i := 0; i < len(a.Nums) || i < len(b.Nums); i++ {
		var x, y int
		if i < len(a.Nums) {
			x = a.Nums[i]
		}
		if i < len(b.Nums) {
			y = b.Nums[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	if a.Rebuild != b.Rebuild {
		if a.Rebuild < b.Rebuild {
			return -1
		}
		return 1
	}
	return 0
}

// satisfies reports whether version v meets a pkgx constraint string.
// Supported: "" / "*" (any), "^A.B.C" (>=, same major), "~A.B.C" (>=, same
// major.minor), the range operators ">=", ">", "<=", "<", an exact "=A.B.C",
// and a bare "A.B.C" (treated as a caret-style lower bound so partial pins like
// "1" or "1.1" match a whole line). The upper-bound operators "<"/"<=" are what
// build-dep pins such as `llvm.org: <19` use.
// satisfies reports whether v meets a pkgx constraint, including the compound
// forms: alternatives separated by "||", and a conjunction of comparators
// written with or without a space (">=3<3.12", ">=3 <3.12").
//
// Neither was handled, and the failure was not a refusal. ParseVer swallows the
// second comparator and concatenates what follows, so the constraint became a
// DIFFERENT one:
//
//	ParseVer("3<3.12")    = [3 12]     -> ">=3<3.12"    read as ">=3.12"
//	ParseVer("1.75<1.78") = [1 75 78]  -> ">=1.75<1.78" read as ">=1.75.78"
//
// A recipe pinning `python.org: '>=3<3.12'` — because it does not work on 3.12
// and later — was therefore refused 3.11.16, the version it wants, and offered
// 3.14.7, the one it excludes. 106 recipes in the pantry write a constraint of
// this shape; none of the ones checked has a bottle built by this factory.
//
// "||" was simply false for everything, so `^16 || ^18 || ^20` matched no
// nodejs at all.
func (v Ver) satisfies(c string) bool {
	c = strings.TrimSpace(strings.Trim(c, "'\""))
	if c == "" || c == "*" {
		return true
	}
	// Alternatives: any one is enough.
	if alts := strings.Split(c, "||"); len(alts) > 1 {
		for _, a := range alts {
			if v.satisfies(a) {
				return true
			}
		}
		return false
	}
	// A conjunction of comparators: every one must hold.
	if parts := splitComparators(c); len(parts) > 1 {
		for _, p := range parts {
			if !v.satisfies(p) {
				return false
			}
		}
		return true
	}
	op := "^"
	switch { // longer operators first so ">=" beats ">" and "<=" beats "<"
	case strings.HasPrefix(c, ">="):
		op, c = ">=", strings.TrimSpace(c[2:])
	case strings.HasPrefix(c, "<="):
		op, c = "<=", strings.TrimSpace(c[2:])
	case strings.HasPrefix(c, ">"):
		op, c = ">", strings.TrimSpace(c[1:])
	case strings.HasPrefix(c, "<"):
		op, c = "<", strings.TrimSpace(c[1:])
	case strings.HasPrefix(c, "^"):
		op, c = "^", c[1:]
	case strings.HasPrefix(c, "~"):
		op, c = "~", c[1:]
	case strings.HasPrefix(c, "="):
		op, c = "=", c[1:]
	}
	base := ParseVer(c)
	switch op {
	case ">=":
		return cmpVer(v, base) >= 0
	case ">":
		return cmpVer(v, base) > 0
	case "<=":
		return cmpVer(v, base) <= 0
	case "<":
		return cmpVer(v, base) < 0
	case "=":
		return cmpVer(v, base) == 0
	case "~":
		if cmpVer(v, base) < 0 {
			return false
		}
		// ~ pins all-but-the-last specified component: ~2 -> major, ~2.6 and
		// ~2.6.3 -> major.minor. Pin count = len(base) capped at 2.
		n := len(base.Nums)
		if n > 2 {
			n = 2
		}
		return sameN(v, base, n)
	default: // "^" and bare
		if cmpVer(v, base) < 0 {
			return false
		}
		return sameN(v, base, 1)
	}
}

// sameN reports whether the first n version components match.
func sameN(v, base Ver, n int) bool {
	for i := 0; i < n; i++ {
		var x, y int
		if i < len(v.Nums) {
			x = v.Nums[i]
		}
		if i < len(base.Nums) {
			y = base.Nums[i]
		}
		if x != y {
			return false
		}
	}
	return true
}

// --- network ----------------------------------------------------------------

// httpGetAttempts is how many times a transient failure is retried. Every
// recipe and every version listing is one GET against raw.githubusercontent,
// which 503s under load: two kernel builds in a row died seven minutes in on
//
//	GET …/projects/perl.org/package.yml: 503 first byte timeout
//	GET …/projects/github.com/westes/flex/package.yml: 503 Service Unavailable
//
// after fetching and configuring a whole kernel. A single-shot GET makes the
// build only as reliable as the flakiest CDN response in the closure.
const httpGetAttempts = 4

// httpRetryDelay is the base of the linear backoff between attempts.
const httpRetryDelay = 250 * time.Millisecond

// sleep is a seam: a test drives the retry loop without waiting for it.
var sleep = time.Sleep

// retriable reports whether a status is worth another attempt: the 5xx family
// and 429, never a 404 (which means "this project has no such file" and is an
// answer, not a hiccup).
func retriable(status int) bool {
	return status == http.StatusTooManyRequests || status >= 500
}

// httpGet fetches url, retrying a transport error or a transient status with a
// short linear backoff.
func httpGet(url string) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt < httpGetAttempts; attempt++ {
		if attempt > 0 {
			sleep(time.Duration(attempt) * httpRetryDelay)
		}
		body, status, err := httpGetOnce(url)
		switch {
		case err == nil && status == 200:
			return body, nil
		case err != nil:
			lastErr = err
		case retriable(status):
			lastErr = &httpStatusError{url: url, status: status}
		default:
			return nil, &httpStatusError{url: url, status: status}
		}
	}
	return nil, lastErr
}

// httpGetOnce is a single attempt: the body on success, the status either way.
// httpStatusError is a non-200 from a plain HTTP dist. It prints exactly what
// the fmt.Errorf it replaced printed, so nothing reading the text changes; it
// carries the STATUS so a caller does not have to read the text at all.
//
// repoAbsent, a few hundred lines below, says why that matters: "Classifying a
// transport failure by the words in its message is how a transient error
// becomes a different, silent answer." The OCI path already had a typed status
// to ask. This path did not.
type httpStatusError struct {
	url    string
	status int
}

func (e *httpStatusError) Error() string {
	return fmt.Sprintf("GET %s: %s", e.url, http.StatusText(e.status))
}

// isNotFound reports a 404 from the plain-HTTP dist path.
func isNotFound(err error) bool {
	var e *httpStatusError
	return errors.As(err, &e) && e.status == http.StatusNotFound
}

func httpGetOnce(url string) ([]byte, int, error) {
	resp, err := HTTPClient.Get(url)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, resp.StatusCode, nil
	}
	b, err := io.ReadAll(resp.Body)
	return b, resp.StatusCode, err
}

// FetchVersions returns the available versions of a project for the host
// os/arch, ascending.
func FetchVersions(project string) ([]Ver, error) {
	osn, arch := HostSlug()
	return VersionsFor(project, osn, arch)
}

// VersionsFor returns the available versions of a project for an explicit pkgx
// os/arch slug (e.g. "linux"/"aarch64"), ascending. Used by mirror tooling that
// spans arches other than the host's.
//
// When DistBase is an OCI registry (the factory default), version listing comes
// from that registry's tags. That registry is a growing subset of the upstream
// catalogue, so build-time deps (e.g. llvm.org, perl.org) may not be published
// there yet and list zero versions. In that case we fall back to the upstream
// pkgx dist so dep resolution matches the version `pkgx +<pkg>` installs at build
// time — the actual bottle *pull* still goes through DistBase unchanged, so this
// only affects version listing, not the install source.
func VersionsFor(project, osn, arch string) ([]Ver, error) {
	vs, _, err := versionsForSourced(project, osn, arch)
	return vs, err
}

// VersionsForSourced is VersionsFor plus WHERE the list came from: true when
// it is this registry's tag listing, false when it is the upstream dist it
// falls back to.
//
// A resolver does not care — either list resolves a constraint, and the
// install still pulls from DistBase. A CATALOGUE does, and this exists
// because it was about to get it wrong: `bk catalog --versions` would have
// written UPSTREAM's versions beside a project this registry has never
// published, and `pkgx ls` would have offered a version that cannot be
// installed. "Available" is a claim about one registry, so a list from a
// different one is not a weaker answer to the question — it is an answer to
// another question.
//
// Pair it with PublishedTagFor to go from "this registry has the tag" to
// "this registry has it FOR YOU": a tag listing spans every platform, so a
// mirror wave that lands one architecture publishes a tag the other cannot
// use.
func VersionsForSourced(project, osn, arch string) ([]Ver, bool, error) {
	return versionsForSourced(project, osn, arch)
}

// PublishedTagFor reports whether THIS registry carries a version for a
// platform, and under which tag.
//
// The second half of the catalogue's question, and the reason it is this
// rather than a bare OCIClient.HasPlatform: one version has several
// spellings and they do not always hold the same platforms — gnu.org/tar
// has its linux bottles under `1.35` and its darwin ones under `1.35.0`.
// Asking about one spelling answers about one spelling. This asks about the
// version.
//
// It also goes through the cached client, which matters when the caller is
// a catalogue build asking about two thousand projects in a row.
func PublishedTagFor(project string, v Ver, osn, arch string) (string, bool, error) {
	return publishedTagFor(project, v, osn, arch)
}

// versionsForSourced is VersionsFor plus WHERE the list came from: true when it
// is this registry's tag listing, false when it fell back to the upstream dist.
// The distinction matters because the tag listing is not per-platform, so a
// caller that must pick an INSTALLABLE version has to check membership itself —
// see PickVersionFor.
func versionsForSourced(project, osn, arch string) ([]Ver, bool, error) {
	if IsOCI(DistBase) {
		vs, err := ociVersionsFor(project)
		if err != nil {
			// A project we have never published isn't a repository in our
			// registry at all — ghcr answers the tag listing with 404
			// NAME_UNKNOWN. That is the same "not carried here" case as an empty
			// list (a build-dep like rust-lang.org/curl.se/python.org), so fall
			// back to the upstream dist rather than failing the whole recipe.
			// Genuine transient/auth errors still propagate.
			if repoAbsent(err) {
				if !haveUpstream() {
					return nil, false, notCarried(project, osn, arch)
				}
				up, err := httpVersionsFor(UpstreamDist, project, osn, arch)
				// bothPlacesLooked here TOO. Two branches fall back to the
				// upstream dist and only the one below said what its 404
				// meant, so the message written for a new architecture was
				// missing from the case a new architecture actually hits: on a
				// seed registry nothing is published, so a project is not a
				// repository AT ALL and the walk arrives here, never below.
				// What a run printed was
				//
				//	resolve deps: GET https://dist.pkgx.dev/llvm.org/linux/s390x/versions.txt: Not Found
				//
				// which is the exact string bothPlacesLooked exists to stop
				// anyone reading as a network fault.
				return up, false, bothPlacesLooked(err, project, osn, arch)
			}
			return nil, false, err
		}
		if len(vs) > 0 {
			return vs, true, nil
		}
		if !haveUpstream() {
			return nil, false, notCarried(project, osn, arch)
		}
		up, err := httpVersionsFor(UpstreamDist, project, osn, arch)
		return up, false, bothPlacesLooked(err, project, osn, arch)
	}
	vs, err := httpVersionsFor(DistBase, project, osn, arch)
	return vs, false, err
}

// haveUpstream reports whether a second distribution is configured at all.
//
// "none" is the explicit off, spelled as ZPKG_PANTRY_OVERLAY spells it, so a
// reader meeting one knows the other.
func haveUpstream() bool {
	return UpstreamDist != "" && UpstreamDist != "none"
}

// notCarried is the answer when THIS distribution does not carry a project
// and there is no second one to ask.
//
// ⛔ IT MUST NOT SAY "NEITHER", which is what bothPlacesLooked says. Naming
// two places when one was consulted is the same defect as a count that stops
// at the answer: it reports a search that did not happen, and sends the
// reader to check a second registry that was never configured.
func notCarried(project, osn, arch string) error {
	return fmt.Errorf("no %s for %s/%s: %s does not carry it, and no upstream is configured (set ZPKG_UPSTREAM_DIST)",
		project, osn, arch, DistBase)
}

// bothPlacesLooked rewrites the upstream fallback's 404 to say what it means.
//
// The raw error is a URL, and it reads like a network fault:
//
//	GET https://dist.pkgx.dev/llvm.org/linux/s390x/versions.txt: Not Found
//
// It is not one. Two registries were consulted and neither carries this
// project for this platform — which on a NEW architecture is the normal state
// of the world, not a failure to reach anything. Upstream publishes no s390x
// at all, so every lookup that falls through here can only 404, and the URL
// sends the reader to check their network instead of their platform.
//
// Only a "not found" is rewritten. A timeout or a 500 IS about reaching the
// server, and saying otherwise would move the lie rather than remove it.
func bothPlacesLooked(err error, project, osn, arch string) error {
	if err == nil || !isNotFound(err) {
		return err
	}
	return fmt.Errorf("no %s for %s/%s: neither %s nor %s publishes it (%w)",
		project, osn, arch, DistBase, UpstreamDist, err)
}

// repoAbsent reports whether err signals that the OCI registry simply does not
// carry the project (ghcr returns HTTP 404 with "name unknown: repository name
// not known to registry"), as opposed to a transient or auth error that should
// propagate.
func repoAbsent(err error) bool {
	// ⛔ NIL IS NOT AN ABSENCE, AND MUST NOT BE A PANIC. Every call inside
	// this package already holds a non-nil error, so the prose fallback
	// below — err.Error() — was never reached with nil and the gap never
	// showed. Exporting it as IsNotPublished puts it in front of callers
	// who will reasonably ask `if bottle.IsNotPublished(err)` after a call
	// that succeeded, and a predicate that panics on "nothing went wrong"
	// is a trap rather than an answer.
	if err == nil {
		return false
	}
	// The registry says what happened in a STATUS, and oras hands it to us
	// typed. Ask that first: a 500 whose body happens to read "repository not
	// found in cache" is not an absent repository, and reading it as one sends
	// resolution quietly upstream — off our own registry — for as long as the
	// upset lasts. Classifying a transport failure by the words in its message
	// is how a transient error becomes a different, silent answer.
	var resp *errcode.ErrorResponse
	if errors.As(err, &resp) {
		switch resp.StatusCode {
		case http.StatusNotFound:
			return true
		case http.StatusForbidden:
			return anonymousRead()
		default:
			return false
		}
	}
	if errors.Is(err, errdef.ErrNotFound) {
		return true
	}
	// Not an oras error: our own js/wasm client and the plain HTTP paths report
	// in prose, so the text is all there is.
	s := strings.ToLower(err.Error())
	if strings.Contains(s, "name unknown") ||
		strings.Contains(s, "not known to registry") ||
		strings.Contains(s, "not found") ||
		strings.Contains(s, "404") {
		return true
	}
	// ghcr does not answer 404 for a repository that does not exist: an
	// ANONYMOUS token request for it is denied with 403, indistinguishable from
	// "exists but you may not read it". For a public registry read without
	// credentials the useful reading is "we do not carry this package" — so fall
	// back to upstream, exactly as an empty listing would. With credentials
	// configured a 403 IS an access problem and must surface: masking it would
	// hide a broken token behind silently different resolution.
	return anonymousRead() && strings.Contains(s, "403")
}

// anonymousRead reports whether the registry is being read with no credentials
// at all (no OCI_TOKEN, no OCI_USERNAME/OCI_PASSWORD).
func anonymousRead() bool {
	return Env("OCI_TOKEN") == "" && Env("OCI_USERNAME") == "" && Env("OCI_PASSWORD") == ""
}

// httpVersionsFor lists a project's versions from a static pkgx dist tree's
// per-arch versions.txt, ascending.
func httpVersionsFor(base, project, osn, arch string) ([]Ver, error) {
	body, err := httpGet(fmt.Sprintf("%s/%s/%s/%s/versions.txt", base, project, osn, arch))
	if err != nil {
		return nil, err
	}
	var vs []Ver
	for _, line := range strings.Fields(string(body)) {
		vs = append(vs, ParseVer(line))
	}
	sort.Slice(vs, func(i, j int) bool { return cmpVer(vs[i], vs[j]) < 0 })
	return vs, nil
}

// ociVersionsFor lists a project's versions from an OCI registry (the repo's
// tags), ascending. The tag list is not per-arch — a version that lacks a bottle
// for the requested platform simply fails at download time, mirroring how the
// static tree 404s a missing per-arch tarball.
func ociVersionsFor(project string) ([]Ver, error) {
	c, err := ociClientForDist()
	if err != nil {
		return nil, err
	}
	tags, err := c.ListTags(project)
	if err != nil {
		return nil, err
	}
	return selectVersions(tags, GlibcFlavor()), nil
}

// selectVersions turns a registry tag listing into the candidate versions for a
// host, ascending.
//
// A glibc-flavored tag (<version>-glibc<ver>) is one BUILD of a version, not a
// version of its own: it must never outrank the plain tag it flavors
// (2.0-glibc2.27.0 parses as 2.0.0.2.27.0 > 2.0). So flavors are matched
// DELIBERATELY — a host that pinned ZPKG_GLIBC takes the build made against that
// glibc, every other flavor is ignored, and the result is independent of the
// order the registry happens to list tags in.
// numericKey is a version's canonical numeric identity: "2.44" and "2.44.0"
// share one, since cmpVer already treats them as the same version.
//
// ⛔⛔ THE REBUILD COUNTER IS PART OF THE IDENTITY, NOT A SPELLING OF IT.
//
// This read v.Nums alone, and the counter is not in v.Nums — the same root
// cause rebuildspelling_test.go names for tagSpellings, arriving here by a
// third route. So "3.3.11" and "3.3.11_1" shared the key "3.3.11",
// selectVersions kept whichever supersedes() preferred, and the other VANISHED
// from every candidate list built from a registry listing.
//
// Measured on ghcr.io/go-zpkg/packages/fftw.org, whose tags include both:
// VersionsFor returned 3.3.11_1 only, and `=3.3.11` resolved to nothing at
// all, though the bottle is published and pullable. A lock pinning a version
// therefore STOPPED RESOLVING the day somebody rebuilt it — the reproducibility
// break is the exact mirror of the one rebuild_test.go was written about, where
// a pin on the rebuilt bottle was satisfied by the un-rebuilt, vulnerable one.
//
// A rebuild is a different build of the same sources: a DIFFERENT bottle, with
// a different digest, which is the whole reason the counter exists. Two
// distinct builds need two distinct keys. cmpVer already sorts _1 after the
// plain tag, so "the newest" still picks the rebuild — this only stops the
// loser of that comparison from being deleted outright.
func numericKey(v Ver) string {
	n := len(v.Nums)
	for n > 1 && v.Nums[n-1] == 0 {
		n-- // trailing zeros carry no information
	}
	parts := make([]string, n)
	for i := 0; i < n; i++ {
		parts[i] = strconv.Itoa(v.Nums[i])
	}
	key := strings.Join(parts, ".")
	if v.Rebuild != 0 {
		// "3.3.11_1" and "v3.3.11_1" still share this key: those ARE two
		// spellings of one build, which is what the key is for.
		key += "_" + strconv.Itoa(v.Rebuild)
	}
	if v.Variant != "" {
		// ⛔ AND THE SAME ARGUMENT, FOR THE SAME REASON. A variant hash names
		// a different BUILD of this version — different options, different
		// closure, different bytes. Leaving it out of the identity would let
		// one variant delete its sibling from the listing, which is exactly
		// what the rebuild counter did before it was added above.
		key += "-h" + v.Variant
	}
	return key
}

// supersedes reports whether candidate v should replace the one already kept for
// the same numeric version: a flavored build always wins (it was asked for), and
// otherwise the MORE SPECIFIC spelling does, so the choice never depends on the
// order the registry happened to list its tags in.
func supersedes(v, prev Ver, flavor string) bool {
	if prev.Tag != "" {
		return false // a flavored build is already held
	}
	if flavor != "" {
		return true
	}
	if len(v.Nums) != len(prev.Nums) {
		return len(v.Nums) > len(prev.Nums)
	}
	return v.Raw > prev.Raw
}

func selectVersions(tags []string, wantFlavor string) []Ver {
	byVersion := map[string]Ver{}
	for _, t := range tags {
		if !isVersionTag(t) {
			continue
		}
		ver, flavor := SplitFlavor(t)
		if flavor != "" && flavor != wantFlavor {
			continue // built against some other glibc: never ours
		}
		// The variant hash comes off AFTER the glibc flavour, because the
		// flavour is the older spelling and sits outermost in the tags that
		// carry it. A tag has at most one of the two in practice — glibc is a
		// dependency now, so a new build records it in the hash — but the
		// order is stated rather than assumed, since a tag carrying both must
		// still read back the same way it was written.
		ver, variant := SplitVariantHash(ver)
		// Key on the NUMERIC version, so "1.0.0", "v1.0.0" and "1.0" are one
		// version. They compare equal, so leaving them as separate candidates
		// makes the pick depend on the registry's listing order — and our own
		// registry does carry both spellings (gnu.org/glibc has a 2.44 tag from a
		// factory build and a 2.44.0 tag from the upstream mirror). A build then
		// installed BOTH glibc trees side by side and linked against a sysroot
		// that was not the one its loader came from.
		v := ParseVer(ver)
		v.Variant = variant
		key := numericKey(v)
		if prev, ok := byVersion[key]; ok && !supersedes(v, prev, flavor) {
			continue
		}
		if flavor != "" || variant != "" {
			// Either suffix means Raw is no longer the tag to pull: Raw is
			// the VERSION, the tag is where this build of it lives.
			v.Tag = t
		}
		byVersion[key] = v
	}
	vs := make([]Ver, 0, len(byVersion))
	for _, v := range byVersion {
		vs = append(vs, v)
	}
	sort.Slice(vs, func(i, j int) bool { return cmpVer(vs[i], vs[j]) < 0 })
	return vs
}

// IsVersionTag reports whether a registry tag names a package VERSION rather
// than registry bookkeeping.
//
// This matters because ghcr implements no referrers API, so ORAS keeps each
// bottle's attestations under a fallback tag named `sha256-<digest>`: those tags
// sit in the same listing as the versions. Parsed as versions they became
// phantom "0" entries — inflating every count, and (worse) making a listing
// look non-empty so the upstream-dist fallback never engaged for a project we
// had published only some versions of.
//
// ⛔ EXPORTED BECAUSE EVERY CALLER OF ListTags NEEDS IT AND ONE COULD NOT
// REACH IT. `pkgs request` (go-zpkg/pkgx) filtered the listing with
// IsPlatformTag alone, and its first live run reported a project with no
// releases as "2 version(s) tagged" — the two being `sha256-…` referrers,
// one of which it then asked for platforms and got "the index has 3
// entry(ies) and none of them names a platform". The rule was already
// written and tested here; what was missing was the ability to use it, and
// a second copy in the caller is how two answers to one question begin.
func IsVersionTag(tag string) bool { return isVersionTag(tag) }

func isVersionTag(tag string) bool {
	// THE SHAPE, not just the first byte. A tag list is what a registry
	// says, and a registry is a configured endpoint — ZPKG_DIST and the
	// mirror can both be pointed elsewhere. A tag beginning with a digit
	// and continuing into an escape sequence passed the first-byte test
	// and went on to be printed in version lists.
	//
	// This keeps ONE invariant instead of a judgement per channel: no
	// version string from anywhere — lock, catalogue or registry — reaches
	// a terminal unvalidated. The allowlist admits `v1.2.3` and the
	// `1.0.0+glibc2.28` flavour spelling; real tags are these plus the
	// `sha256-…` referrer tags, which fail on the first byte as before.
	if ValidateVersionString(tag) != nil {
		return false
	}
	s := strings.TrimPrefix(strings.TrimPrefix(tag, "v"), "V")
	return s != "" && s[0] >= '0' && s[0] <= '9'
}

// PickVersion returns the highest available version satisfying constraint,
// among those published for the HOST platform.
func PickVersion(project, constraint string) (Ver, error) {
	osn, arch := HostSlug()
	return PickVersionFor(project, constraint, osn, arch)
}

// PickVersionFor is PickVersion for an EXPLICIT pkgx os/arch slug. A project's
// published version sets differ per platform — a linux/aarch64 bottle can exist
// where the darwin one does not — so a host that stages a rootfs for another
// platform must resolve against that platform's catalogue, not its own.
func PickVersionFor(project, constraint, osn, arch string) (Ver, error) {
	return PickVersionForAll(project, []string{constraint}, osn, arch)
}

// PickVersionForAll is PickVersionFor for SEVERAL constraints that must all
// hold — the case a dependency closure creates when two packages ask for the
// same project.
//
// Taking one constraint was not a simplification, it was a silent choice. The
// closure walk kept the FIRST constraint it reached and discarded every later
// one, so `gnome.org/glib` asking for `gnu.org/gettext: ^0.21` and
// `freedesktop.org/fontconfig` asking for `^1` never met: whichever was
// dequeued first won, and the other package could not load. Worse, the queue
// was seeded from a Go map, so the winner changed between runs — the same
// closure resolved gettext to 0.26 eight times and 1.0.0 four times out of
// twelve.
//
// Among the versions that satisfy, one on an end-of-life line (see
// DeprecatedEnv) ranks LAST: it is chosen only when nothing else satisfies, and
// the fall back is announced on stderr. With no list the behaviour is exactly
// the newest satisfier.
func PickVersionForAll(project string, constraints []string, osn, arch string) (Ver, error) {
	v, warn, err := PickVersionForAllWarn(project, constraints, osn, arch)
	if warn != "" {
		fmt.Fprintln(deprecationOut, warn)
	}
	return v, err
}

// PickVersionForAllWarn is PickVersionForAll returning the deprecation warning
// as data instead of printing it: "" when the pick is not on an end-of-life
// line.
func PickVersionForAllWarn(project string, constraints []string, osn, arch string) (Ver, string, error) {
	v, warn, err := pickVersionForAll(project, constraints, osn, arch)
	return v, warn, err
}

// variantSiblings lists the OTHER builds of the same version and rebuild as v:
// tags that differ from it only by their variant hash.
//
// ⛔⛔ A COIN FLIP IS NOT A RESOLUTION. Two variants of one version compare
// EQUAL under cmpVer — deliberately, since a hash is not an order — so a loop
// that takes "the newest" would return whichever the sort happened to leave
// last, and the same command would install a different bottle tomorrow. That
// is the failure this repository keeps finding in another costume: an answer
// that depends on the order a registry listed its tags.
//
// Until a concretiser exists to choose by variant constraint, the honest
// answer is to refuse and name the candidates. Nothing published today
// carries a variant hash, so this guard costs nothing now and is in place
// before the first build that would need it — which is the only time a gate
// can be added without an incident first.
func variantSiblings(vs []Ver, v Ver) []string {
	var out []string
	for _, o := range vs {
		if o.Variant == v.Variant || o.Raw != v.Raw || o.Rebuild != v.Rebuild {
			continue
		}
		name := o.Variant
		if name == "" {
			name = "(no variant)"
		}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func pickVersionForAll(project string, constraints []string, osn, arch string) (Ver, string, error) {
	vs, fromRegistry, err := versionsForSourced(project, osn, arch)
	if err != nil {
		return Ver{}, "", err
	}
	dead := deprecatedLines(project)
	// The newest satisfier on an end-of-life line, kept (not discarded) so a
	// request that admits nothing else still resolves. RANK, not FILTER.
	var fallback Ver
	var fallbackLine string
	haveFallback := false
	// Our registry's tag listing spans every platform, so the newest tag that
	// satisfies a constraint is not necessarily installable for the one being
	// resolved: a mirror wave that lands one arch publishes a tag the other
	// arch cannot use. Picking it produced
	//     install kernel.org/linux-headers 7.2.1: no bottle for
	//     kernel.org/linux-headers v7.2.1 (linux/x86-64): platform not in index
	// at STAGING time, where the only clue is a version nobody asked for.
	// Membership is checked lazily, newest-first, so the ordinary case costs one
	// index fetch and a half-published version is stepped over instead.
	var absent []string
	for i := len(vs) - 1; i >= 0; i-- {
		if !satisfiesAll(vs[i], constraints) {
			continue
		}
		if sibs := variantSiblings(vs, vs[i]); len(sibs) > 0 {
			return Ver{}, "", fmt.Errorf(
				"%s %s was published as %d different builds (%s) and nothing here says which: "+
					"a variant hash is not a version, so there is no newest one to pick",
				project, vs[i].Raw, len(sibs)+1, strings.Join(sibs, ", "))
		}
		if fromRegistry {
			tag, ok, err := publishedTagFor(project, vs[i], osn, arch)
			if err != nil {
				return Ver{}, "", err
			}
			if !ok {
				absent = append(absent, vs[i].Raw)
				continue
			}
			v := vs[i]
			v.Tag = tag
			if line, isDead := deprecatedLine(v.Raw, dead); isDead {
				if !haveFallback {
					fallback, fallbackLine, haveFallback = v, line, true
				}
				continue
			}
			return v, "", nil
		}
		if line, isDead := deprecatedLine(vs[i].Raw, dead); isDead {
			if !haveFallback {
				fallback, fallbackLine, haveFallback = vs[i], line, true
			}
			continue
		}
		return vs[i], "", nil
	}
	if haveFallback {
		return fallback, fmt.Sprintf("pkgx: %s %s is on end-of-life release line %s and nothing supported satisfies %s; using it",
			project, fallback.Raw, fallbackLine, quoteAll(constraints)), nil
	}
	// ⛔ NO CONSTRAINT MEANS THE CLAUSE IS OMITTED, not printed empty.
	//
	// Reported from the field on 2026-10-12. `pkgx hugo version` asks for any
	// version, so `constraints` is empty, quoteAll renders "" and the message
	// read:
	//
	//	no version of opentofu.org satisfies  AND is published for darwin/aarch64 (available: 1.12.5…)
	//
	// Two spaces where the reason should be. A reader looking for what they
	// asked for finds a hole, and the sentence blames a constraint that does
	// not exist. The report's own suggestion — omit the clause, or say "any
	// version" — and omitting is the one that leaves a sentence worth reading:
	// what went wrong is the PLATFORM, and with nothing constrained that is
	// the whole of it.
	// ⛔ A TYPE, NOT THE SENTENCE IT PRINTS. The wording below is unchanged —
	// both forms were settled by field reports — but a caller that wants to
	// offer a next step cannot act on prose. This is the COMMON state (567 of
	// 1940 projects on darwin/aarch64, 2026-10-23), and for one release the
	// hint that names `pkgs request` could not see it. See NoBottleHereError.
	if len(absent) > 0 {
		return Ver{}, "", &NoBottleHereError{
			Project: project, OS: osn, Arch: arch,
			Constraints: constraints, Available: vs, Absent: absent,
		}
	}
	if len(constraints) == 0 {
		// Reachable only with no versions at all: with nothing constrained
		// every version satisfies, so the loop above would have returned one.
		return Ver{}, "", fmt.Errorf("no versions of %s are known", project)
	}
	return Ver{}, "", fmt.Errorf("no version of %s satisfies %s (available: %s)", project, quoteAll(constraints), availableVersions(vs))
}

// availableVersions renders what the reader could have asked for instead.
//
// ⛔ A COUNT IS NOT AN ANSWER, AND THIS ONE READS AS A VERSION. The message
// used to end "(available: 1)". Measured 2026-10-08 on myself, seconds after
// writing it:
//
//	$ pkgm pin stedolan.github.io/jq@1.7.1
//	pkgm: no version of stedolan.github.io/jq satisfies "=1.7.1" (available: 1)
//
// Beside "=1.7.1", "available: 1" reads as a claim about version 1 — and I
// went looking for the wrong thing. A count also withholds the single fact
// that would end the problem: WHICH versions exist. nix, guix and spack all
// list the candidates when a constraint cannot be met.
//
// Newest first, because that is what somebody retyping a constraint reaches
// for, and capped because a project can carry hundreds. Every version here
// has already passed ValidateVersionString on the way in (see isVersionTag),
// which is what makes printing them safe.
func availableVersions(vs []Ver) string {
	if len(vs) == 0 {
		return "none"
	}
	const show = 6
	var out []string
	for i := len(vs) - 1; i >= 0 && len(out) < show; i-- {
		out = append(out, vs[i].Raw)
	}
	s := strings.Join(out, " ")
	if len(vs) > show {
		s = fmt.Sprintf("%s … (%d in all)", s, len(vs))
	}
	return s
}

// satisfiesAll reports whether v meets EVERY constraint. An empty set is met by
// anything: a project reached only as a dependency of something that named no
// version still has to resolve.
func satisfiesAll(v Ver, constraints []string) bool {
	for _, c := range constraints {
		if !v.satisfies(c) {
			return false
		}
	}
	return true
}

// quoteAll renders a constraint set for an error an operator has to act on.
// One constraint reads as before; several are listed with " AND " between them,
// because the failure is that they cannot hold TOGETHER and naming only one of
// them sends the reader to the wrong recipe.
func quoteAll(constraints []string) string {
	if len(constraints) == 1 {
		return strconv.Quote(constraints[0])
	}
	q := make([]string, len(constraints))
	for i, c := range constraints {
		q[i] = strconv.Quote(c)
	}
	return strings.Join(q, " AND ")
}

// publishedTagFor finds which registry TAG carries this version for os/arch,
// trying every spelling the version can be written in.
//
// Our registry carries more than one spelling of the same version, and they do
// not always hold the same platforms: gnu.org/tar has the linux bottles under
// `1.35` and the darwin ones under `1.35.0`. selectVersions deliberately
// collapses those to ONE candidate — leaving both would make the pick depend on
// the registry's listing order, which once installed two glibc trees side by
// side — so the spelling that wins may be the one that lacks this platform.
// Checking only it reported the version as unpublished while its bottles were
// sitting under the other tag:
//
//	resolve deps: no version of gnu.org/tar satisfies "*" AND is published
//	for linux/x86-64 (available: …; satisfy but not published here: 1.35.0)
func publishedTagFor(project string, v Ver, osn, arch string) (string, bool, error) {
	c, err := ociClientForDist()
	if err != nil {
		return "", false, err
	}
	for _, tag := range tagSpellings(v) {
		ok, err := c.HasPlatform(project, tag, osn, arch)
		if err != nil {
			return "", false, err
		}
		if ok {
			return tag, true, nil
		}
	}
	return "", false, nil
}

// tagSpellings lists the tags that can denote this version, the one the listing
// chose first. A glibc-flavored tag is left alone: it names one BUILD of a
// version, and trimming it would name a different artifact.
//
// ⛔ A SHORTER SPELLING IS ONLY THE SAME VERSION WHEN WHAT IT DROPS IS ZERO.
// "1.35.0" is also spelled "1.35"; "26.8.1" is NOT also spelled "26.8", and
// "26.8.0" is a different release of the software. Until 2026-10-22 this
// built both, and the consequence was measured on the published registry:
//
//	nodejs.org 26.8.1 has no linux/x86-64 bottle; 26.8.0 does.
//	publishedTagFor(26.8.1, linux/x86-64) tried "26.8.0", got a hit, and
//	answered yes — so `bk catalog` recorded 26.8.1 as the version that
//	platform carries. The published linux/x86-64 catalogue then advertised
//	a node nobody could install, and the 26.8.0 it does have was unreachable.
//
// The same function answers "is this lock's pin published" (lockpublished),
// where a yes about a NEIGHBOURING version is worse: a lock exists to say
// that nothing moved.
func tagSpellings(v Ver) []string {
	first := v.tag()
	if v.Tag != "" {
		return []string{first}
	}
	// ⛔ A REBUILD HAS NO SHORTER SPELLING. The alternatives below are built
	// from v.Nums, and the rebuild counter is not in v.Nums — so `3.3.11_1`
	// used to offer `3.3.11`, which is not another spelling of it but the
	// build it SUPERSEDES.
	//
	// PublishedTagFor walks these and asks the registry about each, so a lock
	// pinning the rebuilt bottle was told "published" on finding the
	// un-rebuilt one, and a catalogue would advertise a rebuild that does not
	// exist. Same defect the non-zero rule below exists for — "26.8.1 must
	// not suggest 26.8.0" — and the same one rebuild_test.go describes from
	// the comparator's side, arriving here by a second route.
	if v.Rebuild != 0 {
		return []string{first}
	}
	out := []string{first}
	seen := map[string]bool{first: true}
	nums := v.Nums
	for n := len(nums); n > 0; n-- {
		// Dropping a non-zero component names another version, not another
		// spelling of this one.
		if !allZero(nums[n:]) {
			continue
		}
		parts := make([]string, n)
		for i := 0; i < n; i++ {
			parts[i] = strconv.Itoa(nums[i])
		}
		// The `.0` extension is the same version written longer ("1.2" is
		// "1.2.0"), so it rides along with a truncation that was legal.
		for _, cand := range []string{strings.Join(parts, "."), strings.Join(parts, ".") + ".0"} {
			if !seen[cand] {
				seen[cand] = true
				out = append(out, cand)
			}
		}
	}
	return out
}

func allZero(nums []int) bool {
	for _, n := range nums {
		if n != 0 {
			return false
		}
	}
	return true
}

// splitComparators cuts a conjunction into its comparator-led parts. A new part
// begins at any "<" or ">" that is not the first character; the "=" of ">=" and
// "<=" is part of its operator and never starts one. A constraint with a single
// comparator comes back whole.
func splitComparators(c string) []string {
	var out []string
	start := 0
	for i := 1; i < len(c); i++ {
		if c[i] != '<' && c[i] != '>' {
			continue
		}
		if p := strings.TrimSpace(c[start:i]); p != "" {
			out = append(out, p)
		}
		start = i
	}
	if p := strings.TrimSpace(c[start:]); p != "" {
		out = append(out, p)
	}
	return out
}

// Satisfies reports whether the version meets a pkgx constraint
// ("^1.2", "~2", ">=1.0", "=1.2.3", "*", or "").
func (v Ver) Satisfies(constraint string) bool { return v.satisfies(constraint) }

// DownloadBottle fetches the raw compressed bottle tarball for a specific
// project/version/os/arch, trying .tar.gz then .tar.xz. It returns the bytes
// and the extension that succeeded (".tar.gz" or ".tar.xz") — for mirror tooling
// that copies bottles verbatim without extracting them.
func DownloadBottle(project, ver, osn, arch string) ([]byte, string, error) {
	if IsOCI(DistBase) {
		c, err := ociClientForDist()
		if err != nil {
			return nil, "", err
		}
		data, ext, err := c.Pull(project, ver, osn, arch)
		if err != nil {
			return nil, "", err
		}
		if err := verifyPulled(c, project, ver, osn, arch, data); err != nil {
			return nil, "", err
		}
		return data, ext, nil
	}
	if err := httpDistUnverifiable(); err != nil {
		return nil, "", err
	}
	base := fmt.Sprintf("%s/%s/%s/%s/v%s", DistBase, project, osn, arch, ver)
	for _, ext := range []string{ExtTarGz, ExtTarXz} {
		resp, err := HTTPClient.Get(base + ext)
		if err != nil {
			return nil, "", err
		}
		if resp.StatusCode == 200 {
			data, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				return nil, "", err
			}
			return data, ext, nil
		}
		resp.Body.Close()
	}
	return nil, "", fmt.Errorf("no bottle for %s v%s (%s/%s)", project, ver, osn, arch)
}

// --- a recipe's dependencies and provides -----------------------------------

// reduceDeps flattens a platform-keyed dependency map (`linux: {...}`,
// `darwin/aarch64: {...}`) onto one os/arch, the shape both `dependencies` and
// `companions` use.
// The platform block WINS, and it wins in a fixed order.
//
// A recipe may name the same dependency twice — qt.io asks for unicode.org
// `^71` at the top level and `~71` under `linux:`. Merging both in one pass
// over a Go map let iteration order decide, so the client answered `~71` four
// times in five and `^71` the other time: a different closure, from the same
// recipe, on the same machine. Sampled 25 runs per arm; the nondeterminism
// predates HCL and this only changes its bias.
//
// Exactly one recipe in the upstream pantry is affected on linux and one on
// darwin, where both constraints happen to be `^2` and the coin toss cannot be
// seen. Rare is not the same as harmless: it is one build in five of the
// largest package in the pantry.
func reduceDeps(m map[string]any, osn, arch string) map[string]string {
	out := map[string]string{}
	for k, v := range m {
		if !isPlatformKey(k) {
			out[k] = constraintText(v)
		}
	}
	// `linux:` then `linux/x86-64:`, never the reverse: both match this host,
	// and the one that names the ARCH is the more specific of the two. Left to
	// map order that pair would race exactly as the one above did.
	for _, key := range []string{osn, osn + "/" + arch} {
		sub, ok := m[key].(map[string]any)
		if !ok {
			continue
		}
		for pk, pv := range sub {
			out[pk] = constraintText(pv)
		}
	}
	return out
}

// constraintText renders a version constraint the way the resolver reads it.
//
// A constraint is text — `^3`, `>=1.2<2` — but YAML lets an author write one
// that looks like a number, and `zlib.net: 1` decodes to an integer. Rendering
// it is what the yaml.Node this replaces did too: it decoded the node into a
// string, which for a scalar is the scalar's text.
//
// A value that is not a scalar yields "", which is also what came before: a
// mapping decoded into a string field failed, the error was dropped, and the
// empty string stayed. "" means "any version" to the resolver, so a recipe
// with a malformed constraint is installed rather than refused — worth
// knowing, and not a thing to change while the requirement is compatibility.
func constraintText(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case map[string]any, []any:
		return ""
	default:
		return fmt.Sprint(x)
	}
}

// CompanionsFor returns a recipe's `companions:` for an explicit os/arch slug.
//
// A companion is not a dependency: the package works without it, and nothing
// links against it. It is what the recipe says belongs in the same ENVIRONMENT,
// and some packages are unusable without theirs — `rust-lang.org` ships
// bin/cargo-clippy and bin/cargo-fmt and no `cargo` at all, because cargo is
// the separate `rust-lang.org/cargo` project it names here.
//
// Reading it was the whole of issue #65: a recipe that declares
// `rust-lang.org` and then runs `cargo` is correct against upstream pkgx and
// died against ours with `"cargo": executable file not found in $PATH` — 74
// pantry recipes declare the key, and 21 of those are named as a dependency by
// some other recipe.
func CompanionsFor(project, osn, arch string) (map[string]string, error) {
	doc, err := recipeDoc(project)
	if err != nil {
		return nil, err
	}
	comp, err := mapField(doc, "companions")
	if err != nil {
		return nil, fmt.Errorf("%s: %w", project, err)
	}
	return reduceDeps(comp, osn, arch), nil
}

// mapField reads a mapping under key, distinguishing ABSENT from MALFORMED.
//
// A recipe that declares no `companions:` is the common case and not an error.
// One that declares `env: [this is not a map]` is a defect, and must be said
// so: the decode this replaces failed on it, and reading it as "no env" would
// install a package whose consumers silently lack the environment it says they
// need — help2man without PERL5LIB, which is how gnu.org/libidn2 failed to
// build in the first place.
func mapField(doc map[string]any, path ...string) (map[string]any, error) {
	cur := doc
	for i, key := range path {
		v, present := cur[key]
		if !present || v == nil {
			return nil, nil
		}
		m, ok := v.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s: want a mapping, got %T", strings.Join(path[:i+1], "."), v)
		}
		cur = m
	}
	return cur, nil
}

// FetchMeta returns the host-relevant runtime dependencies (project ->
// constraint) and the list of provided paths for a project's package.yml.
func FetchMeta(project string) (deps map[string]string, provides []string, err error) {
	osn, arch := HostSlug()
	return FetchMetaFor(project, osn, arch)
}

// FetchMetaFor is FetchMeta for an EXPLICIT pkgx os/arch slug. A recipe's
// dependencies are platform-keyed (`linux: {...}`, `darwin/aarch64: {...}`), so
// reading them through the host's slug while staging a rootfs for another
// platform silently produces the WRONG closure — a linux image missing the deps
// only linux declares, and carrying the ones only darwin needs.
func FetchMetaFor(project, osn, arch string) (deps map[string]string, provides []string, err error) {
	doc, err := recipeDoc(project)
	if err != nil {
		return nil, nil, err
	}
	d, err := mapField(doc, "dependencies")
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", project, err)
	}
	return reduceDeps(d, osn, arch), decodeProvides(doc["provides"]), nil
}

// platformKeys are the OS names a recipe may use to scope a dependency block.
// A name absent from this list is read as a PROJECT — which is why adding an OS
// to osSlug without adding it here turns a recipe's `js:` block into a
// dependency on a package called "js". The suite under js/wasm caught exactly
// that: TestFetchMeta builds its fixture from HostSlug(), so the moment the host
// reported "js" the block stopped being a platform.
// The BSDs are here because osSlug now answers with them, and the two lists
// have to agree: a slug absent from this one turns a recipe's `freebsd:` block
// into a dependency on a project called "freebsd". Measured before adding
// them — the upstream pantry scopes no block to any BSD today, so this
// enables a spelling rather than changing how one is read.
var platformKeys = []string{"linux", "darwin", "windows", "js", "wasip1",
	"freebsd", "openbsd", "netbsd", "dragonfly"}

func isPlatformKey(k string) bool {
	for _, p := range platformKeys {
		if k == p || strings.HasPrefix(k, p+"/") {
			return true
		}
	}
	return false
}

func platformMatches(k, osn, arch string) bool {
	if k == osn {
		return true
	}
	return k == osn+"/"+arch
}

func decodeProvides(v any) []string {
	if list, ok := stringList(v); ok {
		return list
	}
	// may be a platform map: {linux: [...], darwin: [...]}
	if m, ok := v.(map[string]any); ok {
		osn, _ := HostSlug()
		list, _ := stringList(m[osn])
		return list
	}
	return nil
}

// stringList reads a list of strings, and refuses one that is not.
//
// Refusing the whole list rather than the element is deliberate, and it is
// what the yaml.Node decode this replaces did: a `provides:` holding anything
// but strings failed to decode and yielded nothing. Taking the strings and
// dropping the rest would hand the caller a SHORTER list that looks complete.
func stringList(v any) ([]string, bool) {
	items, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(items))
	for _, it := range items {
		s, ok := it.(string)
		if !ok {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

// --- resolution -------------------------------------------------------------

// Resolved is a project pinned to a concrete version.
type Resolved struct {
	Project string
	Version Ver
}

// ResolveClosure walks the runtime dependency graph breadth-first.
func ResolveClosure(roots map[string]string) ([]Resolved, error) {
	osn, arch := HostSlug()
	return ResolveClosureFor(roots, osn, arch)
}

// ResolveClosureFor is ResolveClosure for an EXPLICIT pkgx os/arch slug: the
// whole walk — version pick and dependency read alike — happens in the target
// platform's terms. This is what lets a darwin machine stage a complete
// linux/aarch64 userland, which is how the sovereign builder image is built.
func ResolveClosureFor(roots map[string]string, osn, arch string) ([]Resolved, error) {
	constraints, askedBy, order, err := collectConstraints(roots, osn, arch)
	if err != nil {
		return nil, err
	}
	out := make([]Resolved, 0, len(order))
	for _, p := range order {
		v, err := PickVersionForAll(p, constraints[p], osn, arch)
		if err != nil {
			// The demands do not intersect. Before refusing, ask whether they
			// describe two different libraries rather than one contested
			// version — libxml2 broke its ABI inside major 2, so ">=2.14" and
			// "~2.13" are both right and name disjoint sonames.
			if vers, lerr := pickABILines(p, constraints[p], osn, arch); lerr == nil {
				for _, lv := range vers {
					out = append(out, Resolved{p, lv})
				}
				continue
			}
			// Report the ORIGINAL refusal: why one version could not be found
			// is what an operator can act on, and why it could not be split is
			// a detail of the attempt to rescue it.
			return nil, closureErr(p, constraints[p], askedBy[p], err)
		}
		out = append(out, Resolved{p, v})
	}
	return out, nil
}

// collectConstraints walks the graph and gathers EVERY constraint on each
// project, with who asked for it, before any version is chosen.
//
// Two passes are exact here because FetchMetaFor does not take a version: the
// dependency graph does not depend on what gets picked, so nothing can change
// once the walk is done. Resolving as it walked is what made the old version
// keep the first constraint and drop the rest.
//
// The walk is DETERMINISTIC: roots and each project's dependencies are visited
// in sorted order. Seeding the queue from a Go map meant the same closure
// resolved differently between runs — measured at gettext 0.26 eight times and
// 1.0.0 four times out of twelve — and the losing package could not load.
func collectConstraints(roots map[string]string, osn, arch string) (constraints map[string][]string, askedBy map[string][]string, order []string, err error) {
	constraints, askedBy, _, order, err = collectGraph(roots, osn, arch)
	return
}

// collectGraph is collectConstraints keeping the EDGES as well: who depends on
// whom, under which constraint.
//
// The resolver has always known this — it is what lets a refusal say "asked for
// by ^1 (x.org/exts), =1.8.11 (tcl-lang.org)" — and nothing could ask it. An
// operator composing an environment needs the same answer BEFORE it fails:
// which version was chosen, and which demand chose it.
func collectGraph(roots map[string]string, osn, arch string) (constraints map[string][]string, askedBy map[string][]string, edges []Edge, order []string, err error) {
	constraints, askedBy = map[string][]string{}, map[string][]string{}
	add := func(project, constraint, who string) {
		if constraint == "" || constraint == "*" {
			return // nothing to intersect, and nothing an operator needs told
		}
		for _, have := range constraints[project] {
			if have == constraint {
				return // the same demand twice is one demand
			}
		}
		constraints[project] = append(constraints[project], constraint)
		askedBy[project] = append(askedBy[project], who)
	}
	seen := map[string]bool{}
	queue := sortedKeys(roots)
	for _, p := range queue {
		add(p, roots[p], "requested")
		edges = append(edges, Edge{Of: "", On: p, Constraint: roots[p]})
	}
	for len(queue) > 0 {
		project := queue[0]
		queue = queue[1:]
		if seen[project] {
			continue
		}
		seen[project] = true
		order = append(order, project)
		deps, _, ferr := FetchMetaFor(project, osn, arch)
		if ferr != nil {
			return nil, nil, nil, nil, ferr
		}
		for _, dp := range sortedKeys(deps) {
			add(dp, deps[dp], project)
			edges = append(edges, Edge{Of: project, On: dp, Constraint: deps[dp]})
			if !seen[dp] {
				queue = append(queue, dp)
			}
		}
	}
	return constraints, askedBy, edges, order, nil
}

// Edge is one dependency: Of depends On, under Constraint. An Of of "" is a
// project the operator asked for directly.
type Edge struct {
	Of         string
	On         string
	Constraint string
}

// Graph is a resolved closure with its edges kept, so a caller can show WHY a
// version was chosen and not only WHICH.
type Graph struct {
	Roots    []string       // what was asked for, sorted
	Versions map[string]Ver // project -> the version the unifier picked
	// Lines holds every version of a project the closure carries, and is set
	// ONLY where there is more than one: demands that do not intersect but
	// name disjoint sonames are two ABI lines, not a conflict. Versions keeps
	// the leading one, so a reader that does not know about lines still gets
	// an answer rather than an arbitrary half.
	Lines map[string][]Ver
	Deps  map[string][]Edge // project -> the edges leaving it, sorted by On
	Asks  map[string][]Edge // project -> the edges pointing AT it
}

// GraphFor resolves a closure and returns it with its structure intact.
//
// Same walk, same unifier and same determinism as ResolveClosureFor: this is a
// view of the resolution, not a second implementation of it, so what it shows
// is what a build or an environment will get.
func GraphFor(roots map[string]string, osn, arch string) (*Graph, error) {
	constraints, askedBy, edges, order, err := collectGraph(roots, osn, arch)
	if err != nil {
		return nil, err
	}
	g := &Graph{
		Roots:    sortedKeys(roots),
		Versions: map[string]Ver{},
		Lines:    map[string][]Ver{},
		Deps:     map[string][]Edge{},
		Asks:     map[string][]Edge{},
	}
	for _, p := range order {
		v, err := PickVersionForAll(p, constraints[p], osn, arch)
		if err != nil {
			if vers, lerr := pickABILines(p, constraints[p], osn, arch); lerr == nil {
				// Versions keeps the LEADING line, so every existing reader
				// still gets one answer; Lines is what says there were two.
				g.Versions[p] = vers[0]
				g.Lines[p] = vers
				continue
			}
			return nil, closureErr(p, constraints[p], askedBy[p], err)
		}
		g.Versions[p] = v
	}
	for _, e := range edges {
		if e.Of != "" {
			g.Deps[e.Of] = append(g.Deps[e.Of], e)
		}
		g.Asks[e.On] = append(g.Asks[e.On], e)
	}
	return g, nil
}

// closureErr names WHO asked for each constraint when a project cannot satisfy
// them together.
//
// "no version of gnu.org/gettext satisfies \"^0.21\" AND \"^1\"" states the
// conflict and leaves the reader to grep the pantry for both. The packages that
// disagree are what has to change, so the error names them.
func closureErr(project string, constraints, askedBy []string, err error) error {
	if len(constraints) < 2 {
		// NOT a ConflictError: one demand is not a conflict, and callers
		// classify on that type — pkgx's `compat` counts conflicts apart from
		// everything else, and calling this one would corrupt that count.
		//
		// But it still has an AUTHOR, and losing it is expensive in exactly
		// the case where it matters most. Measured on libvips.org:
		//
		//   no version of ijg.org satisfies "9.6" (available: …)
		//
		// which says a demand is wrong and not whose. A single unsatisfiable
		// demand is somebody's mistake, and naming them is the difference
		// between a report and a search.
		if len(constraints) == 1 && len(askedBy) == 1 && askedBy[0] != "" {
			// THROUGH displayText, because a constraint can come from a
			// lock or from a recipe's dependency line — content a third
			// party writes — and this sentence is printed to a terminal.
			// A crafted version turned it into a different, reassuring
			// line; see ValidateVersionString. The lock is refused at
			// parse time now, and this is the channel closed behind it.
			return fmt.Errorf("%w; asked for by %s (%s)", err,
				displayText(constraints[0], maxVersionString+8), displayText(askedBy[0], maxProjectName))
		}
		return err
	}
	return &ConflictError{Project: project, Constraints: constraints, AskedBy: askedBy, Err: err}
}

// ConflictError is a closure that has no solution: several demands on one
// project whose intersection is empty.
//
// Structured rather than only formatted, because the interesting question is
// never one closure. Asking how much of a pantry a chosen base reaches means
// resolving hundreds of them and counting WHICH demand did the excluding —
// libxml2 ~2.13 shutting out 68 recipes is a decision about what to rebuild,
// and a caller should not have to parse a sentence to learn it.
type ConflictError struct {
	Project     string   // the project nobody could agree on
	Constraints []string // every demand on it, in the order collected
	AskedBy     []string // who made each; "requested" for a root
	Err         error    // what the version pick said
}

func (e *ConflictError) Error() string {
	parts := make([]string, len(e.Constraints))
	for i := range e.Constraints {
		// Same reason as the single-demand sentence above: these strings
		// come from locks and recipes, and this one reaches a terminal.
		parts[i] = fmt.Sprintf("%s (%s)",
			displayText(e.Constraints[i], maxVersionString+8), displayText(e.AskedBy[i], maxProjectName))
	}
	return fmt.Sprintf("%v; asked for by %s", e.Err, strings.Join(parts, ", "))
}

func (e *ConflictError) Unwrap() error { return e.Err }

// sortedKeys is map iteration made reproducible. Go randomises it, and a
// resolution order that changes between runs is a closure that changes between
// runs.
func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// --- download + extract -----------------------------------------------------

// Install downloads and extracts one bottle into pkgxDir (skips if the
// versioned prefix already exists), then writes major/minor convenience links.
// Extraction is atomic — the bottle is unpacked into a temp dir and the
// versioned prefix is renamed into place — so concurrent installs sharing one
// ZPKG_DIR never observe a half-extracted prefix.
// Install materialises a bottle for the HOST platform. Use InstallFor to stage
// a rootfs for another one -- building a linux image from a mac, say.
func Install(r Resolved, pkgxDir string) (bool, error) {
	osn, arch := HostSlug()
	return InstallFor(r, pkgxDir, osn, arch)
}

// InstallFor materialises a bottle for an EXPLICIT platform. The extracted tree
// is identical whatever the host: only the bottle fetched differs, so a builder
// can stage a linux/aarch64 rootfs from a darwin/arm64 machine.
func InstallFor(r Resolved, pkgxDir, osn, arch string) (bool, error) {
	// ⛔ THE NAME BUILDS A PATH THAT IS WRITTEN TO, so it is checked here.
	//
	// Until now this was safe only by ORDER: fetchBottle below goes through
	// OCIClient.repository, which validates, so a `..` would have failed at
	// the fetch. But the os.Stat on the next line happens FIRST — and for a
	// project of `../..` naming a directory that exists, it returns
	// (false, nil), which this function's contract reads as "already
	// present". A caller would be told the bottle is installed, having
	// installed nothing, on the strength of a directory outside the store.
	//
	// Resolved is an exported struct with exported fields, so a caller can
	// fill it by hand without passing through a resolver or a catalogue —
	// both of which already validate. Depending on the order of two
	// unrelated checks inside one function is not a boundary.
	//
	// Measured before adding it: the upstream pantry's 1929 recipes carry
	// 6381 dependency keys and every one passes, so this rejects nothing that
	// exists today.
	if err := ValidateProjectName(r.Project); err != nil {
		return false, err
	}
	// The store says what it holds, so the next reader of a SHARED store can
	// be told it is the wrong architecture instead of being handed a prefix
	// whose binaries the kernel refuses. Written here because this is where
	// the platform being installed is known for certain.
	MarkStorePlatform(pkgxDir, osn, arch)
	prefix := StorePrefix(pkgxDir, r.Project, r.Version)
	if st, err := os.Stat(prefix); err == nil && st.IsDir() {
		return false, nil // already present
	}
	body, ext, digest, err := fetchBottle(r, osn, arch)
	if err != nil {
		return false, err
	}
	defer body.Close()
	dec, closeDec, err := Decompressor(ext, body)
	if err != nil {
		return false, err
	}
	defer closeDec()
	// Unpack into a private temp dir, then atomically rename the extracted
	// <project>/v<ver> into place.
	if err := os.MkdirAll(pkgxDir, 0o755); err != nil {
		return false, err
	}
	tmp, err := os.MkdirTemp(pkgxDir, ".tmp-")
	if err != nil {
		return false, err
	}
	defer os.RemoveAll(tmp)
	if err := untar(dec, tmp); err != nil {
		return false, err
	}
	if err := os.MkdirAll(filepath.Dir(prefix), 0o755); err != nil {
		return false, err
	}
	// The directory INSIDE the bottle is named after the tag it was published
	// under, which is not always how we spell the version: gnu.org/tar is
	// published as `1.35` for linux and `1.35.0` for darwin, so a bottle pulled
	// from the linux tag unpacks to v1.35 while the resolved version reads
	// 1.35.0, and the install died with
	//   rename /pkgx/.tmp-…/gnu.org/tar/v1.35.0 …: no such file or directory
	// Install under the name the bottle carries — absolute paths baked inside it
	// point there — and link the canonical spelling to it.
	// ⛔⛔ THE REAL DIRECTORY ALWAYS CARRIES THE HASH. `dest` used to be the
	// name the BOTTLE carries, which is `v<version>` for almost every bottle
	// — so almost every install landed in a directory that said nothing about
	// WHICH build it was, and a second build of one version had nowhere to go.
	//
	// It is now `v<version>-h<hash>` without exception, and `v<version>`
	// becomes a symlink to it. Readers that compute a path from (project,
	// version) follow the symlink and need no change; what the symlink points
	// at is which build is the store's default.
	src, _ := extractedPrefix(tmp, r)
	hash := StoreHash(r.Version, digest, DistBase+"\x00"+r.Project+"\x00"+r.Version.Raw+"\x00"+osn+"/"+arch)
	if moved, err := renameOrExplain(src, pkgxDir, r.Project, r.Version, hash); err != nil || !moved {
		return false, err
	}
	// ⛔⛔ NO VERSION-ONLY PATH IS WRITTEN. NOT `v<version>`, NOT `v1`, NOT
	// `v1.2`, NOT `v*`.
	//
	// Those were pkgx's convenience aliases and this store inherited them.
	// Every one of them is a path that names a VERSION and not a BUILD, and
	// a store that offers such a path offers a way to address a package
	// without saying which build you mean — which is the defect the hashed
	// layout exists to end, reintroduced one directory up.
	//
	// It was kept for one real reason: published bottles name the version in
	// their own rpaths (`@rpath/zlib.net/v1.3.2/lib/libz.1.dylib`, read with
	// otool out of a real bottle). That reason expires with the rebuild —
	// a bottle built with a hashed prefix carries the hash in its own
	// references — and the bottles that need it are the ones we have decided
	// not to install.
	//
	// A per-user or per-image default is NOT this: it is a VIEW, built
	// outside the store by LinkView, which is what lets a shared NFS export
	// stay read-only and lets a container compute its own links at creation
	// time.
	writeABILinks(pkgxDir, r, osn, arch)
	return true, nil
}

// renameOrExplain moves the unpacked tree into place and reports whether it
// moved. It exists for the one ambiguous failure: `dest` already occupied.
//
// ⛔ "ALREADY INSTALLED" MUST MEAN THE REQUESTED PREFIX IS THERE. This used
// to answer on the strength of `dest` alone — and `dest` is the directory the
// BOTTLE carries, which is not always the version that was asked for. A
// rebuild is published as `3.3.11_1` and still unpacks to `v3.3.11`.
//
// So installing a rebuild into a store that already held `v3.3.11` renamed
// onto an occupied directory, saw it occupied, and reported success having
// installed nothing. The caller then ran a binary under a prefix that was
// never created and got a bare `no such file or directory`
// (go-zpkg/bk#386, found on the first real use of the rebuild counter):
//
//	Install         -> fresh=false err=<nil>
//	stat(v3.3.11_1) -> no such file or directory
//
// A genuine concurrent install leaves `prefix` behind too — the other worker
// writes the alias — so asking about `prefix` separates "somebody else did
// this" from "this did not happen".
//
// It does NOT create the alias here. That would serve the OLD content under
// the new name, which is worse than failing: the caller asked for a rebuild
// and would silently get the bottle it was meant to supersede.
// ⛔⛔ THE AMBIGUITY THIS GUARDED IS GONE BY CONSTRUCTION, AND THE HASH IS WHY.
// bk#386 happened because `dest` was the directory the BOTTLE carries —
// `v3.3.11` for a rebuild published as `3.3.11_1` — so an occupied `dest`
// could mean either "somebody installed this" or "somebody installed a
// DIFFERENT build and yours is still missing". The only way to tell was to
// ask about `prefix` separately, and that answer raced: a concurrent worker
// between its rename and its alias has created `dest` and not yet `prefix`.
//
// `dest` is now `v<version>-h<hash>`, which is unique to THIS build. Occupied
// can only mean this exact build is already there, which is precisely
// "another worker got there first" — the thing the old code was trying to
// infer. `prefix` is kept only to name in an error.
// ⛔ IT COMPUTES `dest` ITSELF, so the mismatch cannot be constructed. The
// old signature took `dest` from the caller, which is how it came to be the
// ARCHIVE's directory; a helper that cannot be handed the wrong destination
// has no wrong destination to detect.
func renameOrExplain(src, dir, project string, v Ver, hash string) (bool, error) {
	dest := StoreBuildPrefix(dir, project, v, hash)
	if err := os.Rename(src, dest); err != nil {
		if st, e := os.Stat(dest); e == nil && st.IsDir() {
			return false, nil // this build is already installed
		}
		return false, err
	}
	return true, nil
}

// extractedPrefix returns the versioned directory the bottle actually unpacked,
// and whether it differs from the canonical `v<version>` spelling. Preferring
// the canonical name keeps the ordinary case exact; falling back to the single
// `v*` directory present handles a bottle published under another spelling of
// the same version. Two candidates is not a case to guess at.
//
// ⛔ THIS IS THE ARCHIVE'S LAYOUT, NOT THE STORE'S — DO NOT "FIX" IT TO USE
// StorePrefix. A bottle's tarball contains `<project>/v<version>/`, with no
// variant hash in it: the factory names what it built, and a tarball is the
// same bytes wherever it is unpacked. The hash belongs to where the bottle
// GOES, which is why the caller extracts to this path and then renames it
// onto StorePrefix. That rename is the whole mechanism by which two builds of
// one version can sit side by side without the factory changing at all.
func extractedPrefix(tmp string, r Resolved) (path string, aliased bool) {
	canonical := filepath.Join(tmp, r.Project, "v"+r.Version.Raw)
	if st, err := os.Stat(canonical); err == nil && st.IsDir() {
		return canonical, false
	}
	ents, err := os.ReadDir(filepath.Join(tmp, r.Project))
	if err != nil {
		return canonical, false // let the rename report the real problem
	}
	var found string
	for _, e := range ents {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), "v") {
			continue
		}
		if found != "" {
			return canonical, false // ambiguous: do not guess
		}
		found = e.Name()
	}
	if found == "" {
		return canonical, false
	}
	return filepath.Join(tmp, r.Project, found), true
}

// verifyPulled enforces the fail-closed signature check on a pulled bottle.
// EVERY path that brings bottle bytes onto the machine goes through it or
// through httpDistUnverifiable — the install path used not to, so `pkgx` and
// `pkgm` happily installed an unsigned bottle with ZPKG_VERIFY=1 while only the
// mirror tooling checked. A guarantee enforced on one path out of two is not a
// guarantee.
//
// The claim in that first sentence has been wrong twice now, and both times
// in the same way: a path was added that did not look like installing.
// FetchCatalog was the second — a catalogue "is only a list of names", and a
// list of names is what a person then types. Anything added here that pulls
// bytes gets this call, whatever it does with them.
func verifyPulled(c *OCIClient, project, ver, osn, arch string, data []byte) error {
	sum := sha256.Sum256(data)
	return verifyPulledDigest(c, project, ver, osn, arch, "sha256:"+hex.EncodeToString(sum[:]))
}

// verifyPulledDigest is verifyPulled for a bottle already staged on disk, whose
// digest was computed as it was written.
func verifyPulledDigest(c *OCIClient, project, ver, osn, arch, digest string) error {
	if !VerifyRequired() {
		return nil
	}
	if err := c.VerifyBottleDigest(project, ver, osn, arch, digest); err != nil {
		return fmt.Errorf("verify %s v%s (%s/%s): %w", project, ver, osn, arch, err)
	}
	return nil
}

// httpDistUnverifiable fails closed when verification is demanded but ZPKG_DIST
// speaks static HTTP, which carries no signatures at all (referrers are
// OCI-only).
func httpDistUnverifiable() error {
	if !VerifyRequired() {
		return nil
	}
	return fmt.Errorf("signature verification is on by default but ZPKG_DIST=%s (HTTP) has no signatures; use an oci:// dist or set ZPKG_VERIFY=0", DistBase)
}

// fetchBottle returns the compressed bottle stream, trying .tar.gz then .tar.xz.
// When DistBase selects the OCI transport it pulls the bottle blob, VERIFIES it
// and wraps the bytes in a reader, so Install (and thus pkgm/pkgx) works over
// OCI unchanged.
// fetchBottle returns the bottle body and the EXTENSION that names its
// compression — a string rather than the old isXz bool, because there are now
// three codecs and a boolean cannot say which.
// It returns the bottle's content DIGEST alongside the stream, or "" when the
// transport has none.
//
// ⛔ THE DIGEST WAS ALREADY COMPUTED AND THROWN AWAY. PullFile hashes the
// bytes on the way past — that is what the signature is checked against — and
// this function used to drop it at the return. It is the strongest witness of
// WHICH build is being installed for a bottle whose tag carries no variant
// hash, which is every bottle published so far, so the store path needs it.
//
// An HTTP dist has none: it serves a tarball and `httpDistUnverifiable`
// already refuses that path unless verification is off. "" says so rather
// than inventing one.
func fetchBottle(r Resolved, osn, arch string) (io.ReadCloser, string, string, error) {
	if IsOCI(DistBase) {
		c, err := ociClientForDist()
		if err != nil {
			return nil, "", "", err
		}
		// The registry tag, which is the flavored one for a glibc-pinned build;
		// the installed prefix stays v<version> either way.
		tag := r.Version.tag()
		// Streamed to DISK, not into a []byte: llvm.org is ~1.7 GiB and making
		// the biggest bottle the memory floor of every install is what killed a
		// 2 GiB micro-VM mid-build. The file is removed when the caller closes
		// it, and the digest computed on the way past is what the signature is
		// checked against — so the tarball is never read twice either.
		// The cache is an optimisation and never an authority: whatever it
		// serves is checked against the digest and signature DistBase
		// advertises, and any failure falls through to the registry itself.
		if cc := ociCacheClient(); cc != nil {
			if f, ext, err := cc.PullFile(r.Project, tag, osn, arch); err == nil {
				if err := verifyPulledDigest(c, r.Project, tag, osn, arch, f.Digest); err == nil {
					// ⛔ THE DIGEST THE REGISTRY ADVERTISES, NOT THE CACHE'S.
					// verifyPulledDigest has just established they agree, so
					// either value is the same string here — but the cache is
					// "an optimisation and never an authority", and a path
					// named from what a cache said would quietly become the
					// exception to that the day the check is relaxed.
					return f, ext, f.Digest, nil
				}
				f.Close()
			}
		}
		f, ext, err := c.PullFile(r.Project, tag, osn, arch)
		if err != nil {
			return nil, "", "", err
		}
		if err := verifyPulledDigest(c, r.Project, tag, osn, arch, f.Digest); err != nil {
			f.Close()
			return nil, "", "", err
		}
		return f, ext, f.Digest, nil
	}
	if err := httpDistUnverifiable(); err != nil {
		return nil, "", "", err
	}
	base := fmt.Sprintf("%s/%s/%s/%s/v%s", DistBase, r.Project, osn, arch, r.Version.Raw)
	// Newest codec first: a dist that carries both serves the cheaper install.
	for _, ext := range []string{ExtTarZst, ExtTarGz, ExtTarXz} {
		resp, err := HTTPClient.Get(base + ext)
		if err != nil {
			return nil, "", "", err
		}
		if resp.StatusCode == 200 {
			// No digest: an HTTP dist serves bytes and advertises nothing to
			// check them against. StoreHash falls back to the source.
			return resp.Body, ext, "", nil
		}
		resp.Body.Close()
		if resp.StatusCode != 404 {
			return nil, "", "", fmt.Errorf("GET %s: %s", base+ext, resp.Status)
		}
	}
	return nil, "", "", fmt.Errorf("no bottle for %s v%s (%s/%s)", r.Project, r.Version.Raw, osn, arch)
}

// untar unpacks a bottle stream into dest. It delegates to the shared Extract
// (strip == 0), which restores file mtimes, rejects insecure paths with
// ErrInsecurePath, and reproduces directories, files, symlinks and hard links.
func untar(r io.Reader, dest string) error {
	return Extract(tar.NewReader(r), dest, 0)
}

// ⛔⛔ writeVersionLinks AND aliasAdvances ARE GONE, AND THE DEFECT THEY
// FIXED CANNOT RECUR BECAUSE THE THING THEY MANAGED NO LONGER EXISTS.
//
// They wrote `v{maj}`, `v{maj}.{min}` and `v*` beside each install, pkgx's
// convenience aliases, and `aliasAdvances` existed because the first version
// rewrote them unconditionally: installing an OLDER line of a project
// demoted `v*` and `v<major>` onto it —
//
//	v*    -> v2.13.9   (after installing 2.13.9 beside 2.15.4)
//	v2    -> v2.13.9
//
// — so every consumer bound to `v2` loaded the older library, which is the
// failure the ABI lines exist to end, reached from the other side.
//
// That was a careful fix to a problem created by having the alias at all.
// Every one of those paths names a VERSION and not a BUILD, so a store
// offering them offers a way to address a package without saying which build
// is meant — the defect the hashed layout exists to end, one directory up.
// Now that the store holds only `v<version>-h<hash>`, there is nothing to
// advance and nothing to demote.
//
// The rule they encoded survives where it is still needed: `writeABILinks`
// resolves a soname to a build, and the catalogue answers "which versions
// are installed" from InstalledBuilds.
// ABIProvidesAnnotation lists the sonames a bottle's shared libraries call
// themselves by, comma-separated and sorted. Written by bk at publish time.
// Declared in annotations.go and read through Annotation().

// abiAnnotations is a seam: the manifest read that answers what a bottle
// provides.
var abiAnnotations = func(project, tag, osn, arch string) map[string]string {
	if !IsOCI(DistBase) {
		return nil
	}
	c, err := ociClientForDist()
	if err != nil {
		return nil
	}
	ann, err := c.PlatformAnnotations(project, tag, osn, arch)
	if err != nil {
		return nil
	}
	return ann
}

// writeABILinks creates one `abi-<soname>` symlink per ABI the bottle provides,
// beside the v* aliases.
//
// v<major> is where a reference is bound at load time, and it holds ONE
// version. That is what lets a bottle follow a patch upgrade, and it is exactly
// what breaks when a project changes its ABI INSIDE a major. Measured, both
// lines installed into one store:
//
//	gnome.org/libxml2          unicode.org
//	  v2     -> v2.15.4          v73  v73.2  v73.2.0
//	  v2.13  -> v2.13.9          v78  v78.3  v78.3.0
//	  v2.15  -> v2.15.4
//
// ICU coexists because it bumps its major with its soname. libxml2 does not:
// 2.13.9 ships libxml2.2.dylib, 2.15.4 ships libxml2.16.dylib, and both claim
// v2 — so a consumer of the other line cannot resolve. An abi-<soname> link is
// the same late binding keyed on the thing that actually decides
// compatibility.
//
// The sonames come from the annotation and never from filenames: zlib's real
// file is libz.1.3.2.dylib and its soname is libz.1.dylib, the SYMLINK. Only
// LC_ID_DYLIB / DT_SONAME answers, which is what bk reads at publish time.
//
// A bottle published before that annotation existed gets no abi- links, and
// everything behaves as it did. This is deliberately inert on its own: what
// reads the links comes later.
func writeABILinks(pkgxDir string, r Resolved, osn, arch string) {
	ann := abiAnnotations(r.Project, r.Version.tag(), osn, arch)
	provides := Annotation(ann, ABIProvidesAnnotation)
	if provides == "" {
		return
	}
	dir := filepath.Join(pkgxDir, r.Project)
	full := "v" + r.Version.Raw
	for _, soname := range strings.Split(provides, ",") {
		soname = strings.TrimSpace(soname)
		// A soname is a bare filename. Anything with a separator in it would
		// put the link somewhere else entirely, so it is not one.
		if soname == "" || strings.ContainsAny(soname, `/\`) || soname == "." || soname == ".." {
			continue
		}
		p := filepath.Join(dir, "abi-"+soname)
		_ = os.Remove(p)
		_ = os.Symlink(full, p)
	}
}

// --- a recipe's runtime env -------------------------------------------------

// The `runtime: env:` block is how a package declares the environment IT needs
// its consumers to have. It is not decoration: help2man
// bundles the perl module Locale::gettext into its own prefix and publishes
// PERL5LIB so the module is findable, and without that export help2man dies
// with "Can't locate Locale/gettext.pm in @INC" — which is how gnu.org/libidn2
// failed to build. Perl, Python, Ruby and Tcl module packages all work this way.
//
// The block is NOT a flat table. A recipe may key part of it by platform, and
// rust-lang.org/cargo does:
//
//	runtime:
//	  env:
//	    CARGO_INSTALL_ROOT: ${{home}}/.local
//	    linux:
//	      CARGO_HTTP_CAINFO: ${{deps.curl.se/ca-certs.prefix}}/ssl/cert.pem
//
// Read as map[string]string that is `line 15: cannot unmarshal !!map into
// string`, and the WHOLE runtime env is then lost — not just the linux half.
// A value may also be a list, which the pantry joins with spaces. So it is
// read as a document and flattened below, never decoded into a typed table.

// FetchRuntimeEnv returns a project's runtime env declarations with the recipe
// placeholders resolved against the version actually installed. A project that
// declares none yields an empty map, not an error.
func FetchRuntimeEnv(project, prefix, version string) (map[string]string, error) {
	return fetchRuntimeEnv(project, prefix, version, nil)
}

// FetchRuntimeEnvIn is FetchRuntimeEnv with the resolved closure in hand, so
// `deps.<project>.prefix` and the dep version tokens resolve.
//
// libpkgx's useMoustaches tokenises, for every installed dependency:
//
//	map.push({ from: `deps.${dep.pkg.project}.prefix`, to: dep.path.string })
//	map.push(...tokenize.version(dep.pkg.version, `deps.${dep.pkg.project}.version`))
//
// Without them rust-lang.org/cargo declares
//
//	CARGO_HTTP_CAINFO: ${{deps.curl.se/ca-certs.prefix}}/ssl/cert.pem
//
// and cargo builds with no CA bundle at all — `[77] Problem with the SSL CA
// cert … error setting certificate file: /ssl/cert.pem` — which is where the
// whole crates.io family stopped.
func FetchRuntimeEnvIn(project string, closure []Resolved, dir string) (map[string]string, error) {
	var version string
	for _, r := range closure {
		if r.Project == project {
			version = r.Version.Raw
			break
		}
	}
	return fetchRuntimeEnv(project, PrefixOf(project, closure, dir), version, depTokens(closure, dir))
}

// depTokens builds the `deps.<project>.*` substitutions for a closure.
func depTokens(closure []Resolved, dir string) map[string]string {
	m := make(map[string]string, len(closure)*6)
	for _, r := range closure {
		p := "deps." + r.Project
		v := r.Version
		m[p+".prefix"] = filepath.Join(dir, r.Project, "v"+v.Raw)
		m[p+".version"] = v.Raw
		m[p+".version.raw"] = v.Raw
		m[p+".version.major"] = verPart(v, 0)
		m[p+".version.minor"] = verPart(v, 1)
		m[p+".version.marketing"] = verPart(v, 0) + "." + verPart(v, 1)
	}
	return m
}

func fetchRuntimeEnv(project, prefix, version string, deps map[string]string) (map[string]string, error) {
	doc, err := recipeDoc(project)
	if err != nil {
		return nil, err
	}
	env, err := mapField(doc, "runtime", "env")
	if err != nil {
		return nil, fmt.Errorf("%s: %w", project, err)
	}
	out := make(map[string]string, len(env))
	osn, arch := HostSlug()
	flattenEnv(env, out, osn, arch, prefix, version, deps)
	return out, nil
}

// flattenEnv copies scalar entries and descends into the platform-keyed blocks
// that apply here, so `linux:` reaches a linux host and `darwin:` does not. A
// map under any other key is a platform this host is not, and is skipped —
// silently, because a recipe naming platforms we do not build for is normal.
//
// The platform keys and the array rule come from libpkgx's platform_reduce,
// which is the reference implementation: it matches `linux`, `darwin`,
// `linux/x86-64`-style pairs AND a bare arch, and says of the values
//
//	// if user specifies an array then we assume we are supplementing
//	// otherwise we are replacing.
//
// so a list inside a platform block APPENDS to what the flat block set, while a
// scalar replaces it. Reading that first would have saved a guess: I had it
// replacing in both cases.
func flattenEnv(in map[string]any, out map[string]string, osn, arch, prefix, version string, deps map[string]string) {
	// Flat entries first, so a platform block supplements what they set —
	// Go map iteration has no order of its own.
	for k, v := range in {
		if _, isPlatform := platformBlock(v, k, osn, arch); !isPlatform {
			setEnv(out, k, v, prefix, version, deps, false)
		}
	}
	for k, v := range in {
		if blk, ok := platformBlock(v, k, osn, arch); ok {
			for bk, bv := range blk {
				_, supplement := bv.([]any)
				setEnv(out, bk, bv, prefix, version, deps, supplement)
			}
		}
	}
}

// platformBlock reports whether this key names a platform block that applies to
// osn/arch, returning its contents. A map under a key naming ANY platform is a
// platform block — one that does not apply is dropped, not treated as a value.
func platformBlock(v any, k, osn, arch string) (map[string]any, bool) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, false
	}
	switch k {
	case osn, osn + "/" + arch, arch:
		return m, true
	case "x86-64", "aarch64", "wasm":
		return nil, true // another arch's block: applies to nobody here
	}
	// Every OS platformKeys names, bare or as an os/arch pair, is a platform
	// block too: a recipe's `wasip1:` or `windows/x86-64:` block was read as a
	// plain value on a linux host because only linux and darwin were listed.
	if isPlatformKey(k) {
		return nil, true // another platform's block: applies to nobody here
	}
	return nil, false
}

func setEnv(out map[string]string, k string, v any, prefix, version string, deps map[string]string, supplement bool) {
	var val string
	switch t := v.(type) {
	case []any:
		parts := make([]string, 0, len(t))
		for _, e := range t {
			p, ok := resolvedOrEmpty(fmt.Sprint(e), prefix, version, deps)
			if !ok {
				return // one unresolved element makes the whole value wrong
			}
			parts = append(parts, p)
		}
		val = strings.Join(parts, " ")
	case nil:
		return // an empty value is not a declaration
	case map[string]any:
		return // a map that is not a platform block is not a value
	default:
		v, ok := resolvedOrEmpty(fmt.Sprint(t), prefix, version, deps)
		if !ok {
			return
		}
		val = v
	}
	if supplement && out[k] != "" {
		out[k] += " " + val
		return
	}
	out[k] = val
}

// expandRecipeVars resolves the moustache placeholders that can appear in a
// runtime env value. Only the ones that mean something for an INSTALLED package
// are handled — the prefix and the version — because a runtime env is read long
// after the build, where {{hw.concurrency}} and friends have no meaning. A
// placeholder left unresolved would end up verbatim in the environment, so an
// unknown one is dropped rather than exported as literal moustaches.
func expandRecipeVars(s, prefix, version string) string {
	// `${{prefix}}` is how 338 of the pantry's recipes write the placeholder,
	// and the `$` belongs to the placeholder, not to the value. Replacing only
	// the braces left it behind:
	//
	//	SSL_CERT_FILE=$/…/curl.se/ca-certs/v2026.8.13/ssl/cert.pem
	//	PYTHONPATH=$/…/gnome.org/libxml2/v2.13.9/lib/python3.11/site-packages
	//
	// curl says so out loud — "error adding trust anchors from file: $/…" —
	// and everything else just silently fails to find what it was pointed at.
	//
	// Only a `$` GLUED to the braces goes: `$PYTHONPATH:${{prefix}}/lib` has a
	// real shell variable in it, and that one has to survive.
	s = strings.ReplaceAll(s, "${{", "{{")
	v := ParseVer(version)
	rep := strings.NewReplacer(
		"{{prefix}}", prefix,
		"{{ prefix }}", prefix,
		"{{version}}", version,
		"{{ version }}", version,
		"{{version.raw}}", version,
		"{{ version.raw }}", version,
		"{{version.major}}", verPart(v, 0),
		"{{ version.major }}", verPart(v, 0),
		"{{version.minor}}", verPart(v, 1),
		"{{ version.minor }}", verPart(v, 1),
		"{{version.marketing}}", verPart(v, 0)+"."+verPart(v, 1),
		"{{ version.marketing }}", verPart(v, 0)+"."+verPart(v, 1),
	)
	return moustacheLeftovers.ReplaceAllString(rep.Replace(s), "")
}

// expandRecipeVarsRaw is expandRecipeVars without the final sweep, so a caller
// can see whether a placeholder it does not know survived.
func expandRecipeVarsRaw(s, prefix, version string, deps map[string]string) string {
	s = strings.ReplaceAll(s, "${{", "{{")
	v := ParseVer(version)
	// Dependency tokens first: a project name can contain dots and slashes, so
	// they are matched literally rather than by pattern.
	for k, val := range deps {
		s = strings.ReplaceAll(s, "{{"+k+"}}", val)
		s = strings.ReplaceAll(s, "{{ "+k+" }}", val)
	}
	return strings.NewReplacer(
		"{{prefix}}", prefix,
		"{{ prefix }}", prefix,
		"{{version}}", version,
		"{{ version }}", version,
		"{{version.raw}}", version,
		"{{ version.raw }}", version,
		"{{version.major}}", verPart(v, 0),
		"{{ version.major }}", verPart(v, 0),
		"{{version.minor}}", verPart(v, 1),
		"{{ version.minor }}", verPart(v, 1),
		"{{version.marketing}}", verPart(v, 0)+"."+verPart(v, 1),
		"{{ version.marketing }}", verPart(v, 0)+"."+verPart(v, 1),
	).Replace(s)
}

// resolvedOrEmpty returns the expansion, and false when a placeholder we do not
// know survived it.
//
// Dropping the unknown one and keeping the rest is what we used to do, and it
// FABRICATES a path. rust-lang.org/cargo declares
//
//	CARGO_INSTALL_ROOT: ${{home}}/.local
//	CARGO_HTTP_CAINFO: ${{deps.curl.se/ca-certs.prefix}}/ssl/cert.pem
//
// and we exported `CARGO_INSTALL_ROOT=/.local` and
// `CARGO_HTTP_CAINFO=/ssl/cert.pem` — two absolute paths that exist nowhere,
// pointing the TLS trust store at nothing, with no error anywhere.
//
// libpkgx's useMoustaches `apply()` only substitutes tokens it has, so an
// unknown one survives VERBATIM rather than being deleted. Leaving `{{home}}`
// in an environment variable is no better for us, so the variable is dropped
// instead: absent is a condition a caller can notice, wrong is not.
func resolvedOrEmpty(s, prefix, version string, deps map[string]string) (string, bool) {
	out := expandRecipeVarsRaw(s, prefix, version, deps)
	if moustacheLeftovers.MatchString(out) {
		return "", false
	}
	return out, true
}

// verPart returns the i-th numeric component of a version, or "0".
func verPart(v Ver, i int) string {
	if i < len(v.Nums) {
		return strconv.Itoa(v.Nums[i])
	}
	return "0"
}

// moustacheLeftovers matches any placeholder expandRecipeVars does not know.
var moustacheLeftovers = regexp.MustCompile(`\{\{[^}]*\}\}`)
