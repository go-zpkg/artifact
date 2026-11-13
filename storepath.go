package artifact

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// The store's layout, in one place.
//
// ⛔⛔ A PATH KEYED ON THE VERSION ALONE CANNOT HOLD TWO BUILDS OF ONE VERSION,
// AND THAT IS THE WHOLE PROBLEM THIS FILE EXISTS FOR.
//
// Measured before writing it: the convention `<dir>/<project>/v<version>` was
// spelled out at NINE call sites — install.go:131, 240, 241, 271, 357,
// closure.go:278, 532, zpkg.go:2057, 2155 — and read back at none. Two artifacts
// that differ only in their build options resolve to the same directory, so
// installing the second one meets the first and the installer refuses:
//
//	already holds other content … the artifact carries v3.3.11
//
// That refusal is correct behaviour on a wrong layout. `+cuda` and `~cuda`
// are not a sequence, there is no newer one, and nothing in the path says
// which of them is on disk.
//
// So the directory carries the concrete spec's hash when there IS one:
//
//	<dir>/<project>/v3.3.11                      identity not recorded
//	<dir>/<project>/v3.3.11-habcdefghij012345    THIS build of 3.3.11
//
// The bare form is not a default and not a fallback for a hash we could have
// computed. It is the honest statement that an artifact arrived without a spec
// annotation — a mirrored artifact, or one built before bk published one — and
// that nothing on disk can say which build it is. Minting a hash for it would
// put a claim in the path that no witness supports.
//
// ⛔ THE SEPARATOR IS SHARED WITH THE REGISTRY TAG ON PURPOSE. variantSep is
// what `bk` writes into the tag and what SplitVariantHash reads back out, so
// a directory name and a tag suffix cannot drift apart into two spellings of
// one idea. The round trip is asserted, not assumed.

// StorePrefix returns the directory an artifact occupies in a store.
//
// It is the ONLY place that composes one. Nine inline spellings is nine
// chances for one of them to forget the variant hash, and a path that forgets
// it silently addresses somebody else's build.
// ⛔⛔ IT RESOLVES FIRST, AND THAT IS WHAT KEEPS EVERY CALLER CORRECT. Since
// every installed directory carries a hash, `<dir>/<project>/v<version>` is
// no longer a path that exists in a store; six read sites compute it and
// would all have to learn to ask. They ask through here instead.
//
// When nothing is installed — or when several builds are and the request
// does not say which — it falls back to the COMPOSED path, which is the
// same string those callers got before anything was installed. Their
// "not installed" branch is a failing os.Stat either way, so none of them
// changes behaviour; what changes is that an installed build is now found
// under its hash.
func StorePrefix(dir, project string, v Ver) string {
	if p, ok := ResolveBuild(dir, project, v); ok {
		return p
	}
	return filepath.Join(dir, project, StoreDirName(v))
}

// StoreDirName is the single directory component under the project — the
// ALIAS when there is no recorded variant, because that is what a reader
// computes from (project, version) alone.
//
// ⛔ THIS IS NOT ALWAYS THE REAL DIRECTORY. Since every install is written to
// a hashed directory (see StoreBuildDirName), a bare `v<version>` here names
// a SYMLINK to one. Readers follow it; the installer never writes it as a
// directory.
func StoreDirName(v Ver) string {
	name := "v" + v.Raw
	if v.Variant != "" {
		name += variantSep + v.Variant
	}
	return name
}

// StoreBuildDirName is the REAL directory a build occupies: always hashed.
//
// ⛔⛔ EVERY INSTALLED TREE CARRIES ITS HASH, WITH NO EXCEPTION. A layout with
// two shapes — `v3.3.11` here and `v3.3.11-h…` there — is one a reader has to
// branch on, and the branch is where two builds of one version silently
// become one. The alias `v3.3.11` still exists, as a SYMLINK, so nothing that
// computes a path from (project, version) has to change; what it points at
// names which build it is.
//
// The hash comes from the strongest witness available, in this order:
//
//	the tag's variant hash   the concrete spec: platform, declared variants,
//	                         resolved closure, recipe plan. What `bk` published.
//	the content digest       the artifact's own manifest digest. Says "these
//	                         exact bytes" and nothing about why.
//	the source               neither is available: an unverified HTTP dist,
//	                         which by construction offers no digest to trust.
//
// ⛔ THE THIRD IS NAMED AND NOT HIDDEN. It hashes where the bytes were asked
// for, not what came back, so it does NOT distinguish two different builds
// served from one URL. That is the honest limit of an unsigned dist —
// ZPKG_VERIFY already has to be off to reach it — and giving it the same
// shape as the others keeps the layout uniform without pretending the
// guarantee is the same.
func StoreBuildDirName(v Ver, hash string) string {
	if hash == "" {
		// A caller that reached here with nothing is a bug, not an artifact:
		// StoreHash always answers. Fail visibly rather than write a path
		// that silently rejoins the old shape.
		panic("artifact: StoreBuildDirName with no hash — the layout has two shapes again")
	}
	return "v" + v.Raw + variantSep + hash
}

// StoreBuildPrefix is StorePrefix for the real, hashed directory.
func StoreBuildPrefix(dir, project string, v Ver, hash string) string {
	return filepath.Join(dir, project, StoreBuildDirName(v, hash))
}

// StoreHash picks the hash a build's directory carries. See
// StoreBuildDirName for the order and why.
func StoreHash(v Ver, contentDigest, source string) string {
	if v.Variant != "" {
		return v.Variant
	}
	if contentDigest != "" {
		return hashOf("digest\x00" + contentDigest)
	}
	return hashOf("source\x00" + source)
}

// hashOf is the project's one hash shape: hashLen characters of lowercase
// base32 over sha256, exactly as Concrete.Hash renders a spec. One shape
// everywhere means a directory name cannot say which kind of hash it is —
// which is deliberate: the path addresses a build, and what is known ABOUT
// that build is the spec annotation's job, not the path's.
func hashOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return strings.ToLower(lowerBase32.EncodeToString(sum[:]))[:hashLen]
}

// ShortHash renders any identity string in the one shape a store path and an
// OCI tag both use.
//
// ⛔ IT LIVES HERE BECAUSE BOTH WRITERS DO. The factory computes a build's
// identity (go-zpkg/zbk's spec package) and has to put it in a tag; the
// installer has to find the matching directory. If each shortened in its own
// way the two would silently address different things, and the symptom would
// be "the artifact is not published" for an artifact that is.
func ShortHash(identity string) string { return hashOf(identity) }

// linkStoreAlias makes `<store>/<project>/v<version>` resolve to one build.
//
// ⛔⛔ THIS LINK IS PART OF THE PUBLISHED ABI, WHICH IS WHY IT LIVES IN THE
// STORE AND NOT IN A VIEW. Measured on a real published artifact —
// `otool -l` on zlib.net 1.3.2 for darwin/aarch64 gives
// `name @rpath/zlib.net/v1.3.2/lib/libz.1.dylib` — so every binary linking
// zlib names that exact path. A store without it breaks them at load time.
//
// ⛔ RELATIVE TARGET. An artifact tree is relocatable; an absolute link would be
// the one thing in it that is not, and the whole store is routinely mounted
// somewhere else (an NFS export, a container rootfs, a staged builder).
//
// ⛔ IT DOES NOT OVERWRITE A REAL DIRECTORY. One there is a store written by
// a release that did not hash paths, and replacing an installed tree with a
// symlink is not something to do silently — the install is refused instead,
// naming the path.
// LinkView materialises the `v<version>` alias for ONE build inside a VIEW —
// a user's profile, an environment, or a container rootfs being assembled.
//
// ⛔⛔ A DEFAULT IS NOT A PROPERTY OF THE STORE, AND AN HPC SITE IS WHERE THAT
// STOPS BEING A NICETY. The store is a shared NFS export: one copy of each
// build, read by everyone, writable by few. An alias written INTO it would
// make one user's choice of default everyone's, and would need write access
// to a tree that is often mounted read-only. The first version of this wrote
// the alias into the store, and that is the bug.
//
// So the store holds hashed directories and nothing else — no mutable state,
// no selection, safe to share and safe to freeze. "Which build do I get when
// I do not say" is answered by a VIEW, and a view is built for a context:
//
//	a user's default      their own state directory
//	an environment        resolved to exact hashes when it is loaded, so it
//	                      never consults a default at all
//	a container/microVM   the links are COMPUTED INTO THE IMAGE at creation
//	                      time from the shared store, which is why they must
//	                      not be in the store to begin with
//
// That is Nix's profiles and Spack's views, and the reason both keep the
// store immutable.
//
// ⛔ THE TARGET IS ABSOLUTE HERE, UNLIKE AN IN-STORE LINK. A view normally
// sits on a different filesystem from the store — a home directory beside an
// NFS export, an image being staged under a build root — so a relative
// target would resolve against the view and find nothing. A view is a
// projection of one particular store; it is not itself relocatable, and
// pretending otherwise would produce links that are silently dangling.
func LinkView(viewDir, storeDir, project string, v Ver, hash string) error {
	real := StoreBuildPrefix(storeDir, project, v, hash)
	if st, err := os.Stat(real); err != nil || !st.IsDir() {
		return fmt.Errorf("artifact: %s %s build %s is not installed in %s",
			project, v.Raw, hash, storeDir)
	}
	abs, err := filepath.Abs(real)
	if err != nil {
		return err
	}
	alias := filepath.Join(viewDir, project, "v"+v.Raw)
	if err := os.MkdirAll(filepath.Dir(alias), 0o755); err != nil {
		return err
	}
	// Replace a link; refuse a directory. A directory there is either a store
	// written by a release that did not hash paths, or a view somebody filled
	// by hand — and deleting an installed tree to make room for a symlink is
	// not something to do quietly.
	if st, err := os.Lstat(alias); err == nil && st.Mode()&os.ModeSymlink == 0 && st.IsDir() {
		return fmt.Errorf("artifact: %s is a directory, not a view link — "+
			"remove or move it first", alias)
	}
	_ = os.Remove(alias)
	return os.Symlink(abs, alias)
}

// ResolveBuild finds the installed build a (project, version) names.
//
// ⛔⛔ THIS IS WHAT REPLACES COMPUTING `<dir>/<project>/v<version>`. Since
// every real directory carries a hash, that path no longer exists in the
// store, and a reader cannot derive it — it has to ASK. The order is:
//
//	the version says which    a Ver carrying a variant hash is exact, and
//	                          nothing else is consulted
//	exactly one is installed  the ordinary case, and unambiguous
//	several are installed     AMBIGUOUS. "" with ok=false, and the caller
//	                          says so rather than picking one
//
// ⛔ SEVERAL IS NOT "TAKE THE NEWEST". Two builds of one version are siblings
// — that is the whole reason they both exist — and there is no order between
// them to take the first of. A reader that silently picked would give a
// different answer tomorrow for the same request, which is exactly the defect
// the hashed layout was introduced to remove.
func ResolveBuild(dir, project string, v Ver) (string, bool) {
	if v.Variant != "" {
		p := StoreBuildPrefix(dir, project, v, v.Variant)
		if st, err := os.Stat(p); err == nil && st.IsDir() {
			return p, true
		}
		return "", false
	}
	var found []Ver
	for _, b := range InstalledBuilds(project, dir) {
		if b.Raw == v.Raw {
			found = append(found, b)
		}
	}
	if len(found) != 1 || found[0].Variant == "" {
		return "", false
	}
	return StoreBuildPrefix(dir, project, found[0], found[0].Variant), true
}

// ParseStoreDirName is the other direction: what a directory in the store
// says about the artifact inside it.
//
// It reports false for anything that is not a version directory, which
// includes the `v1` / `v1.2` / `v*` aliases writeVersionLinks leaves beside
// the real ones. A digit after the `v` is what separates a version from a
// word, and the aliases' second character is not one.
//
// ⛔ THE HASH IS CUT BEFORE ParseVer SEES THE NAME. Without that, a variant
// directory parses as a version whose Raw is `3.3.11-habcdefghij012345` — a
// string that matches no constraint, compares below every real 3.3.11, and
// names a release that does not exist. The order here is the correctness.
func ParseStoreDirName(name string) (Ver, bool) {
	if !strings.HasPrefix(name, "v") {
		return Ver{}, false
	}
	body := name[1:]
	if body == "" || body[0] < '0' || body[0] > '9' {
		return Ver{}, false
	}
	raw, hash := SplitVariantHash(body)
	v := ParseVer(raw)
	v.Variant = hash
	return v, true
}
