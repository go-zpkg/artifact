package artifact

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Listing the builds of a version, and naming one.
//
// ⛔⛔ THE RESOLVER REFUSES AN AMBIGUOUS VERSION, AND UNTIL NOW THAT WAS A
// DEAD END. It says, correctly:
//
//	fftw.org 3.3.11 was published as 2 different builds (…) and nothing here
//	says which: a variant hash is not a version, so there is no newest one
//	to pick
//
// A refusal that cannot be answered is only half a design. These are the two
// halves it was missing: ask WHICH builds exist, and say which one you mean.

// Build is one build of one version: what distinguishes it, and where it is.
type Build struct {
	Version Ver
	// Installed is its path in the store, or "" when it is only published.
	Installed string
	// Published says the registry carries it.
	Published bool
	// Spec is what the build IS, read from its manifest. Zero when the
	// registry could not be asked, when the artifact predates identities, or
	// when it was only mirrored — all three are "nothing records what this
	// was built from", which a caller must say rather than show as blank.
	//
	// ⛔ IT IS WHY THE LIST IS USABLE AT ALL. Two hashes with nothing beside
	// them hand the reader the problem the command was asked to solve; see
	// Distinguish.
	Spec Concrete
	// InstalledAt is when this build's directory appeared in THIS store, or
	// the zero time when it is not installed.
	//
	// ⛔ IT IS NOT A BUILD DATE AND MUST NOT BE SHOWN AS ONE. A published
	// artifact has no recoverable build date — the timestamp is pinned so a
	// re-publish is byte-identical. This is when you got it. See BuildOrder.
	InstalledAt time.Time
	// Builder is what made this build, from the in-toto provenance —
	// `https://github.com/go-zpkg/zbk@v0.64.0`. Empty when nothing records
	// it.
	//
	// ⛔ IT IS NOT IN THE HASH, ON PURPOSE, AND THAT IS WHY IT HAS TO BE
	// SHOWN. A zbk release must not re-address every artifact in the registry
	// — Nix and Spack take the same position about their own builders — so
	// two artifacts built by different factories from identical inputs share
	// an identity. The only way a reader can tell them apart is this field,
	// which means a listing that omits it has thrown away the answer to
	// "with what was this built?".
	Builder string
	// Signatures is who vouches for this build, or nil when the registry was
	// not asked or would not answer.
	//
	// ⛔ NIL IS "NOT ASKED", NOT "NOBODY". The two must stay distinguishable
	// all the way to the screen: a column that printed an empty cell for
	// both would turn a network failure into the claim that a build is
	// unsigned, which is how a user ends up rebuilding something that was
	// fine — or trusting something that was not.
	Signatures *SignatureReport
}

// Hash is the build's address — the short form that appears in its tag and
// its directory name.
func (b Build) Hash() string { return b.Version.Variant }

// ShortBuilder renders a SLSA builder id for a column:
//
//	https://github.com/go-zpkg/zbk@v0.64.0  →  zbk@v0.64.0
//	https://github.com/go-pkgx/bk@v0.26.0   →  bk@v0.26.0
//
// ⛔ THE ORGANISATION IS DROPPED AND THE TOOL AND VERSION ARE NOT. A reader
// scanning the column is asking "which factory, how old"; the host and owner
// are the same for every row we publish and spend a third of the line. An id
// that does not look like a URL is returned whole — a builder we do not
// recognise is exactly the one worth reading in full.
func ShortBuilder(id string) string {
	i := strings.LastIndexByte(id, '/')
	if i < 0 || !strings.Contains(id, "://") {
		return id
	}
	return id[i+1:]
}

// BuildsOf lists every build of one version of a project: those installed in
// dir, those published for osn/arch, and the ones that are both.
//
// ⛔ ONE ANSWER FOR TWO SOURCES, BECAUSE A USER ASKING "WHICH BUILDS ARE
// THERE" DOES NOT MEAN ONE OF THEM. A list of only the installed ones cannot
// answer "what else could I have"; a list of only the published ones cannot
// answer "what do I already have". Reporting them separately would make the
// caller join two lists by hash, which is this function.
//
// ⛔ A REGISTRY THAT COULD NOT BE REACHED IS AN ERROR, NOT AN EMPTY LIST. An
// unobtained answer must not read as "nothing is published" — that is how a
// user concludes a build does not exist and rebuilds it. The installed half
// is still returned alongside the error, because it is a true answer to half
// the question and it needs no network.
func BuildsOf(project, version, dir, osn, arch string) ([]Build, error) {
	byHash := map[string]*Build{}
	var order []string

	for _, v := range InstalledBuilds(project, dir) {
		if v.Raw != version {
			continue
		}
		p := StoreBuildPrefix(dir, project, v, v.Variant)
		b := &Build{Version: v, Installed: p, InstalledAt: installedAt(p)}
		byHash[v.Variant] = b
		order = append(order, v.Variant)
	}

	published, err := publishedBuildsOf(project, version, osn, arch)
	if err != nil {
		return collect(byHash, order), err
	}
	for _, v := range published {
		if b, ok := byHash[v.Variant]; ok {
			b.Published = true
			continue
		}
		byHash[v.Variant] = &Build{Version: v, Published: true}
		order = append(order, v.Variant)
	}
	out := collect(byHash, order)
	describeBuilds(out, project, osn, arch)
	return out, nil
}

// describeBuilds reads each published build's spec off its manifest.
//
// ⛔ A SPEC THAT CANNOT BE READ IS LEFT ZERO AND THE LISTING STILL HAPPENS.
// The hashes, the store paths and the published flags are already correct and
// are what the caller asked for; refusing the whole answer because one
// manifest would not parse would trade a complete list for none. The caller
// says "nothing recorded" for the rows it could not describe, which is true
// whether the artifact predates identities or its manifest was unreadable.
//
// ⛔ AND IT IS A FEW FETCHES PER BUILD, NOT PER VERSION. That is the cost of
// the question: each build costs its manifest, its referrers listing and one
// blob per signature. A caller that cannot pay it should not be asking which
// builds exist. It stays bounded — a version has a handful of builds, not a
// catalogue's worth.
func describeBuilds(builds []Build, project, osn, arch string) {
	var c *OCIClient
	for i := range builds {
		if !builds[i].Published {
			continue
		}
		if c == nil {
			var err error
			if c, err = NewOCIClient(DistBase); err != nil {
				return
			}
		}
		// The tag the build was published under: the version, plus the hash
		// when it has one. An artifact from before identities has no suffix,
		// and asking for one would 404 a tag that exists.
		tag := builds[i].Version.Raw
		if h := builds[i].Hash(); h != "" {
			tag += variantSep + h
		}
		if spec, ok, err := c.SpecOf(project, tag, osn, arch); err == nil && ok {
			builds[i].Spec = spec
		}
		// Left nil on any error, which says "not asked" rather than
		// "nobody signed it". A report that came back short of the
		// threshold is still an ANSWER and is kept.
		//
		// One call for both: who signed it and what built it come off the
		// same referrer listing, so asking for both costs what asking for
		// one used to.
		if rep, builder, err := c.ProvenanceOfTag(project, tag, osn, arch); err == nil {
			builds[i].Signatures = &rep
			builds[i].Builder = builder
		}
	}
}

// publishedBuildsOf is the registry half, kept separate so the store half
// works with no network at all.
func publishedBuildsOf(project, version, osn, arch string) ([]Ver, error) {
	vers, err := VersionsFor(project, osn, arch)
	if err != nil {
		return nil, err
	}
	var out []Ver
	for _, v := range vers {
		if v.Raw == version {
			out = append(out, v)
		}
	}
	return out, nil
}

// collect renders the map in a stable order: by hash, because builds of one
// version are SIBLINGS.
//
// ⛔ NOT "NEWEST FIRST". There is no newest: two builds of one version differ
// in their options, not in time, and cmpVer ignores the hash for exactly that
// reason. Sorting by hash is arbitrary and says so; sorting by anything that
// looked like precedence would invent one.
func collect(byHash map[string]*Build, order []string) []Build {
	sort.Strings(order)
	out := make([]Build, 0, len(order))
	seen := map[string]bool{}
	for _, h := range order {
		if seen[h] {
			continue
		}
		seen[h] = true
		out = append(out, *byHash[h])
	}
	return out
}

// ParseBuildRef splits a spec that may name a build by hash.
//
//	fftw.org                  → "fftw.org", ""
//	fftw.org@3.3.11           → "fftw.org@3.3.11", ""
//	fftw.org@3.3.11/7k2mq4xv  → "fftw.org@3.3.11", "7k2mq4xv"
//
// ⛔ `/<hash>` IS SPACK'S SPELLING AND IT IS BORROWED ON PURPOSE. Its manual:
// "In place of a spec in any command, substitute /<hash> where <hash> is any
// amount from the beginning of a spec hash." It is the one form that works
// without knowing a package's variant vocabulary, which matters most exactly
// when a user has just been handed two hashes by a refusal and has to pick.
//
// ⛔⛔ THE `@version` IS REQUIRED BEFORE THE HASH, AND THAT IS THE WHOLE RULE.
// A project name contains slashes — a third of the pantry is named that way
// — so a trailing component cannot be told from a hash by LOOKING at it.
//
// The first attempt tried: split on the last slash when the tail "looks like
// a hash", justified by the claim that a pantry component would contain a
// letter outside base32's alphabet or be longer than a hash. That claim is
// FALSE, and a test refuted it immediately: base32 is a–z plus 2–7, which
// covers very nearly every lowercase word. `x.org/pciaccess`,
// `gnome.org/libxml2`, `wpewebkit.org/libwpe` and `github.com/gabime/spdlog`
// all parsed as hash references.
//
// So the syntax decides, not the shape: a hash may only follow an `@version`,
// and without one a trailing component is part of the project name. Always,
// with no exception to get wrong.
func ParseBuildRef(spec string) (rest, hash string) {
	i := strings.LastIndexByte(spec, '/')
	if i < 0 {
		return spec, ""
	}
	// No version, no hash: `x.org/pciaccess` is a project, full stop.
	if !strings.Contains(spec[:i], "@") {
		return spec, ""
	}
	h := spec[i+1:]
	if !isPartialHash(h) {
		return spec, ""
	}
	return spec[:i], h
}

// isPartialHash reports whether s could be the start of a build hash: at
// least four characters, all from the hash alphabet, and no longer than a
// whole one.
//
// ⛔ THIS IS A SANITY CHECK, NOT THE DISAMBIGUATION. ParseBuildRef already
// knows a hash is a hash because an `@version` precedes it; this only
// catches a typo early — `fftw.org@3.3.11/not-a-hash` says so here rather
// than failing later as "no build matches".
func isPartialHash(s string) bool {
	if len(s) < 4 || len(s) > hashLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < '2' || c > '7') {
			return false
		}
	}
	return true
}

// MatchBuild finds the one build whose hash starts with prefix.
//
// ⛔ EXACTLY ONE, OR AN ERROR NAMING THE CANDIDATES. A prefix that matches
// two builds is a question, not a choice, and answering it by picking the
// first would give a different answer as soon as another build is published.
// The error lists them so the next attempt can be longer.
func MatchBuild(builds []Build, prefix string) (Build, error) {
	var hit []Build
	for _, b := range builds {
		if strings.HasPrefix(b.Hash(), prefix) {
			hit = append(hit, b)
		}
	}
	switch len(hit) {
	case 1:
		return hit[0], nil
	case 0:
		return Build{}, fmt.Errorf("no build here has a hash starting %q (have: %s)", prefix, hashList(builds))
	default:
		return Build{}, fmt.Errorf("%q matches %d builds (%s): say more of the hash", prefix, len(hit), hashList(hit))
	}
}

func hashList(builds []Build) string {
	if len(builds) == 0 {
		return "none"
	}
	hs := make([]string, 0, len(builds))
	for _, b := range builds {
		hs = append(hs, b.Hash())
	}
	return strings.Join(hs, ", ")
}
