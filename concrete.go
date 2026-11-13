package artifact

import (
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// A CONCRETE SPEC IS WHAT A ARTIFACT IS.
//
// # The question this answers
//
// Two artifacts of the same version, compiled with different options, were
// indistinguishable: the identity of an artifact was
//
//	<project> : <version>[_N][-glibc<X>]  ×  <os>/<arch>
//
// and nothing in it names a build option. `openmpi+cuda` and `openmpi~cuda`
// could not coexist — the only way to publish both was the `_N` rebuild
// counter, which is an ORDER ("the newer replaces the older"), not a choice.
// In an HPC pantry that is the difference between expressing a dependency and
// hoping for one.
//
// # Why a hash, and why over everything
//
// Spack is the precedent, including its false starts: it carried THREE hashes
// — dag_hash, build_hash and full_hash — and in 2022 collapsed them into one
// dag_hash covering build, link and run dependencies plus the hash of the
// package file itself. The project that lived this tension longest tried the
// split and came back from it.
//
// # ⛔⛔ A CONCRETE SPEC IS NOT A REQUEST
//
// The first version of this type used one map for both, and that was the
// design error. Spack keeps them apart and must: `fabrics=verbs,ofi` means
// AT LEAST those, `fabrics:=verbs,ofi` means EXACTLY those, and `++debug`
// propagates to dependents. All three describe how to CHOOSE a build. None of
// them describes a build — once concretised, a node has one definite set of
// values, and the question "was this asked for exactly or at least?" has no
// answer here because it was already answered.
//
// So: VariantConstraints are what a user writes (see ParseConstraints), and
// Variants are what an artifact has. Mixing them would put a question into an
// identity, and two artifacts reached by different questions would hash apart
// while being the same bytes.
//
// # glibc is not a special case
//
// It used to be one: a `-glibc<X>` tag suffix with its own splitter, its own
// branch in selectVersions and its own host-derived selector. It is a
// DEPENDENCY whose version changes the ABI, so it belongs in Deps like any
// other, and the readable suffix was a second spelling of identity — the exact
// shape of defect that let numericKey drop a published version three times
// over (see its comment).
//
// Readability is served by the annotation and the local catalogue, which is
// where `spack find -l` serves it too. The tag carries the address.
type Concrete struct {
	// Platform is "<os>/<arch>", eg. "linux/x86-64".
	//
	// ⛔ IN THE HASH, because reuse across operating systems is otherwise
	// silently wrong. Spack carries an `os_compatible` map and it is
	// DIRECTIONAL — sonoma may reuse monterey's builds and not the reverse —
	// which is only expressible if the identity says which one it is. An
	// identity that omitted the platform would let a darwin artifact answer a
	// linux pin, and the error would surface as a missing symbol.
	Platform string

	// Variants are the build options this artifact WAS BUILT WITH: definite,
	// possibly multi-valued, never a constraint. A boolean is ["true"] or
	// ["false"].
	Variants Variants

	// Deps is the resolved closure: every project this build was made
	// against, at the exact version and hash it was made against. glibc is
	// one of these.
	Deps []Dep

	// Recipe is the digest of the build PLAN the recipe produced — never of
	// the recipe file's bytes.
	//
	// ⛔ CANONICALISED, AND THE DISTINCTION IS THE WHOLE VALUE. Nix hashes the
	// derivation — the instantiated plan — not the expression that produced
	// it, and Spack's package_hash strips comments and docstrings from
	// package.py before hashing. Digesting the file's bytes instead would
	// make a reflowed comment rebuild the world: every dependent's hash
	// changes, every artifact is republished, and nothing about any binary
	// differs. That is not a conservative choice, it is a wrong one — it
	// spends the fleet's whole build capacity on whitespace.
	//
	// So the producer owes this field a digest over the RESOLVED build: the
	// script after substitution, the environment, the flags. bk computes it;
	// artifact only carries it, and states the contract here because a field
	// that merely says "digest" invites the cheap, wrong answer.
	Recipe string

	// Graft, when set, is the hash of the spec this artifact was produced from
	// by rewriting references rather than by building.
	//
	// ⛔⛔ THE FIELD EXISTS NOW BECAUSE IT CANNOT BE ADDED LATER. A full-closure
	// identity means a CVE fix in a leaf changes the hash of every dependent,
	// so shipping one would rebuild and re-download the world. Guix's answer
	// is not to weaken the hash: it patches store references in the already
	// built output — "grafting works by patching files, including binary
	// files, directly" — in "time proportional to the size of the package,
	// usually less than a minute", and the result is a NEW store item while
	// the original stays reachable (`guix build bash --no-grafts`).
	//
	// That only works if a grafted artifact has an identity of its own, which
	// means this field is in the canonical form. Adding it after the first
	// artifact is published would change every hash already issued.
	//
	// Guix's restrictions come with it and are not ours to relax: the
	// replaced and replacing name+version must be the SAME LENGTH (the patch
	// is in-place in binaries), and a shared library's replacement must keep
	// the same SONAME and be binary-compatible. The layer that performs
	// grafts enforces those; this field only records that one happened.
	Graft string
}

// Dep is one resolved edge of a closure: a project at a version, and the hash
// of the concrete spec that version was itself built from.
//
// The hash is part of the edge, not a lookup: depending on "openssl.org 3.6.4"
// is ambiguous once openssl itself has variants, and an identity built from
// the ambiguous half would collide exactly where it matters.
type Dep struct {
	Project string
	Version string
	Hash    string
}

// Variants are the definite build options of a built artifact: name to its
// values, sorted. Multi-valued because Spack's are — `languages=c,c++` is one
// variant with two values, not two variants — and a single-string map would
// have had to invent an escape for the comma.
type Variants map[string][]string

// canonSep separates fields inside one canonical line.
//
// ⛔⛔ IT IS NOT WHAT MAKES THE FORM UNAMBIGUOUS — the length prefix is. An
// earlier version separated a variant's values with a second reserved byte
// and relied on ParseConstraints to refuse it in a value, and the test caught
// the hole immediately: a Concrete can be built straight from a registry
// annotation, which never passes through that parser, and then
//
//	{"x": ["a", "b"]}   and   {"x": ["a\x01b"]}
//
// render to the same bytes and so to the same hash. A validator guards the
// door it stands at; an encoding has to be injective wherever the value came
// from, because the attacker supplies the annotation.
const canonSep = "\x00"

// Canonical renders the spec as the exact bytes that are hashed.
//
// ⛔ EVERY FIELD IS SORTED AND DELIMITED. A canonical form that depended on map
// order would give one build two identities, and one built by concatenation
// without a delimiter would give two builds one: {"ab","c"} and {"a","bc"}
// hash alike the moment the separator is "". Both are tested.
//
// ⛔ AND THE INSTALL PREFIX IS NOT IN IT. $ZPKG_DIR is where an artifact lands,
// not what it is. Nix states the consequence of getting this wrong: "One
// cannot copy a store object to a store with a different store directory",
// and a cache stops being shareable the moment identity depends on where the
// reader keeps it. Our having no fixed prefix is only an advantage while the
// prefix stays out of here.
func (c Concrete) Canonical() string {
	var b strings.Builder
	b.WriteString("v1")

	if c.Platform != "" {
		field(&b, "platform", c.Platform)
	}

	names := make([]string, 0, len(c.Variants))
	for n := range c.Variants {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		vals := append([]string(nil), c.Variants[n]...)
		sort.Strings(vals)
		// The COUNT is written too, so a variant's value list cannot be
		// confused with a longer list belonging to the next field.
		field(&b, "var", n, strconv.Itoa(len(vals)))
		for _, v := range vals {
			field(&b, v)
		}
	}

	deps := append([]Dep(nil), c.Deps...)
	sort.Slice(deps, func(i, j int) bool {
		if deps[i].Project != deps[j].Project {
			return deps[i].Project < deps[j].Project
		}
		if deps[i].Version != deps[j].Version {
			return deps[i].Version < deps[j].Version
		}
		return deps[i].Hash < deps[j].Hash
	})
	for _, d := range deps {
		field(&b, "dep", d.Project, d.Version, d.Hash)
	}

	if c.Recipe != "" {
		field(&b, "recipe", c.Recipe)
	}
	if c.Graft != "" {
		field(&b, "graft", c.Graft)
	}
	return b.String()
}

// field writes each part length-prefixed, which is what makes the canonical
// form injective: "<len>:<bytes>" can be read back one way only, whatever the
// bytes are. See canonSep for the hole this closes.
func field(b *strings.Builder, parts ...string) {
	for _, p := range parts {
		b.WriteString(canonSep)
		b.WriteString(strconv.Itoa(len(p)))
		b.WriteString(":")
		b.WriteString(p)
	}
}

// hashLen is how many base32 characters of the digest reach the tag.
//
// 16 characters is 80 bits. An OCI tag is 128 characters at most and must
// match [a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}, which excludes base64's "+" and
// "/" and is why this is base32 and not something shorter. Spack spends 32
// characters, conda 7; 16 leaves room for a long version beside it and puts a
// collision far outside the reach of a registry that holds thousands of
// artifacts, not quintillions.
//
// It is also long enough and fixed enough to be SCANNED FOR. Nix derives a
// build's runtime references by looking for "the digest of each input" in the
// output bytes, and "the name part and the store directory path are ignored
// when scanning" — so that technique needs a fixed-length high-entropy
// digest, not a fixed store prefix. Ours qualifies; our soname analysis
// misses what scanning catches (dlopen, shebangs, RPATH, .pc and .la files),
// and this is the hook that lets us add it.
const hashLen = 16

// lowerBase32 is RFC 4648 base32 without padding, lowercased: the alphabet an
// OCI tag accepts, and stable across Go versions.
var lowerBase32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// Hash is the spec's address: the first hashLen base32 characters of the
// SHA-256 of its canonical form.
//
// An EMPTY spec hashes to "": an artifact with no platform, no declared
// variants, no recorded closure and no recipe digest is one we know nothing
// about, and giving it an address would claim knowledge we do not have. That
// is also what makes every tag published before this existed readable — it
// has no hash because nothing recorded one, which is true.
func (c Concrete) Hash() string {
	if c.IsZero() {
		return ""
	}
	sum := sha256.Sum256([]byte(c.Canonical()))
	return strings.ToLower(lowerBase32.EncodeToString(sum[:]))[:hashLen]
}

// IsZero reports whether nothing about this build was recorded.
func (c Concrete) IsZero() bool {
	return c.Platform == "" && len(c.Variants) == 0 && len(c.Deps) == 0 && c.Recipe == "" && c.Graft == ""
}

// String renders variants the way a person writes them, which is the way
// `pkgx ls` and the catalogue show them: `+cuda ~mpi fabrics=ofi,verbs`.
//
// This is a RENDERING, never an identity. Hash is the identity, and the two
// must not be confused: a reader that compared these strings would call two
// builds equal whenever their deps differ and their variants do not.
func (v Variants) String() string {
	if len(v) == 0 {
		return ""
	}
	names := make([]string, 0, len(v))
	for n := range v {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]string, 0, len(names))
	for _, n := range names {
		vals := append([]string(nil), v[n]...)
		sort.Strings(vals)
		switch {
		case len(vals) == 1 && vals[0] == "true":
			out = append(out, "+"+n)
		case len(vals) == 1 && vals[0] == "false":
			out = append(out, "~"+n)
		default:
			out = append(out, n+"="+strings.Join(vals, ","))
		}
	}
	return strings.Join(out, " ")
}

// VariantTag is the suffix a concrete spec contributes to a registry tag, or
// "" when there is nothing to say.
func (c Concrete) VariantTag() string {
	h := c.Hash()
	if h == "" {
		return ""
	}
	return variantSep + h
}

// variantSep introduces the hash in a tag. "-h" rather than "-v" because "v"
// already prefixes versions everywhere in this codebase (the v<version>
// install prefix, the `v` ParseVer strips), and a reader meeting `-v8f3a2c1`
// would reasonably take it for one.
const variantSep = "-h"

// SplitVariantHash cuts a trailing variant hash off a registry tag.
//
//	"3.3.11"                   → "3.3.11", ""
//	"3.3.11-habcdefghij012345" → "3.3.11", "abcdefghij012345"
//
// A suffix that is not exactly hashLen characters of the hash alphabet is NOT
// a hash: a version like "1.0-h2" would otherwise read as a truncated one,
// and that silently changes which artifact a pin means.
func SplitVariantHash(tag string) (version, hash string) {
	i := strings.LastIndex(tag, variantSep)
	if i <= 0 {
		return tag, ""
	}
	h := tag[i+len(variantSep):]
	if !isVariantHash(h) {
		return tag, ""
	}
	return tag[:i], h
}

// isVariantHash reports whether s is exactly a variant hash: hashLen
// characters drawn from lowercase base32.
func isVariantHash(s string) bool {
	if len(s) != hashLen {
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

// --- the request side ------------------------------------------------------

// VariantConstraint is what a USER asks for, which is strictly more than what
// an artifact has.
type VariantConstraint struct {
	// Values the variant must take. For a boolean, ["true"] or ["false"].
	Values []string
	// Exact distinguishes Spack's two spellings: `fabrics=verbs,ofi` asks for
	// AT LEAST those values, `fabrics:=verbs,ofi` for EXACTLY those. Without
	// the distinction "give me a build with ofi" and "give me a build with
	// ofi and nothing else" are the same request, and one of them gets the
	// wrong artifact.
	Exact bool
	// Propagate carries the constraint down to dependencies — Spack's `++`,
	// `~~` and `==`. It is resolved during concretisation, which is why no
	// such field exists on Variants: by then every node holds the value it
	// was given, and how it came to hold it is not part of what it IS.
	Propagate bool
}

// VariantConstraints is a parsed variant request.
type VariantConstraints map[string]VariantConstraint

// ParseConstraints reads the spec spelling of a variant request:
//
//	+cuda  ~mpi  ++debug  ~~debug  fabrics=verbs,ofi  fabrics:=verbs,ofi
//
// ⛔ `~` IS ALSO OUR TILDE RANGE OPERATOR, and that collision is the reason
// this parser exists rather than a Split. pkgx spells a version range `~5.44`
// (verDelims is "@^~<>="), while Spack spells a disabled variant `~cuda`.
// They are told apart by what FOLLOWS the tilde: a digit begins a version, a
// letter begins a variant name. `-cuda` is not an option at all — project
// names contain hyphens (llvm.org/mingw-w64), so it cannot be a boundary.
func ParseConstraints(s string) (VariantConstraints, error) {
	out := VariantConstraints{}
	for _, tok := range strings.Fields(s) {
		name, c, err := parseConstraint(tok)
		if err != nil {
			return nil, err
		}
		if prev, dup := out[name]; dup && !sameConstraint(prev, c) {
			return nil, fmt.Errorf("variant %q constrained twice, as %q and %q",
				name, strings.Join(prev.Values, ","), strings.Join(c.Values, ","))
		}
		out[name] = c
	}
	return out, nil
}

func sameConstraint(a, b VariantConstraint) bool {
	if a.Exact != b.Exact || a.Propagate != b.Propagate || len(a.Values) != len(b.Values) {
		return false
	}
	for i := range a.Values {
		if a.Values[i] != b.Values[i] {
			return false
		}
	}
	return true
}

func parseConstraint(tok string) (name string, c VariantConstraint, err error) {
	switch {
	case strings.HasPrefix(tok, "++"):
		name, c = tok[2:], VariantConstraint{Values: []string{"true"}, Propagate: true}
	case strings.HasPrefix(tok, "~~"):
		name, c = tok[2:], VariantConstraint{Values: []string{"false"}, Propagate: true}
	case strings.HasPrefix(tok, "+"):
		name, c = tok[1:], VariantConstraint{Values: []string{"true"}}
	case strings.HasPrefix(tok, "~"):
		name, c = tok[1:], VariantConstraint{Values: []string{"false"}}
		if name != "" && name[0] >= '0' && name[0] <= '9' {
			return "", c, fmt.Errorf("%q is a version range, not a variant: a tilde variant names a variant (~cuda)", tok)
		}
	default:
		var raw string
		switch {
		case strings.Contains(tok, ":="):
			name, raw, _ = strings.Cut(tok, ":=")
			c.Exact = true
		case strings.Contains(tok, "=="):
			name, raw, _ = strings.Cut(tok, "==")
			c.Propagate = true
		case strings.Contains(tok, "="):
			name, raw, _ = strings.Cut(tok, "=")
		default:
			return "", c, fmt.Errorf("%q is not a variant: write +name, ~name or name=value", tok)
		}
		c.Values = splitValues(raw)
		if len(c.Values) == 0 {
			return "", c, fmt.Errorf("%q gives variant %q no value", tok, name)
		}
	}
	if name == "" {
		return "", c, fmt.Errorf("%q names no variant", tok)
	}
	if !isVariantName(name) {
		return "", c, fmt.Errorf("%q is not a variant name: letters, digits and underscore, starting with a letter", name)
	}
	for _, v := range c.Values {
		if !isVariantValue(v) {
			return "", c, fmt.Errorf("variant %q has value %q, which cannot appear in an identity", name, v)
		}
	}
	sort.Strings(c.Values)
	return name, c, nil
}

// splitValues cuts a comma-separated value list, dropping empties so
// "a,,b" and "a,b" are one request rather than two spellings of it.
func splitValues(raw string) []string {
	out := []string{}
	for _, v := range strings.Split(raw, ",") {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

// Satisfies reports whether a built artifact's variants answer this request.
//
// ⛔ THE TWO SPELLINGS MEAN DIFFERENT THINGS, which is the whole reason
// VariantConstraint exists: `=` is a subset test and `:=` an equality. A
// resolver that treated them alike would hand "built with ofi and verbs" to
// someone who asked for ofi ALONE — an artifact linked against a fabric library
// their machine does not have.
func (cs VariantConstraints) Satisfies(have Variants) bool {
	for name, c := range cs {
		got, present := have[name]
		if !present {
			return false
		}
		set := map[string]bool{}
		for _, v := range got {
			set[v] = true
		}
		for _, want := range c.Values {
			if !set[want] {
				return false
			}
		}
		if c.Exact && len(got) != len(c.Values) {
			return false
		}
	}
	return true
}

// isVariantName bounds what may reach a canonical form and, through it, a
// hash. Anything outside this cannot appear in a tag, and a name carrying the
// canonical separator could forge another spec's identity.
func isVariantName(s string) bool {
	if s == "" || !isLetter(s[0]) {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !isLetter(c) && !(c >= '0' && c <= '9') && c != '_' {
			return false
		}
	}
	return true
}

// isVariantValue is looser than isVariantName — a value may be "c++" or
// "-O3" — but it refuses the canonical separator, the comma that divides a
// value list, and whitespace that would split the token.
//
// Belt beside braces: Canonical is injective on its own now (see field), so a
// value arriving by another route cannot forge an identity. What this buys is
// a REFUSAL AT THE DOOR rather than a surprising hash later, for the one
// input a person types by hand.
// The empty string never reaches here: splitValues drops empties and
// parseConstraint refuses a variant left with no value at all, so a guard for
// it would be one no caller can reach — the kind the coverage gate finds and
// a reader later mistakes for a reachable case.
// ⛔ IT ALSO REQUIRES VALID UTF-8, WHICH IS A WIRE CONSTRAINT AND NOT A
// TASTE. A spec travels as JSON in an OCI annotation, and encoding/json
// replaces invalid UTF-8 with U+FFFD rather than failing. The value that
// comes back is then NOT the value that went out, so its hash is not the
// hash that went out, and a perfectly honest artifact fails its own
// verification. Caught by a test that put a stray \xff in a variant value
// and watched the hash change across the wire.
//
// Refusing here keeps the annotation lossless for everything the door
// admits, which is every flag anyone writes: -O3, c++, 80. Base64 in the
// annotation would buy a case that does not exist by making the one thing a
// person reads unreadable.
func isVariantValue(s string) bool {
	return utf8.ValidString(s) && !strings.ContainsAny(s, canonSep+", \t\n")
}

func isLetter(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

// Bool reads a variant as a boolean, reporting whether it was a single
// boolean value at all.
func (v Variants) Bool(name string) (val, ok bool) {
	vals, present := v[name]
	if !present || len(vals) != 1 {
		return false, false
	}
	switch vals[0] {
	case "true":
		return true, true
	case "false":
		return false, true
	}
	return false, false
}
