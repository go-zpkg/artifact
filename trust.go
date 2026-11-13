package artifact

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/go-attest/sign"
)

// Who may vouch for a build, and how many of them it takes.
//
// # ⛔⛔ TWO PEOPLE BUILDING THE SAME THING PRODUCE THE SAME HASH, ON PURPOSE
//
// The question this answers is "how do I tell a build made by two different
// people apart?", and the first half of the answer is that you do not, and
// must not want to. A build's identity is a function of its inputs; if my
// name went into it, my rebuild of your artifact would get a different address
// and could never be compared with yours. Identity has to collide for two
// independent builds of the same inputs — that collision IS the evidence.
//
// What differs between two builders is therefore not the artefact but the
// ATTESTATION: who put their key on it. So the registry holds one artifact and,
// potentially, several signatures over it, and the client counts them.
//
// # ⛔ WHICH IS WHY ONE PINNED KEY WAS NOT ENOUGH
//
// Until now artifact carried a single SigningPublicKey and oci.go verified the
// FIRST signature referrer it found. With one signer that is correct and with
// two it is not merely incomplete, it is wrong twice over:
//
//   - it cannot count — "signed by both builders" and "signed by one" are the
//     same answer;
//   - it is order-dependent — if the registry lists the other builder's
//     signature first, verification FAILS on an artifact that our own key signed,
//     and the message reads as tampering.
//
// # THE MODEL, AND WHERE IT COMES FROM
//
// A trust SET plus a THRESHOLD, which is TUF's shape (§4.3: a threshold is
// "a positive integer number of keys (>=1) of that role whose signatures are
// required"), with TUF's counting rule (§5.4.2: a client "MUST NOT count more
// than one verified SIGNATURE from that KEYID towards the THRESHOLD").
//
// The spelling of the key list is Nix's `trusted-public-keys` — whitespace
// separated, `name:key` — because an operator who has configured a Nix binary
// cache already knows it. Nix requires one signature from one trusted key;
// Guix likewise checks a single authorised signature on a narinfo, and
// compares servers out of band with `guix challenge`. The threshold is what
// lets that comparison be a precondition of installing rather than an audit
// someone runs afterwards.
const (
	// TrustedKeysEnv REPLACES the trust set. An operator who sets it has
	// said which keys they trust, and silently keeping ours in the list
	// would be deciding that for them.
	TrustedKeysEnv = "ZPKG_TRUSTED_KEYS"
	// ExtraTrustedKeysEnv ADDS to it, which is what almost everyone wants:
	// trust the project plus a colleague. Nix's `extra-` convention, for
	// the reason Nix has it — replacing a default list by hand is how you
	// drop the entry that made everything work.
	ExtraTrustedKeysEnv = "ZPKG_EXTRA_TRUSTED_KEYS"
	// TrustThresholdEnv is how many DISTINCT trusted keys must have signed.
	TrustThresholdEnv = "ZPKG_TRUST_THRESHOLD"
)

// DefaultSignerName names the project's own key in messages.
const DefaultSignerName = "go-zpkg"

// DefaultThreshold is 1.
//
// ⛔ AND THAT IS A DELIBERATE CHOICE, NOT A PLACEHOLDER. The mechanism is
// worth having before a second builder exists, because it has to be in place
// BEFORE the registry is rebuilt — an artifact signed under the old scheme would
// have to be republished to gain a second signature. But shipping a default
// of 2 today would make every published artifact unverifiable by its own client
// the moment this is released, which is not a security improvement, it is an
// outage. Two is one environment variable away, and it becomes the right
// default the day a second builder publishes.
const DefaultThreshold = 1

// Bounds. A trust set comes from the operator's own configuration, so its cap
// is there to catch a mistake; the signature list comes from a REGISTRY, so
// its cap is a resource bound against a subject that can be made to carry
// thousands of referrers — each of which would otherwise cost a fetch and a
// signature verification per trusted key.
//
// ⛔ BOTH REFUSE RATHER THAN TRUNCATE. Verifying the first 32 of 5000
// signatures and reporting success would be a filter pretending to be a
// check: the answer "this is signed by alice" would depend on where the list
// happened to be cut.
const (
	MaxTrustedKeys = 64
	MaxSignatures  = 32
)

// Signer is one key that may vouch for a build.
type Signer struct {
	// Name is how this key is spoken of in output. It comes from the
	// operator's configuration — NEVER from the registry.
	//
	// ⛔⛔ A NAME TAKEN FROM THE ARTEFACT WOULD BE THE ATTACKER'S NAME. The
	// whole value of the line "signed by: go-zpkg, alice" is that both
	// words were written by the person reading it. The referrer carries a
	// key id, which is checkable, and no name, which would not be.
	Name string
	// Key is the minisign-format public key.
	Key string

	id  sign.KeyID
	pub ed25519.PublicKey
}

// KeyID is the key's 8-byte minisign identifier, hex. It is what a signature
// referrer names, and what two entries for the same key share.
func (s Signer) KeyID() string {
	id := s.id
	if s.pub == nil {
		// A Signer built by a composite literal has no parsed key. Parse it
		// here rather than return the zero id, which would make two such
		// signers look like the same key to the deduplication.
		if parsed, _, err := sign.ParsePublicKey(s.Key); err == nil {
			id = parsed
		}
	}
	return hex.EncodeToString(id[:])
}

// String is "name (keyid)".
func (s Signer) String() string { return s.Name + " (" + s.KeyID() + ")" }

// verifies reports whether this key signed a payload that commits to digest.
//
// A Signer built by a composite literal (as a test will) has no parsed key,
// so parse on the spot rather than silently never verifying.
func (s Signer) verifies(digest string, a Attestation) bool {
	pub := s.pub
	if pub == nil {
		var err error
		if _, pub, err = sign.ParsePublicKey(s.Key); err != nil {
			return false
		}
	}
	if sign.VerifyBlob(a.Payload, a.Sig, pub) != nil {
		return false
	}
	return payloadCommitsTo(a.Payload, digest) == nil
}

// ParseSigner reads one `name:KEY` entry, or a bare `KEY`.
//
// A bare key is named by its own key id: an unnamed key still has to be
// printable, and printing it as "" would make "signed by: , alice" out of a
// perfectly good trust set.
func ParseSigner(entry string) (Signer, error) {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return Signer{}, errors.New("artifact: empty trusted-key entry")
	}
	name, key := "", entry
	// A minisign public key is base64 of 42 bytes — no colon in its
	// alphabet — so the first colon, if any, ends the name.
	if i := strings.IndexByte(entry, ':'); i >= 0 {
		name, key = strings.TrimSpace(entry[:i]), strings.TrimSpace(entry[i+1:])
	}
	if err := validSignerName(name); err != nil {
		return Signer{}, err
	}
	id, pub, err := sign.ParsePublicKey(key)
	if err != nil {
		return Signer{}, fmt.Errorf("artifact: bad trusted key %q: %w", entry, err)
	}
	s := Signer{Name: name, Key: key, id: id, pub: pub}
	if s.Name == "" {
		s.Name = s.KeyID()
	}
	return s, nil
}

// MaxSignerNameLen bounds a signer's name. A name is read aloud in a verdict,
// not stored; anything longer is a paragraph someone is trying to put on the
// screen.
const MaxSignerNameLen = 64

// validSignerName REFUSES a name that could write on a terminal, rather than
// stripping it.
//
// ⛔⛔ THE LINE IT APPEARS IN IS A SECURITY STATEMENT. displaytext.go draws
// the distinction: a project SUMMARY is cosmetic and is stripped, a project
// NAME means somebody wanted something and is refused. "signed by: go-zpkg"
// is the second kind and then some — a name of
//
//	go-zpkg\x1b[2K\rsigned by: go-zpkg, alice
//
// erases the line it is on and reprints it as a stronger claim than the one
// that was true. Stripping would leave a name that is not the one configured;
// refusing says so at the moment the configuration is read.
func validSignerName(name string) error {
	if name == "" {
		return nil // an unnamed key is named by its key id
	}
	if len([]rune(name)) > MaxSignerNameLen {
		return fmt.Errorf("artifact: trusted-key name is longer than %d characters", MaxSignerNameLen)
	}
	for _, r := range name {
		switch {
		case r == 0x7f, unicode.IsControl(r):
			return fmt.Errorf("artifact: trusted-key name %q contains a control character", name)
		case r == '​', r == ' ', r == ' ':
			// Zero-width space and the Unicode line separators: not
			// control characters by category, and all three can hide or
			// break a line.
			return fmt.Errorf("artifact: trusted-key name %q contains an invisible character", name)
		}
	}
	return nil
}

// ParseSigners reads a whitespace-separated list of entries.
func ParseSigners(list string) ([]Signer, error) {
	fields := strings.Fields(list)
	if len(fields) > MaxTrustedKeys {
		return nil, fmt.Errorf("artifact: %d trusted keys, more than the %d allowed", len(fields), MaxTrustedKeys)
	}
	out := make([]Signer, 0, len(fields))
	for _, f := range fields {
		s, err := ParseSigner(f)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

// TrustSet is the whole policy: who may vouch, how many must, and whose word
// is no longer accepted.
type TrustSet struct {
	Signers   []Signer
	Threshold int
	// Revoked are keys that were ours and are not believed any more.
	//
	// ⛔ THEY ARE NOT SIMPLY ABSENT FROM Signers. Absent means "we do not
	// know this key", which is a stranger and is noise. Present-and-revoked
	// means "this was ours and somebody else may hold it", which is a fact
	// about our own supply chain that a reader must be told in those words.
	Revoked []RevokedKey
}

// revokedBy reports which revoked key made this signature, if any.
func (t TrustSet) revokedBy(digest string, a Attestation) (RevokedKey, bool) {
	for _, r := range t.Revoked {
		if (Signer{Name: r.Name, Key: r.Key}).verifies(digest, a) {
			return r, true
		}
	}
	return RevokedKey{}, false
}

// DefaultTrustSet is the project's CURRENT key plus every key it has retired,
// threshold 1.
//
// ⛔⛔ THE RETIRED ONES ARE IN IT, AND THAT IS WHAT MAKES ROTATION POSSIBLE AT
// ALL. Rotating is how you answer a lost or compromised key; if rotating also
// invalidated every artifact the old key signed, the registry would go dark the
// day it was most needed and nobody would ever rotate. A signature is a
// statement about bytes; changing the key we sign WITH says nothing about
// what is already signed.
//
// ⛔ THEY ARE NOT RANKED AND NOT DATED. Verify counts DISTINCT keys, so a
// artifact signed by the current key and an old one counts as two — which is
// exactly right during an overlap, where the same publisher deliberately
// signs with both. A scheme that discounted retired keys would make an
// overlap artifact look like one signer, and a threshold of two unmeetable
// precisely while rotating.
//
// It reads the variables at call time rather than at init, because
// SigningPublicKey is the seam tests swap to sign with a throwaway key.
//
// ⛔ AN UNPARSEABLE RETIRED ENTRY IS SKIPPED, NOT FATAL. It is a compiled-in
// typo in a list that grows by hand, and refusing to build any trust set
// over it would take out verification entirely — including for the current
// key, which is fine. The current key is the one whose failure returns an
// empty set, because without it there is nothing to trust.
func DefaultTrustSet() TrustSet {
	s, err := ParseSigner(DefaultSignerName + ":" + SigningPublicKey)
	if err != nil {
		// An unparseable compiled-in key is a build-time mistake, and a
		// trust set with no keys verifies nothing — which Verify says
		// plainly rather than passing.
		return TrustSet{Threshold: DefaultThreshold}
	}
	signers := []Signer{s}
	for _, entry := range RetiredSigningPublicKeys {
		if r, err := ParseSigner(entry); err == nil {
			signers = append(signers, r)
		}
	}
	// ⛔ A REVOKED KEY IS REMOVED FROM THE SIGNERS, NOT MERELY LISTED BESIDE
	// THEM. Leaving it in both would let it satisfy the threshold while the
	// report called it revoked — a verdict that contradicts itself, and the
	// contradiction resolves in the attacker's favour.
	return TrustSet{
		Signers:   withoutRevoked(dedupeSigners(signers), RevokedSigningKeys),
		Revoked:   RevokedSigningKeys,
		Threshold: DefaultThreshold,
	}
}

// withoutRevoked drops any signer whose key has been revoked.
func withoutRevoked(in []Signer, revoked []RevokedKey) []Signer {
	if len(revoked) == 0 {
		return in
	}
	bad := map[string]bool{}
	for _, r := range revoked {
		bad[(Signer{Key: r.Key}).KeyID()] = true
	}
	out := in[:0:0]
	for _, s := range in {
		if !bad[s.KeyID()] {
			out = append(out, s)
		}
	}
	return out
}

// LoadTrustSet builds the trust set from the environment (or ~/.zpkg/config.hcl2,
// via Env).
//
// ⛔ A THRESHOLD NOBODY COULD MEET IS REFUSED HERE, NOT AT INSTALL TIME. Three
// signatures required of a one-key trust set is a configuration that fails
// every install with a message about the artifact. Said at load time it is a
// message about the configuration, which is where the mistake is.
func LoadTrustSet() (TrustSet, error) {
	t := DefaultTrustSet()
	if v := strings.TrimSpace(Env(TrustedKeysEnv)); v != "" {
		s, err := ParseSigners(v)
		if err != nil {
			return TrustSet{}, fmt.Errorf("%s: %w", TrustedKeysEnv, err)
		}
		t.Signers = s
	}
	if v := strings.TrimSpace(Env(ExtraTrustedKeysEnv)); v != "" {
		s, err := ParseSigners(v)
		if err != nil {
			return TrustSet{}, fmt.Errorf("%s: %w", ExtraTrustedKeysEnv, err)
		}
		t.Signers = append(t.Signers, s...)
	}
	t.Signers = dedupeSigners(t.Signers)
	if v := strings.TrimSpace(Env(TrustThresholdEnv)); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return TrustSet{}, fmt.Errorf("%s=%q: want a whole number of keys, at least 1", TrustThresholdEnv, v)
		}
		t.Threshold = n
	}
	if t.Threshold > len(t.Signers) {
		return TrustSet{}, fmt.Errorf("%s=%d cannot be met: the trust set has %d key(s) (%s)",
			TrustThresholdEnv, t.Threshold, len(t.Signers), strings.Join(t.Names(), ", "))
	}
	return t, nil
}

// dedupeSigners keeps one entry per key id — the first, so a name given in
// ZPKG_TRUSTED_KEYS is not overwritten by the same key repeated in the extra
// list. Two entries for one key must not let one signature count twice.
func dedupeSigners(in []Signer) []Signer {
	seen := map[string]bool{}
	out := in[:0:0]
	for _, s := range in {
		id := s.KeyID()
		if seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, s)
	}
	return out
}

// Names lists the trusted signers' names, in configured order.
func (t TrustSet) Names() []string {
	out := make([]string, 0, len(t.Signers))
	for _, s := range t.Signers {
		out = append(out, s.Name)
	}
	return out
}

// Attestation is one candidate signature found on an artifact: the simple-signing
// payload, the base64 signature over it, and — when the publisher recorded one
// — the key id that is claimed to have made it.
type Attestation struct {
	Payload []byte
	Sig     string
	// KeyID is a HINT and nothing more. It orders which trusted key is tried
	// first; it never restricts which may succeed, so a referrer that names
	// the wrong key id costs a few microseconds and still verifies.
	KeyID string
}

// Count names the DISTINCT trusted keys that signed this digest, and says how
// many signatures were made by keys outside the trust set.
//
// ⛔⛔ IT COUNTS, IT DOES NOT JUDGE, AND THE SPLIT IS THE POINT. "Who vouches
// for this build?" is a question a listing asks about builds it has no
// intention of installing, and it has a true answer — possibly "nobody" —
// that is not a failure. Folding the threshold in here would have made every
// listing of an under-signed build an error, which is how a column ends up
// printing blanks that read as "unsigned". The verdict is SignatureReport.Err.
//
// ⛔ ONE SIGNATURE PER KEY (TUF §5.4.2). Without that rule a threshold of two
// is met by attaching the same signature twice, which anyone who can push a
// referrer can do.
//
// Cost: with a key id on each referrer this is one signature verification per
// signature; without, it is one per (signature, trusted key) pair. Both are
// bounded by MaxSignatures × MaxTrustedKeys.
//
// Its errors — an unusable trust set, or more signatures than it will look at
// — name the finding and NOT the artifact, because only the caller knows which
// artifact was being checked.
func (t TrustSet) Count(digest string, atts []Attestation) (names []string, untrusted int, err error) {
	n, u, _, err := t.count(digest, atts)
	return n, u, err
}

// count is Count plus the revoked keys it found, which SignatureReport needs
// and which Count's two-number signature has no room for.
func (t TrustSet) count(digest string, atts []Attestation) (names []string, untrusted int, revoked []RevokedKey, err error) {
	if len(t.Signers) == 0 && len(t.Revoked) == 0 {
		return nil, 0, nil, errors.New("the trust set is empty, so nothing can be verified")
	}
	if len(atts) > MaxSignatures {
		return nil, 0, nil, fmt.Errorf("%d signatures attached, more than the %d this will examine: refusing", len(atts), MaxSignatures)
	}
	counted := map[string]bool{}
	seenRevoked := map[string]bool{}
	for _, a := range atts {
		// ⛔ REVOCATION IS CHECKED FIRST. A key can only be in one of the
		// two sets — DefaultTrustSet removes revoked keys from the signers
		// — but an operator's own ZPKG_TRUSTED_KEYS can name one, and a
		// verdict that both counted it and called it revoked would resolve
		// in the attacker's favour.
		if r, yes := t.revokedBy(digest, a); yes {
			if !seenRevoked[(Signer{Key: r.Key}).KeyID()] {
				seenRevoked[(Signer{Key: r.Key}).KeyID()] = true
				revoked = append(revoked, r)
			}
			continue
		}
		s, ok := t.verifyOne(digest, a)
		if !ok {
			untrusted++
			continue
		}
		if counted[s.KeyID()] {
			continue
		}
		counted[s.KeyID()] = true
		names = append(names, s.Name)
	}
	sort.Strings(names)
	return names, untrusted, revoked, nil
}

// SignatureReport is what a registry had to say about who signed one artifact:
// the trusted keys that did, and everything that did not count, kept apart so
// a caller can tell "nobody signed this" from "we could not read what was
// attached".
type SignatureReport struct {
	// Signers are the distinct trusted keys that vouch for this artifact.
	Signers []string
	// Untrusted counts signatures made by keys outside the trust set.
	//
	// ⛔ THEY ARE NOT AN ERROR. Anybody may attach a signature to a public
	// artefact; if a stranger's signature invalidated an artifact, invalidating
	// any artifact would cost one push.
	Untrusted int
	// Malformed counts signature referrers that could not be read at all.
	// Counted rather than skipped: "unsigned" and "signed, but the referrer
	// is broken" are different facts, and the second names a publishing bug.
	Malformed int
	// Revoked are OUR OWN keys, found on this artifact, that are no longer
	// believed.
	//
	// ⛔⛔ THIS IS NOT "Untrusted WITH A NAME". A stranger's signature is
	// noise anybody can make and is correctly ignored. Our own revoked key
	// on an artifact means either that we published it before the key was
	// compromised — and cannot prove which — or that whoever took the key
	// published it. A reader has to act on that, and they can only act on
	// it if the verdict says it in those words.
	Revoked []RevokedKey
	// Threshold is how many Signers were required.
	Threshold int
}

// Signed reports whether anything at all was attached.
func (r SignatureReport) Signed() bool {
	return len(r.Signers) > 0 || r.Untrusted > 0 || r.Malformed > 0 || len(r.Revoked) > 0
}

// OK reports whether the threshold was met.
func (r SignatureReport) OK() bool { return len(r.Signers) >= r.want() }

func (r SignatureReport) want() int {
	if r.Threshold < 1 {
		return DefaultThreshold
	}
	return r.Threshold
}

// Err is the verdict: nil when the threshold is met, else why not.
func (r SignatureReport) Err() error {
	if r.OK() {
		return nil
	}
	if !r.Signed() {
		return errors.New("unsigned (no signature referrer)")
	}
	return shortOfThreshold(r.Signers, r.Untrusted, r.Malformed, r.want(), r.Revoked)
}

// RevokedNote is the line a command prints when an artifact carries one of our
// own revoked keys, or "" when it does not.
//
// ⛔ IT IS SEPARATE FROM THE VERDICT ON PURPOSE. An artifact can meet the
// threshold on its current signature AND still carry a revoked one — that is
// what a re-signed artifact looks like before the old referrer is removed, and
// what a planted signature looks like too. The verdict says whether to
// install; this says what else is on the artefact.
func (r SignatureReport) RevokedNote() string {
	if len(r.Revoked) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("⚠ this artifact carries a signature from a key we REVOKED:")
	for _, k := range r.Revoked {
		b.WriteString("\n  " + k.Name)
		if k.Because != "" {
			b.WriteString(" — " + k.Because)
		}
	}
	b.WriteString("\n  It signs for nothing. Whether this artefact predates the compromise " +
		"cannot be told from it:\n  every artifact carries the same pinned timestamp.")
	return b.String()
}

// String is the one cell a listing prints: who vouches for this build.
func (r SignatureReport) String() string {
	if len(r.Signers) > 0 {
		return strings.Join(r.Signers, ", ")
	}
	if r.Signed() {
		return "no trusted signature"
	}
	return "unsigned"
}

// verifyOne finds the trusted key that made this signature, trying the hinted
// key id first.
func (t TrustSet) verifyOne(digest string, a Attestation) (Signer, bool) {
	if a.KeyID != "" {
		for _, s := range t.Signers {
			if s.KeyID() == a.KeyID && s.verifies(digest, a) {
				return s, true
			}
		}
	}
	for _, s := range t.Signers {
		if s.verifies(digest, a) {
			return s, true
		}
	}
	return Signer{}, false
}

// shortOfThreshold says what was found and what was wanted, in that order,
// because the reader's next question is always "signed by whom, then?".
func shortOfThreshold(names []string, untrusted, malformed, want int, revoked []RevokedKey) error {
	var b strings.Builder
	switch len(names) {
	case 0:
		b.WriteString("signed by no trusted key")
	case 1:
		b.WriteString("signed by 1 trusted key (" + names[0] + ")")
	default:
		fmt.Fprintf(&b, "signed by %d trusted keys (%s)", len(names), strings.Join(names, ", "))
	}
	if untrusted == 1 {
		b.WriteString("; 1 further signature was made by a key that is not in the trust set")
	} else if untrusted > 1 {
		fmt.Fprintf(&b, "; %d further signatures were made by keys that are not in the trust set", untrusted)
	}
	if malformed == 1 {
		b.WriteString("; 1 signature referrer is malformed")
	} else if malformed > 1 {
		fmt.Fprintf(&b, "; %d signature referrers are malformed", malformed)
	}
	// ⛔ NAMED, NOT COUNTED. "1 revoked signature" tells a reader nothing
	// they can act on; the key's name and the reason it was revoked is the
	// whole content of the warning.
	for _, k := range revoked {
		b.WriteString("; signed by REVOKED key " + k.Name)
		if k.Because != "" {
			b.WriteString(" (" + k.Because + ")")
		}
	}
	fmt.Fprintf(&b, "; %s=%d requires %d", TrustThresholdEnv, want, want)
	return errors.New(b.String())
}
