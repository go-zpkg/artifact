package artifact

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
)

// WithdrawnEnv names a JSON file listing, per project, the BUILDS that should
// no longer be chosen — the ones a CVE has caught:
//
//	{"fftw.org": [
//	  {"version": "3.3.11",
//	   "hash": "27o3ysxva6swayci",
//	   "because": "CVE-2026-1234",
//	   "superseded_by": "rnp44isdgdtzxcit"}
//	]}
//
// # WHY A BUILD AND NOT A VERSION
//
// ZPKG_DEPRECATED retires a release LINE, which is the right grain for "3.6 is
// end-of-life". It is the wrong grain for the case this exists for: the
// package is fine, the source is fine, and what is wrong is the TOOLCHAIN it
// was compiled with. A Go patch release fixes a standard-library defect;
// nothing about the recipe or the upstream version changes, only `go.dev` in
// the closure — so the fixed artefact is another build of the SAME version,
// and the broken one has to be nameable without condemning the version.
//
// That is only expressible because a build has an identity. It is the first
// thing the hashed layout buys that a version-addressed store could not do
// at all.
//
// # ⛔⛔ IT RANKS, IT DOES NOT FILTER — THE SAME RULE AS DEPRECATION
//
// A withdrawn build stays resolvable. The reasoning is deprecated.go's and
// has not changed: a LOCK pins a build, and a lock that stops resolving is a
// worse defect than the one being fixed. Reproducibility and an explicit
// request outrank the preference.
//
// So:
//
//   - two builds, one withdrawn → the other, and the withdrawal is announced;
//   - one build, withdrawn      → that one, loudly, because there is nothing
//     else and refusing would strand the caller;
//   - several left after the withdrawn ones are set aside → still AMBIGUOUS.
//     Setting aside a build somebody recorded a reason for is not the same as
//     inventing an order among the rest.
//
// # ⛔ AND IT CARRIES THE REASON AND THE REPLACEMENT
//
// A warning that does not say why is noise, and one that does not say where
// to go next leaves the reader to find the fixed build themselves — which
// means reading hashes, which is the thing nobody can do. `because` is the
// advisory identifier; `superseded_by` is the hash that fixes it, when one
// exists. Empty is honest: a withdrawal with no replacement yet is a real
// state and must be sayable.
//
// Read locally, once, like the deprecation list: the resolver never touches
// the network to choose, because FROM scratch and air-gapped use must keep
// working. Where the file comes from — `bk advisories` and the VEX documents
// attached to published artifacts — is a separate matter, the same separation
// as `bk eol` and ZPKG_DEPRECATED.
const WithdrawnEnv = "ZPKG_WITHDRAWN"

// Withdrawal is one recorded reason not to choose a build.
type Withdrawal struct {
	Version string `json:"version"`
	// Hash is the build's identity. Empty withdraws EVERY build of the
	// version, which is the right shape when the flaw is in the source
	// rather than in how it was compiled.
	Hash string `json:"hash,omitempty"`
	// Because is why — an advisory identifier, e.g. "CVE-2026-1234".
	Because string `json:"because"`
	// SupersededBy is the hash of the build that fixes it, when there is one.
	SupersededBy string `json:"superseded_by,omitempty"`
}

// DefaultWithdrawn is the list used when WithdrawnEnv is unset.
//
// ⛔ EMPTY, AND THAT IS NOT THE SAME DECISION AS DefaultDeprecated's. The
// deprecation list ships populated because end-of-life dates are a public
// fact anybody can compute and being wrong about one costs a warning. A
// withdrawal says "do not use this build", which is a claim about OUR
// artefacts that only our own advisory process can make — and shipping a
// guess would either condemn a build nobody has examined or, worse, imply
// that an empty list means every build has been cleared.
var DefaultWithdrawn = map[string][]Withdrawal{}

var (
	withdrawnOnce sync.Once
	withdrawnSet  map[string][]Withdrawal
)

// withdrawnFor is the recorded withdrawals of a project. A var so tests can
// supply a list without a file.
var withdrawnFor = func(project string) []Withdrawal {
	withdrawnOnce.Do(func() { withdrawnSet = loadWithdrawn() })
	return withdrawnSet[project]
}

// loadWithdrawn reads the list. Separate from the sync.Once above so a test
// can exercise it: a Once is read once per PROCESS, so a test that went
// through it would measure whichever test ran first.
func loadWithdrawn() map[string][]Withdrawal {
	path := os.Getenv(WithdrawnEnv)
	if path == "" {
		return DefaultWithdrawn
	}
	b, err := os.ReadFile(path)
	if err != nil {
		// Warned and NOT replaced by the default, for deprecated.go's
		// reason: an operator who named a file has said what they want, and
		// quietly substituting something else hides their mistake behind
		// working behaviour.
		fmt.Fprintf(deprecationOut, "pkgx: ignoring %s=%s: %v\n", WithdrawnEnv, path, err)
		return nil
	}
	var set map[string][]Withdrawal
	if err := json.Unmarshal(b, &set); err != nil {
		fmt.Fprintf(deprecationOut, "pkgx: ignoring %s=%s: %v\n", WithdrawnEnv, path, err)
		return nil
	}
	return set
}

// WithdrawalOf reports whether a build has been withdrawn, and why.
//
// ⛔ A WITHDRAWAL WITH NO HASH APPLIES TO EVERY BUILD OF THE VERSION, and an
// exact one wins over it: a flaw in the source condemns them all, and a later
// entry naming one build says something more specific about that build. A
// reader that took the first match would report "the source is bad" for a
// build whose own entry says it is the FIXED one.
func WithdrawalOf(project, version, hash string) (Withdrawal, bool) {
	var wide Withdrawal
	var haveWide bool
	for _, w := range withdrawnFor(project) {
		if w.Version != version {
			continue
		}
		if w.Hash == "" {
			if !haveWide {
				wide, haveWide = w, true
			}
			continue
		}
		if w.Hash == hash {
			return w, true
		}
	}
	return wide, haveWide
}

// String renders a withdrawal the way a line of output wants it.
func (w Withdrawal) String() string {
	if w.Because == "" {
		return "withdrawn"
	}
	s := "withdrawn: " + w.Because
	if w.SupersededBy != "" {
		s += " → " + shortHashPrefix(w.SupersededBy)
	}
	return s
}

// PreferNotWithdrawn sets aside the builds that have been withdrawn, and
// reports which it set aside.
//
// ⛔⛔ IT RETURNS EVERYTHING WHEN EVERYTHING IS WITHDRAWN. That is the case
// the rank-not-filter rule exists for: a caller asking for the only build
// there is must get it, with the reason said out loud, rather than an empty
// list and a refusal it cannot act on.
func PreferNotWithdrawn(project string, builds []Build) (keep []Build, setAside []Build) {
	for _, b := range builds {
		if _, yes := WithdrawalOf(project, b.Version.Raw, b.Hash()); yes {
			setAside = append(setAside, b)
			continue
		}
		keep = append(keep, b)
	}
	if len(keep) == 0 {
		return builds, nil
	}
	return keep, setAside
}

// WithdrawnNote is the one line a command prints under a list when something
// in it has been withdrawn, or "" when nothing has.
func WithdrawnNote(project string, builds []Build) string {
	var lines []string
	for _, b := range builds {
		w, yes := WithdrawalOf(project, b.Version.Raw, b.Hash())
		if !yes {
			continue
		}
		h := b.Hash()
		if h == "" {
			h = "(none)"
		}
		lines = append(lines, "  "+h+": "+w.String())
	}
	if len(lines) == 0 {
		return ""
	}
	return "withdrawn builds — resolvable, but ranked last:\n" + strings.Join(lines, "\n")
}
