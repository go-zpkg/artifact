package artifact

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
)

// DeprecatedEnv names a JSON file that lists, per project, release lines that
// are end-of-life:
//
//	{"openssl.org": ["3.6", "3.4", "1.1.1"]}
//
// ⛔ THIS IS A PREFERENCE, NOT A CONSTRAINT. A deprecated version stays
// resolvable: it is RANKED LAST among the versions that satisfy a constraint,
// never removed from the list. The two shapes behave the same on every request
// except one, and that one is the whole correctness question:
//
//	^3.6.4  admits ONLY 3.6.4, which is deprecated.
//
// A RANK resolves it to 3.6.4 (and warns). A FILTER would leave nothing and
// fail the request. This is RANK, on purpose: reproducibility and an explicit
// request for a dead line outrank the preference, and a lock that stopped
// resolving would be a worse defect than the one this fixes.
//
// It follows that the preference only changes an answer where a supported
// candidate ALSO satisfies the constraint. `=3.6.4` and `^3.6.4` have none, so
// they get 3.6.4; `^3` and `^3.5` have 3.5.x, so they get 3.5.8; `^4` and `^3`
// share no satisfier, so the preference can never reach across a soname
// boundary. No special case for exact pins is needed or present.
//
// The file is read locally, once. The resolver never touches the network to
// choose a version (FROM scratch and air-gapped use must keep working). Where
// the list comes from — `bk eol` computing it from endoflife.date — is a
// separate matter. An unset variable, a missing file or an unreadable one all
// mean an empty list, i.e. exactly the behaviour without this feature; an
// unparsable file is reported once on stderr and also means an empty list.
const DeprecatedEnv = "ZPKG_DEPRECATED"

// DefaultDeprecated is the list used when DeprecatedEnv is unset.
//
// ⛔ IT EXISTS BECAUSE AN OPT-IN ENVIRONMENT VARIABLE FIXES NOTHING. Shipped
// with the variable as the only source, this whole feature changed no answer
// for anybody: openssl's 3.6 line went end-of-life on 2026-11-01 and `^3` went
// on resolving to 3.6.4 across the fleet, because nothing set the variable.
// A capability nobody switches on is a capability the fleet does not have.
//
// ⛔⛔ AND LETTING EACH BINARY CARRY ITS OWN DEFAULT FIXED IT ONLY WHERE
// SOMEONE REMEMBERED. That was the second shape of the same defect: the
// activation lived in `pkgx/internal/app`, unimportable from any other module,
// so `pkgm` — the INSTALLER — went on resolving `openssl.org@^3` to the
// end-of-life 3.6.4 while `pkgx` gave 3.5.8. Measured 2026-11-03, A/B on one
// pkgm binary. See KnownDeprecated.
//
// So this now HOLDS the library's list rather than starting empty: every
// consumer inherits the ranking, and a binary that wants a different list
// assigns this variable as before. The precedence is unchanged, and the
// surprising direction is still the one to avoid:
//
//   - DeprecatedEnv set and readable → that file, and ONLY that file;
//   - DeprecatedEnv set and broken   → empty, with a warning. It does NOT fall
//     back to this default: an operator who named a file has said what they
//     want, and quietly substituting something else would hide their mistake
//     behind working behaviour;
//   - DeprecatedEnv unset            → this default.
//
// A caller that overrides it must do so before the first resolution: the list
// is latched once, so assigning it afterwards does nothing.
var DefaultDeprecated = KnownDeprecated

// deprecationOut is where a fall back to a deprecated version is announced.
var deprecationOut io.Writer = os.Stderr

var (
	deprecatedOnce sync.Once
	deprecatedSet  map[string][]string
)

// deprecatedLines is the end-of-life release lines of a project. A var so
// tests can supply a list without a file.
var deprecatedLines = func(project string) []string {
	deprecatedOnce.Do(func() {
		path := os.Getenv(DeprecatedEnv)
		if path == "" {
			deprecatedSet = DefaultDeprecated
			return
		}
		b, err := os.ReadFile(path)
		if err != nil {
			// Warned, not silent, and NOT replaced by DefaultDeprecated. Before
			// a default existed this could return quietly because the result
			// was the same either way; now the two differ, and an operator who
			// named an unreadable file must not be given a different list
			// without being told.
			fmt.Fprintf(deprecationOut, "pkgx: ignoring %s=%s: %v\n", DeprecatedEnv, path, err)
			return
		}
		if err := json.Unmarshal(b, &deprecatedSet); err != nil {
			fmt.Fprintf(deprecationOut, "pkgx: ignoring %s=%s: %v\n", DeprecatedEnv, path, err)
			deprecatedSet = nil
		}
	})
	return deprecatedSet[project]
}

// deprecatedLine reports which listed line a version belongs to. A line
// prefixes the version on a COMPONENT boundary: 3.6 holds 3.6.4 and 3.6.0-rc1
// but not 3.60 — the rule bk's support.CycleFor uses, so the list and the
// verdict that produced it agree.
func deprecatedLine(raw string, lines []string) (string, bool) {
	for _, l := range lines {
		if l == "" || !strings.HasPrefix(raw, l) {
			continue
		}
		if rest := raw[len(l):]; rest != "" && rest[0] >= '0' && rest[0] <= '9' {
			continue
		}
		return l, true
	}
	return "", false
}
