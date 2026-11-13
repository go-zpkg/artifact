package artifact

import (
	"errors"
	"fmt"
	"strings"
)

// NotPublishedError says that THIS registry does not carry a project, and
// says which project, so a caller can act rather than parse.
//
// # WHY A TYPE AND NOT A SENTENCE
//
// ⛔ BECAUSE THE PROSE TEST IS TOO WIDE ONCE IT LEAVES THIS PACKAGE.
// repoAbsent's last resort matches `not found` anywhere in an error's text,
// which is safe where it was written — it only ever sees the result of a
// registry call — and wrong as soon as an exported predicate is pointed at
// arbitrary errors. Measured 2026-10-23, the first use of the exported
// IsNotPublished at pkgx's top-level error printer:
//
//	pkgx: command not found in the requested packages: true
//	pkgx: if it should be here: `pkgs request <project>` …
//
// The package was published; the COMMAND was not there. The hint fired on
// the word "not found" in an unrelated sentence.
//
// A type cannot be matched by accident, and it carries the project — so a
// caller can name it instead of printing a placeholder and hoping the
// reader fills it in from the line above.
type NotPublishedError struct {
	Project  string
	Registry string
	Repo     string
	Err      error
}

func (e *NotPublishedError) Error() string {
	return fmt.Sprintf("%s is not published in %s/%s (%v)", e.Project, e.Registry, e.Repo, e.Err)
}

func (e *NotPublishedError) Unwrap() error { return e.Err }

// IsNotPublished reports whether err means this registry simply does not
// carry the project, as opposed to a transient or authentication failure.
//
// ⛔ IT IS ABOUT AN ERROR FROM A REGISTRY CALL. The typed form above is
// exact; the fallback is repoAbsent, whose last resort reads the error's
// TEXT, and text written for another purpose can contain "not found". Pass
// it what came back from the registry, not whatever reached your error
// printer — or match *NotPublishedError yourself and be sure.
func IsNotPublished(err error) bool {
	var np *NotPublishedError
	if errors.As(err, &np) {
		return true
	}
	return repoAbsent(err)
}

// NoArtifactHereError says the project IS published — just not anything this
// platform can install.
//
// # WHY A SECOND TYPE, AND WHY IT IS THE COMMON ONE
//
// ⛔ NotPublishedError ALONE COVERED THE RARE HALF. It is returned when the
// repository does not exist at all, which is what a brand-new package looks
// like. The ordinary state is the other one: measured 2026-10-23 against the
// published darwin/aarch64 catalogue, 567 of 1940 projects had a recipe and
// no artifact — 29% of the pantry, against which `pkgx <project>` answered
//
//	no version of aerc-mail.org is published for darwin/aarch64
//	(available: 0.22.0; not published here: 0.22.0)
//
// A good sentence and a dead end: it names no next step, and the hint that
// exists to name one could not fire, because this error was a sentence and
// not a type. Found by RUNNING the shipped binary over a list derived from
// the catalogue — the unit test passed and the mutation was caught, and
// neither could see that the covered case was the rare one.
//
// The fields are the message's own parts, so a caller that wants to say
// something else does not have to parse the sentence back apart.
type NoArtifactHereError struct {
	Project     string
	OS, Arch    string
	Constraints []string // what was asked for; empty means "any version"
	Available   []Ver    // every version the pantry knows, oldest first
	Absent      []string // of those, the ones with no artifact here
}

// Error keeps the two sentences the field reports settled on, verbatim.
//
// ⛔ NO CONSTRAINT MEANS THE CLAUSE IS OMITTED, not printed empty: reported
// 2026-10-12, when `pkgx hugo version` produced "satisfies  AND is published
// for", two spaces where the reason should be, blaming a constraint that did
// not exist.
func (e *NoArtifactHereError) Error() string {
	if len(e.Constraints) == 0 {
		return fmt.Sprintf("no version of %s is published for %s/%s (available: %s; not published here: %s)",
			e.Project, e.OS, e.Arch, availableVersions(e.Available), strings.Join(e.Absent, " "))
	}
	return fmt.Sprintf("no version of %s satisfies %s AND is published for %s/%s (available: %s; satisfy but not published here: %s)",
		e.Project, quoteAll(e.Constraints), e.OS, e.Arch, availableVersions(e.Available), strings.Join(e.Absent, " "))
}

// ProjectToRequest names the project a caller could ask to have published,
// for the errors that mean "there is nothing here you can install", and ""
// for every other error.
//
// ⛔ ONE QUESTION, ONE ANSWER. The two states above differ in their data —
// one has a registry and an HTTP refusal, the other has versions and a
// platform — but a caller deciding whether to offer `pkgs request` is asking
// the same thing of both. Two predicates at that call site is how one of
// them comes to be forgotten, which is exactly what happened to the second
// state for the length of one release.
func ProjectToRequest(err error) string {
	var nb *NoArtifactHereError
	if errors.As(err, &nb) {
		return nb.Project
	}
	var np *NotPublishedError
	if errors.As(err, &np) {
		return np.Project
	}
	return ""
}
