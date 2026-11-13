package artifact

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// The lock FILE FORMAT: what a lock says, how it is written, how it is read
// back.
//
// # WHY IT LIVES HERE AND NOT IN bk
//
// `bk lock` wrote locks and nothing anywhere could read one back except
// `bk lock --check`, because the reader was in bk's `package main` — which
// is importable by nothing. A format with exactly one program able to read
// it is a format that has not left the program it was written for, and the
// whole point of a lock is that something ELSE acts on it later: `pkgx
// install --lock` is the other end, and it is in another repository.
//
// So the FORMAT moves here, where both ends can reach it, and the
// RESOLUTION stays in bk. That is the real seam: deciding which versions a
// set means today needs a pantry, an overrides set and a version resolver,
// none of which belong in an artifact client. Reading a file that records the
// answer needs none of them.
//
// Writing moves with reading, deliberately. A format whose writer lives in
// one repository and whose reader lives in another is a round trip waiting
// to break on a field one side forgot.

// LockPin is one project as a lock pins it.
//
// Spec is a Merkle hash over the platform, the name, the resolved version,
// the PARSED recipe and the dependencies' spec hashes — Spack's shape. A
// version alone calls two builds the same when a build script changed under
// them.
type LockPin struct{ Project, Version, Spec string }

// Lock is a whole lock: what was asked for, what it resolved to, and the
// facts a later reader needs in order to decide whether the answer still
// holds.
//
// # THE HEADER IS DATA, NOT A COMMENT
//
// The first version of this wrote the platform, the roots and the two
// revisions as `#` lines. They were the right facts in the wrong place: a
// comment cannot be read back, so a check would have had to re-derive them
// from arguments the caller might give differently, and would then be
// checking a different question from the one the file answers.
//
// Spack's lockfile is the precedent for every field. Its `_meta` carries a
// `lockfile-version`; it records the Spack version "to track information
// that should enhance reproducibility"; and its top level holds `roots`
// beside `concrete_specs`.
// lockWriterKeys are the spellings this key has had, NEWEST FIRST. It is a
// list so that renaming the tool again is a visible edit here rather than a
// consequence of a rule — the same reason zpkm's obsoleteEnv is a table.
//
// ⛔ A RENAME ADDS AN ENTRY. It does not replace one: a lock written under any
// previous name is still a lock, and the field exists to say what wrote it.
var lockWriterKeys = []string{"zpkb", "zbk", "bk"}

// lockWriter returns the writing tool's version under whichever spelling the
// file carries. A file has exactly one of these, so first non-empty wins and
// no file can make the choice ambiguous.
func lockWriter(m map[string]any) string {
	for _, k := range lockWriterKeys {
		if v := lockString(m[k]); v != "" {
			return v
		}
	}
	return ""
}

type Lock struct {
	Version   int    // lockfile_version
	Platform  string // the platform it was taken on: it CHANGES the answer
	Generated string // RFC3339, UTC
	ZPKB      string // which zpkb wrote it
	Roots     []string
	Pantry    string
	Overlay   string
	// Pinned says which question the versions answer: PinsFromRecipes (the
	// newest the recipes can BUILD) or PinsPublished (the newest the factory
	// has PUBLISHED for this platform). They are different sets — measured
	// 2026-10-08, 2 of 5 pins for curl.se on linux/aarch64 — and only the
	// second can be installed by `pkgx --lock`.
	//
	// It is written down rather than inferred because `bk lock --check`
	// re-resolves, and re-resolving by the wrong question reports every
	// pin as having moved. The file answers its own roots and platform for
	// that same reason; the mode is one more of them.
	//
	// Empty means PinsFromRecipes: that is what every lock written before
	// this field existed holds.
	Pinned string
	Pins   []LockPin
}

// The two questions a lock's versions can answer. See Lock.Pinned.
const (
	PinsFromRecipes = "recipes"
	PinsPublished   = "published"
)

// LockfileVersion is this format's number. Bumped when a reader of the
// previous one would MISREAD a file rather than merely miss a field.
//
// The compatibility rule is Spack's, and worth copying: new readers read
// old locks, old readers refuse new ones.
const LockfileVersion = 1

// LockPinned is d.Pinned with the default filled in, so every reader
// resolves "absent" the same way instead of each one deciding.
func LockPinned(d Lock) string {
	if d.Pinned == PinsPublished {
		return PinsPublished
	}
	return PinsFromRecipes
}

// RenderLock writes a lock. HCL, because every other file this ecosystem
// reads by hand is HCL and HCLToMap reads it straight back.
func RenderLock(d Lock) string {
	var b strings.Builder
	b.WriteString("# zbk lock\n#\n" +
		"# `spec` is a Merkle hash over the platform, the name, the resolved\n" +
		"# version, the PARSED recipe (so reformatting does not move it) and the\n" +
		"# spec hashes of the dependencies — Spack's shape, whose packaging guide\n" +
		"# counts \"a canonical hash of the package.py recipes\" among a spec hash's\n" +
		"# inputs. A version alone calls two builds the same when a build script\n" +
		"# changed under them.\n#\n" +
		"# What this still does NOT pin: the BYTES of the built artifact. The spec\n" +
		"# hash covers the inputs, as Nix's and Spack's do; an output digest is a\n" +
		"# different promise and is not made here.\n#\n" +
		"# Sorted by project, not in build order: a lock is read as a diff, and a\n" +
		"# topological order makes every line move when one dependency does.\n#\n" +
		"# `zbk lock --check <this file>` re-resolves and says what moved.\n" +
		"# `zbk factory --lock <this file>` BUILDS these versions.\n#\n" +
		"# `zpkx --lock <this file>` RUNS them — but only if every pin is\n" +
		"# PUBLISHED for this platform. A lock pins what the RECIPES can build,\n" +
		"# which runs ahead of what the factory has published: measured\n" +
		"# 2026-10-08, a fresh lock of curl.se for linux/aarch64 had 2 of its 5\n" +
		"# pins ahead of the published artifacts, and `zpkx --lock` refused it.\n" +
		"# `zbk lock` says at write time which pins are not installable, and\n" +
		"# `zbk lock -runnable` pins what is published instead.\n\n")
	fmt.Fprintf(&b, "lockfile_version = %d\n", d.Version)
	fmt.Fprintf(&b, "zpkb             = %q\n", d.ZPKB)
	fmt.Fprintf(&b, "platform         = %q\n", d.Platform)
	fmt.Fprintf(&b, "generated        = %q\n", d.Generated)
	fmt.Fprintf(&b, "pantry           = %q\n", d.Pantry)
	fmt.Fprintf(&b, "overlay          = %q\n", d.Overlay)
	// Always written, including the default: a reader must be able to tell
	// "pinned from the recipes" from "written by a bk that had no modes",
	// and an absent line says both.
	fmt.Fprintf(&b, "pinned           = %q\n", LockPinned(d))
	b.WriteString("roots            = [")
	for i, r := range d.Roots {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%q", r)
	}
	b.WriteString("]\n\nlocked = {\n")
	for _, p := range d.Pins {
		fmt.Fprintf(&b, "  %q = { version = %q, spec = %q }\n", p.Project, p.Version, p.Spec)
	}
	b.WriteString("}\n")
	return b.String()
}

// ReadLock parses a lock from a file.
func ReadLock(path string) (Lock, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return Lock{}, err
	}
	return ParseLock(src, path)
}

// ParseLock parses a lock from bytes. path is used only in error messages,
// so a caller that already has the content — a test, or a tool reading from
// a pipe — does not have to put it on disk first.
//
// Through HCLToMap, the same reader the pantry overlay's HCL recipes go
// through, so the lock cannot develop a dialect of its own.
func ParseLock(src []byte, path string) (Lock, error) {
	m, err := HCLToMap(src, path)
	if err != nil {
		return Lock{}, err
	}
	d := Lock{
		Version:   int(lockInt(m["lockfile_version"])),
		Platform:  lockString(m["platform"]),
		Generated: lockString(m["generated"]),
		// ⛔⛔ EVERY GENERATION IS READ, NEWEST FIRST, AND THIS REVERSES AN
		// EARLIER DECISION ON PURPOSE. This key said `bk`, then `zbk`, and now
		// `zpkb`; the previous comment refused to read the older one, arguing
		// that "reading it would be an alias for a spelling the rename
		// removed".
		//
		// That argument is right about ENVIRONMENT VARIABLES and wrong here,
		// and the difference is what decides it. Two variables can BOTH be set
		// in one shell, so an alias resolves by a precedence nobody can see —
		// which is why ZPKGM_PREFIX and ZPKGE_SPECS are refused rather than
		// read. A lock file was written by exactly ONE tool and carries
		// exactly ONE of these keys, so there is nothing to disambiguate:
		// first non-empty wins, and no file can make that choice ambiguous.
		//
		// What the refusal cost was provenance. The field names the tool that
		// wrote the lock, and dropping it silently made every lock from a
		// previous era read as though nothing wrote it. With a THIRD spelling
		// the loss would have covered two eras at once.
		//
		// lockfile_version is deliberately NOT bumped, by the same argument
		// the `pinned` key uses below: an old reader that does not know this
		// key still reads the versions correctly, which is the bar the number
		// exists for. Bumping would make every binary built before today
		// refuse every lock written after it, over a field that names a tool.
		ZPKB:    lockWriter(m),
		Pantry:  lockString(m["pantry"]),
		Overlay: lockString(m["overlay"]),
		Pinned:  lockString(m["pinned"]),
	}
	// A mode this build does not know is not a mode it may GUESS at: it
	// would re-resolve by the wrong question and report what moved against
	// a set it never computed. lockfile_version is not bumped for the new
	// key — an old reader that ignores it still reads the versions
	// correctly, which is the bar the version number exists for — so this
	// is the check that catches a FUTURE third mode.
	if d.Pinned != "" && d.Pinned != PinsFromRecipes && d.Pinned != PinsPublished {
		return Lock{}, fmt.Errorf("%s: pinned = %q, and this build knows %q and %q — "+
			"read it with a newer bk rather than with this, which would re-resolve a different question",
			path, d.Pinned, PinsFromRecipes, PinsPublished)
	}
	// THE VERSION IS READ BEFORE THE CONTENTS, and that order is the whole
	// point of having one: it has to say "stop, you cannot interpret what
	// follows" BEFORE this build interprets it by its own rules.
	//
	// Checked last, as it was, a lock from a newer bk is first judged
	// against this build's expectations — so a format that renamed or
	// restructured `locked` would be reported as "this is not a lock",
	// which is false and sends the reader hunting for a corrupt file
	// instead of for a newer binary.
	if d.Version > LockfileVersion {
		return Lock{}, fmt.Errorf("%s: lockfile_version %d, and this build understands %d — "+
			"read it with a newer one rather than with this, which would miss whatever the "+
			"bump was for", path, d.Version, LockfileVersion)
	}
	for _, r := range lockSlice(m["roots"]) {
		d.Roots = append(d.Roots, lockString(r))
	}
	// A lock with no readable `locked` block is not an empty lock. An error
	// for the same reason `bk lock` refuses to pin nothing: the caller
	// would read "nothing moved" off a file that says nothing.
	locked, ok := m["locked"].(map[string]any)
	if !ok || len(locked) == 0 {
		return Lock{}, fmt.Errorf("%s: no `locked` entries — this is not a lock", path)
	}
	for proj, v := range locked {
		e, ok := v.(map[string]any)
		if !ok {
			return Lock{}, fmt.Errorf("%s: %q is not a { version = …, spec = … } entry", path, proj)
		}
		// A lock is a file fetched from a repository and ACTED ON, so a
		// name in it is as untrusted as one in a catalogue. Refused
		// here, where the whole file can be rejected, rather than deep
		// in a URL builder where only one lookup would fail.
		if err := ValidateProjectName(proj); err != nil {
			return Lock{}, fmt.Errorf("%s: %w", path, err)
		}
		// THE VERSION IS A KEY, not a caption: it selects the bytes to
		// download and names the directory they go in. Refused rather than
		// cleaned, unlike a catalogue summary — a version that is not
		// version-shaped means somebody wanted something, and exactness is
		// the entire point of a lock. See ValidateVersionString, which
		// records the crafted version that wrote on a terminal through the
		// unsatisfiable-pin message.
		version, spec := lockString(e["version"]), lockString(e["spec"])
		if err := ValidateVersionString(version); err != nil {
			return Lock{}, fmt.Errorf("%s: %s: %w", path, proj, err)
		}
		if err := ValidateSpecHash(spec); err != nil {
			return Lock{}, fmt.Errorf("%s: %s: %w", path, proj, err)
		}
		d.Pins = append(d.Pins, LockPin{proj, version, spec})
	}
	sort.Slice(d.Pins, func(i, j int) bool { return d.Pins[i].Project < d.Pins[j].Project })
	return d, nil
}

// LockAge says how old a lock is, in the words every other age in this
// ecosystem is said in.
func LockAge(generated string, now time.Time) string {
	t, err := time.Parse(time.RFC3339, generated)
	if err != nil {
		return "unknown age"
	}
	d := now.UTC().Sub(t)
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%d minute(s) old", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d hour(s) old", int(d.Hours()))
	}
	return fmt.Sprintf("%d day(s) old", int(d.Hours()/24))
}

// lockString, lockInt and lockSlice read a value HCLToMap produced. They do
// not report a type error: a field of the wrong type reads as its zero, and
// a comparison then SAYS so by name instead of refusing the whole file over
// one line. The one shape that cannot be tolerated — a missing `locked` —
// is checked in ParseLock.
func lockString(v any) string {
	s, _ := v.(string)
	return s
}

func lockInt(v any) int64 {
	switch n := v.(type) {
	case int64:
		return n
	case float64:
		return int64(n)
	}
	return 0
}

func lockSlice(v any) []any {
	s, _ := v.([]any)
	return s
}
