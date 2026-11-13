package artifact

import (
	"errors"
	"fmt"
)

// A VERSION OUT OF A LOCK IS UNTRUSTED INPUT, and a lock is fetched from a
// repository and ACTED ON.
//
// # WHAT A CRAFTED VERSION DID
//
// `pkgx --lock` reports an unsatisfiable pin, and the sentence it prints
// ends by naming the demand. Measured, not imagined:
//
//	locked = {
//	  "zlib.net" = { version = "1.3.2\u001b[2K\rzlib.net  1.9.9  ✓ verified", … }
//	}
//
//	$ pkgx --lock esc.lock.hcl true | cat -v
//	pkgx: no version of zlib.net satisfies "=1.3.2\x1b[2K\r…" (available: …);
//	  asked for by =1.3.2^[[2K^Mzlib.net  1.9.9  ✓ verified (requested)
//
// The first half is %q-quoted and harmless. The second is not, and on a
// terminal `ESC[2K` erases the line and `\r` returns the cursor, so it
// reprints as a different and reassuring one.
//
// This is the same class as the catalogue summary fixed in v0.37.0 — a
// field a third party writes reaching a terminal — through a channel that
// fix did not cover, which is the usual way such a thing comes back.
//
// # REFUSED, NOT STRIPPED, AND THAT IS THE DIFFERENCE FROM A SUMMARY
//
// A summary is cosmetic, so it is cleaned and shown. A version is a KEY: it
// selects bytes to download and names a directory to put them in. A version
// that is not version-shaped means somebody wanted something, exactness is
// the entire point of a lock, and there is nothing to salvage.
//
// # THE SHAPE WAS MEASURED BEFORE IT WAS GUARDED
//
// Across the two published catalogues of 2026-10-06, 2801 version strings
// use fifteen distinct runes — `0-9`, `.`, and `b e f n` — and the longest
// is 19 bytes (`min.io 2023.10.25.06.33.25`). The allowlist below is wider
// than that on purpose: `+`, `~`, `_` and `-` are ordinary in versions
// elsewhere and refusing them would be a guard written against an attack
// that also refuses the ordinary case.
const maxVersionString = 64

// ErrBadVersionString is returned for a version a lock has no business
// carrying.
var ErrBadVersionString = errors.New("not a version")

// ValidateVersionString refuses anything that is not shaped like a version.
func ValidateVersionString(v string) error {
	if v == "" {
		return fmt.Errorf("%w: empty", ErrBadVersionString)
	}
	if len(v) > maxVersionString {
		return fmt.Errorf("%w: %d bytes, limit %d", ErrBadVersionString, len(v), maxVersionString)
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c >= '0' && c <= '9',
			c >= 'a' && c <= 'z',
			c >= 'A' && c <= 'Z',
			c == '.', c == '-', c == '+', c == '_', c == '~':
		default:
			// %q so the byte is NAMED rather than printed: a message that
			// echoes a control character to say it refused one would do
			// the very thing it is refusing.
			return fmt.Errorf("%w: %q at byte %d", ErrBadVersionString, string(c), i)
		}
	}
	return nil
}

// ValidateSpecHash refuses a spec that could not be a digest.
//
// # WHY THIS IS LOOSER THAN THE VERSION, DELIBERATELY
//
// A version is a KEY: it picks bytes and names a directory, so it is held
// to a shape. A spec is only ever COMPARED — `bk lock --check` reports it
// moved — and never becomes a path, a URL or an argument. The whole risk it
// carries is that it is printed.
//
// Demanding `sha256:` plus exactly 64 hex digits would add nothing against
// that risk and would refuse locks this project's own tests write with
// short placeholder digests, as well as any future algorithm prefix. A
// guard stricter than its reason is a compatibility break with no security
// to show for it.
//
// Empty is allowed: a lock from a bk that recorded none is still a lock,
// and the fields are compared only when both sides have them.
func ValidateSpecHash(s string) error {
	if len(s) > maxSpecString {
		return fmt.Errorf("spec: %d bytes, limit %d", len(s), maxSpecString)
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9',
			c >= 'a' && c <= 'z',
			c >= 'A' && c <= 'Z',
			c == ':', c == '.', c == '-', c == '_':
		default:
			// %q names the byte rather than printing it: a message that
			// echoed a control character to say it refused one would do
			// the very thing it is refusing.
			return fmt.Errorf("spec: %q at byte %d", string(c), i)
		}
	}
	return nil
}

// maxSpecString bounds a digest with room for a longer algorithm than
// sha256 without inviting a paragraph.
const maxSpecString = 128

// ValidatePlatformSlug refuses anything that is not an `os/arch` slug.
//
// A platform is written by the factory, not by a recipe, so a bad one means
// the file was forged rather than that somebody upstream was careless. It
// is still only dropped, not fatal: the asymmetry that matters is between
// a KEY and a CAPTION, and a reader who loses one platform line keeps a
// usable catalogue.
//
// Exactly one tool prints these today — which is precisely the argument
// people use for leaving a field unchecked until something new prints it.
func ValidatePlatformSlug(s string) error {
	if s == "" {
		return fmt.Errorf("%w: empty", ErrBadVersionString)
	}
	if len(s) > maxPlatformSlug {
		return fmt.Errorf("%w: %d bytes, limit %d", ErrBadVersionString, len(s), maxPlatformSlug)
	}
	slashes := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9',
			c >= 'a' && c <= 'z',
			c == '.', c == '-', c == '_':
		case c == '/':
			slashes++
		default:
			return fmt.Errorf("%w: %q at byte %d", ErrBadVersionString, string(c), i)
		}
	}
	if slashes != 1 || s[0] == '/' || s[len(s)-1] == '/' {
		return fmt.Errorf("%w: %q is not os/arch", ErrBadVersionString, displayText(s, maxPlatformSlug))
	}
	return nil
}

// maxPlatformSlug bounds an os/arch pair; the longest in use is
// `windows/x86-64`.
const maxPlatformSlug = 32
