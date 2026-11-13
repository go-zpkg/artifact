package artifact

import (
	"strings"
	"unicode"
)

// Text that reaches a TERMINAL is not a program.
//
// # WHAT A CRAFTED SUMMARY DID
//
// A catalogue carries a one-line summary per project, and `pkgx search`
// prints it. Nothing stripped control characters, so a recipe could write
// its own output:
//
//	summary: "harmless\x1b[2K\rcurl.se  SAFE  8.20  ✓ verified by maintainers"
//
// On a terminal that is not a summary, it is an ERASE-LINE followed by a
// carriage return: the line rubs itself out and reprints as a different,
// reassuring one. Measured, not imagined — the probe produced exactly that
// line from `pkgx search`.
//
// # WHERE IT COMES FROM
//
// A recipe, in the upstream pantry or in our overlay. It flows from there
// into the published catalogue and from the catalogue into every reader's
// terminal, so a contributor to a recipe set gets to write on the screen of
// everyone who searches. The same is true of `provides`, which is printed
// beside a hit.
//
// # STRIPPED, NOT REFUSED
//
// Unlike a project name — where a bad value means somebody wanted something
// — a summary is cosmetic, and refusing a whole catalogue over one
// paragraph would deny service for a typo. Control characters carry no
// meaning in a one-line description, so dropping them loses nothing a
// reader wanted.
//
// A project NAME is the opposite case and is refused outright; see
// ValidateProjectName.

// displayText is one line of text safe to print: no control characters, no
// DEL, no line breaks, and bounded.
//
// Unicode is kept. A package described in Japanese is a description, and a
// rule that allowed only ASCII would be a different, worse bug — the one
// where a guard written against an attack also refuses the ordinary case.
func displayText(s string, max int) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\t' || r == '\n' || r == '\r':
			// A summary is ONE line. A tab or a newline inside it is
			// either a mistake or an attempt to move the cursor; a space
			// is what was meant either way.
			b.WriteRune(' ')
		case r == 0x7f, unicode.IsControl(r):
			// Dropped, not replaced: a visible placeholder would let a
			// crafted string spend the reader's attention anyway.
		case r == '​' || r == ' ' || r == ' ':
			// Zero-width space and the Unicode line separators: not
			// control characters by category, and all three can hide or
			// break a line.
		default:
			b.WriteRune(r)
		}
	}
	out := strings.Join(strings.Fields(b.String()), " ")
	if max > 0 && len(out) > max {
		// Cut on a rune boundary, or the truncation itself emits a
		// replacement character.
		for max > 0 && !utf8ValidPrefix(out, max) {
			max--
		}
		out = out[:max]
	}
	return out
}

func utf8ValidPrefix(s string, n int) bool {
	if n >= len(s) {
		return true
	}
	// A continuation byte is 10xxxxxx; cutting before one splits a rune.
	return s[n]&0xc0 != 0x80
}
