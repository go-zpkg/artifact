package artifact

import (
	"strings"
	"testing"
)

// THE ATTACK, measured before the fix: `pkgx search` printed this summary
// straight to the terminal, and `\x1b[2K\r` is an erase-line followed by a
// carriage return — the line rubs itself out and reprints as a different,
// reassuring one.
const spoof = "harmless\x1b[2K\rcurl.se  SAFE  8.20  ✓ verified by maintainers"

func TestACraftedSummaryCannotWriteOnTheTerminal(t *testing.T) {
	got := displayText(spoof, summaryLimit)
	for _, bad := range []string{"\x1b", "\r", "\n", "\x00", "\x7f"} {
		if strings.Contains(got, bad) {
			t.Errorf("%q survived: %q", bad, got)
		}
	}
	// The TEXT is kept — stripping is not censoring, and a reader should
	// still see what the recipe claims, minus the cursor moves.
	if !strings.Contains(got, "harmless") || !strings.Contains(got, "verified by maintainers") {
		t.Errorf("the words were lost with the escapes: %q", got)
	}
	// And it is one line.
	if strings.Count(got, "\n") != 0 {
		t.Errorf("more than one line: %q", got)
	}
}

// Through the CATALOGUE, which is the path that matters: a forged or
// compromised catalogue must not reach a terminal with escapes in it.
func TestACatalogueCannotCarryTerminalEscapes(t *testing.T) {
	body := `{"generated":"2026-10-06T09:00:00Z","projects":[` +
		`{"project":"evil.org","summary":"harmless\u001b[2K\rcurl.se SAFE",` +
		`"provides":["ok","ev\u001b[31mil"]}]}`
	c, err := UnmarshalCatalog([]byte(body))
	if err != nil {
		t.Fatalf("UnmarshalCatalog: %v", err)
	}
	p := c.Projects[0]
	if strings.ContainsRune(p.Summary, 0x1b) {
		t.Errorf("an escape reached the summary: %q", p.Summary)
	}
	for _, cmd := range p.Provides {
		if strings.ContainsRune(cmd, 0x1b) {
			t.Errorf("an escape reached a command name: %q", cmd)
		}
	}
	// PROVIDES is checked too, and it is easy to forget: it is printed
	// beside a search hit exactly as the summary is.
	if len(p.Provides) != 2 {
		t.Errorf("provides = %v", p.Provides)
	}
}

// UNICODE IS KEPT. A rule that allowed only ASCII would be a different and
// worse bug — the one where a guard written against an attack also refuses
// the ordinary case. A package described in Japanese is a description.
func TestDisplayTextKeepsRealText(t *testing.T) {
	for _, s := range []string{
		"a JSON processor",
		"処理系: 日本語の説明",
		"a C++ library — with an em dash and «quotes»",
		"naïve, café, Ωmega",
	} {
		if got := displayText(s, summaryLimit); got != s {
			t.Errorf("displayText(%q) = %q", s, got)
		}
	}
}

// Whitespace collapses, so a summary cannot be padded into a shape.
func TestDisplayTextCollapsesWhitespace(t *testing.T) {
	for in, want := range map[string]string{
		"  spaced   out  ": "spaced out",
		"tabs\there":       "tabs here",
		"lines\nbroken":    "lines broken",
		"zero​width":       "zerowidth",
		"sep arator":       "separator",
		"":                 "",
	} {
		if got := displayText(in, summaryLimit); got != want {
			t.Errorf("displayText(%q) = %q, want %q", in, got, want)
		}
	}
}

// THE RESIDUE IS DELIBERATE, and my first expectation here was wrong.
//
// Stripping ESC from "\x1b[31m" leaves "[31m" — the sequence's parameters,
// as ordinary text. I expected "" and the test said otherwise, which is the
// right answer: a recipe may legitimately write "[31m" in a description,
// and removing it would be guessing at intent rather than defanging an
// attack.
//
// The threat is CURSOR CONTROL, and ESC is the only thing that enables it.
// That boundary is the whole rule; everything past it is censorship.
func TestTheEscapeGoesAndItsParametersStay(t *testing.T) {
	got := displayText("\x1b[31mred\x1b[0m", summaryLimit)
	if strings.ContainsRune(got, 0x1b) {
		t.Fatalf("the escape survived: %q", got)
	}
	if got != "[31mred[0m" {
		t.Errorf("displayText = %q, want the parameters kept as text", got)
	}
}

// Bounded, and cut on a RUNE boundary: truncating mid-rune emits a
// replacement character, which is a corruption the limit was meant to
// prevent.
func TestDisplayTextIsBoundedAndCutsCleanly(t *testing.T) {
	long := strings.Repeat("é", 300) // two bytes each
	got := displayText(long, 101)
	if len(got) > 101 {
		t.Errorf("%d bytes, limit 101", len(got))
	}
	if strings.ContainsRune(got, '�') {
		t.Errorf("cut mid-rune: %q", got[len(got)-4:])
	}
	for _, r := range got {
		if r != 'é' {
			t.Fatalf("unexpected rune %q", r)
		}
	}
}
