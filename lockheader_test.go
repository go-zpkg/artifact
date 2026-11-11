package bottle

import (
	"regexp"
	"strings"
	"testing"
)

// The header of a lock is the only documentation most readers of one will
// ever see: it is in the file, in front of them, at the moment they are
// wondering what to do with it. It advertised `pkgx install --lock`, and
// pkgx has no `install` subcommand — the name was written before the
// command was, and nothing connected the two.
//
// Caught by generating a real lock during the end-to-end check and reading
// what came out, which is the only way a comment's accuracy is ever
// checked.
//
// This test cannot know what pkgx's commands are. What it CAN do is refuse
// the spellings that have already been wrong once, which is what a
// regression test is for.
func TestTheLockHeaderNamesCommandsThatExist(t *testing.T) {
	out := RenderLock(sampleLock())

	for _, wrong := range []string{
		"pkgx install --lock", // pkgx has no `install`
		"bk lock --apply",     // never existed
	} {
		if strings.Contains(out, wrong) {
			t.Errorf("the header advertises %q, which is not a command", wrong)
		}
	}

	// And it still points at the three that do, because a lock whose
	// header says nothing about how to use it is a file people delete.
	for _, right := range []string{
		"zbk lock --check",
		"zpkgx --lock",
		"zbk factory --lock",
	} {
		if !strings.Contains(out, right) {
			t.Errorf("the header no longer mentions %q", right)
		}
	}

	// ⛔⛔ AND IT MUST NOT NAME THE RETIRED COMMANDS, which the check above
	// CANNOT SEE: `strings.Contains(out, "bk lock --check")` is satisfied by
	// "zbk lock --check", because the new name contains the old one. This test
	// passed unchanged when the header still said `bk lock` and when it was
	// corrected to `zbk lock` — it could not tell the two apart, so it was
	// policing nothing.
	//
	// A left word boundary is what distinguishes them, the same rule the
	// rename sweep needed. Every lock this package writes carries this header
	// to a user, so a retired command here is advice that does not run.
	for _, retired := range []string{`bk`, `pkgx`, `pkgm`} {
		re := regexp.MustCompile(`(^|[^A-Za-z0-9_])` + retired + `[ \x60]`)
		if m := re.FindString(out); m != "" {
			t.Errorf("the header names the retired command %q (matched %q)", retired, m)
		}
	}

	// ⛔ AND IT PROMISED BOTH USES WHEN IT CAN ONLY DELIVER ONE. The header
	// said "`pkgx --lock <this file>` runs exactly these versions, and
	// `bk factory --lock <this file>` builds them" — flatly, for every lock.
	//
	// Measured 2026-10-08, by generating a real lock and running it: a fresh
	// lock of curl.se for linux/aarch64 pinned curl.se/ca-certs 2026.09.25
	// and openssl.org 4.0.3, neither of which the factory had published, and
	// `pkgx --lock` refused the file. A lock pins what the RECIPES can build,
	// which runs ahead of what has been built; the two uses are not the same
	// question and the header must not merge them.
	if strings.Contains(out, "runs exactly these versions, and") {
		t.Error("the header still promises pkgx --lock unconditionally")
	}
	for _, needed := range []string{
		"PUBLISHED", // the condition under which pkgx --lock works
		"-runnable", // and what to do when it does not
	} {
		if !strings.Contains(out, needed) {
			t.Errorf("the header does not mention %q", needed)
		}
	}

	// The header is a comment, so every line of it must be one: a line
	// that lost its `#` would be parsed as HCL and refuse the whole file.
	for _, line := range strings.Split(out, "\n") {
		if line == "" {
			break // the header ends at the first blank line
		}
		if !strings.HasPrefix(line, "#") {
			t.Fatalf("a header line is not a comment: %q", line)
		}
	}

	// Proven by the round trip rather than by reading: whatever the header
	// says, the file still parses.
	if _, err := ParseLock([]byte(out), "header.lock.hcl"); err != nil {
		t.Errorf("the rendered lock does not parse: %v", err)
	}
}

// ⛔ A LOCK MUST SAY WHICH QUESTION ITS VERSIONS ANSWER. `bk lock --check`
// re-resolves; re-resolving by the wrong question reports every pin as
// having moved. The file already answers its own roots and platform for
// that reason — this is one more of them.
func TestALockSaysHowItsVersionsWerePinned(t *testing.T) {
	d := sampleLock()
	// THE DEFAULT IS WRITTEN OUT, not left absent: "pinned from the recipes"
	// and "written by a bk that had no modes" must not look the same.
	out := RenderLock(d)
	if !strings.Contains(out, `pinned           = "recipes"`) {
		t.Errorf("the default mode is not stated:\n%s", out)
	}
	got, err := ParseLock([]byte(out), "r.lock.hcl")
	if err != nil || got.Pinned != PinsFromRecipes {
		t.Errorf("round trip: Pinned=%q err=%v", got.Pinned, err)
	}

	d.Pinned = PinsPublished
	out = RenderLock(d)
	if !strings.Contains(out, `pinned           = "published"`) {
		t.Errorf("the published mode is not stated:\n%s", out)
	}
	got, err = ParseLock([]byte(out), "p.lock.hcl")
	if err != nil || got.Pinned != PinsPublished {
		t.Errorf("round trip: Pinned=%q err=%v", got.Pinned, err)
	}
}

// A LOCK WRITTEN BEFORE THE FIELD EXISTED still reads, as the recipes mode
// it was. That is the compatibility rule this format states: new readers
// read old locks.
func TestALockWithNoModeReadsAsTheRecipesOne(t *testing.T) {
	out := RenderLock(sampleLock())
	before, _, _ := strings.Cut(out, "\npinned ")
	_, after, _ := strings.Cut(out, "\npinned           = \"recipes\"")
	old := before + after
	if strings.Contains(old, "pinned") {
		t.Fatalf("the fixture still carries the field:\n%s", old)
	}
	got, err := ParseLock([]byte(old), "old.lock.hcl")
	if err != nil {
		t.Fatalf("a lock from before the field does not parse: %v", err)
	}
	if LockPinned(got) != PinsFromRecipes {
		t.Errorf("an absent mode read as %q, want %q", LockPinned(got), PinsFromRecipes)
	}
}

// ⛔ AND A MODE THIS BUILD DOES NOT KNOW IS REFUSED, not guessed at: a
// guess would re-resolve a different question and report what moved
// against a set it never computed.
func TestALockWithAnUnknownModeIsRefused(t *testing.T) {
	d := sampleLock()
	d.Pinned = PinsPublished
	out := strings.Replace(RenderLock(d), `"published"`, `"whatever-comes-next"`, 1)
	_, err := ParseLock([]byte(out), "future.lock.hcl")
	if err == nil {
		t.Fatal("a mode this build does not know was accepted")
	}
	if !strings.Contains(err.Error(), "whatever-comes-next") {
		t.Errorf("the refusal does not name the mode: %v", err)
	}
}
