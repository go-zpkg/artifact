package artifact

import (
	"errors"
	"strings"
	"testing"
)

// THE ATTACK, measured through `pkgx --lock` before the fix. The version
// field of a lock reached the terminal unquoted in the second half of the
// unsatisfiable-pin message:
//
//	asked for by =1.3.2^[[2K^Mzlib.net  1.9.9  ✓ verified (requested)
//
// `ESC[2K` erases the line and `\r` returns the cursor, so it reprints as a
// different, reassuring one.
const craftedVersion = "1.3.2\x1b[2K\rzlib.net  1.9.9  ✓ verified"

func TestACraftedVersionIsRefusedNotCleaned(t *testing.T) {
	err := ValidateVersionString(craftedVersion)
	if err == nil {
		t.Fatal("a version carrying an escape was accepted")
	}
	if !errors.Is(err, ErrBadVersionString) {
		t.Errorf("refused for the wrong reason: %v", err)
	}
	// AND THE REFUSAL DOES NOT REPEAT THE ATTACK. A message that echoed the
	// control character in order to say it refused one would do the very
	// thing it is refusing.
	if strings.ContainsRune(err.Error(), 0x1b) {
		t.Errorf("the refusal printed the escape: %q", err.Error())
	}
}

// THROUGH ParseLock, which is the path that matters: a lock is fetched from
// a repository and acted on, so the whole file is rejected rather than one
// pin being quietly dropped.
func TestALockCarryingACraftedVersionIsRefused(t *testing.T) {
	// The escape goes in as HCL's own `\u001b` and `\r`, because a literal
	// carriage return would split the quoted string and HCL would refuse
	// the FILE — which looks like the guard working and is not it. That
	// mistake was made here once already.
	src := "lockfile_version = 1\nplatform = \"linux/x86-64\"\n" +
		"locked = {\n  \"zlib.net\" = { version = \"1.3.2\\u001b[2K\\rzlib.net 1.9.9 verified\", spec = \"\" }\n}\n"
	_, err := ParseLock([]byte(src), "evil.lock.hcl")
	if err == nil {
		t.Fatal("a lock with a crafted version parsed cleanly")
	}
	if !strings.Contains(err.Error(), "zlib.net") {
		t.Errorf("the refusal does not name the pin: %v", err)
	}
	if strings.ContainsRune(err.Error(), 0x1b) {
		t.Errorf("the refusal printed the escape: %q", err.Error())
	}
}

// REAL VERSIONS PASS. Measured across the two published catalogues of
// 2026-10-06: 2801 version strings, fifteen distinct runes, longest 19
// bytes. A guard written against an attack that also refuses the ordinary
// case is a different and worse bug, so the ordinary case is pinned here.
func TestRealVersionsPass(t *testing.T) {
	for _, v := range []string{
		"1.3.2", "9.1.0", "20260526.0", "2026.1", "1.0.8", "2.14.3",
		"2023.10.25.06.33.25", // min.io, the longest in the catalogue
		"1.8.13", "0.29.2", "2026.09.25",
		// Wider than anything measured, deliberately: these are ordinary
		// versions elsewhere and refusing them would be the guard
		// overreaching.
		"1.2.3-rc1", "1.2.3+build.5", "4.0.0~beta", "v1_2",
	} {
		if err := ValidateVersionString(v); err != nil {
			t.Errorf("ValidateVersionString(%q) = %v", v, err)
		}
	}
}

func TestVersionBoundsAndEmptiness(t *testing.T) {
	if err := ValidateVersionString(""); err == nil {
		t.Error("an empty version was accepted")
	}
	if err := ValidateVersionString(strings.Repeat("1", maxVersionString)); err != nil {
		t.Errorf("a version at the limit was refused: %v", err)
	}
	if err := ValidateVersionString(strings.Repeat("1", maxVersionString+1)); err == nil {
		t.Error("a version past the limit was accepted")
	}
	// A path separator is not a length problem and is the other thing a
	// version must never carry: it names a directory.
	for _, v := range []string{"../../etc", "1.2/3", `1.2\3`, "1.2 3", "1.2;3"} {
		if err := ValidateVersionString(v); err == nil {
			t.Errorf("ValidateVersionString(%q) was accepted", v)
		}
	}
}

func TestSpecHashShape(t *testing.T) {
	good := "sha256:" + strings.Repeat("ab12", 16)
	if err := ValidateSpecHash(good); err != nil {
		t.Errorf("a real spec was refused: %v", err)
	}
	// Empty is allowed: a lock from a bk that recorded none is still a lock.
	if err := ValidateSpecHash(""); err != nil {
		t.Errorf("an absent spec was refused: %v", err)
	}
	// LOOSER THAN THE VERSION, deliberately: a spec is only ever compared,
	// never made into a path, a URL or an argument, so the only risk it
	// carries is that it is printed. A short placeholder digest — which
	// this project's own fixtures use — and a future algorithm prefix are
	// both fine; a guard stricter than its reason is a compatibility break
	// with no security to show for it.
	for _, s := range []string{
		"sha256:tooshort",
		"sha1:" + strings.Repeat("ab12", 16),
		"blake3:" + strings.Repeat("ab12", 16),
	} {
		if err := ValidateSpecHash(s); err != nil {
			t.Errorf("ValidateSpecHash(%q) = %v, want accepted", s, err)
		}
	}
	// What it does refuse is what could reach a terminal, or a paragraph.
	for _, s := range []string{
		"\x1b[2K\rsha256:" + strings.Repeat("ab12", 16),
		"sha256:" + strings.Repeat("ab12", 16) + " and some prose",
		"sha256:aa\nbb",
		strings.Repeat("a", maxSpecString+1),
	} {
		if err := ValidateSpecHash(s); err == nil {
			t.Errorf("ValidateSpecHash(%q) was accepted", s)
		}
	}
	// And its refusal is cleaned too, since it quotes what it saw.
	err := ValidateSpecHash("\x1b[2K\rnope")
	if err == nil || strings.ContainsRune(err.Error(), 0x1b) {
		t.Errorf("the spec refusal printed the escape: %v", err)
	}
}

// THE PATH THE PROBE ACTUALLY HIT, and the one a test nearly missed.
//
// A lock with ONE unsatisfiable pin takes the single-demand branch of
// closureErr, not ConflictError — a different sentence built in a different
// place. That is the branch the crafted version came out of:
//
//	asked for by =1.3.2^[[2K^Mzlib.net  1.9.9  ✓ verified (requested)
//
// Mutating only this branch survived the suite until this test existed,
// while the ConflictError one was already covered. Two sentences, one
// defect, and the covered half said nothing about the other.
func TestTheSingleDemandMessageCannotCarryAnEscape(t *testing.T) {
	err := closureErr("zlib.net",
		[]string{"=1.3.2\x1b[2K\rzlib.net 1.9.9 verified"},
		[]string{"requested"},
		errors.New(`no version of zlib.net satisfies "=…" (available: 2)`))
	got := err.Error()
	if strings.ContainsRune(got, 0x1b) || strings.ContainsRune(got, '\r') {
		t.Errorf("an escape reached the single-demand message: %q", got)
	}
	if !strings.Contains(got, "1.3.2") || !strings.Contains(got, "requested") {
		t.Errorf("the demand was lost with the escapes: %q", got)
	}
}

// THE CHANNEL, closed behind the source. A constraint also reaches this
// sentence from a RECIPE's dependency line, which no lock parser sees, so
// the message cleans what it prints as well as the lock refusing what it
// stores.
func TestTheUnsatisfiableMessageCannotCarryAnEscape(t *testing.T) {
	e := &ConflictError{
		Project:     "zlib.net",
		Constraints: []string{"=1.3.2\x1b[2K\rzlib.net 1.9.9 verified", "^1"},
		AskedBy:     []string{"requested", "app.org/x\x1b[2K\r"},
		Err:         errors.New("no version satisfies both"),
	}
	got := e.Error()
	if strings.ContainsRune(got, 0x1b) {
		t.Errorf("an escape reached the conflict message: %q", got)
	}
	if strings.ContainsRune(got, '\r') {
		t.Errorf("a carriage return reached the conflict message: %q", got)
	}
	// The TEXT is kept: cleaning is not censoring, and the reader still
	// needs to see which demand was impossible.
	if !strings.Contains(got, "1.3.2") || !strings.Contains(got, "app.org/x") {
		t.Errorf("the demands were lost with the escapes: %q", got)
	}
}

// A REGISTRY IS A CONFIGURED ENDPOINT. ZPKG_DIST and the mirror can both be
// pointed elsewhere, and a tag list is whatever the far side says. The old
// test was on the FIRST BYTE only, so a tag beginning with a digit and
// continuing into an escape sequence passed and went on to be printed in
// version lists.
func TestARegistryTagIsHeldToTheVersionShape(t *testing.T) {
	for _, tag := range []string{"1.3.2", "v9.1.0", "1.0.0+glibc2.28", "20260526.0", "V2.1"} {
		if !isVersionTag(tag) {
			t.Errorf("isVersionTag(%q) = false, want true", tag)
		}
	}
	for _, tag := range []string{
		"1.3.2\x1b[2K\rzlib.net 1.9.9 verified",
		"1.0 and a sentence",
		"1.0.0\n2.0.0",
		// Still excluded for the original reason, which must not regress:
		// the referrer tags a real registry carries beside the versions.
		"sha256-21c9e22167bb8b188809b78e730a03df58aa4c657648f614aa52eaa4be5851c9",
		"latest",
	} {
		if isVersionTag(tag) {
			t.Errorf("isVersionTag(%q) = true, want false", tag)
		}
	}
}
