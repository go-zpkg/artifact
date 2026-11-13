package artifact

import (
	"path/filepath"
	"strings"
	"testing"
	"unicode"
)

// WHAT SURVIVES PARSING IS SAFE TO PRINT.
//
// That is the invariant the three channel fixes add up to, and it is worth
// a fuzz target rather than a table: a table tests the inputs I thought of,
// and every hole found here so far was in a field I had not thought of.
// There were no Fuzz targets anywhere in this family before this file,
// while artifact parses a catalogue, a lock and a project name — all three
// fetched from somewhere else and all three printed.
//
// The property is deliberately not "it does not panic". It is that a value
// which got PAST the parser cannot carry a cursor movement, because the
// parser is the only place that decides.
func FuzzUnmarshalCatalog(f *testing.F) {
	f.Add(`{"generated":"2026-10-06T15:04:06Z","projects":[{"project":"gnu.org/bash","versions":["5.3"],"platforms":["linux/aarch64"],"provides":["bash"],"summary":"a shell"}]}`)
	f.Add(`{"generated":"","projects":[]}`)
	f.Add(`{"generated":"x","projects":[{"project":"a.org","summary":"\u001b[2K\rspoof","versions":["1.0\u001b[2K"],"platforms":["l\u001b/a"],"provides":["\u0007bell"],"deps":["b.org"]}]}`)
	f.Add(`{"projects":[{"project":"../../etc/passwd"}]}`)
	f.Fuzz(func(t *testing.T, body string) {
		c, err := UnmarshalCatalog([]byte(body))
		if err != nil {
			return
		}
		for _, p := range c.Projects {
			if err := ValidateProjectName(p.Project); err != nil {
				t.Fatalf("a catalogue carried project %q: %v", p.Project, err)
			}
			mustBePrintable(t, "summary of "+p.Project, p.Summary)
			for _, cmd := range p.Provides {
				mustBePrintable(t, "a command of "+p.Project, cmd)
			}
			for _, v := range p.Versions {
				if err := ValidateVersionString(v); err != nil {
					t.Fatalf("a catalogue carried version %q of %s: %v", v, p.Project, err)
				}
			}
			for _, pl := range p.Platforms {
				if err := ValidatePlatformSlug(pl); err != nil {
					t.Fatalf("a catalogue carried platform %q of %s: %v", pl, p.Project, err)
				}
			}
			for _, d := range p.Deps {
				if err := ValidateProjectName(d); err != nil {
					t.Fatalf("%s declares dependency %q: %v", p.Project, d, err)
				}
			}
		}
	})
}

// A lock is the stricter half of the same invariant: nothing is dropped, so
// anything the parser returns was accepted whole.
func FuzzParseLock(f *testing.F) {
	f.Add("lockfile_version = 1\nplatform = \"linux/x86-64\"\nlocked = {\n  \"zlib.net\" = { version = \"1.3.2\", spec = \"sha256:ab\" }\n}\n")
	f.Add("lockfile_version = 99\nlocked = {}\n")
	f.Add("locked = {\n  \"a.org\" = { version = \"1.0\\u001b[2K\\r\", spec = \"\" }\n}\n")
	f.Add("not hcl at all {{{")
	f.Fuzz(func(t *testing.T, body string) {
		d, err := ParseLock([]byte(body), "fuzz.lock.hcl")
		if err != nil {
			// A refusal is printed too, so it is held to the same rule.
			mustBePrintable(t, "the refusal", err.Error())
			return
		}
		if d.Version > LockfileVersion {
			t.Fatalf("a lock from the future parsed: version %d", d.Version)
		}
		if len(d.Pins) == 0 {
			t.Fatal("a lock pinning nothing parsed")
		}
		for _, p := range d.Pins {
			if err := ValidateProjectName(p.Project); err != nil {
				t.Fatalf("a lock carried project %q: %v", p.Project, err)
			}
			if err := ValidateVersionString(p.Version); err != nil {
				t.Fatalf("a lock carried version %q of %s: %v", p.Version, p.Project, err)
			}
			if err := ValidateSpecHash(p.Spec); err != nil {
				t.Fatalf("a lock carried spec %q of %s: %v", p.Spec, p.Project, err)
			}
		}
	})
}

// displayText is the other half: what it returns is SHOWN, so its output is
// the thing that must be printable no matter what went in.
func FuzzDisplayText(f *testing.F) {
	f.Add("a JSON processor", 200)
	f.Add("harmless\x1b[2K\rcurl.se  SAFE", 200)
	f.Add("処理系: 日本語の説明", 200)
	f.Add(strings.Repeat("é", 300), 101)
	f.Add("\x00\x07\x1b  ​", 64)
	f.Fuzz(func(t *testing.T, s string, max int) {
		if max < 0 || max > 1<<16 {
			return
		}
		got := displayText(s, max)
		mustBePrintable(t, "displayText", got)
		if max > 0 && len(got) > max {
			t.Fatalf("displayText returned %d bytes with a limit of %d", len(got), max)
		}
		// Cutting mid-rune is the corruption the limit was meant to
		// prevent, so a replacement character must never be INTRODUCED.
		if strings.ContainsRune(got, '�') && !strings.ContainsRune(s, '�') {
			t.Fatalf("displayText cut mid-rune: %q", got)
		}
	})
}

// A TRUST SET IS CONFIGURATION, AND CONFIGURATION TRAVELS.
//
// ZPKG_TRUSTED_KEYS is read from the environment or from ~/.zpkg/config.hcl2,
// which is the sort of thing a team ships in a dotfiles repository, a base
// image or a CI snippet. What a signer is NAMED there is then printed in the
// one line a user reads to decide whether to trust an artifact:
//
//	signed by: go-zpkg, alice
//
// A name carrying ERASE-LINE + CR rewrites that line into a stronger claim
// than the one that was true — the same attack displaytext.go documents
// against a project summary, aimed at the verdict instead of a description.
// So the invariant here is the project-NAME one, not the summary one: a name
// that gets past the parser is printable, or there is no Signer.
func FuzzParseSigners(f *testing.F) {
	// A real key, so the seeds reach the name check rather than stopping at
	// the key. (It is the published go-zpkg key; nothing secret is here.)
	const k = "RWQ+rmH+fXy2iYr+gReQAOQtYWtH0A7UlxcAa2hpr+txNBwGqtpFsR6L"
	f.Add("go-zpkg:" + k)
	f.Add(k)
	f.Add("go-zpkg:" + k + "  alice:" + k)
	// ⛔⛔ THE SPOOF SEED TOOK TWO CORRECTIONS TO BECOME ONE. Written as
	// "…signed by: go-zpkg, alice" it failed on the KEY, because its own
	// colon ended the name; rewritten without the colon it was split by
	// strings.Fields at the spaces into six unparseable entries. Either way
	// it went green without ever reaching the check it exists for. An escape
	// sequence needs neither a colon nor a space, which is the version that
	// actually attacks: the line erases itself and reprints.
	f.Add("go-zpkg\x1b[2Kalice:" + k)
	f.Add("ok\x07bell:" + k)
	f.Add("a​b:" + k)
	f.Add(":" + k)
	f.Add("::::" + k)
	f.Add("name-with-no-key:")
	f.Fuzz(func(t *testing.T, list string) {
		signers, err := ParseSigners(list)
		if err != nil {
			return
		}
		if len(signers) > MaxTrustedKeys {
			t.Fatalf("parsed %d keys, over the %d bound", len(signers), MaxTrustedKeys)
		}
		for _, s := range signers {
			if s.Name == "" {
				t.Fatal("a signer with no name would print as an empty verdict")
			}
			mustBePrintable(t, "a signer name", s.Name)
			mustBePrintable(t, "a signer line", s.String())
			if len(s.KeyID()) != 16 {
				t.Fatalf("key id %q is not 8 bytes of hex", s.KeyID())
			}
		}
	})
}

// A MACH-O LOAD COMMAND IS INPUT FROM A STRANGER.
//
// The three targets above all read something fetched as DATA — a catalogue, a
// lock, a summary. This one reads something fetched as a BINARY: the @rpath
// references in a downloaded artifact's load commands. They were never
// validated, and they decide two things that leave the process:
//
//   - the path the closure stats to call a reference "already satisfied"
//     (<dir>/<rel>), so a reference that escapes the store could be satisfied
//     by any file the process can see;
//   - the PROJECT, which becomes a registry repository in FetchVersions and a
//     store path in InstallFor — <dir>/<project>/v<version>, written to.
//
// The property is not "it does not panic". It is that nothing which gets past
// these two can name anything outside the store.
func FuzzMachoRef(f *testing.F) {
	f.Add("@rpath/abseil.io/v20260526.0/lib/libabsl_base.2605.0.0.dylib")
	f.Add("@rpath/gnupg.org/gpgme/abi-libgpgme.11.dylib/lib/libgpgme.11.dylib")
	f.Add("@rpath/libabsl_base.2608.0.0.dylib") // the bare shape, 1266 of 3003
	f.Add("/usr/lib/libSystem.B.dylib")
	f.Add("@rpath/../../../../etc/passwd")
	f.Add("@rpath/../../v1/x")
	f.Add("@rpath//v1/x")
	f.Add("@rpath/a/../../../b/v1/x")
	f.Add("@rpath/" + strings.Repeat("a/", 40) + "v1/x")
	f.Add("@rpath/a\x00b/v1/x")
	f.Fuzz(func(t *testing.T, ref string) {
		if !strings.HasPrefix(ref, "@rpath/") {
			return // the host's; the walk skips it before either check
		}
		rel, inStore := storeRel(ref)
		if inStore {
			// The property is about the JOIN, not about how the string looks.
			//
			// ⛔ The first version of this assertion was
			// `strings.HasPrefix(filepath.Clean(rel), "..")`, and the fuzzer
			// refuted it in 0.16s with `@rpath/..0`: "..0" is an ordinary
			// filename that merely starts with two dots, and joining it stays
			// inside. The hand-rolled re-derivation of IsLocal was wrong where
			// IsLocal was right — so assert what actually matters, which is
			// that <root>/<rel> is still under <root>.
			root := filepath.FromSlash("/store")
			p := filepath.Join(root, rel)
			if p != root && !strings.HasPrefix(p, root+string(filepath.Separator)) {
				t.Fatalf("storeRel accepted %q -> %q, and %q leaves %q", ref, rel, p, root)
			}
		}
		// And the project, which is the half that gets WRITTEN to.
		m := storeRefRE.FindStringSubmatch(ref)
		if m == nil {
			return // named no project directory; no want is built
		}
		if err := ValidateProjectName(m[1]); err != nil {
			return // rejected at the use site, which is the point
		}
		// It passed, so it is safe to use as a store path: the same rule the
		// catalogue is held to.
		p := filepath.Join("/store", filepath.FromSlash(m[1]))
		if !strings.HasPrefix(p, filepath.FromSlash("/store/")) {
			t.Fatalf("%q yielded project %q, which escapes the store: %q", ref, m[1], p)
		}
	})
}

// The concrete hostile inputs, named rather than left to the fuzzer to
// rediscover: a corpus is a record of what was already understood.
func TestMachoRefRejectsWhatLeavesTheStore(t *testing.T) {
	for _, ref := range []string{
		"@rpath/../../../../etc/passwd",
		"@rpath/../x",
		"@rpath/a/../../../../etc/v1/x",
	} {
		if rel, ok := storeRel(ref); ok {
			t.Errorf("storeRel(%q) = %q, true — it escapes the store", ref, rel)
		}
	}
	// A reference that stays inside is still accepted, or the guard would be
	// a refusal of everything, which passes just as quietly.
	rel, ok := storeRel("@rpath/abseil.io/v20260526.0/lib/libabsl_base.2605.0.0.dylib")
	if !ok {
		t.Fatalf("a normal store reference was refused")
	}
	if rel != filepath.FromSlash("abseil.io/v20260526.0/lib/libabsl_base.2605.0.0.dylib") {
		t.Fatalf("storeRel gave %q", rel)
	}
}

// mustBePrintable is the one rule, stated once: no control character, no
// DEL, and none of the three Unicode characters that are not controls by
// category yet can still hide or break a line.
func mustBePrintable(t *testing.T, what, s string) {
	t.Helper()
	for i, r := range s {
		switch {
		case r == 0x7f, unicode.IsControl(r):
			t.Fatalf("%s carries %q at byte %d: %q", what, r, i, s)
		case r == '​', r == ' ', r == ' ':
			t.Fatalf("%s carries %q at byte %d: %q", what, r, i, s)
		}
	}
}
