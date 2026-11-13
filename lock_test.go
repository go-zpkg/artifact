package artifact

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func sampleLock() Lock {
	return Lock{
		Version:   LockfileVersion,
		Platform:  "linux/x86-64",
		Generated: "2026-10-06T09:00:00Z",
		ZPKB:       "v0.12.0",
		Roots:     []string{"curl.se", "gnu.org/bash"},
		Pantry:    "2df061bd",
		Overlay:   "a1b2c3d4",
		Pins: []LockPin{
			{"curl.se", "8.17.0", "sha256:aaa"},
			{"gnu.org/bash", "5.3.0", "sha256:bbb"},
			{"zlib.net", "1.3.2", "sha256:ccc"},
		},
	}
}

// ⛔⛔ A LOCK FROM EVERY ERA STILL SAYS WHAT WROTE IT, ONE CASE PER SPELLING.
// This key has been `bk`, then `zbk`, now `zpkb`. The previous decision was to
// read only the current one, which made every lock from a previous era come
// back as though nothing had written it — and no test noticed, because the
// round trip only ever writes and reads the CURRENT spelling, so it is green
// by construction whatever the reader does with the older ones.
//
// The literals are deliberate: a constant here could be renamed in sympathy
// with lockWriterKeys during a tidy-up, and then this would assert nothing.
func TestALockFromAnyEraNamesItsWriter(t *testing.T) {
	for _, c := range []struct{ key, era string }{
		{"zpkb", "current"},
		{"zbk", "retired by zbk -> zpkb"},
		{"bk", "retired at the brewkit break"},
	} {
		// A `locked` block is required: ReadLock refuses a file without one
		// rather than returning an empty lock, which is the right refusal and
		// which my first fixture tripped over.
		body := "lockfile_version = 1\n" + c.key + " = \"v9.9.9\"\n" +
			"platform = \"linux/x86-64\"\ngenerated = \"2026-10-06T09:00:00Z\"\n" +
			"\nlocked = {\n  \"zlib.net\" = { version = \"1.3.2\", spec = \"sha256:ccc\" }\n}\n"
		p := filepath.Join(t.TempDir(), "x.lock.hcl")
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		got, err := ReadLock(p)
		if err != nil {
			t.Fatalf("%s: ReadLock: %v", c.key, err)
		}
		if got.ZPKB != "v9.9.9" {
			t.Errorf("a lock whose writer key is %q (%s) came back with ZPKB=%q: "+
				"the field exists to say what wrote the lock", c.key, c.era, got.ZPKB)
		}
	}
}

// The reason the format moved here: it has TWO ends, and they were in
// different repositories with the reader unreachable from one of them.
// A round trip is the thing that has to keep working.
func TestALockRoundTrips(t *testing.T) {
	want := sampleLock()
	p := filepath.Join(t.TempDir(), "seed.lock.hcl")
	if err := os.WriteFile(p, []byte(RenderLock(want)), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := ReadLock(p)
	if err != nil {
		t.Fatalf("ReadLock: %v", err)
	}
	if got.Version != want.Version || got.Platform != want.Platform ||
		got.Generated != want.Generated || got.ZPKB != want.ZPKB ||
		got.Pantry != want.Pantry || got.Overlay != want.Overlay {
		t.Errorf("header lost fields:\n got %+v\nwant %+v", got, want)
	}
	if strings.Join(got.Roots, " ") != strings.Join(want.Roots, " ") {
		t.Errorf("roots = %v", got.Roots)
	}
	if len(got.Pins) != len(want.Pins) {
		t.Fatalf("%d pins, want %d", len(got.Pins), len(want.Pins))
	}
	for i := range want.Pins {
		if got.Pins[i] != want.Pins[i] {
			t.Errorf("pin %d = %+v, want %+v", i, got.Pins[i], want.Pins[i])
		}
	}
	// SORTED, and stable: a lock is read as a diff, and `locked` comes back
	// out of a map whose order is different every time.
	for i := 0; i < 20; i++ {
		again, err := ReadLock(p)
		if err != nil {
			t.Fatal(err)
		}
		for j := range again.Pins {
			if again.Pins[j] != got.Pins[j] {
				t.Fatalf("run %d: pin %d moved to %+v", i, j, again.Pins[j])
			}
		}
	}
}

// A file with nothing in its `locked` block is not an empty lock. Accepting
// it would let a caller read "nothing moved" off a file that says nothing.
func TestALockWithNothingLockedIsRefused(t *testing.T) {
	for name, src := range map[string]string{
		"no locked block": "lockfile_version = 1\nplatform = \"linux/x86-64\"\n",
		"empty block":     "lockfile_version = 1\nlocked = {}\n",
		"a pin that is not an entry": "lockfile_version = 1\n" +
			"locked = {\n  \"curl.se\" = \"8.17.0\"\n}\n",
	} {
		if _, err := ParseLock([]byte(src), name); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// New readers read old locks; old readers REFUSE new ones. Spack's rule,
// and the reason lockfile_version is in the file rather than inferred.
func TestANewerLockfileVersionIsRefused(t *testing.T) {
	d := sampleLock()
	d.Version = LockfileVersion + 1
	_, err := ParseLock([]byte(RenderLock(d)), "future.lock.hcl")
	if err == nil {
		t.Fatal("a lock from the future was read as if understood")
	}
	if !strings.Contains(err.Error(), "lockfile_version") {
		t.Errorf("the refusal does not say why: %v", err)
	}
	// And an OLDER one is read, which is the other half of the rule and
	// the half a test could easily leave out.
	d.Version = 1
	if _, err := ParseLock([]byte(RenderLock(d)), "old.lock.hcl"); err != nil {
		t.Errorf("an older lock was refused: %v", err)
	}
}

// THE VERSION IS READ BEFORE THE CONTENTS, which is the whole point of
// having one: it says "stop, you cannot interpret what follows" before this
// build interprets it by its own rules.
//
// Checked last, as it was, a lock from a newer bk was first judged against
// THIS build's expectations. A v2 that renamed or restructured `locked`
// therefore came back as "this is not a lock" — false, and it sends the
// reader hunting for a corrupt file instead of for a newer binary.
//
// The file below is exactly that case: a future version whose body this
// build cannot make sense of. Both complaints are available; only one is
// true.
func TestAFutureVersionIsNamedBeforeItsBodyIsJudged(t *testing.T) {
	src := fmt.Sprintf("lockfile_version = %d\nplatform = \"linux/x86-64\"\npins = { \"a.org\" = \"1.0\" }\n", LockfileVersion+1)
	_, err := ParseLock([]byte(src), "future.lock.hcl")
	if err == nil {
		t.Fatal("a lock from the future was read as if understood")
	}
	if !strings.Contains(err.Error(), "lockfile_version") {
		t.Errorf("the refusal does not name the version: %v", err)
	}
	if strings.Contains(err.Error(), "not a lock") {
		t.Errorf("a lock from the future was called malformed: %v", err)
	}
}

// A field of the wrong type reads as its zero rather than killing the file:
// a comparison then says so by name, where refusing the whole lock over one
// line tells the reader nothing about which line.
func TestAWrongTypeIsNotFatal(t *testing.T) {
	src := "lockfile_version = 1\nplatform = 42\nroots = \"not-a-list\"\n" +
		"locked = {\n  \"curl.se\" = { version = \"8.17.0\", spec = \"sha256:a\" }\n}\n"
	d, err := ParseLock([]byte(src), "odd.lock.hcl")
	if err != nil {
		t.Fatalf("one odd field killed the file: %v", err)
	}
	if d.Platform != "" || len(d.Roots) != 0 {
		t.Errorf("a wrong type was not read as its zero: %+v", d)
	}
	if len(d.Pins) != 1 {
		t.Errorf("the pins were lost with it: %+v", d.Pins)
	}
}

func TestReadLockOnAnAbsentFile(t *testing.T) {
	if _, err := ReadLock(filepath.Join(t.TempDir(), "nope.hcl")); err == nil {
		t.Error("an absent lock read as a lock")
	}
}

func TestLockAge(t *testing.T) {
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	for in, want := range map[string]string{
		"2026-10-06T11:30:00Z": "30 minute(s) old",
		"2026-10-06T06:00:00Z": "6 hour(s) old",
		"2026-10-01T12:00:00Z": "5 day(s) old",
		"not a time":           "unknown age",
	} {
		if got := LockAge(in, now); got != want {
			t.Errorf("LockAge(%q) = %q, want %q", in, got, want)
		}
	}
}
