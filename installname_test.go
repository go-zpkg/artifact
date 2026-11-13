package artifact

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// ⛔ InstallFor BUILDS A PATH IT WRITES TO FROM r.Project, and was safe only
// by the ORDER of two unrelated checks.
//
// fetchArtifact goes through OCIClient.repository, which validates the name, so
// a `..` failed at the fetch. But the os.Stat that decides "already present"
// runs BEFORE that fetch. For a project of `../..` naming a directory that
// exists, InstallFor returned (false, nil) — which its own contract reads as
// "the artifact is already installed". The caller is told the work is done,
// nothing was installed, and the evidence was a directory outside the store.
//
// Resolved is an exported struct with exported fields: a caller can fill it
// without going through a resolver or a catalogue, both of which validate.
func TestInstallForRefusesAProjectThatIsNotAName(t *testing.T) {
	store := t.TempDir()

	// ⛔ THE WITNESS HAS TO MAKE THE STAT SUCCEED, and my first version of
	// this test did not.
	//
	// With the guard removed, a bare `..` still came back with
	// ErrBadProjectName — because the fetch it fell through to validates the
	// name too, and returns the SAME sentinel. The test passed with the
	// check deleted: it could not tell "guarded here" from "guarded four
	// calls later", which is the only thing this guard changes.
	//
	// So the traversed prefix is created IN FULL, `<outside>/v1.0`, so that
	// os.Stat succeeds and the unguarded function returns (false, nil) —
	// "already present" — before any fetch can object.
	outside := filepath.Join(store, "..", "installfor-probe")
	if err := os.MkdirAll(filepath.Join(outside, "v1.0"), 0o755); err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(outside)

	r := Resolved{Project: "../installfor-probe", Version: ParseVer("1.0")}
	installed, err := InstallFor(r, store, "linux", "x86-64")
	if err == nil {
		t.Fatalf("InstallFor returned (%v, nil): a directory OUTSIDE the store was read as an installed artifact", installed)
	}
	if !errors.Is(err, ErrBadProjectName) {
		t.Errorf("failed with %v, want ErrBadProjectName", err)
	}
	if installed {
		t.Errorf("reported an install it did not do")
	}

	// The other unusable shapes, where any refusal will do: they cannot
	// reach the stat at all, so they only confirm the name is checked and
	// not that it is checked HERE.
	for _, project := range []string{"../../etc", "/absolute", "", "has space"} {
		if _, err := InstallFor(Resolved{Project: project, Version: ParseVer("1.0")}, store, "linux", "x86-64"); err == nil {
			t.Errorf("InstallFor(%q) was accepted", project)
		}
	}
}

// The control: an ordinary name still reaches the "already present" answer,
// so the guard has not simply refused everything — which would pass the test
// above just as quietly.
func TestInstallForStillSeesAnInstalledArtifact(t *testing.T) {
	store := t.TempDir()
	if err := os.MkdirAll(filepath.Join(store, "openssl.org", "v3.5.0"), 0o755); err != nil {
		t.Fatal(err)
	}
	installed, err := InstallFor(
		Resolved{Project: "openssl.org", Version: ParseVer("3.5.0")},
		store, "linux", "x86-64")
	if err != nil {
		t.Fatalf("an ordinary name was refused: %v", err)
	}
	if installed {
		t.Fatalf("want false for an artifact already in the store, got true")
	}
}
