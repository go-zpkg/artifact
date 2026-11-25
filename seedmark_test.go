package artifact

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-attest/sign"
)

var markFixtureResolved = Resolved{Project: "f.test", Version: ParseVer("1.0.0")}

const markFixturePayload = "f.test/v1.0.0/bin/f"

func seededInstall(t *testing.T) string {
	t.Helper()
	resetSeedState(t)
	reg := newFakeRegistry(t, false)
	seedBase := reg.base("go-pkgx/packages")
	pinSeed(seedBase)
	kp, err := sign.Generate()
	if err != nil {
		t.Fatal(err)
	}
	oldKey := SigningPublicKey
	SigningPublicKey = kp.PublicKeyString()
	t.Cleanup(func() { SigningPublicKey = oldKey; SetSeedLedgerFile("") })
	c, err := NewOCIClient(seedBase)
	if err != nil {
		t.Fatal(err)
	}
	pushSignedArtifact(t, c, "f.test", kp, makeGzTarballAt(markFixturePayload, "x"), true)
	SetSeedLedgerFile(filepath.Join(t.TempDir(), "ledger.jsonl"))
	store := t.TempDir()
	err = WithSeedSource(seedBase, func() error {
		_, err := InstallFor(markFixtureResolved, store, "linux", "x86-64")
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	p, ok := ResolveBuild(store, "f.test", markFixtureResolved.Version)
	if !ok {
		t.Fatalf("no build of f.test under %s", store)
	}
	return p
}

func ordinaryInstall(t *testing.T) string {
	t.Helper()
	resetSeedState(t)
	reg := newFakeRegistry(t, false)
	base := reg.base("go-zpkg/artifacts")
	old := DistBase
	DistBase = base
	resetOCICache()
	t.Setenv("ZPKG_VERIFY", "0")
	t.Cleanup(func() { DistBase = old; resetOCICache() })
	c, err := NewOCIClient(base)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.PushWithReferrers("f.test", "1.0.0", "linux", "x86-64",
		makeGzTarballAt(markFixturePayload, "x"), ".tar.gz", nil); err != nil {
		t.Fatal(err)
	}
	store := t.TempDir()
	if _, err := InstallFor(markFixtureResolved, store, "linux", "x86-64"); err != nil {
		t.Fatal(err)
	}
	p, ok := ResolveBuild(store, "f.test", markFixtureResolved.Version)
	if !ok {
		t.Fatalf("no build of f.test under %s", store)
	}
	return p
}

// A prefix installed from the seed carries a marker written by the installer;
// one installed any other way does not.
func TestASeedInstalledPrefixIsMarked(t *testing.T) {
	p := seededInstall(t)
	digest, seeded, err := IsSeedPrefix(p)
	if err != nil || !seeded || !strings.HasPrefix(digest, "sha256:") {
		t.Fatalf("IsSeedPrefix(%s) = %q %v %v, want a seeded prefix with its digest", p, digest, seeded, err)
	}
}

func TestAnOrdinaryInstallIsNotMarked(t *testing.T) {
	p := ordinaryInstall(t)
	if _, seeded, err := IsSeedPrefix(p); err != nil || seeded {
		t.Fatalf("IsSeedPrefix(%s) = %v %v, want unmarked", p, seeded, err)
	}
}

// A marker that is not the regular file the installer writes still reads as
// seeded: the question is whether the prefix may be believed unseeded.
func TestAMarkerThatIsNotARegularFileStillCountsAsSeeded(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, SeedMarkerName), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, seeded, err := IsSeedPrefix(dir); err != nil || !seeded {
		t.Fatalf("a directory named like the marker: seeded=%v err=%v", seeded, err)
	}
	dir2 := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir2, SeedMarkerName), []byte(strings.Repeat("x", 1000)), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, seeded, _ := IsSeedPrefix(dir2); !seeded {
		t.Fatal("an oversized marker must still read as seeded")
	}
}

// A marker that cannot be written or read is an error, never a quiet "not seeded".
func TestAMarkerThatCannotBeWrittenOrReadIsAnError(t *testing.T) {
	if err := markSeedPrefix(filepath.Join(t.TempDir(), "absent"), "sha256:00"); err == nil {
		t.Error("writing a marker into a prefix that is not there succeeded")
	}
	file := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, seeded, err := IsSeedPrefix(file); err == nil || seeded {
		t.Errorf("a prefix that is a file: seeded=%v err=%v, want an error", seeded, err)
	}
	dir := t.TempDir()
	m := filepath.Join(dir, SeedMarkerName)
	if err := os.WriteFile(m, []byte("sha256:00\n"), 0o000); err != nil {
		t.Fatal(err)
	}
	if f, err := os.Open(m); err == nil {
		f.Close()
		t.Skip("the marker is readable anyway (running as root)")
	}
	if _, seeded, err := IsSeedPrefix(dir); err == nil || seeded {
		t.Errorf("an unreadable marker: seeded=%v err=%v, want an error", seeded, err)
	}
}

// An artifact that cannot take the marker is not installed under the seed:
// here the marker's own name is a directory inside it.
func TestASeedInstallThatCannotBeMarkedFails(t *testing.T) {
	resetSeedState(t)
	reg := newFakeRegistry(t, false)
	seedBase := reg.base("go-pkgx/packages")
	pinSeed(seedBase)
	kp, err := sign.Generate()
	if err != nil {
		t.Fatal(err)
	}
	oldKey := SigningPublicKey
	SigningPublicKey = kp.PublicKeyString()
	t.Cleanup(func() { SigningPublicKey = oldKey; SetSeedLedgerFile("") })
	c, err := NewOCIClient(seedBase)
	if err != nil {
		t.Fatal(err)
	}
	pushSignedArtifact(t, c, "f.test", kp, makeGzTarballAt("f.test/v1.0.0/"+SeedMarkerName+"/x", "x"), true)
	SetSeedLedgerFile(filepath.Join(t.TempDir(), "ledger.jsonl"))
	store := t.TempDir()
	err = WithSeedSource(seedBase, func() error {
		_, err := InstallFor(markFixtureResolved, store, "linux", "x86-64")
		return err
	})
	if err == nil {
		t.Fatal("a seed install whose prefix cannot take the marker succeeded")
	}
	if _, ok := ResolveBuild(store, "f.test", markFixtureResolved.Version); ok {
		t.Fatal("the unmarked prefix was left in the store")
	}
}
