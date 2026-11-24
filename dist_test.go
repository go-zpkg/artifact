package artifact

import (
	"bytes"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/go-attest/sign"
)

func TestSplitDistList(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"   ,, ", nil},
		{"oci://a/b", []string{"oci://a/b"}},
		{"oci://a/b/", []string{"oci://a/b"}},
		{"oci://a/b oci://c/d", []string{"oci://a/b", "oci://c/d"}},
		{"oci://a/b,oci://c/d", []string{"oci://a/b", "oci://c/d"}},
		{"oci://a/b,\n\toci://c/d  oci://e/f/", []string{"oci://a/b", "oci://c/d", "oci://e/f"}},
		{"oci://a/b oci://c/d oci://a/b", []string{"oci://a/b", "oci://c/d"}},
	} {
		got := SplitDistList(tc.in)
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("SplitDistList(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestApplyEnvTakesAnOrderedList(t *testing.T) {
	oldB, oldX := DistBase, DistExtra
	t.Cleanup(func() { DistBase, DistExtra = oldB, oldX })

	env := func(v string) func(string) string {
		return func(k string) string {
			if k == "ZPKG_DIST" {
				return v
			}
			return ""
		}
	}
	applyEnv(env("oci://run/stage, oci://ghcr.io/go-zpkg/packages"))
	if DistBase != "oci://run/stage" || !reflect.DeepEqual(DistExtra, []string{"oci://ghcr.io/go-zpkg/packages"}) {
		t.Fatalf("list form: DistBase=%q DistExtra=%q", DistBase, DistExtra)
	}
	// The single-value form still works, and drops the previous extras.
	applyEnv(env("oci://only/one/"))
	if DistBase != "oci://only/one" || len(DistExtra) != 0 {
		t.Fatalf("single form: DistBase=%q DistExtra=%q", DistBase, DistExtra)
	}
}

func TestTheDefaultIsGoZpkgAndNotGoPkgx(t *testing.T) {
	if DefaultDistBase != "oci://ghcr.io/go-zpkg/packages" {
		t.Fatalf("DefaultDistBase = %q", DefaultDistBase)
	}
	if err := CheckDistSource(DefaultDistBase); err != nil {
		t.Fatalf("the default is refused by its own rule: %v", err)
	}
}

func TestGoPkgxIsRefusedWhateverTheSpelling(t *testing.T) {
	for _, bad := range []string{
		"oci://ghcr.io/go-pkgx/packages",
		"oci://ghcr.io/Go-PKGX/packages",
		"oci://ghcr.io/go-pkgx",
		"oci://10.0.0.1:5111/go-pkgx/packages/",
		"https://example.com/mirror/go-pkgx/packages",
		"oci://ghcr.io/go%2Dpkgx/packages",
		"ghcr.io/go-pkgx/packages",
	} {
		err := CheckDistSource(bad)
		if err == nil {
			t.Errorf("%q was accepted", bad)
			continue
		}
		if !errors.Is(err, ErrClosedDistRegistry) || !strings.Contains(err.Error(), "go-pkgx") {
			t.Errorf("%q: the refusal does not name the rule: %v", bad, err)
		}
	}
	for _, ok := range []string{
		"oci://ghcr.io/go-zpkg/packages",
		"oci://http://10.46.81.1:5111/s6clevis-lan/packages",
		"https://dist.pkgx.dev",
		"oci://go-pkgx.example.com/packages", // a HOST is not a repository path
		"oci://ghcr.io/go-pkgxtra/packages",  // a component must EQUAL go-pkgx
	} {
		if err := CheckDistSource(ok); err != nil {
			t.Errorf("%q was refused: %v", ok, err)
		}
	}
}

func TestEveryResolutionPathRefusesGoPkgx(t *testing.T) {
	oldB, oldX := DistBase, DistExtra
	t.Cleanup(func() { DistBase, DistExtra = oldB, oldX; resetOCICache() })
	r := Resolved{Project: "a.test", Version: ParseVer("1.0.0")}

	for name, set := range map[string]func(){
		"as the only source": func() { DistBase, DistExtra = "oci://ghcr.io/go-pkgx/packages", nil },
		"as the first source": func() {
			DistBase, DistExtra = "oci://ghcr.io/go-pkgx/packages", []string{"oci://ghcr.io/go-zpkg/packages"}
		},
		"as a fallback source": func() {
			DistBase, DistExtra = "oci://ghcr.io/go-zpkg/packages", []string{"oci://ghcr.io/go-pkgx/packages"}
		},
		"as the extra of three": func() { DistBase, DistExtra = "oci://a/b", []string{"oci://c/d", "oci://ghcr.io/go-pkgx/packages"} },
	} {
		set()
		if _, _, err := versionsForSourced("a.test", "linux", "x86-64"); !errors.Is(err, ErrClosedDistRegistry) {
			t.Errorf("%s: versionsForSourced: %v", name, err)
		}
		if _, _, _, err := fetchArtifact(r, "linux", "x86-64"); !errors.Is(err, ErrClosedDistRegistry) {
			t.Errorf("%s: fetchArtifact: %v", name, err)
		}
		if _, _, err := DownloadArtifact("a.test", "1.0.0", "linux", "x86-64"); !errors.Is(err, ErrClosedDistRegistry) {
			t.Errorf("%s: DownloadArtifact: %v", name, err)
		}
		if _, _, err := publishedTagFor("a.test", ParseVer("1.0.0"), "linux", "x86-64"); !errors.Is(err, ErrClosedDistRegistry) {
			t.Errorf("%s: publishedTagFor: %v", name, err)
		}
		if err := ValidateDist(); !errors.Is(err, ErrClosedDistRegistry) {
			t.Errorf("%s: ValidateDist: %v", name, err)
		}
		if name == "as the only source" || name == "as the first source" {
			if c, err := ociClientForDist(); !errors.Is(err, ErrClosedDistRegistry) || c != nil {
				t.Errorf("%s: ociClientForDist: %v, %v", name, c, err)
			}
		}
	}
}

// twoSources builds one fake host serving two namespaces: "run/packages" (the
// run's staging registry, listed first) and "go-zpkg/packages".
func twoSources(t *testing.T) (stage, zpkg *OCIClient, kp *sign.Keypair) {
	t.Helper()
	stage, zpkg, kp, _ = twoSourcesFR(t)
	return stage, zpkg, kp
}

// twoSourcesFR is twoSources that also hands back the fake registry, for a
// test that injects a fault into one of the namespaces.
func twoSourcesFR(t *testing.T) (stage, zpkg *OCIClient, kp *sign.Keypair, fr *fakeRegistry) {
	t.Helper()
	fr = newFakeRegistry(t, false)
	t.Cleanup(fr.close)
	var err error
	if stage, err = NewOCIClient(fr.base("run/packages")); err != nil {
		t.Fatal(err)
	}
	if zpkg, err = NewOCIClient(fr.base("go-zpkg/packages")); err != nil {
		t.Fatal(err)
	}
	if kp, err = sign.Generate(); err != nil {
		t.Fatal(err)
	}
	oldK, oldB, oldX := SigningPublicKey, DistBase, DistExtra
	SigningPublicKey = kp.PublicKeyString()
	DistBase, DistExtra = fr.base("run/packages"), []string{fr.base("go-zpkg/packages")}
	resetOCICache()
	t.Cleanup(func() {
		SigningPublicKey, DistBase, DistExtra = oldK, oldB, oldX
		resetOCICache()
	})
	return stage, zpkg, kp, fr
}

func readArtifact(t *testing.T, project string) ([]byte, error) {
	t.Helper()
	f, _, _, err := fetchArtifact(Resolved{Project: project, Version: ParseVer("1.0.0")}, "linux", "x86-64")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

func TestAnInRunArtifactAndAPublishedOneBothResolve(t *testing.T) {
	stage, zpkg, kp := twoSources(t)
	inRun, published := makeGzTarball("in-run"), makeGzTarball("published")
	pushSignedArtifact(t, stage, "inrun.test", kp, inRun, true)
	pushSignedArtifact(t, zpkg, "published.test", kp, published, true)

	// Versions: each project is found in whichever source carries it, the other
	// source answering "unknown repository" without failing the walk.
	for _, p := range []string{"inrun.test", "published.test"} {
		vs, fromRegistry, err := versionsForSourced(p, "linux", "x86-64")
		if err != nil || len(vs) != 1 || vs[0].Raw != "1.0.0" || !fromRegistry {
			t.Errorf("%s: vs=%v registry=%v err=%v", p, vs, fromRegistry, err)
		}
		if tag, ok, err := publishedTagFor(p, ParseVer("1.0.0"), "linux", "x86-64"); err != nil || !ok || tag != "1.0.0" {
			t.Errorf("%s: publishedTagFor = %q %v %v", p, tag, ok, err)
		}
	}
	// Install falls through the first source (which lacks it) to the second.
	if got, err := readArtifact(t, "published.test"); err != nil || !bytes.Equal(got, published) {
		t.Errorf("published.test not taken from the second source: err=%v", err)
	}
	if got, err := readArtifact(t, "inrun.test"); err != nil || !bytes.Equal(got, inRun) {
		t.Errorf("inrun.test not taken from the first source: err=%v", err)
	}
	if data, _, err := DownloadArtifact("published.test", "1.0.0", "linux", "x86-64"); err != nil || !bytes.Equal(data, published) {
		t.Errorf("DownloadArtifact did not fall through: err=%v", err)
	}
	// Nothing carries this one: an error that names every source.
	if _, _, err := versionsForSourced("nowhere.test", "linux", "x86-64"); err == nil {
		t.Error("a project in no source resolved")
	}
}

func TestTheFirstSourceWinsWhenBothHaveIt(t *testing.T) {
	stage, zpkg, kp := twoSources(t)
	first, second := makeGzTarball("first"), makeGzTarball("second")
	pushSignedArtifact(t, stage, "both.test", kp, first, true)
	pushSignedArtifact(t, zpkg, "both.test", kp, second, true)

	if got, err := readArtifact(t, "both.test"); err != nil || !bytes.Equal(got, first) {
		t.Fatalf("the later source answered, or failed: err=%v", err)
	}
	// Swap the order and the other one wins: the order IS the contract.
	DistBase, DistExtra = DistExtra[0], []string{DistBase}
	resetOCICache()
	if got, err := readArtifact(t, "both.test"); err != nil || !bytes.Equal(got, second) {
		t.Fatalf("order not honoured after swap: err=%v", err)
	}
}

func TestEachSourceIsVerifiedOnItsOwn(t *testing.T) {
	stage, zpkg, kp := twoSources(t)
	// The first source holds an UNSIGNED copy; the second a signed one. The
	// unsigned one must not be installed, and the walk goes on to the signed.
	pushSignedArtifact(t, stage, "v.test", kp, makeGzTarball("unsigned"), false)
	signed := makeGzTarball("signed")
	pushSignedArtifact(t, zpkg, "v.test", kp, signed, true)

	got, err := readArtifact(t, "v.test")
	if err != nil || !bytes.Equal(got, signed) {
		t.Fatalf("expected the verified copy from the second source, err=%v", err)
	}
	// And when only an unsigned copy exists the install is refused.
	pushSignedArtifact(t, stage, "only-unsigned.test", kp, makeGzTarball("x"), false)
	if _, err := readArtifact(t, "only-unsigned.test"); err == nil {
		t.Fatal("an unsigned artifact was installed")
	}
}
