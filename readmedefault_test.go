package bottle

import (
	"os"
	"strings"
	"testing"
)

// ⛔⛔ A STATED DEFAULT MUST BE THE DEFAULT, AND THIS IS THE THIRD PLACE THE
// SAME SENTENCE WAS WRONG.
//
// The README said `ZPKG_DIST` defaults to `oci://ghcr.io/go-zpkg/packages`
// while DistBase has always been `oci://ghcr.io/go-pkgx/packages`. The
// go-pkgx → go-zpkg rename rewrote the prose and could not rewrite the
// constant, because the constant is a deployment fact: GitHub's container
// packages are org-scoped and did not follow the repository transfer, so
// every bottle stayed where it was.
//
// zpkgx's two usage strings had exactly this defect and are now gated there
// (TestEveryHelpTextNamesTheRealRegistryDefault). The README was not, and on
// 2026-11-07 it cost a reading: a stale `zpkgs` binary printed the wrong
// default, the claim looked corroborated by this README, and half an hour
// went into "the clients already point at the new org" before the constant
// settled it. A reader who follows the stated default points ZPKG_DIST at a
// registry holding none of the bottles and reads the 403 as a permissions
// problem.
//
// A repeated lesson becomes a gate. This does not say which value is right;
// it says the README and the constant cannot differ.
//
// ⛔ IT READS DefaultDistBase, NOT DistBase. DistBase is a var other tests in
// this package reassign to an httptest URL; the first version of this gate
// compared against it, passed under `-run TestTheReadme`, and failed in the
// full suite with `the README does not name the real default
// "http://127.0.0.1:55863"`. A gate that reads mutable global state tests the
// order the suite happened to run in.
func TestTheReadmeNamesTheRealRegistryDefault(t *testing.T) {
	body, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	readme := string(body)

	if DefaultDistBase == "" {
		t.Fatal("DefaultDistBase is empty: this test would then pass against any README at all")
	}
	if !strings.Contains(readme, "ZPKG_DIST") {
		t.Fatal("the README does not mention ZPKG_DIST at all — if that is deliberate, " +
			"this test should go with it rather than pass vacuously")
	}
	if !strings.Contains(readme, DefaultDistBase) {
		t.Errorf("the README does not name the real default %q — a reader who follows "+
			"what it says points ZPKG_DIST at a registry this binary does not use",
			DefaultDistBase)
	}
}

// ⛔ AND IT MUST NOT NAME THE OTHER ONE AS IF IT WERE THE DEFAULT. The stale
// value is a perfectly good-looking URL, so a reader cannot tell it apart;
// naming it here is what makes the next rename stop.
func TestTheReadmeDoesNotNameTheEmptyRegistry(t *testing.T) {
	const empty = "oci://ghcr.io/go-zpkg/packages"
	if strings.Contains(DefaultDistBase, "go-zpkg/packages") {
		t.Skip("the default now points there, so the bottles moved and this check is obsolete")
	}
	body, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), empty) {
		t.Errorf("the README names %s, which is not where the published bottles are "+
			"(the default is %q)", empty, DefaultDistBase)
	}
}
