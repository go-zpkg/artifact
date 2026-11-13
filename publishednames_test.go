package artifact

import "testing"

// distBaseAtInit is the COMPILED-IN default, captured before any test runs.
// DistBase is a var that a dozen tests point at a fake registry, so reading
// it inside a test case would be reading whichever one ran last — a pin that
// depends on test order is not a pin. Go initialises this after DistBase
// itself, because it depends on it.
var distBaseAtInit = DistBase

// ⛔⛔ A CONSTANT THAT ADDRESSES A PUBLISHED ARTEFACT IS PINNED HERE, AND THIS
// FILE IS THE GATE THAT MAKES A RENAME STOP AND LOOK.
//
// Twice now a repository-wide rename has rewritten one of these and moved
// nothing:
//
//	DistBase            go-pkgx/packages → go-zpkg/packages        (#192)
//	                    five releases pointed the fleet at an empty registry
//	CatalogProjectName  go-pkgx.dev/catalog → go-zpkg.github.io/…  (#192)
//	                    every `catalog update` on defaults failed since
//
// Both were found from the outside, long after release, because nothing in
// the repository could tell the difference between "renamed" and "broken":
// the code compiled, every unit test passed, and the value was wrong.
//
// So the values are written down twice — once where they are used, once here
// — and the second copy carries the reason. A rename pass that rewrites the
// first and not the second fails this test with the paragraph below in front
// of it. That is the whole mechanism, and it is deliberately not clever: the
// point is that the value cannot change SILENTLY, not that this file knows
// which value is right.
//
// To change one for real: copy the artefact first, verify it anonymously
// (`ghcrprobe -ns <org>/<repo> <project> <a-known-present-control>`), then
// change both copies in the same commit and say in the message what the probe
// returned.
func TestANameThatAddressesSomethingPublishedCannotChangeSilently(t *testing.T) {
	for _, tc := range []struct{ what, got, want string }{
		{
			"CatalogProjectName",
			CatalogProjectName,
			// Probed PRESENT 2026-11-04 in ghcr.io/go-pkgx/packages, against
			// gnu.org/bash as a positive control.
			"go-pkgx.dev/catalog",
		},
		{
			"DistBase",
			distBaseAtInit,
			// The org here is a DEPLOYMENT FACT and not our name: GitHub's
			// container packages are org-scoped and did not follow the
			// repository transfer, so every artifact is still here.
			"oci://ghcr.io/go-pkgx/packages",
		},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %q, pinned at %q.\n"+
				"If the artefact really moved: copy it, probe the new name "+
				"anonymously against a known-present control, then change the "+
				"constant AND this pin in one commit, with the probe output in "+
				"the message. If it did not move, this is a rename that "+
				"rewrote an address — the second time, see the comment above.",
				tc.what, tc.got, tc.want)
		}
	}
}

// ⛔ AND THE PIN HAS TO BE ABLE TO FAIL. A test comparing a constant to itself
// passes forever; this one checks that the two values above are genuinely
// different strings from each other, so a copy-paste that pinned one name
// twice shows up rather than reading as two independent pins.
func TestThePinsAreTwoDistinctValues(t *testing.T) {
	if CatalogProjectName == distBaseAtInit {
		t.Fatal("the two pinned names are the same string — one of them was pasted over the other")
	}
}
