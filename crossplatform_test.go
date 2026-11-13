package artifact

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// crossPantry serves a pantry + dist for ONE explicit platform slug, so a test
// can resolve for a platform that is not the host's. fakeServer answers only
// under HostSlug(), which is exactly the assumption these functions exist to
// break.
//
// versions maps "<project>/<os>/<arch>" to the published version list, so the
// same project can exist on one platform and be absent on another.
func crossPantry(t *testing.T, recipes map[string]string, versions map[string][]string) func() {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/")
		if proj, ok := strings.CutSuffix(p, "/package.yml"); ok {
			y, ok := recipes[proj]
			if !ok {
				http.NotFound(w, r)
				return
			}
			fmt.Fprint(w, y)
			return
		}
		if key, ok := strings.CutSuffix(p, "/versions.txt"); ok {
			vs, ok := versions[key]
			if !ok {
				http.NotFound(w, r)
				return
			}
			fmt.Fprint(w, strings.Join(vs, "\n"))
			return
		}
		http.NotFound(w, r)
	}))
	// PantryOverlay too, and it is not decoration. It defaults to the LIVE
	// go-zpkg/pantry-overlay, so a test that pinned only PantryBase was
	// reaching the network on every recipe it read — and passing because the
	// real host answers 404 for an invented project. On wasm, where DNS fails
	// with a connection reset rather than a 404, the same tests failed the
	// moment resolution stopped treating a transport failure as an absence.
	//
	// The comment on the helper in pkgx_test.go already said it: a test must
	// not depend on another repository's contents, nor on the network being
	// there. This one simply did not do it.
	oldPantry, oldUp, oldOver := PantryBase, UpstreamDist, PantryOverlay
	PantryBase, UpstreamDist, PantryOverlay = srv.URL, srv.URL, ""
	withDist(t, srv.URL)
	return func() {
		PantryBase, UpstreamDist, PantryOverlay = oldPantry, oldUp, oldOver
		srv.Close()
	}
}

// otherPlatform returns a pkgx slug that is NOT the host's, so a test can
// prove a lookup used the slug it was GIVEN. Hardcoding "linux/x86-64" as
// "the other platform" passes on a Mac and evaporates on a linux CI runner,
// where it IS the host — the assertion disappears exactly where it is
// cheapest to run.
func otherPlatform() (string, string) {
	osn, arch := HostSlug()
	if osn == "linux" {
		return "darwin", arch
	}
	return "linux", arch
}

// TestPickVersionForOtherPlatform: a project can be published for one platform
// and absent from another. Resolving through the host's slug would either miss
// the version or pick a different one.
func TestPickVersionForOtherPlatform(t *testing.T) {
	hostOS, hostArch := HostSlug()
	tgtOS, tgtArch := otherPlatform()
	defer crossPantry(t,
		map[string]string{"x.org/tool": "provides:\n  - bin/tool\n"},
		map[string][]string{
			"x.org/tool/" + tgtOS + "/" + tgtArch: {"1.0.0", "2.4.0"},
			// nothing under the host slug on purpose
		})()

	v, err := PickVersionFor("x.org/tool", "*", tgtOS, tgtArch)
	if err != nil {
		t.Fatalf("PickVersionFor(%s/%s): %v", tgtOS, tgtArch, err)
	}
	if v.Raw != "2.4.0" {
		t.Errorf("picked %q, want the highest published version 2.4.0", v.Raw)
	}
	if _, err := PickVersionFor("x.org/tool", "*", hostOS, hostArch); err == nil {
		t.Errorf("host slug %s/%s resolved a version published only for %s/%s",
			hostOS, hostArch, tgtOS, tgtArch)
	}
}

// TestFetchMetaForPlatformKeyedDeps: recipes key their dependencies by
// platform. Reading them through the host's slug while staging another
// platform's rootfs yields the wrong closure — silently, since both answers
// are well-formed.
func TestFetchMetaForPlatformKeyedDeps(t *testing.T) {
	recipe := "dependencies:\n" +
		"  common.org/lib: '*'\n" +
		"  linux:\n" +
		"    linux.org/only: '*'\n" +
		"  darwin:\n" +
		"    darwin.org/only: '*'\n" +
		"provides:\n  - bin/tool\n"
	defer crossPantry(t, map[string]string{"x.org/tool": recipe}, nil)()

	deps, provides, err := FetchMetaFor("x.org/tool", "linux", "x86-64")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := deps["linux.org/only"]; !ok {
		t.Errorf("linux-only dependency missing: %v", deps)
	}
	if _, ok := deps["darwin.org/only"]; ok {
		t.Errorf("darwin-only dependency leaked into a linux closure: %v", deps)
	}
	if _, ok := deps["common.org/lib"]; !ok {
		t.Errorf("unkeyed dependency dropped: %v", deps)
	}
	if len(provides) != 1 || provides[0] != "bin/tool" {
		t.Errorf("provides = %v", provides)
	}

	// The same recipe, read for darwin, must give the mirror answer — proving
	// the slug is what selects, not some ambient default.
	deps, _, err = FetchMetaFor("x.org/tool", "darwin", "aarch64")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := deps["darwin.org/only"]; !ok {
		t.Errorf("darwin-only dependency missing: %v", deps)
	}
	if _, ok := deps["linux.org/only"]; ok {
		t.Errorf("linux-only dependency leaked into a darwin closure: %v", deps)
	}
}

// TestResolveClosureForWalksTargetPlatform is the end of the chain: the whole
// walk — version picks and dependency reads — must happen in the target's
// terms. This is what lets a darwin machine stage a linux/aarch64 userland.
// Run for BOTH targets, not just one: whichever of them happens to be the
// host, the other one still proves the walk followed the slug it was given.
func TestResolveClosureForWalksTargetPlatform(t *testing.T) {
	_, arch := HostSlug()
	versions := map[string][]string{}
	for _, osn := range []string{"linux", "darwin"} {
		// Every project is published for every target, so a wrong closure is a
		// choice the walk made, never a version it could not find.
		versions["x.org/tool/"+osn+"/"+arch] = []string{"1.0.0"}
		versions["linux.org/only/"+osn+"/"+arch] = []string{"3.1.0"}
		versions["darwin.org/only/"+osn+"/"+arch] = []string{"9.9.9"}
	}
	defer crossPantry(t,
		map[string]string{
			"x.org/tool": "dependencies:\n" +
				"  linux:\n    linux.org/only: '*'\n" +
				"  darwin:\n    darwin.org/only: '*'\n" +
				"provides:\n  - bin/tool\n",
			"linux.org/only":  "provides:\n  - lib/liblinux.so\n",
			"darwin.org/only": "provides:\n  - lib/libdarwin.dylib\n",
		}, versions)()

	for _, tc := range []struct{ target, want, unwanted, wantVer string }{
		{"linux", "linux.org/only", "darwin.org/only", "3.1.0"},
		{"darwin", "darwin.org/only", "linux.org/only", "9.9.9"},
	} {
		clo, err := ResolveClosureFor(map[string]string{"x.org/tool": "*"}, tc.target, arch)
		if err != nil {
			t.Fatalf("ResolveClosureFor(%s): %v", tc.target, err)
		}
		got := map[string]string{}
		for _, r := range clo {
			got[r.Project] = r.Version.Raw
		}
		if got["x.org/tool"] != "1.0.0" || got[tc.want] != tc.wantVer {
			t.Errorf("%s closure = %v, want tool 1.0.0 + %s %s", tc.target, got, tc.want, tc.wantVer)
		}
		if _, ok := got[tc.unwanted]; ok {
			t.Errorf("%s closure walked the other platform's branch: %v", tc.target, got)
		}
		if len(clo) != 2 {
			t.Errorf("%s closure has %d entries, want 2: %v", tc.target, len(clo), got)
		}
	}
}

// TestResolveClosureForPropagatesErrors keeps the failure modes explicit: an
// unresolvable version and an unreadable recipe must both stop the walk rather
// than yield a partial rootfs.
func TestResolveClosureForPropagatesErrors(t *testing.T) {
	defer crossPantry(t,
		map[string]string{
			"x.org/tool": "dependencies:\n  gone.org/dep: '*'\nprovides:\n  - bin/tool\n",
			"v.org/tool": "provides:\n  - bin/tool\n",
		},
		map[string][]string{
			"x.org/tool/linux/aarch64": {"1.0.0"},
			"v.org/tool/linux/aarch64": {"1.0.0"},
		})()

	if _, err := ResolveClosureFor(map[string]string{"x.org/tool": "*"}, "linux", "aarch64"); err == nil {
		t.Error("a dependency with no published version must fail the closure")
	}
	if _, err := ResolveClosureFor(map[string]string{"v.org/tool": "^9"}, "linux", "aarch64"); err == nil {
		t.Error("an unsatisfiable root constraint must fail the closure")
	}
}

// TestCrossPlatformTestsBiteOnALinuxHost re-runs the cross-platform tests with
// the host slug FAKED to linux — the CI runner's platform.
//
// The first version of these tests hardcoded "linux/x86-64" as "the other
// platform". On this Mac that is a genuinely different platform and the tests
// passed; on the linux CI runner it IS the host, so one test asserted that the
// host slug fails to resolve a version published under... the host slug, and
// went red. A test whose meaning depends on where it runs is not a test.
// This one pins the failure mode down where it is cheap to see.
func TestCrossPlatformTestsBiteOnALinuxHost(t *testing.T) {
	setGoos(t, "linux")
	setGoarch(t, "x86-64")

	t.Run("PickVersionFor", TestPickVersionForOtherPlatform)
	t.Run("FetchMetaFor", TestFetchMetaForPlatformKeyedDeps)
	t.Run("ResolveClosureFor", TestResolveClosureForWalksTargetPlatform)
}
