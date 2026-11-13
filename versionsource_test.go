package artifact

import "testing"

// "Available" is a claim about ONE registry.
//
// VersionsFor answers a resolver's question — "what version satisfies this
// constraint" — and for that, a list borrowed from the upstream dist is a
// fine answer, because the install still pulls from DistBase and either
// list resolves the same constraint.
//
// A CATALOGUE asks a different question with the same words. `pkgx ls
// doxygen.nl` showing "1.14.0" means "you can have this"; if that number
// came from dist.pkgx.dev while our registry has never published the
// project, the next command fails. The catalogue was about to be built on
// exactly that answer.
//
// So the flag is the test: the SAME call, two registries, two verdicts.
func TestAVersionListSaysWhichRegistryItCameFrom(t *testing.T) {
	fr := newFakeRegistry(t, false)
	defer fr.close()
	kp := pushTwoVersions(t, fr, "zlib.net", "linux", "aarch64")
	_ = kp

	// A project this registry has never published: the repo is not there at
	// all, which is how ghcr answers for anything unmirrored.
	up, hits := upstreamVersionsServer(t, "doxygen.nl", "linux", "aarch64", []string{"1.14.0"})
	oldDist, oldUp := DistBase, UpstreamDist
	DistBase, UpstreamDist = fr.base("go-zpkg/packages"), up
	defer func() { DistBase, UpstreamDist = oldDist, oldUp; resetOCICache() }()
	resetOCICache()
	t.Setenv("ZPKG_VERIFY", "0")

	vs, fromRegistry, err := VersionsForSourced("doxygen.nl", "linux", "aarch64")
	if err != nil {
		t.Fatalf("VersionsForSourced: %v", err)
	}
	if fromRegistry {
		t.Error("a list borrowed from the upstream dist is reported as OURS")
	}
	if len(vs) != 1 || vs[0].Raw != "1.14.0" {
		t.Errorf("fallback list = %v", vs)
	}
	if *hits == 0 {
		t.Error("the upstream dist was never consulted — the test proves nothing")
	}

	// And the positive control, without which the assertion above also
	// passes when the flag is wired to the constant false.
	vs, fromRegistry, err = VersionsForSourced("zlib.net", "linux", "aarch64")
	if err != nil {
		t.Fatalf("VersionsForSourced: %v", err)
	}
	if !fromRegistry {
		t.Error("this registry's own tag listing is not reported as ours")
	}
	if len(vs) != 2 {
		t.Errorf("our versions = %v, want 2", vs)
	}

	// A tag listing spans every platform, so "the registry has the tag" is
	// not "the registry has it for YOU". That second question has its own
	// call, and the catalogue needs both.
	newest := vs[len(vs)-1]
	tag, here, err := PublishedTagFor("zlib.net", newest, "linux", "aarch64")
	if err != nil || !here {
		t.Errorf("PublishedTagFor(linux/aarch64) = %q, %v, %v", tag, here, err)
	}
	if tag != "1.3.2" {
		t.Errorf("carried under tag %q", tag)
	}
	_, elsewhere, err := PublishedTagFor("zlib.net", newest, "darwin", "aarch64")
	if err != nil {
		t.Fatal(err)
	}
	if elsewhere {
		t.Error("a platform nothing was published for reports an artifact")
	}
}

// pushTwoVersions publishes two versions of a project for one platform, so
// a test has a project that really is carried HERE.
func pushTwoVersions(t *testing.T, fr *fakeRegistry, project, osn, arch string) bool {
	t.Helper()
	c, err := NewOCIClient(fr.base("go-zpkg/packages"))
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"1.3.1", "1.3.2"} {
		if err := c.Push(project, v, osn, arch, makeGzTarball("body-"+v), ExtTarGz); err != nil {
			t.Fatal(err)
		}
	}
	return true
}
