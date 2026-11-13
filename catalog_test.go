package artifact

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"
)

// A pantry-shaped catalogue: a flat project, a one-level namespace, a
// two-level one, and the case that breaks a naive tree.
func sampleCatalog() Catalog {
	return Catalog{
		Generated: "2026-10-05T09:00:00Z",
		Projects: []CatalogProject{
			{Project: "zlib.net", Versions: []string{"1.3.2"}, Platforms: []string{"linux/x86-64"}},
			{Project: "curl.se", Versions: []string{"8.17.0"}},
			{Project: "curl.se/ca-certs", Versions: []string{"2026.09.25"}},
			{Project: "gnu.org/bash"},
			{Project: "gnu.org/gcc"},
			{Project: "gnu.org/gcc/libstdcxx"},
			{Project: "github.com/besser82/libxcrypt"},
			{Project: "github.com/westes/flex"},
		},
	}
}

// The roots are the first segment of every project, and a project with no
// slash is a root that is itself a leaf.
func TestChildrenAtTheRoot(t *testing.T) {
	c0 := sampleCatalog()
	got := c0.Children("")
	var names []string
	for _, n := range got {
		names = append(names, n.Name)
	}
	if strings.Join(names, " ") != "curl.se github.com gnu.org zlib.net" {
		t.Fatalf("roots = %v", names)
	}
	for _, n := range got {
		switch n.Name {
		case "zlib.net":
			if !n.Leaf || n.Under != 0 {
				t.Errorf("zlib.net should be a pure leaf: %+v", n)
			}
		case "github.com":
			if n.Leaf || n.Under != 2 {
				t.Errorf("github.com should be interior with 2 under it: %+v", n)
			}
		}
	}
}

// THE CASE THAT BREAKS A NAIVE TREE: curl.se is a project AND has
// curl.se/ca-certs under it. Leaf and interior are not exclusive, and a tree
// that made them so would hide one of the two.
func TestANodeThatIsBothAProjectAndAParent(t *testing.T) {
	c0 := sampleCatalog()
	for _, n := range c0.Children("") {
		if n.Name != "curl.se" {
			continue
		}
		if !n.Leaf {
			t.Error("curl.se is a project and the tree does not say so")
		}
		if n.Under != 1 {
			t.Errorf("curl.se has curl.se/ca-certs under it; Under = %d", n.Under)
		}
		return
	}
	t.Fatal("curl.se is not among the roots")
}

// Only ONE segment is expanded. Jumping two levels would skip the choice the
// user is making.
func TestChildrenExpandOneSegmentAtATime(t *testing.T) {
	c := sampleCatalog()
	got := c.Children("github.com")
	var names []string
	for _, n := range got {
		names = append(names, n.Name)
	}
	if strings.Join(names, " ") != "github.com/besser82 github.com/westes" {
		t.Fatalf("github.com children = %v (expected the vendor level, not the projects)", names)
	}
	if got[0].Leaf {
		t.Error("github.com/besser82 is not itself a project and is marked a leaf")
	}
	// And the level below.
	deeper := c.Children("github.com/besser82")
	if len(deeper) != 1 || deeper[0].Name != "github.com/besser82/libxcrypt" || !deeper[0].Leaf {
		t.Errorf("github.com/besser82 children = %+v", deeper)
	}
	// A trailing slash is the same node.
	if len(c.Children("github.com/")) != len(got) {
		t.Error("a trailing slash changed the answer")
	}
}

// A node that does not exist has no children — and says nothing else.
func TestChildrenOfNothing(t *testing.T) {
	c0 := sampleCatalog()
	if got := c0.Children("nope.invalid"); len(got) != 0 {
		t.Errorf("children of an absent node = %+v", got)
	}
	// A prefix that is not a whole segment must not match: `gnu.o` is not
	// `gnu.org`, and a tree that walked into it would invent a node.
	if got := c0.Children("gnu.o"); len(got) != 0 {
		t.Errorf("a partial segment matched a node: %+v", got)
	}
}

// Completion is Children filtered by the partial LAST segment.
func TestComplete(t *testing.T) {
	c := sampleCatalog()
	names := func(ns []Node) string {
		var s []string
		for _, n := range ns {
			s = append(s, n.Name)
		}
		return strings.Join(s, " ")
	}
	if got := names(c.Complete("gnu.org/g")); got != "gnu.org/gcc" {
		t.Errorf("gnu.org/g → %q", got)
	}
	if got := names(c.Complete("gnu.org/")); got != "gnu.org/bash gnu.org/gcc" {
		t.Errorf("gnu.org/ → %q", got)
	}
	if got := names(c.Complete("c")); got != "curl.se" {
		t.Errorf("c → %q", got)
	}
	if got := names(c.Complete("")); got != "curl.se github.com gnu.org zlib.net" {
		t.Errorf("empty → %q", got)
	}
	// gnu.org/gcc is a project AND a parent, so completing it offers it.
	if got := names(c.Complete("gnu.org/gcc")); got != "gnu.org/gcc" {
		t.Errorf("gnu.org/gcc → %q", got)
	}
	if got := names(c.Complete("gnu.org/gcc/")); got != "gnu.org/gcc/libstdcxx" {
		t.Errorf("gnu.org/gcc/ → %q", got)
	}
}

func TestLookup(t *testing.T) {
	c := sampleCatalog()
	p, ok := c.Lookup("zlib.net")
	if !ok || p.Versions[0] != "1.3.2" {
		t.Errorf("Lookup(zlib.net) = %+v %v", p, ok)
	}
	if _, ok := c.Lookup("nope.invalid"); ok {
		t.Error("Lookup invented a project")
	}
}

// Deterministic bytes, because the artefact is signed like an artifact and a
// catalogue whose bytes moved for no reason makes every rebuild look like a
// change.
func TestMarshalIsDeterministicAndSorted(t *testing.T) {
	a := sampleCatalog()
	b := Catalog{Generated: a.Generated}
	for i := len(a.Projects) - 1; i >= 0; i-- { // same set, reversed
		b.Projects = append(b.Projects, a.Projects[i])
	}
	x, err := MarshalCatalog(a)
	if err != nil {
		t.Fatal(err)
	}
	y, err := MarshalCatalog(b)
	if err != nil {
		t.Fatal(err)
	}
	if string(x) != string(y) {
		t.Errorf("the same catalogue in a different order marshals differently:\n%s\n---\n%s", x, y)
	}
	if !strings.HasSuffix(string(x), "\n") {
		t.Error("no trailing newline")
	}
}

// An empty catalogue and an unreadable one must not look alike: the first
// says the registry is empty, the second says we failed to ask.
func TestUnmarshalRefusesWhatIsNotACatalogue(t *testing.T) {
	round, err := MarshalCatalog(sampleCatalog())
	if err != nil {
		t.Fatal(err)
	}
	back, err := UnmarshalCatalog(round)
	if err != nil {
		t.Fatal(err)
	}
	if len(back.Projects) != len(sampleCatalog().Projects) || back.Generated != "2026-10-05T09:00:00Z" {
		t.Errorf("round trip lost something: %+v", back)
	}
	for _, bad := range []string{"", "not json", "{}", "[]"} {
		if _, err := UnmarshalCatalog([]byte(bad)); err == nil {
			t.Errorf("accepted %q as a catalogue", bad)
		}
	}
	// A catalogue with zero projects but a timestamp IS one: an empty
	// registry is a real answer.
	if _, err := UnmarshalCatalog([]byte(`{"generated":"2026-10-05T09:00:00Z","projects":[]}`)); err != nil {
		t.Errorf("an empty but dated catalogue was refused: %v", err)
	}
}

func TestCatalogAge(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	for in, want := range map[string]string{
		"2026-10-05T11:30:00Z": "30 minute(s) old",
		"2026-10-05T06:00:00Z": "6 hour(s) old",
		"2026-10-01T12:00:00Z": "4 day(s) old",
		"":                     "of unknown age",
	} {
		if got := (&Catalog{Generated: in}).Age(now); got != want {
			t.Errorf("Age(%q) = %q, want %q", in, got, want)
		}
	}
}

// A real tar, because the manifest says `…layer.tar+gzip` and a reader that
// believes it must not be lied to. This test unpacks it the way `tar tzf`
// would rather than through CatalogFromTarball, so the two cannot agree on a
// shape nothing else can read.
func TestACatalogueLayerIsARealTar(t *testing.T) {
	tgz, err := CatalogTarball(sampleCatalog())
	if err != nil {
		t.Fatal(err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(tgz))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(zr)
	h, err := tr.Next()
	if err != nil {
		t.Fatal(err)
	}
	if h.Name != "catalog.json" {
		t.Errorf("the layer holds %q", h.Name)
	}
	body, _ := io.ReadAll(tr)
	if !strings.Contains(string(body), `"zlib.net"`) {
		t.Errorf("the file is not the catalogue:\n%s", body)
	}
	if _, err := tr.Next(); err != io.EOF {
		t.Error("the layer holds more than the catalogue")
	}
	// And the bytes are reproducible: same catalogue, same digest.
	again, err := CatalogTarball(sampleCatalog())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(tgz, again) {
		t.Error("two packs of the same catalogue differ — the digest would move for nothing")
	}
}

func TestCatalogRoundTripsThroughALayer(t *testing.T) {
	tgz, err := CatalogTarball(sampleCatalog())
	if err != nil {
		t.Fatal(err)
	}
	back, err := CatalogFromTarball(tgz)
	if err != nil {
		t.Fatal(err)
	}
	if len(back.Projects) != 8 || back.Generated != "2026-10-05T09:00:00Z" {
		t.Errorf("round trip = %+v", back)
	}
	if n := back.Children("github.com"); len(n) != 2 {
		t.Errorf("the tree did not survive: %+v", n)
	}
}

// Every way a layer can fail to be a catalogue, each said differently.
func TestCatalogFromTarballRefusals(t *testing.T) {
	pack := func(name string, body []byte) []byte {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		tw := tar.NewWriter(zw)
		_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
		_, _ = tw.Write(body)
		_ = tw.Close()
		_ = zw.Close()
		return buf.Bytes()
	}
	for _, c := range []struct {
		name string
		in   []byte
		want string
	}{
		{"not gzip", []byte("plain"), "catalog:"},
		{"no catalog.json", pack("README", []byte("hi")), "holds no catalog.json"},
		{"not a catalogue", pack("catalog.json", []byte("{}")), "not a catalogue"},
		{"broken json", pack("catalog.json", []byte("{")), "catalog:"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := CatalogFromTarball(c.in)
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("%v does not say %q", err, c.want)
			}
		})
	}
}

// A catalogue is a list of names. Anything artifact-sized in that slot is not
// one, and reading it because the tar said to is how a reader becomes the
// attack.
func TestCatalogRefusesAnOversizedFile(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	big := bytes.Repeat([]byte("a"), CatalogMaxBytes+1)
	_ = tw.WriteHeader(&tar.Header{Name: CatalogFileName, Mode: 0o644, Size: int64(len(big)), Typeflag: tar.TypeReg})
	_, _ = tw.Write(big)
	_ = tw.Close()
	_ = zw.Close()
	_, err := CatalogFromTarball(buf.Bytes())
	if err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("an oversized catalogue was accepted or misreported: %v", err)
	}
}

// The whole point, end to end against a registry: publish a catalogue for
// one platform, pull it back, and browse the tree that comes out.
//
// Per PLATFORM, and the second half of this test is why: what is available
// differs by architecture, so a catalogue pushed for one must not answer for
// another. The s390x lane having a fraction of linux/x86-64's artifacts is the
// case this protects.
func TestPublishAndFetchACatalogue(t *testing.T) {
	t.Setenv("ZPKG_VERIFY", "0") // transport round-trip on an unsigned artefact
	fr := newFakeRegistry(t, false)
	defer fr.close()
	c, err := NewOCIClient(fr.base("go-zpkg/artifacts"))
	if err != nil {
		t.Fatal(err)
	}
	osn, arch := HostSlug()

	if err := PublishCatalog(c, sampleCatalog(), osn, arch); err != nil {
		t.Fatal(err)
	}
	got, err := FetchCatalog(c, osn, arch)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Projects) != 8 {
		t.Fatalf("fetched %d projects", len(got.Projects))
	}
	// The tree, which is what a browser asks for.
	kids := got.Children("gnu.org")
	var names []string
	for _, n := range kids {
		names = append(names, n.Name)
	}
	if strings.Join(names, " ") != "gnu.org/bash gnu.org/gcc" {
		t.Errorf("gnu.org children after a round trip = %v", names)
	}

	// A platform nothing was published for must FAIL, not return an empty
	// catalogue: "this architecture has nothing" and "I could not ask" are
	// different answers and a browser must not merge them.
	if _, err := FetchCatalog(c, "plan9", "mips64"); err == nil {
		t.Error("a platform with no catalogue returned one")
	}
}

// A catalogue with a dependency DAG: curl needs openssl and zlib, openssl
// needs zlib too (the diamond), and one dependency is not in the catalogue
// at all.
func depCatalog() Catalog {
	return Catalog{
		Generated: "2026-10-05T09:00:00Z",
		Projects: []CatalogProject{
			{Project: "curl.se", Versions: []string{"8.17.0"}, Deps: []string{"openssl.org", "zlib.net", "gone.invalid"}},
			{Project: "openssl.org", Versions: []string{"3.6.4"}, Deps: []string{"zlib.net"}},
			{Project: "zlib.net", Versions: []string{"1.3.2"}},
		},
	}
}

// What is under a PACKAGE node is what it needs — a different question
// from what is under a NAMESPACE node, which is what it contains.
func TestDepTree(t *testing.T) {
	c := depCatalog()
	top := c.DepTree("curl.se", 0)
	var names []string
	for _, n := range top {
		names = append(names, n.Project)
	}
	if strings.Join(names, " ") != "gone.invalid openssl.org zlib.net" {
		t.Fatalf("under curl.se = %v", names)
	}
	for _, n := range top {
		switch n.Project {
		case "openssl.org":
			if n.Version != "3.6.4" || !n.Known {
				t.Errorf("openssl = %+v", n)
			}
			// THE DIAMOND, and which side of it gets expanded. zlib is a
			// direct dependency of curl AND of openssl. The one a reader
			// came for is curl's own, so that is the one shown in full and
			// this nested one is named as a repeat.
			if len(n.Under) != 1 || n.Under[0].Project != "zlib.net" || !n.Under[0].Repeat {
				t.Errorf("under openssl = %+v", n.Under)
			}
		case "zlib.net":
			if n.Repeat {
				t.Error("curl's own direct dependency is shown as a repeat; the nested one was expanded instead")
			}
		case "gone.invalid":
			// A dependency the catalogue does not list must say so, not
			// print like any other node.
			if n.Known {
				t.Error("a dependency with no catalogue entry is marked known")
			}
		}
	}
}

// depth limits the walk, as `guix graph --max-depth` does, because a full
// transitive graph of anything interesting is pages long.
func TestDepTreeDepth(t *testing.T) {
	c := depCatalog()
	one := c.DepTree("curl.se", 1)
	if len(one) != 3 {
		t.Fatalf("depth 1 gave %d nodes", len(one))
	}
	for _, n := range one {
		if len(n.Under) != 0 {
			t.Errorf("depth 1 descended into %s", n.Project)
		}
	}
	// And depth 0 is "no limit", not "nothing".
	if deep := c.DepTree("curl.se", 0); len(deep) != 3 {
		t.Errorf("depth 0 gave %d nodes", len(deep))
	}
}

// A leaf, and a project that is not there at all. Neither is an error and
// they are not the same thing — the caller distinguishes them with Lookup.
func TestDepTreeOfALeafAndOfNothing(t *testing.T) {
	c := depCatalog()
	if got := c.DepTree("zlib.net", 0); len(got) != 0 {
		t.Errorf("zlib has no dependencies; got %+v", got)
	}
	if got := c.DepTree("nope.invalid", 0); len(got) != 0 {
		t.Errorf("an absent project has no subtree; got %+v", got)
	}
}

// A CYCLE must terminate. Recipes have them — the closure walk in artifact
// marks a project seen before descending for exactly this reason — and a
// browser that recursed would hang on the first one.
func TestDepTreeTerminatesOnACycle(t *testing.T) {
	c := Catalog{Projects: []CatalogProject{
		{Project: "a.org", Deps: []string{"b.org"}},
		{Project: "b.org", Deps: []string{"a.org"}},
	}}
	got := c.DepTree("a.org", 0)
	if len(got) != 1 || got[0].Project != "b.org" {
		t.Fatalf("under a.org = %+v", got)
	}
	if len(got[0].Under) != 1 || !got[0].Under[0].Repeat {
		t.Errorf("the cycle back to a.org is not marked as already shown: %+v", got[0].Under)
	}
}

// A CATALOGUE'S VERSIONS REACH THE TERMINAL, and it took a probe to see it:
// `pkgx ls` printed them raw, so a version carrying ESC[2K and a carriage
// return rewrote its own line as a different, reassuring one.
//
//	evil.org   1.0.0^[[2K^Mcurl.se  8.20  ✓ verified by maintainers
//
// Dropped and counted rather than refused: a version string reaches a
// published catalogue from an upstream recipe's `versions:` spec, so
// refusing the whole file would hand any recipe author a switch that turns
// off `pkgx ls`, `search` and every <TAB> for everybody.
func TestACraftedVersionIsDroppedFromACatalogueNotShown(t *testing.T) {
	body := `{"generated":"2026-10-07T00:00:00Z","projects":[` +
		`{"project":"evil.org","versions":["1.0.0\u001b[2K\rcurl.se 8.20 verified","2.0.0"],` +
		`"platforms":["darwin/aarch64"]}]}`
	c, err := UnmarshalCatalog([]byte(body))
	if err != nil {
		t.Fatalf("the catalogue was refused outright: %v", err)
	}
	p := c.Projects[0]
	for _, v := range p.Versions {
		if strings.ContainsRune(v, 0x1b) {
			t.Errorf("an escape reached a version: %q", v)
		}
	}
	// The GOOD version survives. A guard that threw away the whole list
	// would be a denial of service wearing a fix's clothes.
	if len(p.Versions) != 1 || p.Versions[0] != "2.0.0" {
		t.Errorf("versions = %q, want just the readable one", p.Versions)
	}
	// AND IT IS NOT SILENT. A guard that quietly removes things leaves a
	// reader comparing a short list against their memory.
	if c.Dropped != 1 {
		t.Errorf("Dropped = %d, want 1", c.Dropped)
	}
	// The project stays LISTED, which is the state the type already
	// documents as legal: named by the pantry, nothing this client can
	// fetch.
	if p.Project != "evil.org" {
		t.Errorf("the project was removed with its version: %q", p.Project)
	}
}

// AND A REAL CATALOGUE LOSES NOTHING. The published catalogues of
// 2026-10-06 carry 2801 version strings over fifteen distinct runes; if any
// of them tripped this, `pkgx ls` would start hiding versions that work.
func TestOrdinaryVersionsAreNotDropped(t *testing.T) {
	body := `{"generated":"2026-10-07T00:00:00Z","projects":[` +
		`{"project":"min.io","versions":["2023.10.25.06.33.25","1.3.2","20260526.0","2026.1","1.2.3-rc1"]}]}`
	c, err := UnmarshalCatalog([]byte(body))
	if err != nil {
		t.Fatalf("UnmarshalCatalog: %v", err)
	}
	if c.Dropped != 0 || len(c.Projects[0].Versions) != 5 {
		t.Errorf("dropped %d, kept %q", c.Dropped, c.Projects[0].Versions)
	}
}

// A PLATFORM IS A KEY TOO, and only one tool prints it today — which is
// exactly the argument for leaving a field unchecked until something new
// prints it.
func TestACraftedPlatformIsDropped(t *testing.T) {
	body := `{"generated":"2026-10-07T00:00:00Z","projects":[` +
		`{"project":"evil.org","platforms":["darwin/aarch64","linux\u001b[2K\r/aarch64","notaslash","a/b/c","/x","y/"]}]}`
	c, err := UnmarshalCatalog([]byte(body))
	if err != nil {
		t.Fatalf("the catalogue was refused outright: %v", err)
	}
	got := c.Projects[0].Platforms
	if len(got) != 1 || got[0] != "darwin/aarch64" {
		t.Errorf("platforms = %q, want just the readable one", got)
	}
	if c.Dropped != 5 {
		t.Errorf("Dropped = %d, want 5", c.Dropped)
	}
}

func TestOrdinaryPlatformsAreNotDropped(t *testing.T) {
	for _, s := range []string{"linux/aarch64", "darwin/aarch64", "windows/x86-64", "linux/x86-64", "linux/s390x", "linux/loong64"} {
		if err := ValidatePlatformSlug(s); err != nil {
			t.Errorf("ValidatePlatformSlug(%q) = %v", s, err)
		}
	}
}

// WHO NEEDS THIS — the question `ls --tree` cannot answer however deep it
// goes, and the one you ask before CHANGING something rather than before
// installing it.
func TestDependentsWalksTheOtherWay(t *testing.T) {
	c := fanCatalog()
	got := names(c.Dependents("zlib.net", 1))
	want := []string{"curl.se", "openssl.org"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("direct dependents = %v, want %v", got, want)
	}
	// Transitive: git needs curl needs zlib, so git is reached at depth 2
	// and not at depth 1 — a bound that did nothing would show it at both.
	deep := c.Dependents("zlib.net", 0)
	if g := names(deep); !reflect.DeepEqual(g, want) {
		t.Errorf("top level of the full walk = %v, want %v", g, want)
	}
	var under []string
	for _, n := range deep {
		if n.Project == "curl.se" {
			under = names(n.Under)
		}
	}
	if !reflect.DeepEqual(under, []string{"git-scm.org"}) {
		t.Errorf("under curl.se = %v, want [git-scm.org]", under)
	}
}

// A DAG, NOT A TREE, in this direction too: zlib is needed by curl AND by
// openssl, and openssl is needed by curl. Whichever of the two occurrences
// of a node is expanded, the other says so instead of repeating a subtree.
func TestDependentsMarksRepeatsInsteadOfRepeatingThem(t *testing.T) {
	c := fanCatalog()
	deep := c.Dependents("zlib.net", 0)
	expanded, repeated := 0, 0
	var walk func([]DepNode)
	walk = func(ns []DepNode) {
		for _, n := range ns {
			if n.Project == "curl.se" {
				if n.Repeat {
					repeated++
				} else {
					expanded++
				}
			}
			walk(n.Under)
		}
	}
	walk(deep)
	if expanded != 1 || repeated != 1 {
		t.Errorf("curl.se expanded %d time(s) and marked repeat %d time(s), want 1 and 1", expanded, repeated)
	}
}

// A project nothing needs is not an error and not a mistake: most leaves of
// a pantry are nobody's dependency.
func TestDependentsOfALeafIsEmpty(t *testing.T) {
	if got := fanCatalog().Dependents("git-scm.org", 0); len(got) != 0 {
		t.Errorf("dependents of a leaf = %v", got)
	}
}

// NIX'S QUESTION: not "what is in the closure" but WHICH LINK put it there.
func TestWhyDependsIsAShortestPath(t *testing.T) {
	c := fanCatalog()
	// git → curl → zlib is length 3; git → curl → openssl → zlib is 4.
	got := c.WhyDepends("git-scm.org", "zlib.net")
	want := []string{"git-scm.org", "curl.se", "zlib.net"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("WhyDepends = %v, want the shortest %v", got, want)
	}
	// A project is trivially its own reason, which is the answer that keeps
	// a caller from having to special-case it.
	if got := c.WhyDepends("curl.se", "curl.se"); !reflect.DeepEqual(got, []string{"curl.se"}) {
		t.Errorf("WhyDepends(x, x) = %v", got)
	}
	// NO PATH IS nil, not an empty slice dressed up as an answer, and not
	// the reverse path by accident: zlib needs nothing.
	if got := c.WhyDepends("zlib.net", "git-scm.org"); got != nil {
		t.Errorf("WhyDepends found a path that does not exist: %v", got)
	}
}

// fanCatalog: git → curl → {openssl, zlib}, openssl → zlib. A diamond, so
// the repeat marking and the shortest path both have something to decide.
func fanCatalog() *Catalog {
	return &Catalog{Projects: []CatalogProject{
		{Project: "git-scm.org", Versions: []string{"2.51.0"}, Deps: []string{"curl.se"}},
		{Project: "curl.se", Versions: []string{"8.20"}, Deps: []string{"openssl.org", "zlib.net"}},
		{Project: "openssl.org", Versions: []string{"4.0.2"}, Deps: []string{"zlib.net"}},
		{Project: "zlib.net", Versions: []string{"1.3.2"}},
	}}
}

func names(ns []DepNode) []string {
	var out []string
	for _, n := range ns {
		out = append(out, n.Project)
	}
	return out
}

// SHORTEST, NOT FIRST FOUND — and the diamond above cannot tell the two
// apart, which mutate proved by turning the breadth-first queue into a
// stack and surviving it.
//
// Here `a` reaches `c` two ways: through `b` in two hops and through the
// `z` chain in four. The long branch sorts LAST, so a stack pops it first
// and walks it to the end; only a queue returns the short one. My first
// attempt at this fixture put the long branch first and still passed under
// the mutation — with a stack it is the LAST child enqueued that is
// explored first, which is the opposite of the intuition.
func TestWhyDependsPrefersTheShortPathOverTheOneItMeetsFirst(t *testing.T) {
	c := &Catalog{Projects: []CatalogProject{
		{Project: "a.org", Deps: []string{"b.org", "z0.org"}},
		{Project: "b.org", Deps: []string{"c.org"}},
		{Project: "z0.org", Deps: []string{"z1.org"}},
		{Project: "z1.org", Deps: []string{"z2.org"}},
		{Project: "z2.org", Deps: []string{"c.org"}},
		{Project: "c.org"},
	}}
	got := c.WhyDepends("a.org", "c.org")
	want := []string{"a.org", "b.org", "c.org"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("WhyDepends = %v (%d hops), want the shortest %v", got, len(got), want)
	}
}

// A CATALOGUE IS UNTRUSTED INPUT, AND A CYCLE IS A HANG WAITING TO HAPPEN.
//
// `deps` comes from recipes; nothing refuses a cycle when the catalogue is
// built, and nothing could cheaply — a→b→a is only visible with the whole
// graph in hand. All three terminate today, because `seen` and `prev` mark
// before descending.
//
// This does NOT replace TestDepTreeTerminatesOnACycle above, and neither
// covers the other:
//
//   - that one asserts the CONTENT — the back edge is marked Repeat — on
//     DepTree alone, and has no timeout, so a regression to infinite
//     recursion would hang it rather than fail it;
//   - this one asserts TERMINATION, under a clock, for all three — and
//     Dependents and WhyDepends are new, so nothing covered them at all.
//
// ⛔ THE TIMEOUT CATCHES ONE OF THE TWO FAILURE MODES, AND SAYING WHICH IS
// THE POINT. Both were measured by breaking the code on purpose:
//
//	WhyDepends without its visited set   → a real infinite loop. The
//	                                       timeout fires and names the
//	                                       function and the cycle. ✅
//	walkGraph without `seen`             → unbounded RECURSION, which
//	                                       stack-overflows in well under
//	                                       five seconds:
//	                                           fatal error: stack overflow
//	                                       A runtime fatal error kills the
//	                                       process; no timeout in any test
//	                                       can intercept it.
//
// So this is load-bearing for the breadth-first search and belt-and-braces
// for the recursive walkers, where the failure is loud anyway. Claiming it
// covered all three would have been claiming a guard nobody demonstrated.
func TestTheGraphWalkersTerminateOnACycle(t *testing.T) {
	for name, c := range map[string]*Catalog{
		"a → b → a": {Projects: []CatalogProject{
			{Project: "a.org", Deps: []string{"b.org"}},
			{Project: "b.org", Deps: []string{"a.org"}},
		}},
		"a → a": {Projects: []CatalogProject{
			{Project: "a.org", Deps: []string{"a.org"}},
		}},
		"a → b → c → a": {Projects: []CatalogProject{
			{Project: "a.org", Deps: []string{"b.org"}},
			{Project: "b.org", Deps: []string{"c.org"}},
			{Project: "c.org", Deps: []string{"a.org"}},
		}},
	} {
		for call, f := range map[string]func(){
			"DepTree":    func() { c.DepTree("a.org", 0) },
			"Dependents": func() { c.Dependents("a.org", 0) },
			"WhyDepends": func() { c.WhyDepends("a.org", "c.org") },
		} {
			done := make(chan struct{})
			go func() { defer close(done); f() }()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatalf("%s did not return on the cycle %q — an installer would freeze here", call, name)
			}
		}
	}
}

// AND THE PATH IT FINDS THROUGH A CYCLE IS STILL A PATH: every consecutive
// pair is a real edge, and no project appears twice. A search that
// terminated by giving up would also pass the test above.
func TestWhyDependsThroughACycleIsAValidPath(t *testing.T) {
	c := &Catalog{Projects: []CatalogProject{
		{Project: "a.org", Deps: []string{"b.org"}},
		{Project: "b.org", Deps: []string{"c.org"}},
		{Project: "c.org", Deps: []string{"a.org"}},
	}}
	path := c.WhyDepends("a.org", "c.org")
	if !reflect.DeepEqual(path, []string{"a.org", "b.org", "c.org"}) {
		t.Fatalf("path = %v", path)
	}
	index := c.index()
	seen := map[string]bool{}
	for i, p := range path {
		if seen[p] {
			t.Errorf("%s appears twice in %v", p, path)
		}
		seen[p] = true
		if i == 0 {
			continue
		}
		var edge bool
		for _, d := range index[path[i-1]].Deps {
			if d == p {
				edge = true
			}
		}
		if !edge {
			t.Errorf("%s → %s is not an edge", path[i-1], p)
		}
	}
}

// providesCatalog is its own fixture rather than an extension of
// sampleCatalog: several tests above assert that one's exact contents, and a
// `provides` added there would be invisible until one of them moved.
func providesCatalog() Catalog {
	return Catalog{
		Generated: "2026-10-12T09:00:00Z",
		Projects: []CatalogProject{
			// Insertion order is the REVERSE of sorted order on purpose, so
			// the sort in ProvidersOf is actually exercised. With these two
			// the other way round the test would pass without it.
			{Project: "zoo.example/hugo-mirror", Provides: []string{"hugo"}},
			{Project: "gohugo.io", Provides: []string{"hugo"}},
			{Project: "crates.io/ripgrep", Provides: []string{"rg"}},
			{Project: "zlib.net", Versions: []string{"1.3.2"}},
			// A MALFORMED entry, deliberately. A catalogue is fetched from a
			// registry, so "provides holds no empty strings" is a property of
			// the publisher and not of the bytes we are handed. Without this
			// the empty-command guard is untested: with every Provides
			// well-formed, removing the guard changes nothing and the test
			// for it passes either way — which is how it was first written,
			// and a mutation is what said so.
			{Project: "malformed.example", Provides: []string{""}},
		},
	}
}

func TestProvidersOfFindsTheProjectBehindACommand(t *testing.T) {
	c := providesCatalog()
	if got := c.ProvidersOf("rg"); len(got) != 1 || got[0] != "crates.io/ripgrep" {
		t.Errorf("ProvidersOf(rg) = %v, want [crates.io/ripgrep]", got)
	}
}

// ⛔ Two providers come back as two. A caller must be able to refuse rather
// than be handed a winner this data cannot justify.
func TestProvidersOfReturnsEveryProviderSorted(t *testing.T) {
	c := providesCatalog()
	got := c.ProvidersOf("hugo")
	want := []string{"gohugo.io", "zoo.example/hugo-mirror"}
	if len(got) != len(want) {
		t.Fatalf("ProvidersOf(hugo) = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("ProvidersOf(hugo)[%d] = %q, want %q (sorted, not insertion order)", i, got[i], want[i])
		}
	}
}

func TestProvidersOfKnowsNothingOfAProjectName(t *testing.T) {
	c := providesCatalog()
	// `zlib.net` is a project, not a command. Matching it here would make
	// `pkgx zlib.net` resolve twice over and hide a real miss.
	if got := c.ProvidersOf("zlib.net"); got != nil {
		t.Errorf("ProvidersOf(zlib.net) = %v, want nil", got)
	}
	if got := c.ProvidersOf("nope"); got != nil {
		t.Errorf("ProvidersOf(nope) = %v, want nil", got)
	}
}

// An empty command is what an empty argument looks like; it must not match
// every project that happens to declare nothing.
func TestProvidersOfRefusesTheEmptyCommand(t *testing.T) {
	c := providesCatalog()
	if got := c.ProvidersOf(""); got != nil {
		t.Errorf(`ProvidersOf("") = %v, want nil`, got)
	}
}
