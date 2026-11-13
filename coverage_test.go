package artifact

// coverage_test.go drives the branches that the feature-oriented tests do not
// reach on a single host: the Windows / linux OS-specific paths (via the goos /
// goarch seams), the fail-closed error branches of the OCI transport and the
// install/untar machinery (via fault injection into the in-memory registry and
// crafted archives), and the DT_NEEDED closure completion (via a hand-built
// minimal ELF). Every assertion checks real behaviour — exact bytes, exact
// error conditions, actual files on disk — not merely "something ran".

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/ulikunitz/xz"
	oras "oras.land/oras-go/v2"
	orascontent "oras.land/oras-go/v2/content"
)

// --- seams ------------------------------------------------------------------

func setGoos(t *testing.T, v string) {
	t.Helper()
	old := goos
	goos = func() string { return v }
	t.Cleanup(func() { goos = old })
}

func setGoarch(t *testing.T, v string) {
	t.Helper()
	old := goarch
	goarch = func() string { return v }
	t.Cleanup(func() { goarch = old })
}

// minimalELF builds a tiny valid ELF64 (little-endian) whose .dynamic section
// lists the given DT_NEEDED sonames, so debug/elf.ImportedLibraries returns them
// and scanNeeded/CompleteClosure can be exercised on a non-linux host.
func minimalELF(needed []string) []byte { return buildELF(needed, 1) }

// buildELF is minimalELF with an explicit .dynamic sh_link (the index of the
// linked .dynstr). A bogus link (>= section count) parses fine but makes
// ImportedLibraries fail its string-table lookup — the scanNeeded error branch.
func buildELF(needed []string, dynLink uint32) []byte {
	le := binary.LittleEndian

	var dynstr bytes.Buffer
	dynstr.WriteByte(0)
	off := map[string]uint64{}
	for _, n := range needed {
		off[n] = uint64(dynstr.Len())
		dynstr.WriteString(n)
		dynstr.WriteByte(0)
	}
	var dyn bytes.Buffer
	for _, n := range needed {
		var e [16]byte
		le.PutUint64(e[0:], 1) // DT_NEEDED
		le.PutUint64(e[8:], off[n])
		dyn.Write(e[:])
	}
	dyn.Write(make([]byte, 16)) // DT_NULL

	var shstr bytes.Buffer
	shstr.WriteByte(0)
	nameOff := func(s string) uint32 { o := uint32(shstr.Len()); shstr.WriteString(s); shstr.WriteByte(0); return o }
	nDynstr := nameOff(".dynstr")
	nDynamic := nameOff(".dynamic")
	nShstr := nameOff(".shstrtab")

	ehsize := uint64(64)
	dynstrOff := ehsize
	dynamicOff := dynstrOff + uint64(dynstr.Len())
	shstrOff := dynamicOff + uint64(dyn.Len())
	shoff := shstrOff + uint64(shstr.Len())

	buf := &bytes.Buffer{}
	hdr := make([]byte, 64)
	copy(hdr[0:], []byte{0x7f, 'E', 'L', 'F'})
	hdr[4], hdr[5], hdr[6] = 2, 1, 1 // class64, LSB, current
	le.PutUint16(hdr[16:], 3)        // e_type ET_DYN
	le.PutUint16(hdr[18:], 62)       // e_machine EM_X86_64
	le.PutUint32(hdr[20:], 1)        // e_version
	le.PutUint64(hdr[40:], shoff)    // e_shoff
	le.PutUint16(hdr[52:], 64)       // e_ehsize
	le.PutUint16(hdr[58:], 64)       // e_shentsize
	le.PutUint16(hdr[60:], 4)        // e_shnum
	le.PutUint16(hdr[62:], 3)        // e_shstrndx
	buf.Write(hdr)
	buf.Write(dynstr.Bytes())
	buf.Write(dyn.Bytes())
	buf.Write(shstr.Bytes())

	sh := func(name, typ uint32, offset, size uint64, link uint32, align, entsize uint64) []byte {
		b := make([]byte, 64)
		le.PutUint32(b[0:], name)
		le.PutUint32(b[4:], typ)
		le.PutUint64(b[24:], offset)
		le.PutUint64(b[32:], size)
		le.PutUint32(b[40:], link)
		le.PutUint64(b[48:], align)
		le.PutUint64(b[56:], entsize)
		return b
	}
	buf.Write(sh(0, 0, 0, 0, 0, 0, 0))                                        // SHT_NULL
	buf.Write(sh(nDynstr, 3, dynstrOff, uint64(dynstr.Len()), 0, 1, 0))       // .dynstr
	buf.Write(sh(nDynamic, 6, dynamicOff, uint64(dyn.Len()), dynLink, 8, 16)) // .dynamic -> link .dynstr
	buf.Write(sh(nShstr, 3, shstrOff, uint64(shstr.Len()), 0, 1, 0))          // .shstrtab
	return buf.Bytes()
}

// --- host.go ----------------------------------------------------------------

func TestSlugMapping(t *testing.T) {
	if osSlug("darwin") != "darwin" || osSlug("windows") != "windows" ||
		osSlug("linux") != "linux" || osSlug("freebsd") != "freebsd" {
		t.Error("osSlug mapping")
	}
	if archSlug("arm64") != "aarch64" || archSlug("amd64") != "x86-64" || archSlug("riscv64") != "riscv64" {
		t.Error("archSlug mapping")
	}
	// the seams route through the pure helpers and so agree with HostSlug.
	o, a := HostSlug()
	if goos() != o || goarch() != a {
		t.Error("goos/goarch disagree with HostSlug")
	}
}

// --- certs.go ---------------------------------------------------------------

func TestNewHTTPClientNoSystemPool(t *testing.T) {
	old := systemCertPool
	systemCertPool = func() (*x509.CertPool, error) { return nil, fmt.Errorf("no system trust store") }
	defer func() { systemCertPool = old }()
	if NewHTTPClient() == nil {
		t.Fatal("client should build on the embedded bundle alone")
	}
}

// --- install.go: ResolveBinPath (windows), IsELF, StubBins, loaders ---------

func TestResolveBinPathWindows(t *testing.T) {
	setGoos(t, "windows")
	dir := t.TempDir()
	bin := filepath.Join(dir, "tool")
	if err := os.WriteFile(bin+".exe", []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := ResolveBinPath(bin); got != bin+".exe" {
		t.Errorf("windows .exe preference = %q, want %q", got, bin+".exe")
	}
	// no .exe on disk -> the bare (extension-free) name is returned.
	bare := filepath.Join(dir, "other")
	if got := ResolveBinPath(bare); got != bare {
		t.Errorf("windows missing .exe = %q, want %q", got, bare)
	}
}

func TestIsELFReadError(t *testing.T) {
	// An empty file opens fine but the 4-byte magic read returns io.EOF.
	p := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(p, []byte{}, 0o644); err != nil {
		t.Fatal(err)
	}
	if IsELF(p) {
		t.Error("empty file must not be reported as ELF")
	}
}

func TestStubBins(t *testing.T) {
	defer fakeServer(t, map[string]fakePkg{
		// two provided bins, only one of which is extracted to disk.
		"acme.org/tool": {
			versions: []string{"1.0.0"},
			yaml:     "provides:\n  - bin/tool\n  - bin/missing\n",
			files:    map[string]string{"bin/tool": "#!x\n"},
		},
	})()
	dir := t.TempDir()
	if _, err := Install(Resolved{"acme.org/tool", ParseVer("1.0.0")}, dir); err != nil {
		t.Fatal(err)
	}
	// closure carries a project whose package.yml is NOT served -> FetchMeta
	// errors and that project is skipped.
	closure := []Resolved{{"acme.org/tool", ParseVer("1.0.0")}, {"ghost.org/x", ParseVer("9.9.9")}}
	prefix := filepath.Join(dir, "stubprefix")
	n, err := StubBins(closure, dir, prefix)
	if err != nil {
		t.Fatalf("StubBins: %v", err)
	}
	if n != 1 {
		t.Fatalf("wrote %d stubs, want 1 (only bin/tool exists)", n)
	}
	stub, err := os.ReadFile(filepath.Join(prefix, "bin", "tool"))
	if err != nil {
		t.Fatalf("stub not written: %v", err)
	}
	// ⛔ THE STUB NAMES THE HASHED DIRECTORY, NOT THE ALIAS. A stub is written
	// once and run for as long as it is on a PATH; pointing it at
	// `v1.0.0` would make it follow whatever that alias is made to mean
	// later, so the binary a stub runs could change without the stub
	// changing. It names the build it was written for.
	real := StorePrefix(dir, "acme.org/tool", ParseVer("1.0.0"))
	if !strings.Contains(real, variantSep) {
		t.Fatalf("the installed prefix carries no hash: %s", real)
	}
	if !strings.Contains(string(stub), "exec \""+filepath.Join(real, "bin", "tool")+"\"") ||
		!strings.Contains(string(stub), "LD_LIBRARY_PATH=") {
		t.Errorf("stub content unexpected:\n%s", stub)
	}
}

func TestStubBinsMkdirError(t *testing.T) {
	dir := t.TempDir()
	// prefix sits under a regular file, so <prefix>/bin cannot be created.
	file := filepath.Join(dir, "afile")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := StubBins(nil, dir, filepath.Join(file, "sub")); err == nil {
		t.Error("expected mkdir error for bin dir under a file")
	}
}

func TestStubBinsWriteError(t *testing.T) {
	defer fakeServer(t, map[string]fakePkg{
		"acme.org/tool": {
			versions: []string{"1.0.0"},
			yaml:     "provides:\n  - bin/tool\n",
			files:    map[string]string{"bin/tool": "#!x\n"},
		},
	})()
	dir := t.TempDir()
	if _, err := Install(Resolved{"acme.org/tool", ParseVer("1.0.0")}, dir); err != nil {
		t.Fatal(err)
	}
	prefix := filepath.Join(dir, "stubprefix")
	// Pre-create <prefix>/bin/tool as a NON-EMPTY directory: os.Remove fails
	// (dir not empty) and os.WriteFile then fails (target is a dir).
	clash := filepath.Join(prefix, "bin", "tool")
	if err := os.MkdirAll(clash, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(clash, "keep"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := StubBins([]Resolved{{"acme.org/tool", ParseVer("1.0.0")}}, dir, prefix); err == nil {
		t.Error("expected write error when the stub path is a non-empty dir")
	}
}

func TestFindLoaderUnmappedArch(t *testing.T) {
	setGoarch(t, "riscv64") // LoaderName() == "" for an unmapped arch
	if got := FindLoader(t.TempDir()); got != "" {
		t.Errorf("FindLoader on unmapped arch = %q, want empty", got)
	}
}

func TestSetupScratchRootfs(t *testing.T) {
	skipOnWASI(t, wasiNoSymlink)
	// Pin a mapped arch instead of trusting the host to have one: on
	// GOARCH=wasm LoaderName() is "" and the loop under test never runs, so
	// this asserted nothing there and failed on the symlink it expected.
	setGoarch(t, "aarch64")
	dir := t.TempDir()
	oldDirs := loaderDirs
	loaderDirs = []string{filepath.Join(dir, "lib"), filepath.Join(dir, "lib64")}
	defer func() { loaderDirs = oldDirs }()

	// Host arch is mapped, so LoaderName() is non-empty and the loader gets
	// symlinked into every loaderDir; shellPath="" skips the /bin/sh branch.
	SetupScratchRootfs("/opt/pkgx/loader", "")
	if _, err := os.Lstat(filepath.Join(dir, "lib", LoaderName())); err != nil {
		t.Errorf("loader symlink not created: %v", err)
	}
	// shellPath set exercises the /bin/sh branch (os.Symlink to an existing
	// /bin/sh no-ops with EEXIST, so this never clobbers the host).
	SetupScratchRootfs("/opt/pkgx/loader", "/opt/pkgx/bin/sh")

	// Unmapped arch -> LoaderName()=="" -> the loader loop is skipped.
	setGoarch(t, "riscv64")
	SetupScratchRootfs("/opt/pkgx/loader", "")
}

func TestCanonicalLoaderExists(t *testing.T) {
	// Same reason as TestSetupScratchRootfs: with LoaderName() == "" the file
	// this writes is the DIRECTORY, and the assertion becomes nonsense.
	setGoarch(t, "aarch64")
	dir := t.TempDir()
	oldDirs := loaderDirs
	loaderDirs = []string{filepath.Join(dir, "lib"), filepath.Join(dir, "lib64")}
	defer func() { loaderDirs = oldDirs }()

	if CanonicalLoaderExists() {
		t.Error("no loader present yet")
	}
	if err := os.MkdirAll(filepath.Join(dir, "lib"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "lib", LoaderName()), []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if !CanonicalLoaderExists() {
		t.Error("loader present but not found")
	}
	setGoarch(t, "riscv64") // unmapped -> false
	if CanonicalLoaderExists() {
		t.Error("unmapped arch must report no canonical loader")
	}
}

// --- oci.go: parsing, auth, error branches ----------------------------------

func TestNewOCIClientEmptyHost(t *testing.T) {
	// host empty after the scheme/slash split.
	if _, err := newOCIClientEnv("oci:///repo", func(string) string { return "" }); err == nil {
		t.Error("expected error for empty host")
	}
}

func TestOCICredentialCallback(t *testing.T) {
	fr := newFakeRegistry(t, true) // require "Bearer test-token"
	defer fr.close()
	base := fr.base("go-zpkg/artifacts")
	// A pre-issued OCI_TOKEN is used directly as the bearer; building it via the
	// env seam sets the Credential callback, which the auth flow then invokes.
	c, err := newOCIClientEnv(base, func(k string) string {
		if k == "OCI_TOKEN" {
			return "test-token"
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Push("cred.test", "1.0.0", "linux", "x86-64", makeGzTarball("cred"), ".tar.gz"); err != nil {
		t.Fatalf("authed push via credential callback: %v", err)
	}
}

func TestOCIListTagsPullBadProject(t *testing.T) {
	fr := newFakeRegistry(t, false)
	defer fr.close()
	c, _ := NewOCIClient(fr.base("go-zpkg/artifacts"))
	bad := "BAD..name/../x"
	if _, err := c.ListTags(bad); err == nil {
		t.Error("ListTags should error for a bad project")
	}
	if _, _, err := c.Pull(bad, "1.0.0", "linux", "x86-64"); err == nil {
		t.Error("Pull should error for a bad project")
	}
}

// pushSinglePlatformManifest tags ver directly at an image manifest (NOT wrapped
// in an index) whose single layer has the given media type — used to reach the
// "layer is not an artifact" / "no artifact layer" branches of Pull.
func pushSinglePlatformManifest(t *testing.T, c *OCIClient, project, ver, layerMedia string, blob []byte) {
	t.Helper()
	ctx := context.Background()
	repo, err := c.repository(project)
	if err != nil {
		t.Fatal(err)
	}
	ld := orascontent.NewDescriptorFromBytes(layerMedia, blob)
	if err := pushIfAbsent(ctx, repo, ld, blob); err != nil {
		t.Fatal(err)
	}
	md, err := oras.PackManifest(ctx, repo, oras.PackManifestVersion1_1, ArtifactType,
		oras.PackManifestOptions{Layers: []ocispec.Descriptor{ld}})
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.Tag(ctx, md, ver); err != nil {
		t.Fatal(err)
	}
}

func TestOCIPullNoArtifactLayer(t *testing.T) {
	fr := newFakeRegistry(t, false)
	defer fr.close()
	c, _ := NewOCIClient(fr.base("go-zpkg/artifacts"))
	// a single-platform manifest whose only layer is not a recognised artifact.
	pushSinglePlatformManifest(t, c, "nolayer.test", "1.0.0", "application/vnd.oci.empty.v1+json", []byte("{}"))
	if _, _, err := c.Pull("nolayer.test", "1.0.0", "linux", "x86-64"); err == nil ||
		!strings.Contains(err.Error(), "no artifact layer") {
		t.Errorf("expected no-artifact-layer error, got %v", err)
	}
}

func TestOCIPullLayerFetchError(t *testing.T) {
	fr := newFakeRegistry(t, false)
	defer fr.close()
	c, _ := NewOCIClient(fr.base("go-zpkg/artifacts"))
	if err := c.Push("layer.fail", "1.0.0", "linux", "x86-64", makeGzTarball("body"), ".tar.gz"); err != nil {
		t.Fatal(err)
	}
	// fail the layer blob GET (blobs are addressed by digest).
	fr.hook = func(r *http.Request) (int, bool) {
		_, verb, _ := splitV2(r.URL.Path)
		return 500, r.Method == "GET" && verb == "blobs"
	}
	if _, _, err := c.Pull("layer.fail", "1.0.0", "linux", "x86-64"); err == nil {
		t.Error("expected layer fetch failure")
	}
}

func TestOCIResolvePlatformReadError(t *testing.T) {
	fr := newFakeRegistry(t, false)
	defer fr.close()
	c, _ := NewOCIClient(fr.base("go-zpkg/artifacts"))
	if err := c.Push("corrupt.test", "1.0.0", "linux", "x86-64", makeGzTarball("body"), ".tar.gz"); err != nil {
		t.Fatal(err)
	}
	// Advertise a bogus digest for the version tag: the read verifies and fails.
	fr.corruptDigest = map[string]bool{c.repoName("corrupt.test") + "|1.0.0": true}
	if _, _, err := c.Pull("corrupt.test", "1.0.0", "linux", "x86-64"); err == nil {
		t.Error("expected read-verification failure on a corrupt digest")
	}
}

func TestOCIUnmarshalErrors(t *testing.T) {
	fr := newFakeRegistry(t, false)
	defer fr.close()
	c, _ := NewOCIClient(fr.base("go-zpkg/artifacts"))
	repo := c.repoName("bad.json")
	// index media type + invalid JSON -> the index unmarshal branch.
	fr.injectManifest(repo, "1.0.0", ocispec.MediaTypeImageIndex, []byte("{not json"))
	if _, _, err := c.Pull("bad.json", "1.0.0", "linux", "x86-64"); err == nil {
		t.Error("expected index unmarshal error")
	}
	// image manifest media type + invalid JSON -> the manifest unmarshal branch.
	fr.injectManifest(repo, "2.0.0", ocispec.MediaTypeImageManifest, []byte("{not json"))
	if _, _, err := c.Pull("bad.json", "2.0.0", "linux", "x86-64"); err == nil {
		t.Error("expected manifest unmarshal error")
	}
}

func TestOCIVerifyArtifactSigFetchError(t *testing.T) {
	fr := newFakeRegistry(t, false)
	defer fr.close()
	c, _ := NewOCIClient(fr.base("go-zpkg/artifacts"))
	tarball := makeGzTarball("sig-body")
	// push with a signature referrer whose annotation/payload are well-formed.
	_, err := c.PushWithReferrers("sigfetch.test", "1.0.0", "linux", "x86-64", tarball, ".tar.gz",
		[]Referrer{{ArtifactType: ArtifactTypeSignature, MediaType: MediaSimpleSigning, Blob: []byte(`{}`),
			Annotations: map[string]string{CosignSignatureAnnotation: "AAAA"}}})
	if err != nil {
		t.Fatal(err)
	}
	// Let the platform manifest resolve (1st by-digest manifest GET) but fail the
	// signature manifest fetch (2nd by-digest manifest GET).
	n := 0
	fr.hook = func(r *http.Request) (int, bool) {
		_, verb, ref := splitV2(r.URL.Path)
		if r.Method == "GET" && verb == "manifests" && strings.HasPrefix(ref, "sha256:") {
			n++
			return 500, n >= 2
		}
		return 0, false
	}
	if err := c.VerifyArtifact("sigfetch.test", "1.0.0", "linux", "x86-64", tarball); err == nil {
		t.Error("expected signature-manifest fetch failure")
	}
}

func TestOCIPushLayerFailure(t *testing.T) {
	fr := newFakeRegistry(t, false)
	defer fr.close()
	c, _ := NewOCIClient(fr.base("go-zpkg/artifacts"))
	// fail every blob upload -> the layer push (and its re-Exists recheck) fail.
	fr.hook = func(r *http.Request) (int, bool) {
		_, verb, _ := splitV2(r.URL.Path)
		return 500, verb == "uploads"
	}
	if err := c.Push("pushlayer.fail", "1.0.0", "linux", "x86-64", makeGzTarball("x"), ".tar.gz"); err == nil {
		t.Error("expected push-layer failure")
	}
}

func TestOCIPushBlobRaceThenPackFailure(t *testing.T) {
	fr := newFakeRegistry(t, false)
	defer fr.close()
	c, _ := NewOCIClient(fr.base("go-zpkg/artifacts"))
	tarball := makeGzTarball("racebody")
	layerMedia := MediaLayerGz
	ld := orascontent.NewDescriptorFromBytes(layerMedia, tarball)
	// Pre-store the LAYER blob so the post-failure re-Exists finds it, driving the
	// "a concurrent push raced us" success branch of pushIfAbsent.
	fr.mu.Lock()
	fr.blobs[c.repoName("race.blob")+"|"+ld.Digest.String()] = tarball
	fr.mu.Unlock()

	firstHead := true
	fr.hook = func(r *http.Request) (int, bool) {
		_, verb, _ := splitV2(r.URL.Path)
		if r.Method == "HEAD" && verb == "blobs" && firstHead {
			firstHead = false
			return 404, true // first existence check misses
		}
		if verb == "uploads" {
			return 500, true // every upload fails
		}
		return 0, false
	}
	// layer pushIfAbsent: miss, push fails, recheck HITS (return nil); then
	// PackManifest's config-blob upload fails -> pack-manifest error.
	if _, err := c.PushWithReferrers("race.blob", "1.0.0", "linux", "x86-64", tarball, ".tar.gz", nil); err == nil {
		t.Error("expected pack-manifest failure after the layer race")
	}
	if firstHead {
		t.Error("the first blob existence check was never exercised")
	}
}

func TestIndexRetryBackoffDefault(t *testing.T) {
	indexRetryBackoff(0) // the real (0ms) sleep body
}

func TestFetchOrNewIndexNonIndexAndBadJSON(t *testing.T) {
	fr := newFakeRegistry(t, false)
	defer fr.close()
	c, _ := NewOCIClient(fr.base("go-zpkg/artifacts"))

	// (a) version tag already points at a plain image manifest (not an index):
	// fetchOrNewIndex must treat it as absent and start fresh, then Push succeeds.
	pushSinglePlatformManifest(t, c, "nonidx.test", "1.0.0", MediaLayerGz, makeGzTarball("x"))
	if err := c.Push("nonidx.test", "1.0.0", "linux", "x86-64", makeGzTarball("x"), ".tar.gz"); err != nil {
		t.Fatalf("push over a non-index tag: %v", err)
	}
	// (b) version tag is an index media type but malformed JSON: fetchOrNewIndex
	// falls back to a fresh index, and the push still succeeds.
	fr.injectManifest(c.repoName("badidx.test"), "1.0.0", ocispec.MediaTypeImageIndex, []byte("{bad"))
	if err := c.Push("badidx.test", "1.0.0", "linux", "x86-64", makeGzTarball("y"), ".tar.gz"); err != nil {
		t.Fatalf("push over a malformed index tag: %v", err)
	}
}

// --- zpkg.go: OCI client wiring + satisfies + version listing ---------------

func withDist(t *testing.T, dist string) {
	t.Helper()
	old := DistBase
	DistBase = dist
	resetOCICache()
	t.Cleanup(func() { DistBase = old; resetOCICache() })
}

func TestOCIClientForDistError(t *testing.T) {
	withDist(t, "oci://hostonly") // no repo path -> NewOCIClient fails
	if _, err := ociClientForDist(); err == nil {
		t.Error("expected client build error")
	}
}

func TestSatisfiesTildeBranches(t *testing.T) {
	if ParseVer("1.1.0").satisfies("~1.2") {
		t.Error("1.1.0 is below the ~1.2 lower bound")
	}
	// a >2-component tilde caps the pin at major.minor.
	if !ParseVer("2.6.3.9").satisfies("~2.6.3.4") {
		t.Error("2.6.3.9 should satisfy ~2.6.3.4 (major.minor pin)")
	}
	if ParseVer("2.7.0.0").satisfies("~2.6.3.4") {
		t.Error("2.7.x must not satisfy ~2.6.3.4")
	}
}

func TestOCIVersionsForClientError(t *testing.T) {
	withDist(t, "oci://hostonly")
	if _, err := VersionsFor("p", "linux", "x86-64"); err == nil {
		t.Error("expected client error from ociVersionsFor")
	}
}

func TestOCIVersionsForSorted(t *testing.T) {
	fr := newFakeRegistry(t, false)
	defer fr.close()
	c, _ := NewOCIClient(fr.base("go-zpkg/artifacts"))
	for _, v := range []string{"2.0.0", "1.0.0", "1.5.0"} {
		if err := c.Push("multi.test", v, "linux", "x86-64", makeGzTarball(v), ".tar.gz"); err != nil {
			t.Fatal(err)
		}
	}
	withDist(t, fr.base("go-zpkg/artifacts"))
	vs, err := VersionsFor("multi.test", "linux", "x86-64")
	if err != nil || len(vs) != 3 {
		t.Fatalf("VersionsFor n=%d err=%v", len(vs), err)
	}
	if vs[0].Raw != "1.0.0" || vs[2].Raw != "2.0.0" {
		t.Errorf("not ascending: %v", []string{vs[0].Raw, vs[1].Raw, vs[2].Raw})
	}
}

func TestPickVersionFetchError(t *testing.T) {
	withDist(t, "oci://hostonly")
	if _, err := PickVersion("p", "*"); err == nil {
		t.Error("expected FetchVersions error to surface")
	}
}

func TestDownloadArtifactOCIClientError(t *testing.T) {
	withDist(t, "oci://hostonly")
	t.Setenv("ZPKG_VERIFY", "0")
	if _, _, err := DownloadArtifact("p", "1.0.0", "linux", "x86-64"); err == nil {
		t.Error("expected OCI client error")
	}
}

func TestDownloadArtifactHTTPGetError(t *testing.T) {
	withDist(t, "http://127.0.0.1:0") // no listener
	t.Setenv("ZPKG_VERIFY", "0")
	if _, _, err := DownloadArtifact("p", "1.0.0", "linux", "x86-64"); err == nil {
		t.Error("expected HTTP GET (dial) error")
	}
}

func TestDownloadArtifactHTTPReadError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".tar.gz") {
			w.Header().Set("Content-Length", "4096") // lie: promise more than we send
			w.WriteHeader(200)
			_, _ = w.Write([]byte("short"))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	withDist(t, srv.URL)
	t.Setenv("ZPKG_VERIFY", "0")
	if _, _, err := DownloadArtifact("p", "1.0.0", "linux", "x86-64"); err == nil {
		t.Error("expected body read error on truncated response")
	}
}

func TestFetchMetaErrors(t *testing.T) {
	// (a) package.yml not served -> httpGet 404 error.
	closeA := fakeServer(t, map[string]fakePkg{
		"present.org/tool": {versions: []string{"1.0.0"}, yaml: "provides:\n  - bin/tool\n"},
	})
	if _, _, err := FetchMeta("absent.org/nope"); err == nil {
		t.Error("expected 404 error for absent package.yml")
	}
	closeA()
	// (b) malformed YAML -> unmarshal error.
	defer fakeServer(t, map[string]fakePkg{
		"bad.org/yaml": {yaml: "dependencies:\n\tbad: indentation\n"}, // tab indent is invalid YAML
	})()
	if _, _, err := FetchMeta("bad.org/yaml"); err == nil {
		t.Error("expected YAML unmarshal error")
	}
}

func TestResolveClosureBranches(t *testing.T) {
	// A diamond (root -> b, c ; b -> d ; c -> d) exercises the already-seen skip.
	defer fakeServer(t, map[string]fakePkg{
		"a/root":   {versions: []string{"1.0.0"}, yaml: "dependencies:\n  b/x: '*'\n  c/x: '*'\nprovides:\n  - bin/root\n"},
		"b/x":      {versions: []string{"1.0.0"}, yaml: "dependencies:\n  d/x: '*'\nprovides:\n  - bin/b\n"},
		"c/x":      {versions: []string{"1.0.0"}, yaml: "dependencies:\n  d/x: '*'\nprovides:\n  - bin/c\n"},
		"d/x":      {versions: []string{"1.0.0"}, yaml: "provides:\n  - bin/d\n"},
		"bad/ver":  {versions: []string{"1.0.0"}, yaml: "provides:\n  - bin/x\n"},
		"bad/yaml": {versions: []string{"1.0.0"}, yaml: "dependencies:\n\tnope\n"},
	})()
	clo, err := ResolveClosure(map[string]string{"a/root": "*"})
	if err != nil {
		t.Fatal(err)
	}
	if len(clo) != 4 {
		t.Fatalf("diamond closure = %d, want 4 (root,b,c,d)", len(clo))
	}
	// PickVersion error inside the walk.
	if _, err := ResolveClosure(map[string]string{"bad/ver": "^9"}); err == nil {
		t.Error("expected version-resolution error")
	}
	// FetchMeta (yaml) error inside the walk.
	if _, err := ResolveClosure(map[string]string{"bad/yaml": "*"}); err == nil {
		t.Error("expected metadata error")
	}
}

// ⛔⛔ VERSION "1.2" WAS THE SELF-SYMLINK CASE, AND IT IS NOW SIMPLY ABSENT.
// The `v{maj}.{min}` alias for 1.2 IS `v1.2`, which used to be the real
// directory — so writeVersionLinks had to SKIP it or write `v1.2 -> v1.2`, a
// self-symlink that left the version unresolvable.
//
// There are no aliases. The install produces exactly one entry, it carries
// the hash, and the whole family of "which alias should move where" problems
// goes with them.
func TestATwoComponentVersionProducesOneHashedEntry(t *testing.T) {
	defer fakeServer(t, map[string]fakePkg{
		"al.org/tool": {versions: []string{"1.2"}, yaml: "provides:\n  - bin/tool\n", files: map[string]string{"bin/tool": "x"}},
	})()
	dir := t.TempDir()
	if _, err := Install(Resolved{"al.org/tool", ParseVer("1.2")}, dir); err != nil {
		t.Fatal(err)
	}
	ents, err := os.ReadDir(filepath.Join(dir, "al.org/tool"))
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 1 {
		t.Fatalf("%d entries, want one hashed build: %v", len(ents), entryNames(ents))
	}
	if !strings.HasPrefix(ents[0].Name(), "v1.2"+variantSep) {
		t.Errorf("entry %q is not the hashed build of 1.2", ents[0].Name())
	}
	// And it resolves to the payload through the one path that exists.
	p := StorePrefix(dir, "al.org/tool", ParseVer("1.2"))
	if _, err := os.Stat(filepath.Join(p, "bin", "tool")); err != nil {
		t.Errorf("the build does not hold the payload: %v", err)
	}
}

// --- install.go / zpkg.go: Install over OCI + failure paths -----------------

func ociGzArtifact(t *testing.T, project, ver string, files map[string]string) []byte {
	t.Helper()
	return makeArtifactGz(t, project, ver, files)
}

func ociXzArtifact(t *testing.T, project, ver string, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	xw, err := xz.NewWriter(&buf)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(xw)
	prefix := project + "/v" + ver + "/"
	_ = tw.WriteHeader(&tar.Header{Name: prefix, Typeflag: tar.TypeDir, Mode: 0o755})
	for rel, c := range files {
		_ = tw.WriteHeader(&tar.Header{Name: prefix + rel, Typeflag: tar.TypeReg, Mode: 0o755, Size: int64(len(c))})
		_, _ = tw.Write([]byte(c))
	}
	_ = tw.Close()
	_ = xw.Close()
	return buf.Bytes()
}

func TestInstallOverOCIGzAndXz(t *testing.T) {
	t.Setenv("ZPKG_VERIFY", "0") // transport round-trip on unsigned artifacts
	fr := newFakeRegistry(t, false)
	defer fr.close()
	c, _ := NewOCIClient(fr.base("go-zpkg/artifacts"))
	osn, arch := HostSlug()
	if err := c.Push("gz.pkg", "1.0.0", osn, arch, ociGzArtifact(t, "gz.pkg", "1.0.0", map[string]string{"bin/g": "x"}), ".tar.gz"); err != nil {
		t.Fatal(err)
	}
	if err := c.Push("xz.pkg", "1.0.0", osn, arch, ociXzArtifact(t, "xz.pkg", "1.0.0", map[string]string{"bin/x": "y"}), ".tar.xz"); err != nil {
		t.Fatal(err)
	}
	withDist(t, fr.base("go-zpkg/artifacts"))
	dir := t.TempDir()

	if fresh, err := Install(Resolved{"gz.pkg", ParseVer("1.0.0")}, dir); err != nil || !fresh {
		t.Fatalf("gz install fresh=%v err=%v", fresh, err)
	}
	// Through StorePrefix: the store holds `v1.0.0-h<hash>` and nothing else,
	// so a path composed from the version alone names nothing.
	if _, err := os.Stat(filepath.Join(StorePrefix(dir, "gz.pkg", ParseVer("1.0.0")), "bin", "g")); err != nil {
		t.Errorf("gz artifact not extracted: %v", err)
	}
	if fresh, err := Install(Resolved{"xz.pkg", ParseVer("1.0.0")}, dir); err != nil || !fresh {
		t.Fatalf("xz install fresh=%v err=%v", fresh, err)
	}
	if _, err := os.Stat(filepath.Join(StorePrefix(dir, "xz.pkg", ParseVer("1.0.0")), "bin", "x")); err != nil {
		t.Errorf("xz artifact not extracted: %v", err)
	}
}

func TestInstallOverOCIErrors(t *testing.T) {
	skipOnWASI(t, wasiNoChmod)
	// Decode/extract errors on unsigned fixtures: without the opt-out the
	// fail-closed check refuses them first and none of these branches is reached.
	t.Setenv("ZPKG_VERIFY", "0")
	fr := newFakeRegistry(t, false)
	defer fr.close()
	c, _ := NewOCIClient(fr.base("go-zpkg/artifacts"))
	osn, arch := HostSlug()

	// a .tar.gz layer whose bytes are not gzip -> gzip.NewReader error.
	if err := c.Push("badgz.pkg", "1.0.0", osn, arch, []byte("not gzip at all"), ".tar.gz"); err != nil {
		t.Fatal(err)
	}
	// a .tar.xz layer whose bytes are not xz -> xz.NewReader error.
	if err := c.Push("badxz.pkg", "1.0.0", osn, arch, []byte("not xz at all"), ".tar.xz"); err != nil {
		t.Fatal(err)
	}
	// gz of a non-tar payload -> untar (tar.Next) error.
	if err := c.Push("notar.pkg", "1.0.0", osn, arch, makeGzTarball("not a tar"), ".tar.gz"); err != nil {
		t.Fatal(err)
	}
	// valid gz tar lacking <project>/v<ver> -> rename source missing error.
	var nb bytes.Buffer
	gz := gzip.NewWriter(&nb)
	tw := tar.NewWriter(gz)
	_ = tw.WriteHeader(&tar.Header{Name: "elsewhere/file", Typeflag: tar.TypeReg, Mode: 0o644, Size: 1})
	_, _ = tw.Write([]byte("x"))
	_ = tw.Close()
	_ = gz.Close()
	if err := c.Push("norename.pkg", "1.0.0", osn, arch, nb.Bytes(), ".tar.gz"); err != nil {
		t.Fatal(err)
	}
	if err := c.Push("ok.pkg", "1.0.0", osn, arch, ociGzArtifact(t, "ok.pkg", "1.0.0", map[string]string{"bin/o": "x"}), ".tar.gz"); err != nil {
		t.Fatal(err)
	}
	withDist(t, fr.base("go-zpkg/artifacts"))

	if _, err := Install(Resolved{"badgz.pkg", ParseVer("1.0.0")}, t.TempDir()); err == nil {
		t.Error("expected gzip reader error")
	}
	if _, err := Install(Resolved{"badxz.pkg", ParseVer("1.0.0")}, t.TempDir()); err == nil {
		t.Error("expected xz reader error")
	}
	if _, err := Install(Resolved{"notar.pkg", ParseVer("1.0.0")}, t.TempDir()); err == nil {
		t.Error("expected untar error")
	}
	if _, err := Install(Resolved{"norename.pkg", ParseVer("1.0.0")}, t.TempDir()); err == nil {
		t.Error("expected rename error for an artifact missing its prefix")
	}
	// Pull failure for an unpushed project -> fetchArtifact OCI error.
	if _, err := Install(Resolved{"ghost.pkg", ParseVer("1.0.0")}, t.TempDir()); err == nil {
		t.Error("expected pull error for an unpushed artifact")
	}

	// pkgxDir under a regular file -> MkdirAll(pkgxDir) error.
	base := t.TempDir()
	file := filepath.Join(base, "afile")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Install(Resolved{"ok.pkg", ParseVer("1.0.0")}, filepath.Join(file, "sub")); err == nil {
		t.Error("expected MkdirAll(pkgxDir) error")
	}
	// pkgxDir exists but is unwritable -> MkdirTemp error.
	//
	// Only askable of a user that permission bits apply to: root is not refused
	// by one, so under a VM or a container that runs as root this reads as a
	// defect in Install rather than as a question that could not be posed.
	if os.Geteuid() != 0 {
		noWrite := filepath.Join(t.TempDir(), "ro")
		if err := os.Mkdir(noWrite, 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(noWrite, 0o755) })
		if _, err := Install(Resolved{"ok.pkg", ParseVer("1.0.0")}, noWrite); err == nil {
			t.Error("expected MkdirTemp error in a read-only pkgxDir")
		}
	}
	// <pkgxDir>/<project> pre-created as a FILE -> MkdirAll(dir(prefix)) error.
	pd := t.TempDir()
	if err := os.WriteFile(filepath.Join(pd, "ok.pkg"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Install(Resolved{"ok.pkg", ParseVer("1.0.0")}, pd); err == nil {
		t.Error("expected MkdirAll(prefix parent) error")
	}
}

func TestFetchArtifactOCIClientError(t *testing.T) {
	withDist(t, "oci://hostonly")
	if _, _, _, err := fetchArtifact(Resolved{"a/b", ParseVer("1.0.0")}, "linux", "x86-64"); err == nil {
		t.Error("expected OCI client error in fetchArtifact")
	}
}

func TestFetchArtifactHTTPGetError(t *testing.T) {
	t.Setenv("ZPKG_VERIFY", "0") // transport error path: an HTTP dist is unverifiable by design
	withDist(t, "http://127.0.0.1:0")
	if _, _, _, err := fetchArtifact(Resolved{"a/b", ParseVer("1.0.0")}, "linux", "x86-64"); err == nil {
		t.Error("expected HTTP GET (dial) error in fetchArtifact")
	}
}

// --- zpkg.go: untar error branches ------------------------------------------

func tarBytes(t *testing.T, build func(tw *tar.Writer)) []byte {
	t.Helper()
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	build(tw)
	_ = tw.Close()
	return b.Bytes()
}

func TestUntarErrorBranches(t *testing.T) {
	// tar.Next parse error on garbage input.
	if err := untar(strings.NewReader("this is not a tar archive at all, no header here"), t.TempDir()); err == nil {
		t.Error("expected tar.Next parse error")
	}

	// TypeDir whose parent is a regular file.
	dir1 := t.TempDir()
	b := tarBytes(t, func(tw *tar.Writer) {
		_ = tw.WriteHeader(&tar.Header{Name: "p", Typeflag: tar.TypeReg, Mode: 0o644, Size: 1})
		_, _ = tw.Write([]byte("x"))
		_ = tw.WriteHeader(&tar.Header{Name: "p/sub", Typeflag: tar.TypeDir, Mode: 0o755})
	})
	if err := untar(bytes.NewReader(b), dir1); err == nil {
		t.Error("expected dir-mkdir error under a file")
	}

	// TypeSymlink whose parent is a regular file.
	dir2 := t.TempDir()
	b = tarBytes(t, func(tw *tar.Writer) {
		_ = tw.WriteHeader(&tar.Header{Name: "q", Typeflag: tar.TypeReg, Mode: 0o644, Size: 1})
		_, _ = tw.Write([]byte("x"))
		_ = tw.WriteHeader(&tar.Header{Name: "q/s", Typeflag: tar.TypeSymlink, Linkname: "target"})
	})
	if err := untar(bytes.NewReader(b), dir2); err == nil {
		t.Error("expected symlink error under a file")
	}

	// TypeLink to a non-existent source.
	dir3 := t.TempDir()
	b = tarBytes(t, func(tw *tar.Writer) {
		_ = tw.WriteHeader(&tar.Header{Name: "h", Typeflag: tar.TypeLink, Linkname: "does-not-exist"})
	})
	if err := untar(bytes.NewReader(b), dir3); err == nil {
		t.Error("expected hardlink error for a missing source")
	}

	// TypeReg whose parent is a regular file.
	dir4 := t.TempDir()
	b = tarBytes(t, func(tw *tar.Writer) {
		_ = tw.WriteHeader(&tar.Header{Name: "r", Typeflag: tar.TypeReg, Mode: 0o644, Size: 1})
		_, _ = tw.Write([]byte("x"))
		_ = tw.WriteHeader(&tar.Header{Name: "r/inner", Typeflag: tar.TypeReg, Mode: 0o644, Size: 1})
		_, _ = tw.Write([]byte("y"))
	})
	if err := untar(bytes.NewReader(b), dir4); err == nil {
		t.Error("expected reg-file mkdir error under a file")
	}

	// TypeReg whose target path is an existing directory -> OpenFile error.
	dir5 := t.TempDir()
	b = tarBytes(t, func(tw *tar.Writer) {
		_ = tw.WriteHeader(&tar.Header{Name: "d/", Typeflag: tar.TypeDir, Mode: 0o755})
		_ = tw.WriteHeader(&tar.Header{Name: "d", Typeflag: tar.TypeReg, Mode: 0o644, Size: 1})
		_, _ = tw.Write([]byte("z"))
	})
	if err := untar(bytes.NewReader(b), dir5); err == nil {
		t.Error("expected open error when a reg target is a directory")
	}

	// TypeReg with a truncated stream -> io.Copy error.
	full := tarBytes(t, func(tw *tar.Writer) {
		_ = tw.WriteHeader(&tar.Header{Name: "big", Typeflag: tar.TypeReg, Mode: 0o644, Size: 8})
		_, _ = tw.Write([]byte("contents"))
	})
	if len(full) < 512+4 {
		t.Fatalf("tar too small: %d", len(full))
	}
	if err := untar(bytes.NewReader(full[:512+4]), t.TempDir()); err == nil {
		t.Error("expected copy error on a truncated file entry")
	}
}

// --- closure.go: scanNeeded + CompleteClosure (linux) -----------------------

func TestScanNeededELF(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "prog"), minimalELF([]string{"libz.so.1", "libc.so.6"}), 0o755); err != nil {
		t.Fatal(err)
	}
	got := scanNeeded([]string{dir})
	if !got["libz.so.1"] || !got["libc.so.6"] {
		t.Errorf("scanNeeded = %v", got)
	}
}

func TestScanNeededImportError(t *testing.T) {
	// A parseable ELF whose .dynamic links a non-existent string table: elf.Open
	// succeeds but ImportedLibraries errors, so scanNeeded skips the file.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "prog"), buildELF([]string{"libz.so.1"}, 99), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := scanNeeded([]string{dir}); len(got) != 0 {
		t.Errorf("expected no sonames from a bad-link ELF, got %v", got)
	}
}

func TestInstallProvidingSonameMaxTry(t *testing.T) {
	vers := make([]string, 45)
	for i := range vers {
		vers[i] = fmt.Sprintf("%d.0.0", i+1)
	}
	defer fakeServer(t, map[string]fakePkg{
		"many.org/lib": {versions: vers, yaml: "provides:\n  - bin/x\n", files: map[string]string{"bin/x": "x"}},
	})()
	// no version ships the soname -> the walk bails at the maxTry bound.
	hostOS, hostArch := HostSlug()
	if _, ok, err := installProvidingSoname("many.org/lib", "libnope.so.9", t.TempDir(), hostOS, hostArch); ok || err != nil {
		t.Errorf("maxTry walk: ok=%v err=%v, want false/nil", ok, err)
	}
}

func TestInstallProvidingSonameInstallSkip(t *testing.T) {
	defer fakeServer(t, map[string]fakePkg{
		"drift.org/lib": {
			versions:   []string{"1.0.0", "2.0.0"},
			yaml:       "provides:\n  - bin/x\n",
			noArtifact: map[string]bool{"2.0.0": true}, // newest install fails -> continue
			filesByVer: map[string]map[string]string{"1.0.0": {"lib/libx.so.2": "x"}},
		},
	})()
	hostOS, hostArch := HostSlug()
	r, ok, err := installProvidingSoname("drift.org/lib", "libx.so.2", t.TempDir(), hostOS, hostArch)
	if err != nil || !ok || r.Version.Raw != "1.0.0" {
		t.Fatalf("expected fallback to 1.0.0: r=%+v ok=%v err=%v", r, ok, err)
	}
}

func TestCompleteClosureResolveError(t *testing.T) {
	defer fakeServer(t, map[string]fakePkg{
		"x/y": {versions: []string{"1.0.0"}, yaml: "provides:\n  - bin/y\n"},
	})()
	if _, err := CompleteClosure(map[string]string{"x/y": "^9"}, t.TempDir()); err == nil {
		t.Error("expected resolve error")
	}
}

func TestCompleteClosureInstallError(t *testing.T) {
	defer fakeServer(t, map[string]fakePkg{
		"x/y": {versions: []string{"1.0.0"}, yaml: "provides:\n  - bin/y\n", noArtifact: map[string]bool{"1.0.0": true}},
	})()
	if _, err := CompleteClosure(map[string]string{"x/y": "*"}, t.TempDir()); err == nil {
		t.Error("expected install error")
	}
}

func TestCompleteClosureImplicitInstallError(t *testing.T) {
	setGoos(t, "linux")
	defer fakeServer(t, map[string]fakePkg{
		"acme.org/tool": {versions: []string{"1.0.0"}, yaml: "provides:\n  - bin/tool\n",
			files: map[string]string{"bin/tool": string(minimalELF([]string{"libc.so.6"}))}},
		// glibc resolves but has no installable artifact -> implicit install fails.
		"gnu.org/glibc": {versions: []string{"2.44.0"}, yaml: "provides:\n  - bin/ld\n", noArtifact: map[string]bool{"2.44.0": true}},
	})()
	if _, err := CompleteClosure(map[string]string{"acme.org/tool": "*"}, t.TempDir()); err == nil {
		t.Error("expected implicit-root install error")
	}
}

func TestCompleteClosureImplicitResolveError(t *testing.T) {
	setGoos(t, "linux")
	// The tool needs libstdc++, so implicitRoots pulls in gnu.org/gcc/libstdcxx —
	// which is not served, so ResolveClosure of the implicit roots errors.
	defer fakeServer(t, map[string]fakePkg{
		"acme.org/tool": {versions: []string{"1.0.0"}, yaml: "provides:\n  - bin/tool\n",
			files: map[string]string{"bin/tool": string(minimalELF([]string{"libc.so.6", "libstdc++.so.6"}))}},
		"gnu.org/glibc": {versions: []string{"2.44.0"}, yaml: "provides:\n  - bin/ld\n", files: map[string]string{"lib/glibc-2.44/libc.so.6": "x"}},
	})()
	if _, err := CompleteClosure(map[string]string{"acme.org/tool": "*"}, t.TempDir()); err == nil {
		t.Error("expected implicit-roots resolve error")
	}
}

func TestCompleteClosureLinuxFull(t *testing.T) {
	setGoos(t, "linux")
	tool := minimalELF([]string{
		"libc.so.6", "libgcc_s.so.1", "libstdc++.so.6", "libgomp.so.1",
		"libz.so.1", "libbz2.so.1", "libncurses.so.6", "libncursesw.so.6",
		"libssl.so.3", // maps to openssl.org, which is NOT served -> provider lookup errors (skipped)
	})
	defer fakeServer(t, map[string]fakePkg{
		// declares glibc so it is in the initial closure (drives the implicit
		// "already have" skip when libstdcxx re-declares glibc).
		"acme.org/tool": {versions: []string{"1.0.0"},
			yaml:  "dependencies:\n  gnu.org/glibc: '*'\nprovides:\n  - bin/tool\n",
			files: map[string]string{"bin/tool": string(tool)}},
		"gnu.org/glibc":         {versions: []string{"2.44.0"}, yaml: "provides:\n  - bin/ld\n", files: map[string]string{"lib/glibc-2.44/libc.so.6": "x"}},
		"gnu.org/gcc/libstdcxx": {versions: []string{"14.0.0"}, yaml: "dependencies:\n  gnu.org/glibc: '*'\nprovides:\n  - bin/x\n", files: map[string]string{"lib/libstdc++.so.6": "x", "lib/libgcc_s.so.1": "x"}},
		"gnu.org/gcc":           {versions: []string{"14.0.0"}, yaml: "provides:\n  - bin/gcc\n", files: map[string]string{"lib/libgomp.so.1": "x"}},
		"zlib.net":              {versions: []string{"1.3.1"}, yaml: "provides:\n  - bin/z\n", files: map[string]string{"lib/libz.so.1": "x"}},
		"sourceware.org/bzip2":  {versions: []string{"1.0.8"}, yaml: "provides:\n  - bin/bz\n", files: map[string]string{"lib/libbz2.so.1": "x"}},
		// ncurses ships BOTH needed sonames from one artifact -> the second soname
		// resolves to an already-installed version (the dedup-by-version skip).
		"invisible-island.net/ncurses": {versions: []string{"6.5.0"}, yaml: "provides:\n  - bin/nc\n", files: map[string]string{"lib/libncurses.so.6": "x", "lib/libncursesw.so.6": "x"}},
	})()

	var said []string
	Warn = func(msg string) { said = append(said, msg) }
	defer func() { Warn = nil }()

	dir := t.TempDir()
	clo, err := CompleteClosure(map[string]string{"acme.org/tool": "*"}, dir)
	if err != nil {
		t.Fatal(err)
	}
	// libc/libgcc_s/libstdc++/libgomp come from the IMPLICIT groups, which install
	// AFTER `provided` is sampled — warning about them reports a gap the same
	// round is closing, and a diagnostic that cries wolf is worse than none.
	for _, msg := range said {
		for _, implicit := range []string{"libc.so.6", "libgcc_s.so.1", "libstdc++.so.6", "libgomp.so.1"} {
			if strings.Contains(msg, implicit) {
				t.Errorf("warned about the implicitly-provided %s: %q", implicit, msg)
			}
		}
	}
	// openssl.org is genuinely not served by this fixture: THAT one must be said.
	if len(said) != 1 || !strings.Contains(said[0], "libssl.so.3") {
		t.Errorf("expected exactly the libssl.so.3 diagnostic, got %v", said)
	}
	have := map[string]bool{}
	for _, r := range clo {
		have[r.Project] = true
	}
	for _, want := range []string{
		"acme.org/tool", "gnu.org/glibc", "gnu.org/gcc/libstdcxx", "gnu.org/gcc",
		"zlib.net", "sourceware.org/bzip2", "invisible-island.net/ncurses",
	} {
		if !have[want] {
			t.Errorf("completed closure missing %q: %v", want, have)
		}
	}
}
