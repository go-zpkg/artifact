package artifact

// OCI-registry transport for package artifacts, backed by the ORAS/CNCF Go
// library (oras.land/oras-go/v2) — the reference implementation for pulling and
// pushing OCI artifacts. Pure Go, CGO_ENABLED=0.
//
// A dist ref beginning with "oci://" (e.g. ZPKG_DIST=oci://ghcr.io/go-zpkg/packages)
// selects this transport instead of the static-HTTP tree. Artifacts are mapped
// to OCI artifacts Homebrew-style:
//
//   - repo   = <oci-base-repo>/<project>            (project lowercased; OCI repos
//              allow '/' and '.'). e.g. go-zpkg/packages/openssl.org
//   - tag    = the version                          (e.g. "1.1.1w")
//   - the manifest at that tag is an OCI image INDEX whose manifests[] each carry
//     platform{os,architecture} and point at a per-platform image manifest.
//   - each per-platform image manifest has a (scratch) config blob + ONE layer =
//     the artifact tarball (layer mediaType
//     application/vnd.go-zpkg.artifact.layer.v1.tar+gzip, or +xz, or +zstd).
//
// The arch slugs our pantry writes (x86-64 / aarch64) map to OCI/Go names
// (amd64 / arm64); os names (linux / darwin / windows) are shared. ORAS handles
// the registry v2 wire protocol (blob/manifest CAS) and anonymous/bearer/basic
// auth (including ghcr.io and Docker Hub token exchange) for us.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	specs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	oras "oras.land/oras-go/v2"
	orascontent "oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
)

// OCI media types.
//
// ⛔⛔ `vnd.pkgx.*` WAS A VENDOR NAMESPACE WE DO NOT OWN, FOR A FORMAT ITS
// OWNER DOES NOT DEFINE. Checked against upstream's own corpus
// (docs.pkgx.sh/llms-full.txt, read 2026-11-04) rather than assumed: pkgx
// distributes **plain HTTPS tarballs** from `dist.pkgx.dev/<pkg>/<os>/<arch>/`
// with `.sha256sum` and `.asc` beside them. It mentions no OCI registry, no
// artifact type and no media type at all. The OCI packaging is entirely ours
// — `bk` invented it — and we minted its names inside somebody else's vendor
// space.
//
// That is the same mistake as `go-pkgx.dev/catalog`: a name that looks like
// ours because we are the only ones using it, in a namespace whose owner
// never agreed. Once we stop promising compatibility with legacy pkgx, there
// is not even an argument of convenience left.
//
// ⛔ WRITE THE NEW ONE, READ BOTH. 42 756 artifacts are published carrying the
// old types and nothing rewrites a published manifest; a reader that accepted
// only the new type would make every one of them unreadable the day it
// shipped. A rename that breaks every install is not a rename.
//
// ⛔ AND THE COMPATIBILITY IS STRUCTURAL, WHICH IS WHY THERE ARE NO
// `legacy…` CONSTANTS HERE. `extForLayer` matches the codec SUFFIX
// (`tar+zstd`), never the whole string, so it reads both vendor spellings
// without being told about either; nothing in the read path compares against
// ArtifactType at all. Declaring unused legacy constants would have
// looked like a compatibility mechanism while being dead code.
//
// What pins it is a test holding the old strings as LITERALS
// (mediacompat_test.go). A literal cannot be changed in sympathy with the new
// constant during a tidy-up; a constant can.
const (
	MediaLayerGz = "application/vnd.go-zpkg.artifact.layer.v1.tar+gzip"
	MediaLayerXz = "application/vnd.go-zpkg.artifact.layer.v1.tar+xz"
	// +zstd is a media type the OCI image-spec itself defines (unlike, say,
	// brotli, which has none and would make every generic tool — skopeo, oras,
	// registry UIs — treat the layer as opaque).
	MediaLayerZst = "application/vnd.go-zpkg.artifact.layer.v1.tar+zstd"
	// ArtifactType marks an artifact image manifest (its manifest.config
	// carries this via ORAS PackManifest v1.1's artifactType).
	ArtifactType = "application/vnd.go-zpkg.artifact"
	// dockerManifestList is Docker's media type for a multi-platform index, which
	// some registries (Docker Hub) return instead of the OCI image index.
	dockerManifestList = "application/vnd.docker.distribution.manifest.list.v2+json"
)

// IsOCI reports whether a dist base selects the OCI transport.
func IsOCI(base string) bool { return strings.HasPrefix(base, "oci://") }

// --- arch mapping -----------------------------------------------------------

// ociArch maps a pkgx arch slug to the OCI/Go architecture name.
func ociArch(arch string) string {
	switch arch {
	case "x86-64":
		return "amd64"
	case "aarch64":
		return "arm64"
	default:
		return arch
	}
}

// pkgxArch maps an OCI/Go architecture name back to the pkgx arch slug.
func pkgxArch(arch string) string {
	switch arch {
	case "amd64":
		return "x86-64"
	case "arm64":
		return "aarch64"
	default:
		return arch
	}
}

// extForLayer maps an artifact layer mediaType to a file extension, or "" for a
// layer (e.g. the config blob) we don't recognise as an artifact tarball.
func extForLayer(mt string) string {
	switch {
	case strings.HasSuffix(mt, "tar+gzip"), strings.HasSuffix(mt, "tar.gzip"):
		return ExtTarGz
	case strings.HasSuffix(mt, "tar+xz"):
		return ExtTarXz
	case strings.HasSuffix(mt, "tar+zstd"):
		return ExtTarZst
	// Loose matches for media types that name the codec without the +form.
	// zstd FIRST: it is the only one of the three whose name contains another's
	// ("zstd" has no "xz", but a future "tar.zstd" must not fall through to a
	// substring rule written for something else).
	case strings.Contains(mt, "zstd"):
		return ExtTarZst
	case strings.Contains(mt, "gzip"):
		return ExtTarGz
	case strings.Contains(mt, "xz"):
		return ExtTarXz
	default:
		return ""
	}
}

// --- client -----------------------------------------------------------------

// OCIClient talks to an OCI distribution (registry v2) endpoint via ORAS. It is
// used by the artifact pull path and by the mirror push tool, so the OCI protocol
// lives in one place (ORAS).
type OCIClient struct {
	host      string // registry host[:port]
	repoBase  string // base repo path within the registry, e.g. "go-zpkg/artifacts"
	plainHTTP bool   // use http:// (localhost/loopback or explicit http scheme)
	client    *auth.Client
}

// NewOCIClient parses an oci:// dist base into a client. Localhost/loopback
// hosts default to plain HTTP (for a local zot/registry on a port); every other
// host uses HTTPS. Credentials are read from the environment: OCI_TOKEN (a
// pre-issued bearer), else OCI_USERNAME / OCI_PASSWORD for token exchange /
// basic auth. Public repositories work anonymously.
func NewOCIClient(base string) (*OCIClient, error) {
	return newOCIClientEnv(base, Env)
}

func newOCIClientEnv(base string, getenv func(string) string) (*OCIClient, error) {
	if !IsOCI(base) {
		return nil, fmt.Errorf("not an oci:// ref: %q", base)
	}
	rest := strings.TrimRight(strings.TrimPrefix(base, "oci://"), "/")
	// Allow an explicit scheme hint via a leading http://|https://.
	plainHint, forcedHTTP := false, false
	switch {
	case strings.HasPrefix(rest, "http://"):
		rest, plainHint, forcedHTTP = strings.TrimPrefix(rest, "http://"), true, true
	case strings.HasPrefix(rest, "https://"):
		rest, forcedHTTP = strings.TrimPrefix(rest, "https://"), true
	}
	slash := strings.IndexByte(rest, '/')
	if slash < 0 {
		return nil, fmt.Errorf("oci ref %q has no repository path", base)
	}
	host := rest[:slash]
	repoBase := strings.Trim(rest[slash+1:], "/")
	if host == "" || repoBase == "" {
		return nil, fmt.Errorf("oci ref %q missing host or repo", base)
	}
	plainHTTP := plainHint
	if !forcedHTTP && isLoopback(host) {
		plainHTTP = true
	}
	tok := getenv("OCI_TOKEN")
	user := getenv("OCI_USERNAME")
	pass := getenv("OCI_PASSWORD")
	cred := auth.Credential{}
	switch {
	case tok != "":
		cred.AccessToken = tok
	case user != "" || pass != "":
		cred.Username, cred.Password = user, pass
	}
	ac := &auth.Client{
		Client: HTTPClient,
		Cache:  auth.NewCache(),
	}
	if cred != (auth.Credential{}) {
		ac.Credential = func(_ context.Context, _ string) (auth.Credential, error) { return cred, nil }
	}
	return &OCIClient{
		host:      host,
		repoBase:  strings.ToLower(repoBase),
		plainHTTP: plainHTTP,
		client:    ac,
	}, nil
}

// isLoopback reports whether host (possibly host:port) is a loopback address,
// for which we default to plain HTTP.
func isLoopback(host string) bool {
	h := host
	if i := strings.LastIndexByte(h, ':'); i >= 0 {
		h = h[:i]
	}
	h = strings.Trim(h, "[]")
	return h == "localhost" || h == "127.0.0.1" || h == "::1"
}

// repoName returns the OCI repository path for a pkgx project (lowercased).
func (c *OCIClient) repoName(project string) string {
	return c.repoBase + "/" + strings.ToLower(project)
}

// repository builds an ORAS remote.Repository for a project.
func (c *OCIClient) repository(project string) (*remote.Repository, error) {
	// The same name, in the other kind of path. A registry reference is
	// not a filesystem path, but it is still assembled by concatenation
	// and a `..` in it is nobody's project.
	if err := ValidateProjectName(project); err != nil {
		return nil, err
	}
	repo, err := remote.NewRepository(c.host + "/" + c.repoName(project))
	if err != nil {
		return nil, err
	}
	repo.PlainHTTP = c.plainHTTP
	repo.Client = c.client
	// Registries that lack the referrers API (e.g. ghcr.io) make ORAS maintain a
	// referrers *tag* instead; its default GC then DELETEs the superseded index,
	// which ghcr rejects (405, no manifest deletion). Skip that GC — a small
	// dangling index manifest is harmless and keeps multi-referrer pushes working.
	repo.SkipReferrersGC = true
	return repo, nil
}

// --- pull -------------------------------------------------------------------

// errPlatformAbsent marks "the version tag exists but has no manifest for this
// os/arch" — a not-published signal (not a transport error) for HasPlatform.
var errPlatformAbsent = errors.New("platform not in index")

// HasPlatform reports whether (project, ver) is published for os/arch in the
// registry: true if a per-platform manifest resolves, false if the tag or the
// platform is absent (a not-yet-published signal), and an error only on a real
// transport/parse failure. The build factory uses it to skip already-published
// (project,version,platform) tuples — a pure-Go replacement for the curl+jq
// ghcr manifest probe.
func (c *OCIClient) HasPlatform(project, ver, osn, arch string) (bool, error) {
	repo, err := c.repository(project)
	if err != nil {
		return false, err
	}
	if _, _, err := c.resolvePlatform(context.Background(), repo, project, ver, osn, arch); err != nil {
		if errors.Is(err, errPlatformAbsent) || errors.Is(err, errdef.ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// ListTags returns the tags (versions) published for a project, or an error if
// the repository does not exist.
func (c *OCIClient) ListTags(project string) ([]string, error) {
	repo, err := c.repository(project)
	if err != nil {
		return nil, err
	}
	var tags []string
	err = repo.Tags(context.Background(), "", func(page []string) error {
		for _, t := range page {
			// `<ver>--<os>-<arch>` names one platform's manifest, not a version.
			// Letting it through would make every published platform look like a
			// release of its own to anything listing versions.
			if IsPlatformTag(t) {
				continue
			}
			tags = append(tags, t)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return tags, nil
}

// Platforms lists the platforms one version tag publishes, in pkgx's spelling
// (`linux/x86-64`), sorted and deduplicated.
//
// # WHY IT EXISTS
//
// A caller could already ask "is THIS platform published" one guess at a time
// — HasPlatform does that — and could not ask which ones are. ⛔ Measured
// 2026-10-20: `go-zpkg/packages`' daily CVE lane carried its platform list in
// the workflow file, the list said two, and the registry published SIX. The
// four nobody asked about were clean, so the cost was coverage rather than an
// exposure, but the mechanism guarantees the next platform is missed too
// (go-zpkg/pkgx#119).
//
// ⛔ AN EMPTY LIST IS AN ERROR, NEVER AN ANSWER. fetchOrNewIndex, the other
// reader of this document, turns every failure into an empty index on purpose
// — it is composing a push and "nothing published yet" is its normal case.
// For a LISTING that behaviour is the defect: "this version publishes no
// platform" and "I could not read the index" would print the same nothing,
// and this fleet has published that zero before.
func (c *OCIClient) Platforms(project, ver string) ([]string, error) {
	repo, err := c.repository(project)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	desc, rc, err := repo.FetchReference(ctx, ver)
	if err != nil {
		if repoAbsent(err) {
			return nil, &NotPublishedError{
				Project:  project,
				Registry: repo.Reference.Registry,
				Repo:     repo.Reference.Repository,
				Err:      err,
			}
		}
		return nil, fmt.Errorf("resolve %s v%s: %w", project, ver, err)
	}
	body, err := orascontent.ReadAll(rc, desc)
	rc.Close()
	if err != nil {
		return nil, fmt.Errorf("read the index of %s v%s: %w", project, ver, err)
	}
	// A single manifest is one platform's worth of bytes with nothing saying
	// which platform, so it cannot answer this question. Saying so beats
	// returning the host's guess.
	if !isIndexMedia(desc.MediaType, body) {
		return nil, fmt.Errorf("%s v%s is a single manifest (%s), not a multi-platform index: it does not say which platforms exist",
			project, ver, desc.MediaType)
	}
	var idx ocispec.Index
	if err := json.Unmarshal(body, &idx); err != nil {
		return nil, fmt.Errorf("decode the index of %s v%s: %w", project, ver, err)
	}
	seen := map[string]bool{}
	var out []string
	for _, m := range idx.Manifests {
		p := m.Platform
		// ⛔ THREE KINDS OF ENTRY ARE NOT A PLATFORM, and all three are
		// ordinary. An index may carry a descriptor with no platform at all;
		// buildkit writes attestation manifests as the literal
		// `unknown/unknown` (image-spec leaves the field optional and says
		// nothing against it); and either, named as one, would put a line in
		// this list that no caller can pass back to --platform.
		if p == nil || p.OS == "" || p.Architecture == "" {
			continue
		}
		if p.OS == "unknown" || p.Architecture == "unknown" {
			continue
		}
		name := p.OS + "/" + pkgxArch(p.Architecture)
		// A variant distinguishes platforms (arm/v7 against arm/v6), so
		// dropping it would merge two entries into one name and under-report.
		if p.Variant != "" {
			name += "/" + p.Variant
		}
		if !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s v%s: the index has %d entry(ies) and none of them names a platform",
			project, ver, len(idx.Manifests))
	}
	sort.Strings(out)
	return out, nil
}

// Pull downloads the artifact tarball for a project/version/os/arch and returns
// it in MEMORY. Prefer PullFile for anything artifact-sized: llvm.org is ~1.7 GiB
// and this makes the biggest package in the catalogue the memory floor of the
// caller. Kept for callers that genuinely want the bytes.
func (c *OCIClient) Pull(project, ver, osn, arch string) ([]byte, string, error) {
	f, ext, err := c.PullFile(project, ver, osn, arch)
	if err != nil {
		return nil, "", err
	}
	defer f.Close()
	data, err := ioReadAll(f)
	if err != nil {
		return nil, "", err
	}
	return data, ext, nil
}

// PullFile downloads the artifact tarball for a project/version/os/arch: fetch the
// version-tag manifest (an index, or a single-platform image manifest), pick the
// platform-matching image manifest, take its single non-config layer, stream the
// layer blob TO DISK. Returns the staged file (Close removes it) and the
// extension (".tar.gz"/".tar.xz") derived from the layer mediaType.
func (c *OCIClient) PullFile(project, ver, osn, arch string) (*BlobFile, string, error) {
	ctx := context.Background()
	repo, err := c.repository(project)
	if err != nil {
		return nil, "", err
	}
	_, man, err := c.resolvePlatform(ctx, repo, project, ver, osn, arch)
	if err != nil {
		return nil, "", err
	}
	for _, l := range man.Layers {
		ext := extForLayer(l.MediaType)
		if ext == "" {
			continue
		}
		// Resumable: a toolchain artifact can be gigabytes and a cut transfer
		// must not throw away what already arrived (see fetchblob.go).
		f, err := c.fetchBlobFile(ctx, project, l)
		if err != nil {
			return nil, "", err
		}
		return f, ext, nil
	}
	return nil, "", fmt.Errorf("no artifact layer for %s v%s (%s/%s)", project, ver, osn, arch)
}

// PlatformAnnotations returns the annotations on the per-platform image
// manifest — the map a publish attaches, e.g. org.go-zpkg.abi.provides.
//
// Separate from PullFile on purpose: the cache may serve the artifact, and a
// mirror's manifest is not the authority on what the artifact DECLARES. This
// always asks the dist the caller named.
func (c *OCIClient) PlatformAnnotations(project, ver, osn, arch string) (map[string]string, error) {
	ctx := context.Background()
	repo, err := c.repository(project)
	if err != nil {
		return nil, err
	}
	_, man, err := c.resolvePlatform(ctx, repo, project, ver, osn, arch)
	if err != nil {
		return nil, err
	}
	return man.Annotations, nil
}

// resolvePlatform resolves a version tag to the per-platform image manifest for
// os/arch: the tag is either a multi-platform index (pick the matching entry) or
// a single image manifest. It returns that manifest's descriptor (for referrer
// lookup) and its parsed body.
func (c *OCIClient) resolvePlatform(ctx context.Context, repo *remote.Repository, project, ver, osn, arch string) (ocispec.Descriptor, ocispec.Manifest, error) {
	tagDesc, rc, err := repo.FetchReference(ctx, ver)
	if err != nil {
		// ⛔ A REGISTRY THAT DOES NOT CARRY THE PACKAGE SAYS SO, rather than
		// handing a reader ghcr's transport error.
		//
		// Reported from the field on 2026-10-12. `pkgx openstack --version`
		// against our signed registry answered:
		//
		//	resolve opendev.org/openstack/python-openstackclient v10.4.0:
		//	  GET ".../manifests/10.4.0": GET "https://ghcr.io/token?scope=…":
		//	  response status code 403: denied: requested access to the resource is denied
		//
		// which reads as a credentials problem. It is not: ghcr answers 403
		// at the TOKEN endpoint for a repository that does not exist, so for
		// an anonymous read the honest reading is "we do not carry this".
		// That is exactly what repoAbsent already decides for the version
		// listing — this path simply never asked it, so the same condition
		// got two different voices depending on which call noticed first.
		//
		// repoAbsent, not a second classifier: it is the one that knows a 403
		// WITH credentials configured is a real access problem and must
		// surface, and duplicating that judgement here is how the two copies
		// would drift.
		if repoAbsent(err) {
			return ocispec.Descriptor{}, ocispec.Manifest{}, &NotPublishedError{
				Project:  project,
				Registry: repo.Reference.Registry,
				Repo:     repo.Reference.Repository,
				Err:      err,
			}
		}
		return ocispec.Descriptor{}, ocispec.Manifest{}, fmt.Errorf("resolve %s v%s: %w", project, ver, err)
	}
	body, err := orascontent.ReadAll(rc, tagDesc)
	rc.Close()
	if err != nil {
		return ocispec.Descriptor{}, ocispec.Manifest{}, err
	}
	manDesc, manBytes := tagDesc, body
	if isIndexMedia(tagDesc.MediaType, body) {
		var idx ocispec.Index
		if err := json.Unmarshal(body, &idx); err != nil {
			return ocispec.Descriptor{}, ocispec.Manifest{}, err
		}
		wantArch := ociArch(arch)
		var pick *ocispec.Descriptor
		for i := range idx.Manifests {
			m := idx.Manifests[i]
			if m.Platform != nil && m.Platform.OS == osn && m.Platform.Architecture == wantArch {
				pick = &m
				break
			}
		}
		if pick == nil {
			return ocispec.Descriptor{}, ocispec.Manifest{}, fmt.Errorf("no artifact for %s v%s (%s/%s): %w", project, ver, osn, arch, errPlatformAbsent)
		}
		manDesc = *pick
		manBytes, err = orascontent.FetchAll(ctx, repo, *pick)
		if err != nil {
			return ocispec.Descriptor{}, ocispec.Manifest{}, err
		}
	}
	var man ocispec.Manifest
	if err := json.Unmarshal(manBytes, &man); err != nil {
		return ocispec.Descriptor{}, ocispec.Manifest{}, err
	}
	return manDesc, man, nil
}

// VerifyArtifact checks the cosign-style signatures attached to a pulled artifact as
// OCI referrers against the configured trust set. It is fail-closed: no
// signature referrer, malformed ones, or too few that verify (or that do not
// commit to this tarball) all return an error.
func (c *OCIClient) VerifyArtifact(project, ver, osn, arch string, tarball []byte) error {
	sum := sha256.Sum256(tarball)
	return c.VerifyArtifactDigest(project, ver, osn, arch, "sha256:"+hex.EncodeToString(sum[:]))
}

// VerifyArtifactDigest is VerifyArtifact for an artifact identified by its DIGEST: the
// form an install uses, having streamed the tarball to disk and hashed it on
// the way past.
func (c *OCIClient) VerifyArtifactDigest(project, ver, osn, arch, digest string) error {
	rep, err := c.SignaturesOfDigest(project, ver, osn, arch, digest)
	if err != nil {
		return err
	}
	if verr := rep.Err(); verr != nil {
		return fmt.Errorf("artifact: %s v%s (%s/%s): %w", project, ver, osn, arch, verr)
	}
	return nil
}

// SignaturesOfDigest reports who signed an artifact. Its error is reserved for
// not being able to ASK — a registry that would not answer, or a subject
// carrying more signatures than this will look at. The verdict is the
// report's: see SignatureReport.Err.
//
// ⛔⛔ EVERY SIGNATURE REFERRER IS COLLECTED, NOT THE FIRST ONE. Taking the
// first was a defect the moment a second signer existed, and a quiet one: the
// registry decides the order of a referrers listing, so the same artifact would
// verify or fail depending on which signature it happened to serve first, and
// the failure would read as tampering. It also made the threshold
// unimplementable — "both builders signed this" and "one did" were the same
// answer.
func (c *OCIClient) SignaturesOfDigest(project, ver, osn, arch, digest string) (SignatureReport, error) {
	trust, err := LoadTrustSet()
	if err != nil {
		return SignatureReport{}, err
	}
	ctx := context.Background()
	repo, err := c.repository(project)
	if err != nil {
		return SignatureReport{}, err
	}
	desc, _, err := c.resolvePlatform(ctx, repo, project, ver, osn, arch)
	if err != nil {
		return SignatureReport{}, err
	}
	atts, malformed, err := c.attestations(ctx, repo, project, desc)
	if err != nil {
		return SignatureReport{}, err
	}
	names, untrusted, revoked, err := trust.count(digest, atts)
	if err != nil {
		return SignatureReport{}, fmt.Errorf("artifact: %s v%s (%s/%s): %w", project, ver, osn, arch, err)
	}
	return SignatureReport{Signers: names, Untrusted: untrusted, Malformed: malformed,
		Revoked: revoked, Threshold: trust.Threshold}, nil
}

// SignaturesOfTag reports who signed the artifact published under one tag,
// WITHOUT downloading the tarball: the digest the signature commits to is the
// per-platform manifest's layer digest, which the manifest already carries.
//
// It is what a listing uses — "who vouches for this build?" is a question you
// must be able to ask about a build you have not installed.
func (c *OCIClient) SignaturesOfTag(project, tag, osn, arch string) (SignatureReport, error) {
	rep, _, err := c.ProvenanceOfTag(project, tag, osn, arch)
	return rep, err
}

// ProvenanceOfTag answers both halves of "can I trust this build?" in ONE
// pass over the artifact's attestations: who signed it, and what built it.
//
// ⛔⛔ THE TWO ARE ONE QUESTION AND MUST COST ONE LISTING. A signature says
// these bytes are somebody's; it says nothing about what produced them. The
// builder — `https://github.com/go-zpkg/zbk@v0.64.0`, recorded by the factory
// in the in-toto statement's runDetails.builder.id — is the other half, and
// it is NOT in the build's identity: a zbk release must not re-address every
// artifact in the registry. So the only way to learn it is to read the
// attestation, and a caller that had to ask twice would pay two referrer
// listings for one screenful.
//
// The builder is "" when the artifact carries no provenance, or one this cannot
// parse. Empty means NOT RECORDED, never "built by nobody", and a caller that
// prints it must keep that distinction — the registry is still full of
// artifacts published before any of this existed.
func (c *OCIClient) ProvenanceOfTag(project, tag, osn, arch string) (SignatureReport, string, error) {
	trust, err := LoadTrustSet()
	if err != nil {
		return SignatureReport{}, "", err
	}
	ctx := context.Background()
	repo, err := c.repository(project)
	if err != nil {
		return SignatureReport{}, "", err
	}
	desc, man, err := c.resolvePlatform(ctx, repo, project, tag, osn, arch)
	if err != nil {
		return SignatureReport{}, "", err
	}
	if len(man.Layers) == 0 {
		return SignatureReport{}, "", fmt.Errorf("artifact: %s %s (%s/%s) has no layer to have signed", project, tag, osn, arch)
	}
	refs, err := c.Referrers(project, desc)
	if err != nil {
		return SignatureReport{}, "", err
	}
	atts, malformed, err := c.signatureAttestations(ctx, repo, project, refs)
	if err != nil {
		return SignatureReport{}, "", err
	}
	names, untrusted, revoked, err := trust.count(man.Layers[0].Digest.String(), atts)
	if err != nil {
		return SignatureReport{}, "", fmt.Errorf("artifact: %s %s (%s/%s): %w", project, tag, osn, arch, err)
	}
	rep := SignatureReport{Signers: names, Untrusted: untrusted, Malformed: malformed,
		Revoked: revoked, Threshold: trust.Threshold}
	return rep, c.builderFrom(ctx, repo, refs), nil
}

// builderFrom reads runDetails.builder.id out of the in-toto provenance.
//
// Every failure is "" — unreachable, unparseable and absent are all "nothing
// here says what built it", and a listing that refused to print because one
// attestation would not parse would trade a complete answer for none.
func (c *OCIClient) builderFrom(ctx context.Context, repo *remote.Repository, refs []ocispec.Descriptor) string {
	for i := range refs {
		if refs[i].ArtifactType != ArtifactTypeProvenance {
			continue
		}
		manBytes, err := orascontent.FetchAll(ctx, repo, refs[i])
		if err != nil {
			continue
		}
		var m ocispec.Manifest
		if json.Unmarshal(manBytes, &m) != nil || len(m.Layers) == 0 {
			continue
		}
		blob, err := orascontent.FetchAll(ctx, repo, m.Layers[0])
		if err != nil {
			continue
		}
		var doc struct {
			Predicate struct {
				RunDetails struct {
					Builder struct {
						ID string `json:"id"`
					} `json:"builder"`
				} `json:"runDetails"`
			} `json:"predicate"`
		}
		if json.Unmarshal(blob, &doc) != nil {
			continue
		}
		if id := doc.Predicate.RunDetails.Builder.ID; id != "" {
			return id
		}
	}
	return ""
}

// ArtifactDigest is the digest of the tarball published under one tag — the
// thing a signature commits to, read from the per-platform manifest without
// downloading a byte of the artifact.
//
// ⛔ IT IS WHAT A REBUILDER COMPARES AGAINST. "Did I produce the same artifact?"
// has to be answerable before deciding whether to sign, and answerable
// cheaply enough that asking is the normal thing to do.
func (c *OCIClient) ArtifactDigest(project, ver, osn, arch string) (string, error) {
	ctx := context.Background()
	repo, err := c.repository(project)
	if err != nil {
		return "", err
	}
	_, man, err := c.resolvePlatform(ctx, repo, project, ver, osn, arch)
	if err != nil {
		return "", err
	}
	if len(man.Layers) == 0 {
		return "", fmt.Errorf("artifact: %s %s (%s/%s) has no layer", project, ver, osn, arch)
	}
	return man.Layers[0].Digest.String(), nil
}

// AttachReferrer adds one attestation to an ALREADY PUBLISHED artifact, leaving
// the artifact itself untouched.
//
// ⛔⛔ A SECOND BUILDER MUST NOT HAVE TO REPUBLISH THE ARTIFACT TO VOUCH FOR IT.
// Every other path here pushes a tarball and its attestations together, which
// is right for the builder who made it and wrong for everyone else: re-pushing
// is how you end up with two objects where the point was that there is one.
// Independent agreement means several signatures on the SAME bytes, so
// attaching has to be an operation of its own.
func (c *OCIClient) AttachReferrer(project, ver, osn, arch string, rf Referrer) error {
	ctx := context.Background()
	repo, err := c.repository(project)
	if err != nil {
		return err
	}
	desc, _, err := c.resolvePlatform(ctx, repo, project, ver, osn, arch)
	if err != nil {
		return err
	}
	return c.pushReferrer(ctx, repo, desc, rf)
}

// attestations fetches every signature referrer on a subject and returns the
// candidate signatures, plus how many referrers were signature-typed but
// unusable.
//
// ⛔ THE MALFORMED ONES ARE COUNTED, NOT DROPPED. A skip that says nothing is
// a filter: "unsigned" and "signed, but the referrer is broken" are different
// facts and the second one names a publishing bug. The count rides along so
// the verdict can say which.
func (c *OCIClient) attestations(ctx context.Context, repo *remote.Repository, project string, subject ocispec.Descriptor) ([]Attestation, int, error) {
	refs, err := c.Referrers(project, subject)
	if err != nil {
		return nil, 0, err
	}
	return c.signatureAttestations(ctx, repo, project, refs)
}

// signatureAttestations is attestations over a referrer listing the caller
// already holds, so a caller that needs the provenance too pays for ONE
// listing instead of two.
func (c *OCIClient) signatureAttestations(ctx context.Context, repo *remote.Repository, project string, refs []ocispec.Descriptor) ([]Attestation, int, error) {
	var atts []Attestation
	malformed := 0
	for i := range refs {
		if refs[i].ArtifactType != ArtifactTypeSignature {
			continue
		}
		if len(atts)+malformed >= MaxSignatures {
			return nil, 0, fmt.Errorf("artifact: more than %d signature referrers on %s: refusing", MaxSignatures, project)
		}
		manBytes, err := orascontent.FetchAll(ctx, repo, refs[i])
		if err != nil {
			return nil, 0, err
		}
		// The referrer manifest is digest-verified content the listing has
		// already parsed, so a decode failure here is a malformed referrer
		// just like a missing annotation or layer — fold them.
		var man ocispec.Manifest
		b64 := ""
		if json.Unmarshal(manBytes, &man) == nil {
			b64 = man.Annotations[CosignSignatureAnnotation]
		}
		if b64 == "" || len(man.Layers) == 0 {
			malformed++
			continue
		}
		payload, err := orascontent.FetchAll(ctx, repo, man.Layers[0])
		if err != nil {
			return nil, 0, err
		}
		atts = append(atts, Attestation{Payload: payload, Sig: b64, KeyID: man.Annotations[SignerKeyIDAnnotation]})
	}
	return atts, malformed, nil
}

// isIndexMedia reports whether a manifest is an image index, by descriptor
// mediaType when set, else by sniffing the JSON body.
func isIndexMedia(mediaType string, body []byte) bool {
	switch mediaType {
	case ocispec.MediaTypeImageIndex, dockerManifestList:
		return true
	case ocispec.MediaTypeImageManifest:
		return false
	}
	var probe struct {
		MediaType string `json:"mediaType"`
		Manifests []any  `json:"manifests"`
	}
	_ = json.Unmarshal(body, &probe)
	if probe.MediaType == ocispec.MediaTypeImageIndex || probe.MediaType == dockerManifestList {
		return true
	}
	return len(probe.Manifests) > 0
}

// --- push -------------------------------------------------------------------

// Referrer is an attestation to attach to an artifact's per-platform manifest as an
// OCI referrer (subject-linked artifact): a CycloneDX/SPDX SBOM, an in-toto SLSA
// provenance statement, or (later) a cosign signature. ArtifactType classifies
// the referrer manifest; MediaType is the layer blob's media type (usually the
// same); Blob is the attestation bytes.
type Referrer struct {
	ArtifactType string
	MediaType    string
	Blob         []byte
	// Annotations are merged into the referrer manifest — used to carry a cosign
	// signature (dev.cosignproject.cosign/signature) alongside its payload blob.
	Annotations map[string]string
}

// Push publishes one artifact for a project/version/os/arch: it pushes the tarball
// as a layer blob, packs a per-platform image manifest (ORAS PackManifest, which
// also pushes a scratch config blob), then merges the platform into the
// version-tag image index (fetching any existing index first) and tags it. ext
// selects the layer mediaType (".tar.gz" or ".tar.xz").
func (c *OCIClient) Push(project, ver, osn, arch string, tarball []byte, ext string) error {
	_, err := c.push(project, ver, osn, arch, tarball, ext, nil, nil)
	return err
}

// PushWithReferrers is Push plus a set of attestations attached to the pushed
// per-platform manifest as OCI referrers. It returns that manifest's descriptor
// so callers can list/verify the referrers. Referrers are pushed before the
// version index is tagged, so a reader that resolves the index always finds a
// manifest whose attestations are already present.
func (c *OCIClient) PushWithReferrers(project, ver, osn, arch string, tarball []byte, ext string, refs []Referrer) (ocispec.Descriptor, error) {
	return c.push(project, ver, osn, arch, tarball, ext, refs, nil)
}

// PushWithReferrersAnnotated is PushWithReferrers plus annotations merged onto
// the per-platform image manifest — used to carry descriptive metadata such as
// org.go-zpkg.glibc.version and org.go-zpkg.glibc.min-kernel so glibc-flavored
// artifacts are self-describing.
func (c *OCIClient) PushWithReferrersAnnotated(project, ver, osn, arch string, tarball []byte, ext string, refs []Referrer, annotations map[string]string) (ocispec.Descriptor, error) {
	return c.push(project, ver, osn, arch, tarball, ext, refs, annotations)
}

func (c *OCIClient) push(project, ver, osn, arch string, tarball []byte, ext string, refs []Referrer, annotations map[string]string) (ocispec.Descriptor, error) {
	ctx := context.Background()
	repo, err := c.repository(project)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	// The extension is the source of truth for the codec; the media type is how
	// a puller learns it without sniffing bytes.
	layerMedia := MediaLayerGz
	switch ext {
	case ExtTarXz:
		layerMedia = MediaLayerXz
	case ExtTarZst:
		layerMedia = MediaLayerZst
	}
	layerDesc := orascontent.NewDescriptorFromBytes(layerMedia, tarball)
	if err := pushIfAbsent(ctx, repo, layerDesc, tarball); err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("push layer: %w", err)
	}
	// Pack + push a per-platform image manifest (config blob is created by ORAS).
	// pin a fixed created-time so the manifest digest is reproducible, then merge
	// any caller annotations (e.g. glibc.version/min-kernel).
	manAnn := map[string]string{ocispec.AnnotationCreated: "1970-01-01T00:00:00Z"}
	for k, v := range annotations {
		manAnn[k] = v
	}
	manDesc, err := oras.PackManifest(ctx, repo, oras.PackManifestVersion1_1, ArtifactType,
		oras.PackManifestOptions{
			Layers:              []ocispec.Descriptor{layerDesc},
			ManifestAnnotations: manAnn,
		})
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("pack manifest: %w", err)
	}
	manDesc.Platform = &ocispec.Platform{OS: osn, Architecture: ociArch(arch)}
	// Attach attestations as referrers of the platform manifest.
	for _, rf := range refs {
		if err := c.pushReferrer(ctx, repo, manDesc, rf); err != nil {
			return manDesc, fmt.Errorf("push referrer %s: %w", rf.ArtifactType, err)
		}
	}
	// Merge this platform into the version-tag image index. The index is a
	// read-modify-write with no registry-side lock, so two publishers racing on
	// the SAME (project, version) — e.g. the two arch matrix jobs both hitting a
	// shared dependency's first publish — could clobber each other (last write
	// wins, silently dropping a platform). mergePlatformIntoIndex reconciles.
	// Tag this platform's manifest under a name only THIS publisher writes, so
	// the set of platforms is enumerable outside the index. That is what makes
	// the index composable rather than merge-able: see platformTag.
	if _, err := oras.Tag(ctx, repo, manDesc.Digest.String(), platformTag(ver, osn, arch)); err != nil {
		return manDesc, fmt.Errorf("tag platform manifest: %w", err)
	}
	if err := c.mergePlatformIntoIndex(ctx, repo, ver, manDesc); err != nil {
		return manDesc, err
	}
	return manDesc, nil
}

// platformTag names one platform's manifest for a version: `<ver>--<os>-<arch>`.
//
// Only the job publishing that platform ever writes it, so it is never
// contended — unlike the version tag, where two arch jobs race on one mutable
// index and 428 entries were silently lost in a day's publishing.
//
// The DOUBLE dash is deliberate. A single one would make `1.2.3-linux-x86-64`
// look like a semver pre-release and be counted as a version by anything
// walking the tag list.
func platformTag(ver, osn, arch string) string {
	return ver + "--" + osn + "-" + arch
}

// IsPlatformTag reports whether a tag names a platform manifest rather than a
// version. Consumers walking a repository's tags need to skip these.
func IsPlatformTag(tag string) bool { return strings.Contains(tag, "--") }

// Reconcile seams (vars so tests can shrink them): indexRetryAttempts bounds the
// loop, indexRetryBackoff paces retries, indexSettle is how long a successful
// write waits before confirming it is still there, and afterTagHook fires right
// after a tag write so a test can simulate a concurrent clobber.
var (
	indexRetryAttempts = 6
	indexRetryBackoff  = func(attempt int) { time.Sleep(time.Duration(attempt) * 20 * time.Millisecond) }
	indexSettleDelay   = 2 * time.Second
	indexSettle        = func() { time.Sleep(indexSettleDelay) }
	afterTagHook       func()
)

// mergePlatformIntoIndex upserts manDesc's platform into the version-tag image
// index and re-tags, reconciling against concurrent writers: after each tag it
// re-reads the index and, if a racing publisher clobbered the tag and dropped
// our platform, re-merges from the now-current index (which preserves the
// racer's platform) and retries until ours survives.
//
// Verifying ONCE is not enough, and that is not a theoretical worry — it
// happened. python.org 3.14.7 was mirrored by the two arch jobs 350 ms apart:
//
//	14:18:42.63  ✅ MIRRORED python.org 3.14.7 linux/aarch64
//	14:18:42.98  ✅ MIRRORED python.org 3.14.7 linux/x86-64
//
// and the published index listed only amd64. The arm64 artifact was pushed, its
// manifest was fine, and it was simply not in the index — so every install for
// that platform failed with "platform not in index". The loop below had already
// run and had already confirmed arm64 was there: the clobber came AFTER, from a
// writer whose read of the index predated arm64's write. A registry that serves
// a stale read breaks the convergence argument — the racer re-merges from a
// state that never had us in it, checks its OWN platform, and exits happy.
//
// So a write is confirmed twice, with a settle window between: the second check
// catches a racer that landed just behind us, and the retry then re-merges from
// the now-current index (which has the racer's platform) and puts both back.
// This narrows the window rather than closing it — the honest fix is a
// single-writer index composition, which needs the platforms to be enumerable
// outside the index itself.
func (c *OCIClient) mergePlatformIntoIndex(ctx context.Context, repo *remote.Repository, ver string, manDesc ocispec.Descriptor) error {
	for attempt := 0; attempt < indexRetryAttempts; attempt++ {
		idx := c.fetchOrNewIndex(ctx, repo, ver)
		// Compose from the per-platform tags, not just from what the index
		// happens to say. Those tags are uncontended, so every racer sees the
		// same set and writes the same COMPLETE index: a clobber then replaces
		// an index with an identical one instead of dropping a platform. The
		// index's own contents are still merged in, so versions published
		// before platform tags existed keep theirs.
		for _, d := range c.platformManifests(ctx, repo, ver) {
			idx.Manifests = upsertPlatform(idx.Manifests, d)
		}
		idx.Manifests = upsertPlatform(idx.Manifests, manDesc)
		idxBytes, err := marshalIndex(idx)
		if err != nil {
			return err
		}
		if _, err := oras.TagBytes(ctx, repo, ocispec.MediaTypeImageIndex, idxBytes, ver); err != nil {
			return fmt.Errorf("tag index: %w", err)
		}
		if afterTagHook != nil {
			afterTagHook()
		}
		// Verify our platform survived a possible concurrent clobber, then wait
		// out the window in which a racer's stale-read write would land, and
		// verify again.
		if indexHasManifest(c.fetchOrNewIndex(ctx, repo, ver), manDesc) {
			indexSettle()
			if indexHasManifest(c.fetchOrNewIndex(ctx, repo, ver), manDesc) {
				return nil
			}
		}
		indexRetryBackoff(attempt + 1)
	}
	return fmt.Errorf("index for %s: platform %s/%s did not survive %d reconcile attempts (concurrent writers)",
		ver, manDesc.Platform.OS, manDesc.Platform.Architecture, indexRetryAttempts)
}

// marshalIndex is a seam so the (near-impossible) marshal-error branch is testable.
var marshalIndex = func(idx ocispec.Index) ([]byte, error) { return json.Marshal(idx) }

// indexHasManifest reports whether idx already lists a manifest with desc's digest.
func indexHasManifest(idx ocispec.Index, desc ocispec.Descriptor) bool {
	for _, m := range idx.Manifests {
		if m.Digest == desc.Digest {
			return true
		}
	}
	return false
}

// pushReferrer pushes one attestation blob and an artifact manifest that links
// it to subject via the OCI subject field (a referrer). On registries with the
// referrers API (ghcr) it is discoverable via Referrers.
func (c *OCIClient) pushReferrer(ctx context.Context, repo *remote.Repository, subject ocispec.Descriptor, rf Referrer) error {
	blobDesc := orascontent.NewDescriptorFromBytes(rf.MediaType, rf.Blob)
	if err := pushIfAbsent(ctx, repo, blobDesc, rf.Blob); err != nil {
		return err
	}
	subj := subject
	ann := map[string]string{ocispec.AnnotationCreated: "1970-01-01T00:00:00Z"}
	for k, v := range rf.Annotations {
		ann[k] = v
	}
	_, err := oras.PackManifest(ctx, repo, oras.PackManifestVersion1_1, rf.ArtifactType,
		oras.PackManifestOptions{
			Subject:             &subj,
			Layers:              []ocispec.Descriptor{blobDesc},
			ManifestAnnotations: ann,
		})
	return err
}

// Referrers lists the attestations attached to a manifest (its OCI referrers),
// each descriptor carrying the referrer's ArtifactType.
func (c *OCIClient) Referrers(project string, subject ocispec.Descriptor) ([]ocispec.Descriptor, error) {
	repo, err := c.repository(project)
	if err != nil {
		return nil, err
	}
	var out []ocispec.Descriptor
	err = repo.Referrers(context.Background(), subject, "", func(page []ocispec.Descriptor) error {
		out = append(out, page...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// pushIfAbsent pushes content only when the registry does not already hold it,
// so re-pushing an existing artifact is a no-op (and avoids EEXIST on registries
// that reject duplicate blob PUTs).
func pushIfAbsent(ctx context.Context, repo *remote.Repository, desc ocispec.Descriptor, data []byte) error {
	if ok, err := repo.Exists(ctx, desc); err == nil && ok {
		return nil
	}
	if err := repo.Push(ctx, desc, strings.NewReader(string(data))); err != nil {
		// A concurrent push may have raced us; treat an already-exists as success.
		if ok, e := repo.Exists(ctx, desc); e == nil && ok {
			return nil
		}
		return err
	}
	return nil
}

// fetchOrNewIndex returns the existing version-tag index, or a fresh empty one
// if the tag does not yet exist (or resolves to a non-index manifest).
func (c *OCIClient) fetchOrNewIndex(ctx context.Context, repo *remote.Repository, ver string) ocispec.Index {
	fresh := ocispec.Index{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: ocispec.MediaTypeImageIndex,
	}
	desc, rc, err := repo.FetchReference(ctx, ver)
	if err != nil {
		return fresh
	}
	body, err := orascontent.ReadAll(rc, desc)
	rc.Close()
	if err != nil || !isIndexMedia(desc.MediaType, body) {
		return fresh
	}
	var idx ocispec.Index
	if err := json.Unmarshal(body, &idx); err != nil {
		return fresh
	}
	idx.Versioned = specs.Versioned{SchemaVersion: 2}
	idx.MediaType = ocispec.MediaTypeImageIndex
	return idx
}

// upsertPlatform adds desc to a manifest list, replacing any existing entry for
// the same os/architecture.
func upsertPlatform(list []ocispec.Descriptor, desc ocispec.Descriptor) []ocispec.Descriptor {
	out := list[:0]
	for _, m := range list {
		if m.Platform != nil && desc.Platform != nil &&
			m.Platform.OS == desc.Platform.OS && m.Platform.Architecture == desc.Platform.Architecture {
			continue // drop the old entry for this platform
		}
		out = append(out, m)
	}
	return append(out, desc)
}

// platformManifests lists the per-platform manifests published for one version,
// read from the uncontended `<ver>--<os>-<arch>` tags.
//
// A registry that will not list tags yields nothing rather than an error: the
// composition then falls back to the index's own contents, which is exactly the
// behaviour that preceded platform tags.
func (c *OCIClient) platformManifests(ctx context.Context, repo *remote.Repository, ver string) []ocispec.Descriptor {
	prefix := ver + "--"
	var out []ocispec.Descriptor
	err := repo.Tags(ctx, "", func(page []string) error {
		for _, t := range page {
			if !strings.HasPrefix(t, prefix) {
				continue
			}
			desc, rc, err := repo.FetchReference(ctx, t)
			if err != nil {
				continue
			}
			// A resolved descriptor is BARE: mediaType, digest, size. Platform
			// is restored from the tag below; artifactType and the annotations
			// live in the manifest BODY, and upsertPlatform replaces a complete
			// index entry with whatever this returns — so without them an index
			// stops saying which of its entries are artifacts, on every platform
			// except the one being pushed.
			body, rerr := orascontent.ReadAll(rc, desc)
			rc.Close()
			if rerr == nil {
				var m struct {
					ArtifactType string            `json:"artifactType"`
					Annotations  map[string]string `json:"annotations"`
				}
				if json.Unmarshal(body, &m) == nil {
					desc.ArtifactType = m.ArtifactType
					desc.Annotations = m.Annotations
				}
			}
			if desc.Platform == nil {
				// Resolve returns a bare manifest descriptor, so the platform
				// comes from the tag. It carries the PKGX arch ("x86-64"), and
				// the index carries the OCI one ("amd64") — without the
				// conversion the composition adds a second entry for the same
				// platform instead of recognising it.
				osn, arch, ok := strings.Cut(strings.TrimPrefix(t, prefix), "-")
				if !ok {
					continue
				}
				desc.Platform = &ocispec.Platform{OS: osn, Architecture: ociArch(arch)}
			}
			out = append(out, desc)
		}
		return nil
	})
	if err != nil {
		return nil
	}
	return out
}
