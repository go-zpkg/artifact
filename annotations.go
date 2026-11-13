package artifact

// The annotation keys this project mints, and the ones it still has to read.
//
// ⛔⛔ A REVERSE-DNS KEY IS A CLAIM ON A DOMAIN, AND WE HAD MADE THREE WE
// COULD NOT BACK. The published artifacts carry `org.go-pkgx.*`; the rename
// turned that into `org.go-zpkg.*`. Neither is ours: `go-pkgx.org` and
// `go-zpkg.org` are domains nobody here has ever registered. It is the same
// error as `go-pkgx.dev/catalog` and as `application/vnd.pkgx.*` — a name
// that looks like ours because we are the only ones using it.
//
// `io.github.go-zpkg` is the reverse-DNS of a host we demonstrably control:
// go-zpkg.github.io answers, and the Pages repository exists. It is the same
// convention OCI itself uses (`org.opencontainers.image.*`) applied honestly.
//
// ⛔ WRITE ONE, READ THREE. Nothing rewrites a published manifest, and
// 42 756 artifacts carry `org.go-pkgx.*`. A reader that accepted only the new
// key would not fail loudly — it would find the annotation ABSENT, and every
// one of these keys means something different when absent: no glibc flavour,
// no declared sonames, no recorded spec. Silence is the worst possible
// failure for exactly these fields, so the legacy keys stay readable until
// nothing in the registry carries them.
const (
	// GlibcVersionAnnotation / GlibcMinKernelAnnotation describe a
	// glibc-flavored build.
	GlibcVersionAnnotation   = "io.github.go-zpkg.glibc.version"
	GlibcMinKernelAnnotation = "io.github.go-zpkg.glibc.min-kernel"
	// ABIProvidesAnnotation lists the sonames an artifact's shared libraries
	// provide.
	ABIProvidesAnnotation = "io.github.go-zpkg.abi.provides"
	// SpecAnnotation carries an artifact's concrete spec.
	SpecAnnotation = "io.github.go-zpkg.spec"
	// AnnotationSourceURI records where a stored source archive came from.
	AnnotationSourceURI = "io.github.go-zpkg.source.uri"
)

// legacyKeys lists, for each current key, the spellings already in the
// registry — oldest first is irrelevant, because only one can be present.
//
// `org.go-zpkg.*` is here although it is unlikely to be on anything: it was
// the rename's output and shipped in artifact v0.64.0–v0.70.0, so an artifact
// built with one of those carries it. Leaving it out would be betting that
// nobody used those five releases, and the cost of being wrong is a silently
// absent annotation.
var legacyKeys = map[string][]string{
	GlibcVersionAnnotation:   {"org.go-zpkg.glibc.version", "org.go-pkgx.glibc.version"},
	GlibcMinKernelAnnotation: {"org.go-zpkg.glibc.min-kernel", "org.go-pkgx.glibc.min-kernel"},
	ABIProvidesAnnotation:    {"org.go-zpkg.abi.provides", "org.go-pkgx.abi.provides"},
	SpecAnnotation:           {"org.go-zpkg.spec", "org.go-pkgx.spec"},
	AnnotationSourceURI:      {"dev.pkgx.source.uri"},
}

// Annotation reads key from ann, falling back to the spellings the same field
// has carried before.
//
// ⛔ THE CURRENT KEY WINS EVEN WHEN BOTH ARE PRESENT. A manifest holding two
// is one somebody wrote with two tools, and the newer spelling is the one
// this build agrees with; preferring the legacy one would make an upgrade
// read older data than the version before it.
//
// An empty value is NOT a hit. `ann[k]` cannot tell "absent" from "present
// and empty", and for every key here an empty string means the same as
// absent — so falling through on it is what makes an artifact written with an
// empty new key still find its legacy value.
func Annotation(ann map[string]string, key string) string {
	if v := ann[key]; v != "" {
		return v
	}
	for _, k := range legacyKeys[key] {
		if v := ann[k]; v != "" {
			return v
		}
	}
	return ""
}

// AnnotationPresent is Annotation for callers that must tell an EMPTY value
// from a MISSING one — the spec annotation does, because an empty spec is a
// malformed artifact and a missing one is an old artifact.
func AnnotationPresent(ann map[string]string, key string) (string, bool) {
	if v, ok := ann[key]; ok {
		return v, true
	}
	for _, k := range legacyKeys[key] {
		if v, ok := ann[k]; ok {
			return v, true
		}
	}
	return "", false
}
