package artifact

import (
	"strings"
	"testing"
)

// ⛔⛔ EVERY STRING IN THIS FILE IS A LITERAL ON PURPOSE. These are the names
// 42 756 PUBLISHED artifacts carry, and nothing rewrites a published manifest.
// Written as constants they could be changed in sympathy with the new ones
// during a tidy-up and the suite would stay green while every existing
// install broke. A literal cannot drift.

// ⛔⛔ THERE ARE NOW TWO RETIRED GENERATIONS, AND THE SWEEP THAT ADDED THE
// SECOND IS WHY THIS FILE EXISTS. The `bottle → artifact` rename ran as a
// substring pass over the whole tree and rewrote the three literals below to
// `vnd.pkgx.artifact.*` — a spelling that has never been published and never
// will be. The suite stayed green, because `extForLayer` matches the codec
// suffix and would have accepted anything ending in `tar+gzip`. Restored by
// hand, and the second generation added beside them.
//
// The first: the vendor namespace the project used to mint names in, before
// it was checked against upstream's own corpus (docs.pkgx.sh/llms-full.txt,
// read 2026-11-04) — pkgx distributes plain HTTPS tarballs and defines no OCI
// artifact, no artifact type and no media type.
const (
	publishedLayerGz  = "application/vnd.pkgx.bottle.layer.v1.tar+gzip"
	publishedLayerXz  = "application/vnd.pkgx.bottle.layer.v1.tar+xz"
	publishedLayerZst = "application/vnd.pkgx.bottle.layer.v1.tar+zstd"
)

// The second: ours, correctly namespaced, but naming the artifact after
// pkgx's word for it. Everything published between the vendor-namespace fix
// and this rename carries these.
const (
	bottleLayerGz  = "application/vnd.go-zpkg.bottle.layer.v1.tar+gzip"
	bottleLayerXz  = "application/vnd.go-zpkg.bottle.layer.v1.tar+xz"
	bottleLayerZst = "application/vnd.go-zpkg.bottle.layer.v1.tar+zstd"
	bottleArtifact = "application/vnd.go-zpkg.bottle"
)

// ⛔ A PUBLISHED ARTIFACT MUST STILL BE READABLE. extForLayer is what turns a
// layer's media type into the codec that unpacks it; if it stops recognising
// the published spelling, every artifact in the registry becomes an unknown
// blob — and the failure is not a clean error, it is `ext == ""`, which reads
// as "not an artifact layer".
func TestEveryPublishedLayerTypeStillNamesItsCodec(t *testing.T) {
	for mt, want := range map[string]string{
		publishedLayerGz:  ExtTarGz,
		publishedLayerXz:  ExtTarXz,
		publishedLayerZst: ExtTarZst,
		// The second retired generation, published under our own namespace.
		bottleLayerGz:  ExtTarGz,
		bottleLayerXz:  ExtTarXz,
		bottleLayerZst: ExtTarZst,
		// And the ones written from now on.
		MediaLayerGz:  ExtTarGz,
		MediaLayerXz:  ExtTarXz,
		MediaLayerZst: ExtTarZst,
		// The source layer carries no codec in its name by design — the bytes
		// are stored exactly as they arrived — so it is NOT an artifact layer.
		"application/vnd.pkgx.source.layer.v1":    "",
		"application/vnd.go-zpkg.source.layer.v1": "",
	} {
		if got := extForLayer(mt); got != want {
			t.Errorf("extForLayer(%q) = %q, want %q", mt, got, want)
		}
	}
}

// ⛔ THE NEW NAMES MUST BE IN A NAMESPACE WE CONTROL, which is the whole point
// of moving. `go-zpkg` is this organisation; `pkgx` is not, and upstream never
// defined these.
func TestTheMintedNamesAreOurs(t *testing.T) {
	for _, s := range []string{
		MediaLayerGz, MediaLayerXz, MediaLayerZst, ArtifactType,
		MediaSourceLayer, ArtifactTypeSource,
	} {
		if !strings.HasPrefix(s, "application/vnd.go-zpkg.") {
			t.Errorf("%q is not in our vendor namespace", s)
		}
	}
	// ⛔ AND NONE OF THEM MAY STILL CARRY THE RETIRED WORD. The namespace
	// check above passed throughout the years this project called the thing a
	// bottle, so on its own it cannot see this rename at all.
	for _, s := range []string{
		MediaLayerGz, MediaLayerXz, MediaLayerZst, ArtifactType,
		MediaSourceLayer, ArtifactTypeSource,
	} {
		if strings.Contains(s, "bottle") {
			t.Errorf("%q still names the artifact after pkgx's word for it", s)
		}
	}
	for _, s := range []string{
		GlibcVersionAnnotation, GlibcMinKernelAnnotation,
		ABIProvidesAnnotation, SpecAnnotation, AnnotationSourceURI,
	} {
		// ⛔ `io.github.go-zpkg`, NOT `org.go-zpkg`. A reverse-DNS key is a
		// claim on a domain; nobody here has registered go-zpkg.org, and the
		// rename had simply carried the same unbacked claim over from
		// go-pkgx.org. go-zpkg.github.io is a host that demonstrably answers.
		if !strings.HasPrefix(s, "io.github.go-zpkg.") {
			t.Errorf("%q claims a domain this project does not control", s)
		}
	}
}

// ⛔⛔ AN ANNOTATION WRITTEN UNDER AN OLD KEY MUST STILL BE FOUND, and the
// failure mode is why: every one of these keys means something DIFFERENT when
// absent — no glibc flavour, no declared sonames, no recorded spec. A reader
// that missed them would not raise an error, it would quietly conclude the
// artifact has none of those things.
func TestAnnotationsPublishedUnderOlderKeysAreStillRead(t *testing.T) {
	for _, c := range []struct{ key, legacy string }{
		{GlibcVersionAnnotation, "org.go-pkgx.glibc.version"},
		{GlibcVersionAnnotation, "org.go-zpkg.glibc.version"},
		{GlibcMinKernelAnnotation, "org.go-pkgx.glibc.min-kernel"},
		{ABIProvidesAnnotation, "org.go-pkgx.abi.provides"},
		{SpecAnnotation, "org.go-pkgx.spec"},
		{AnnotationSourceURI, "dev.pkgx.source.uri"},
	} {
		if got := Annotation(map[string]string{c.legacy: "value"}, c.key); got != "value" {
			t.Errorf("an artifact carrying %q was read as having no %q (got %q)", c.legacy, c.key, got)
		}
	}
}

// ⛔ THE CURRENT KEY WINS WHEN BOTH ARE PRESENT. A manifest holding two was
// written by two tools; preferring the legacy one would make an upgrade read
// OLDER data than the release before it.
func TestTheCurrentKeyWinsOverALegacyOne(t *testing.T) {
	ann := map[string]string{
		SpecAnnotation:     "new",
		"org.go-pkgx.spec": "old",
	}
	if got := Annotation(ann, SpecAnnotation); got != "new" {
		t.Errorf("Annotation = %q, want the current key's value", got)
	}
}

// An EMPTY new key must not shadow a legacy value: `ann[k]` cannot tell
// "absent" from "present and empty", and for these fields the two mean the
// same thing.
func TestAnEmptyCurrentKeyDoesNotHideALegacyValue(t *testing.T) {
	ann := map[string]string{
		ABIProvidesAnnotation:      "",
		"org.go-pkgx.abi.provides": "libz.so.1",
	}
	if got := Annotation(ann, ABIProvidesAnnotation); got != "libz.so.1" {
		t.Errorf("Annotation = %q, want the legacy value", got)
	}
}

// ⛔ AND "ABSENT" MUST STAY DISTINGUISHABLE FROM "PRESENT AND EMPTY" for the
// spec, because they are different defects: an empty spec is a malformed
// artifact, a missing one is simply an older artifact. SpecOf relies on this.
func TestAnnotationPresentSeparatesAbsentFromEmpty(t *testing.T) {
	if _, ok := AnnotationPresent(map[string]string{}, SpecAnnotation); ok {
		t.Error("an absent annotation reported present")
	}
	v, ok := AnnotationPresent(map[string]string{SpecAnnotation: ""}, SpecAnnotation)
	if !ok || v != "" {
		t.Errorf("an EMPTY annotation must be present: v=%q ok=%v", v, ok)
	}
	v, ok = AnnotationPresent(map[string]string{"org.go-pkgx.spec": "{}"}, SpecAnnotation)
	if !ok || v != "{}" {
		t.Errorf("a legacy annotation must be present: v=%q ok=%v", v, ok)
	}
}

// Nothing unknown is invented: a key with no legacy spellings and no value
// answers empty rather than reaching for something else's.
func TestAnUnknownKeyAnswersEmpty(t *testing.T) {
	if got := Annotation(map[string]string{"x": "y"}, "io.github.go-zpkg.nothing"); got != "" {
		t.Errorf("Annotation = %q, want empty", got)
	}
	if _, ok := AnnotationPresent(map[string]string{"x": "y"}, "io.github.go-zpkg.nothing"); ok {
		t.Error("an unknown key reported present")
	}
}
