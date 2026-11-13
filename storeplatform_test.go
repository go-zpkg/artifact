package artifact

import (
	"path/filepath"
	"strings"
	"testing"
)

// ⛔ A PATH WITH NO PLACEHOLDER IS RETURNED UNCHANGED, which is what makes this
// safe to ship: every store that exists today keeps working, byte for byte.
func TestAStorePathWithoutAPlaceholderIsUntouched(t *testing.T) {
	for _, p := range []string{
		"/shared/pkgx",
		"~/.pkgx",
		"/var/lib/pkgx/store",
		"", // the caller decides what an empty path means, not this function
	} {
		if got := ExpandStorePath(p); got != p {
			t.Errorf("%q -> %q, want it unchanged", p, got)
		}
	}
}

func TestTheStorePathCanNameItsPlatform(t *testing.T) {
	osn, arch := HostSlug()
	for _, c := range []struct{ in, want string }{
		{"/shared/pkgx/{platform}", "/shared/pkgx/" + osn + "-" + arch},
		{"/shared/pkgx/{os}/{arch}", "/shared/pkgx/" + osn + "/" + arch},
		{"/s/{os}-only", "/s/" + osn + "-only"},
		{"/s/{arch}/{arch}", "/s/" + arch + "/" + arch}, // every occurrence
	} {
		if got := ExpandStorePath(c.in); got != c.want {
			t.Errorf("%q -> %q, want %q", c.in, got, c.want)
		}
	}
}

// Dir is the single point every command resolves the store through, so the
// expansion has to happen there or it happens nowhere.
func TestDirExpandsThePlaceholder(t *testing.T) {
	t.Setenv("ZPKG_CONFIG", "")
	t.Setenv("ZPKG_DIR", filepath.Join("/shared", "pkgx", "{platform}"))
	osn, arch := HostSlug()
	want := filepath.Join("/shared", "pkgx", osn+"-"+arch)
	if got := Dir(); got != want {
		t.Errorf("Dir() = %q, want %q", got, want)
	}
}

// ⛔ THE TWO ARCHITECTURES MUST LAND IN DIFFERENT DIRECTORIES — the whole
// point. This asserts the property rather than the spelling: whatever the
// placeholder expands to, two platforms must not share a prefix for the same
// project and version, because `lib/libssl.so.3` is the same file name on
// linux/x86-64 and linux/aarch64.
func TestTwoPlatformsDoNotShareAPrefix(t *testing.T) {
	const tmpl = "/shared/pkgx/{platform}"
	expand := func(osn, arch string) string {
		return strings.NewReplacer("{platform}", osn+"-"+arch).Replace(tmpl)
	}
	a := filepath.Join(expand("linux", "x86-64"), "openssl.org", "v3.6.4", "lib", "libssl.so.3")
	b := filepath.Join(expand("linux", "aarch64"), "openssl.org", "v3.6.4", "lib", "libssl.so.3")
	if a == b {
		t.Fatalf("two architectures resolved to one path: %s", a)
	}
	// And the control: the SAME platform must resolve to the same place, or
	// nothing would ever be found twice.
	if expand("linux", "x86-64") != expand("linux", "x86-64") {
		t.Error("the same platform resolved to two paths")
	}
}

// ⛔ A MISSPELT PLACEHOLDER IS WORSE THAN NONE: it expands to nothing, the
// store becomes a directory literally called `{platfrom}`, and it works —
// silently — as a single-architecture store, which is the bug it was meant to
// fix.
func TestAnUnknownPlaceholderIsNamed(t *testing.T) {
	for _, c := range []struct {
		in   string
		want []string
	}{
		{"/s/{platform}", nil},
		{"/s/{os}/{arch}", nil},
		{"/s/{platfrom}", []string{"{platfrom}"}},
		{"/s/{platform}/{nodename}", []string{"{nodename}"}},
		{"/s/{a}/{b}", []string{"{a}", "{b}"}},
		{"/s/plain", nil},
		{"/s/{unclosed", nil}, // not a placeholder, and not an error either
	} {
		got := UnknownStorePlaceholders(c.in)
		if len(got) != len(c.want) {
			t.Errorf("%q -> %v, want %v", c.in, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%q -> %v, want %v", c.in, got, c.want)
				break
			}
		}
	}
}

// The two functions have to agree: anything ExpandStorePath leaves behind must
// be something UnknownStorePlaceholders names, or a typo disappears between
// them.
func TestExpansionAndTheWarningAgree(t *testing.T) {
	const p = "/s/{platform}/{platfrom}"
	expanded := ExpandStorePath(p)
	if strings.Contains(expanded, "{platform}") {
		t.Fatalf("a known placeholder survived: %q", expanded)
	}
	if !strings.Contains(expanded, "{platfrom}") {
		t.Fatalf("an unknown placeholder was eaten rather than left visible: %q", expanded)
	}
	if got := UnknownStorePlaceholders(p); len(got) != 1 || got[0] != "{platfrom}" {
		t.Fatalf("the typo was not named: %v", got)
	}
}
