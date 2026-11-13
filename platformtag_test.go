package artifact

import "testing"

// TestPlatformTagIsNotAVersion: the tag names one platform's manifest, and the
// double dash keeps it from reading as a semver pre-release. A single dash
// would make `1.2.3-linux-x86-64` a plausible version to anything walking the
// tag list — and everything that counts this registry walks the tag list.
func TestPlatformTagIsNotAVersion(t *testing.T) {
	got := platformTag("1.2.3", "linux", "x86-64")
	if got != "1.2.3--linux-x86-64" {
		t.Fatalf("platformTag = %q", got)
	}
	if !IsPlatformTag(got) {
		t.Error("its own tag is not recognised")
	}
	for _, v := range []string{"1.2.3", "1.2.3-rc1", "2026.08.13", "latest"} {
		if IsPlatformTag(v) {
			t.Errorf("%q was mistaken for a platform tag", v)
		}
	}
}
