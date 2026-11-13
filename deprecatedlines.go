package artifact

// The end-of-life release lines this library knows about, and the day they
// were measured.
//
// ⛔⛔ THE LIST LIVES HERE SO THAT NO BINARY HAS TO REMEMBER TO SWITCH IT ON.
//
// This capability has now failed to reach the fleet twice, the same way both
// times. First it read `ZPKG_DEPRECATED` alone, and nobody set it, so openssl's
// 3.6 line reached its end-of-life date with `^3` still resolving to 3.6.4
// everywhere. The remedy was to let a binary carry a default — which moved the
// opt-in from an environment variable to a line of Go in ONE module, and left
// every other binary exactly where it started.
//
// Measured 2026-11-03, A/B on the same `pkgm` binary:
//
//	pkgm install 'openssl.org@^3'                      -> 3.6.4  (EOL 2026-11-01)
//	ZPKG_DEPRECATED=... pkgm install 'openssl.org@^3'  -> 3.5.8  (LTS to 2030)
//
// `pkgm` is the INSTALLER. It was installing an end-of-life TLS library, on a
// fresh install, with the supported line in the same registry — because the
// activation lived in `pkgx/internal/app`, which is `internal` to another
// module and so unimportable even if someone had thought of it.
//
// An opt-in that each new binary must rediscover is not a default; it is a
// capability the fleet keeps not having. So the default is the library's, and
// a binary that wants something else assigns DefaultDeprecated.

// KnownDeprecatedAsOf is the day KnownDeprecated was measured.
//
// A reader has to be able to tell a current judgement from one left behind by
// a release, and a list with no date reads as fresh forever.
const KnownDeprecatedAsOf = "2026-11-01"

// KnownDeprecated is, per project, the release lines upstream has abandoned.
//
// Measured on KnownDeprecatedAsOf against the registry and endoflife.date:
//
//	1.1.1  ended 2023-09-11 (LTS)     3.4  ended 2026-10-22
//	3.0    ended 2026-09-07 (LTS)     3.6  ended 2026-11-01
//	3.1    ended 2025-03-14           3.5  supported to 2030-04-08 (LTS)
//	3.2    ended 2025-11-23           4.0  supported to 2027-05-14
//	3.3    ended 2026-04-09
//
// Only openssl so far, and deliberately: this list changes what a constraint
// resolves to across the whole fleet, so each project earns its place by a
// measurement rather than by a sweep. go-zpkg/artifact#179 moves the judgement
// into the signed catalogue, where it is computed rather than committed.
var KnownDeprecated = map[string][]string{
	"openssl.org": {"1.1.1", "3.0", "3.1", "3.2", "3.3", "3.4", "3.6"},
}

// KnownSupported is the other half of the same measurement: the lines still
// supported on KnownDeprecatedAsOf, and which must therefore NOT appear in
// KnownDeprecated.
//
// ⛔ IT EXISTS TO BE CONTRADICTED. The expensive mistake here is listing a line
// that is still supported — that is how `^3` would be pushed off the 3.5 LTS
// onto something older, quietly, with no error anywhere. Recording both halves
// of the verdict makes that edit fail a test instead of shipping.
var KnownSupported = map[string][]string{
	"openssl.org": {"3.5", "4.0"},
}
