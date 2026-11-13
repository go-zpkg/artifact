package artifact

// VersionsFromTags turns a registry tag listing into the versions a client
// on THIS machine would consider, **oldest first** — so the last is the
// newest.
//
// # WHY A CALLER MUST NOT DO THIS ITSELF
//
// ⛔ MEASURED 2026-10-24, in pkgx's `pkgs request`. It filtered a tag
// listing with IsVersionTag and ordered it with `sort.Strings`, and
// reported:
//
//	nodejs.org
//	state     published for darwin/aarch64 at 26.8.1
//
// an hour after 26.12.1 was published. Version strings do not sort as
// text: "26.8.1" > "26.12.1" because "8" > "1". Every fact under that
// line — which platforms carry it, whether this one does — was then read
// off the index of the wrong version.
//
// Ordering is only one of the three rules this applies, and the other two
// are no more guessable:
//
//   - a FLAVOURED tag ("2.44-glibc2.27.0") is a build against some other
//     glibc and is never this client's, so it is dropped unless it matches
//     GlibcFlavor();
//   - "1.0.0", "v1.0.0" and "1.0" are ONE version, and our own registry
//     carries several of those spellings — gnu.org/glibc has a 2.44 tag
//     from a factory build and a 2.44.0 tag from the upstream mirror.
//     Left as separate candidates the pick depends on the registry's
//     listing order, and a build once installed both glibc trees side by
//     side and linked against a sysroot its loader had not come from.
//
// This is the same function `ociVersionsFor` has always used; it was
// simply unexported, which is the third time in two days that a rule this
// package owns and tests was reimplemented worse one import away.
func VersionsFromTags(tags []string) []Ver {
	return selectVersions(tags, GlibcFlavor())
}

// RegistryTag is the tag to pull this version from.
//
// ⛔ IT IS NOT ALWAYS Raw. A flavoured artifact's version is "2.44" and its
// tag is "2.44-glibc2.27.0", so a caller that took `Raw` and asked the
// registry for it would be told the platform is not in the index — a
// sentence that reads as "we do not publish that for you" and means "I
// asked for a tag that does not exist".
func (v Ver) RegistryTag() string { return v.tag() }
