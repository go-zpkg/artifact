package artifact

import (
	"errors"
	"fmt"
	"strings"
	"sync"
)

// A SEED is a go-pkgx artifact used as the BUILD ENVIRONMENT of one bootstrap
// pass, and as nothing else. It exists because go-zpkg's own toolchain (the
// compiler, libc, make, coreutils...) has to be built by SOMETHING the first
// time, and the only thing that can run today is somebody else's binaries.
//
// The rule that keeps this honest is narrow and has three halves:
//
//   - The seed is READ, inside WithSeedSource, with every package's signature
//     verified against the trust set. Verification off is a refusal, not a
//     warning: an unverified seed would put unknown bytes in every output.
//   - It is NEVER a dependency source. CheckDistSource is untouched, the
//     environment (ZPKG_DIST) clears the allowance, and the allowance exists
//     only for DistBase while a WithSeedSource call is running.
//   - It is NEVER hidden. Every seed artifact that was installed is recorded
//     in a ledger (project, version, digest, signers, source) that the caller
//     writes into the provenance of what it builds.
//
// Publishing to go-pkgx stays refused by the callers; this file does not touch
// that.

// SeedEntry is one seed artifact that was verified and installed.
type SeedEntry struct {
	Project string   `json:"project"`
	Version string   `json:"version"`
	Digest  string   `json:"digest"`
	Signers []string `json:"signers"`
	Source  string   `json:"source"`
}

var (
	seedMu     sync.Mutex
	seedSource string
	seedLedger []SeedEntry
)

// ErrSeedUnverified is returned when a seed was asked for while signature
// verification is off, or for a transport that carries no signatures.
var ErrSeedUnverified = errors.New("a seed is a build environment and is only accepted verified")

// WithSeedSource runs fn with DistBase pointed at from, the go-pkgx registry
// the build environment is staged from, and restores the previous
// configuration afterwards. The seed ledger is reset on entry and stays
// readable (SeedLedger) after fn returns.
func WithSeedSource(from string, fn func() error) error {
	from = strings.TrimRight(from, "/")
	if !IsOCI(from) {
		return fmt.Errorf("seed source %q: %w: HTTP dists carry no signatures", from, ErrSeedUnverified)
	}
	if !VerifyRequired() {
		return fmt.Errorf("seed source %q: %w (signature verification is off)", from, ErrSeedUnverified)
	}
	oldBase, oldExtra := DistBase, DistExtra
	seedMu.Lock()
	oldSeed := seedSource
	seedSource, seedLedger = from, nil
	seedMu.Unlock()
	DistBase, DistExtra = from, nil
	defer func() {
		DistBase, DistExtra = oldBase, oldExtra
		seedMu.Lock()
		seedSource = oldSeed
		seedMu.Unlock()
	}()
	return fn()
}

// SeedLedger returns a copy of what the last WithSeedSource installed.
func SeedLedger() []SeedEntry {
	seedMu.Lock()
	defer seedMu.Unlock()
	return append([]SeedEntry(nil), seedLedger...)
}

// seedAllowed reports whether s is the seed source, as DistBase only.
func seedAllowed(s string, isBase bool) bool {
	seedMu.Lock()
	defer seedMu.Unlock()
	return isBase && seedSource != "" && s == seedSource
}

// noteSeed records an artifact fetched from base when base is the seed source,
// reading the signers that vouched for digest. It fails closed: a seed that
// cannot be accounted for is not installed.
func noteSeed(c *OCIClient, base, project string, v Ver, tag, osn, arch, digest string) error {
	seedMu.Lock()
	src := seedSource
	seedMu.Unlock()
	if src == "" || base != src {
		return nil
	}
	rep, err := c.SignaturesOfDigest(project, tag, osn, arch, digest)
	if err == nil {
		err = rep.Err()
	}
	if err != nil {
		return fmt.Errorf("seed %s v%s: %w", project, v.Raw, err)
	}
	seedMu.Lock()
	seedLedger = append(seedLedger, SeedEntry{Project: project, Version: v.Raw, Digest: digest,
		Signers: append([]string(nil), rep.Signers...), Source: src})
	seedMu.Unlock()
	return nil
}
