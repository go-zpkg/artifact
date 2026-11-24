package artifact

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
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
	// seedLedgerFile is set by SetSeedLedgerFile.
	seedLedgerFile string
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
	e := SeedEntry{Project: project, Version: v.Raw, Digest: digest,
		Signers: append([]string(nil), rep.Signers...), Source: src}
	sort.Strings(e.Signers)
	seedMu.Lock()
	seedLedger = append(seedLedger, e)
	file := seedLedgerFile
	seedMu.Unlock()
	if file == "" {
		return nil
	}
	return appendSeedEntry(file, e)
}

// SetSeedLedgerFile names a file every seed artifact is ALSO appended to, one
// JSON object per line, the moment it is verified. It exists because the
// process that installs a seed is not always the one that builds with it: the
// factory runs zpkx once per recipe, and zpkx replaces itself with the build
// command, so an in-memory ledger would be gone before anyone read it.
//
// Appends are single write calls on an O_APPEND descriptor, so concurrent
// writers do not interleave. A write that fails fails the install: a seed that
// cannot be accounted for is not installed.
func SetSeedLedgerFile(path string) {
	seedMu.Lock()
	seedLedgerFile = path
	seedMu.Unlock()
}

func appendSeedEntry(path string, e SeedEntry) error {
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("seed ledger: %w", err)
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		f.Close()
		return fmt.Errorf("seed ledger: %w", err)
	}
	return f.Close()
}

// ReadSeedLedger reads a ledger file in its canonical form: one entry per
// (project, version, digest), signers sorted, entries sorted. A line that is
// not an entry is an error, never skipped: a ledger that silently loses a
// line understates the seed.
func ReadSeedLedger(path string) ([]SeedEntry, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("seed ledger: %w", err)
	}
	seen := map[string]bool{}
	var out []SeedEntry
	for i, line := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var e SeedEntry
		dec := json.NewDecoder(strings.NewReader(line))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&e); err != nil {
			return nil, fmt.Errorf("seed ledger %s line %d: %w", path, i+1, err)
		}
		if e.Project == "" || e.Version == "" || e.Digest == "" {
			return nil, fmt.Errorf("seed ledger %s line %d: an entry names a project, a version and a digest", path, i+1)
		}
		sort.Strings(e.Signers)
		k := e.Project + "\x00" + e.Version + "\x00" + e.Digest
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Project != b.Project {
			return a.Project < b.Project
		}
		if a.Version != b.Version {
			return a.Version < b.Version
		}
		return a.Digest < b.Digest
	})
	return out, nil
}

// SeedLedgerDigest is the sha256 (hex) of the canonical form of a ledger: its
// entries as JSON lines. The same set of seed artifacts has the same digest
// whatever order they were installed in.
func SeedLedgerDigest(es []SeedEntry) string {
	h := sha256.New()
	for _, e := range es {
		line, _ := json.Marshal(e)
		h.Write(line)
		h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil))
}
