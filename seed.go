package artifact

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	// Keys are the ids of the keys that signed it: a name is a label an
	// operator can rename, a key id is not.
	Keys   []string `json:"keys"`
	Source string   `json:"source"`
}

var (
	seedMu     sync.Mutex
	seedSource string
	seedLedger []SeedEntry
	// seedLedgerFile is set by SetSeedLedgerFile.
	seedLedgerFile string
	// seedLedgerOut is set by SetSeedLedgerFD: a descriptor the caller handed
	// over, written with no path lookup. It and seedLedgerFile are exclusive.
	seedLedgerOut *os.File
	// seedWriteMu serialises the writes to seedLedgerOut so lines never mix.
	seedWriteMu sync.Mutex
)

// SeedRegistry is the only registry a seed is read from. It is a constant, not
// a parameter: a seed named by a caller (or by an environment a recipe can set)
// is a seed chosen by whoever can reach the caller.
const SeedRegistry = "oci://ghcr.io/go-pkgx/packages"

// seedRegistryPin is SeedRegistry as WithSeedSource compares against. It is a
// variable only so a test can point it at a registry on 127.0.0.1; nothing
// outside the package can change it.
var seedRegistryPin = SeedRegistry

// MaxSeedLedgerBytes bounds a ledger file before it is read: the entries are
// capped by the caller, but only after the whole file is in memory.
const MaxSeedLedgerBytes = 16 << 20

// ErrSeedSource is returned when a seed is asked for from anywhere but
// SeedRegistry, or without a ledger to record it in.
var ErrSeedSource = errors.New("a seed has one source and is always recorded")

// SeedTrustSet is the trust a seed is verified against: the compiled-in keys
// and no others. The environment and ~/.zpkg/config.hcl2 are NOT consulted, so
// nothing a dispatcher or a recipe can set widens who may vouch for the seed.
func SeedTrustSet() TrustSet { return DefaultTrustSet() }

// activeTrustSet is the trust set an install verifies against: the seed's while
// a seed is in force, the operator's otherwise.
func activeTrustSet() (TrustSet, error) {
	seedMu.Lock()
	inSeed := seedSource != ""
	seedMu.Unlock()
	if inSeed {
		return SeedTrustSet(), nil
	}
	return LoadTrustSet()
}

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
	if from != seedRegistryPin {
		return fmt.Errorf("seed source %q: %w: the seed is %s and nothing else", from, ErrSeedSource, seedRegistryPin)
	}
	seedMu.Lock()
	file := seedLedgerFile
	out := seedLedgerOut
	seedMu.Unlock()
	if file == "" && out == nil {
		return fmt.Errorf("seed source %q: %w: no ledger file is set, and a seed that is not recorded is not installed", from, ErrSeedSource)
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
	byName := map[string]string{}
	for _, s := range SeedTrustSet().Signers {
		byName[s.Name] = s.KeyID()
	}
	for _, n := range e.Signers {
		if id, ok := byName[n]; ok {
			e.Keys = append(e.Keys, id)
		}
	}
	sort.Strings(e.Keys)
	seedMu.Lock()
	seedLedger = append(seedLedger, e)
	file, out := seedLedgerFile, seedLedgerOut
	seedMu.Unlock()
	if out != nil {
		return writeSeedEntry(out, e)
	}
	return appendSeedEntry(file, e) // "" fails: WithSeedSource never lets a seed run unrecorded
}

// SetSeedLedgerFD names a descriptor every seed artifact is ALSO written to, one
// JSON object per line, the moment it is verified, replacing a ledger file
// (SetSeedLedgerFile). The descriptor is the caller's own, inherited from the
// process that started this one, so recording an entry never looks a path up: a
// path can be missing, or resolve to a file another process made, and a ledger
// written there is a ledger nobody reads. nil clears it. A write that fails
// fails the install.
func SetSeedLedgerFD(f *os.File) {
	seedMu.Lock()
	seedLedgerOut = f
	if f != nil {
		seedLedgerFile = ""
	}
	seedMu.Unlock()
}

func writeSeedEntry(f *os.File, e SeedEntry) error {
	line, _ := json.Marshal(e)
	seedWriteMu.Lock()
	defer seedWriteMu.Unlock()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("seed ledger: %w", err)
	}
	return nil
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
	if path != "" {
		seedLedgerOut = nil
	}
	seedMu.Unlock()
}

func appendSeedEntry(path string, e SeedEntry) error {
	line, _ := json.Marshal(e) // a struct of strings cannot fail to marshal
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err == nil {
		_, err = f.Write(append(line, '\n'))
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}
	if err != nil {
		return fmt.Errorf("seed ledger: %w", err)
	}
	return nil
}

// ReadSeedLedger reads a ledger file in its canonical form: one entry per
// (project, version, digest), signers sorted, entries sorted. A line that is
// not an entry is an error, never skipped: a ledger that silently loses a
// line understates the seed.
func ReadSeedLedger(path string) ([]SeedEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("seed ledger: %w", err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, MaxSeedLedgerBytes+1))
	if err != nil {
		return nil, fmt.Errorf("seed ledger: %w", err)
	}
	if len(b) > MaxSeedLedgerBytes {
		return nil, fmt.Errorf("seed ledger %s: larger than %d bytes", path, MaxSeedLedgerBytes)
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
