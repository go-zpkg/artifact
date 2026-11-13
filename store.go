package artifact

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// What the artifact store HOLDS — the one tree nothing in this family could
// show.
//
// # WHY IT WAS WORTH WRITING
//
// Every ephemeral `pkgx <pkg>` leaves its artifacts in
// $ZPKG_DIR/<project>/v<version>, and nothing ever removes one. `pkgm list`
// lists INSTALLATIONS, which is a different set: it answers "what did I ask
// for", not "what is on this disk".
//
// Measured on this developer's machine before any of this existed: 42 GB
// across 332 versions, 14.1 GB of it llvm.org alone, with three full
// versions of it present. Nobody chose that; nothing could have told them.
//
// # LISTING IS NOT COLLECTING, AND THAT IS DELIBERATE
//
// nix, guix and spack all separate the two — `nix path-info -S` against
// `nix store gc`, `guix gc --list-live` against `guix gc`, `spack find`
// against `spack gc` — and all three make the ROOTS explicit before
// deleting anything. There is no profile here, so there is no root set, and
// a version that looks superseded may be exactly what a lock pins or what
// an environment asks for.
//
// So this reports and deletes nothing. "Older than another version here" is
// a fact about the disk; "garbage" would be a claim about intent, and the
// claim needs roots this package does not have.

// StoreEntry is one version directory and what it occupies.
type StoreEntry struct {
	Project string
	Version string
	Bytes   int64
	// Newest is true for the highest version of its project PRESENT here.
	// Not "the newest that exists" — this says nothing about the registry.
	Newest bool
}

// ScanStore reports every version directory under an artifact store.
//
// Symlinks are counted NEVER: writeVersionLinks puts `v*`, `v22` and
// `v22.1` beside `v22.1.8`, all pointing at it, and following them would
// report llvm.org four times and the store at several times its size. The
// store on this machine carries 118 such aliases.
func ScanStore(dir string) ([]StoreEntry, error) {
	projects, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []StoreEntry
	for _, p := range projects {
		if !p.IsDir() || strings.HasPrefix(p.Name(), ".") {
			// `.local` holds the staging directory a scratch image needs,
			// and it is not a project.
			continue
		}
		sub, err := scanProject(dir, p.Name())
		if err != nil {
			return nil, err
		}
		out = append(out, sub...)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Project != out[j].Project {
			return out[i].Project < out[j].Project
		}
		return out[i].Version < out[j].Version
	})
	return out, nil
}

// scanProject recurses, because a project name has slashes in it:
// gnu.org/bash is a directory inside a directory, and its versions hang off
// the inner one.
func scanProject(root, project string) ([]StoreEntry, error) {
	dir := filepath.Join(root, project)
	kids, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []StoreEntry
	var versions []StoreEntry
	for _, k := range kids {
		// A SYMLINK IS NEVER A VERSION. IsDir() is false for a symlink in a
		// DirEntry, which is what makes this correct — and the reason the
		// walk below uses Lstat too.
		if !k.IsDir() {
			continue
		}
		name := k.Name()
		if strings.HasPrefix(name, "v") && isVersionTag(strings.TrimPrefix(name, "v")) {
			n, err := treeBytes(filepath.Join(dir, name))
			if err != nil {
				return nil, err
			}
			versions = append(versions, StoreEntry{Project: project, Version: strings.TrimPrefix(name, "v"), Bytes: n})
			continue
		}
		// Not a version: a deeper namespace, like gnu.org/bash under gnu.org.
		sub, err := scanProject(root, filepath.Join(project, name))
		if err != nil {
			return nil, err
		}
		out = append(out, sub...)
	}
	if len(versions) > 0 {
		newest := 0
		for i := range versions {
			if cmpVer(ParseVer(versions[i].Version), ParseVer(versions[newest].Version)) > 0 {
				newest = i
			}
		}
		versions[newest].Newest = true
		out = append(out, versions...)
	}
	return out, nil
}

// treeBytes adds up a directory, counting each file once.
//
// Lstat, not Stat: an artifact contains symlinks of its own — every lib/*.so
// line, and the `v*` aliases one level up — and following them would count
// the same bytes repeatedly and could walk out of the store entirely.
func treeBytes(dir string) (int64, error) {
	var total int64
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			// A single unreadable file is not a reason to refuse the whole
			// report: a store is a cache, and a partial answer that says so
			// beats no answer. The caller sees it in the total being low,
			// which is the honest direction to be wrong in.
			return nil
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		total += info.Size()
		return nil
	})
	return total, err
}

// StoreTotals sums a scan: bytes, versions, distinct projects, and the
// bytes held by versions that are NOT the newest of their project present.
//
// That last number is the one worth printing and the easiest to misread, so
// its name says what it is: older, not garbage. Whether an older version
// can go depends on roots — a lock, an environment — that this package
// cannot see.
func StoreTotals(entries []StoreEntry) (bytes int64, versions, projects int, olderBytes int64) {
	seen := map[string]bool{}
	for _, e := range entries {
		bytes += e.Bytes
		versions++
		seen[e.Project] = true
		if !e.Newest {
			olderBytes += e.Bytes
		}
	}
	return bytes, versions, len(seen), olderBytes
}

// LIVE AND DEAD, against roots the caller names.
//
// # WHY A LOCK IS THE ROOT, AND WHY THAT MAKES THIS EXACT
//
// guix's rule is the one to copy: "any file under /gnu/store reachable from
// a root is considered live and cannot be deleted; any other file is
// considered dead". The roots are explicit — symlinks under
// /var/guix/gcroots, the user's profiles — and `guix gc --list-live`
// reports before `guix gc` removes.
//
// There is no profile here, which is why ScanStore reports and nothing
// deletes. But a LOCK is a root set already: it pins every project in the
// closure, not only the roots the person typed, which is the whole reason
// `pkgx --lock` exists. So reachability needs no graph walk and no network
// — membership in the lock IS the closure.
//
// An ENVIRONMENT would not do: it names constraints, which have to be
// resolved against the registry, and that is a network call this cannot
// make. Saying which of the two is usable here is better than offering both
// and failing on one.
//
// # IT STILL DELETES NOTHING, AND THE WORDING SAYS WHOSE ROOTS
//
// "Dead" here means "not reachable from the roots you named" — not
// "garbage". Name a different lock and a different half of the store is
// dead. The caller holds that judgement, and the report has to hand it back
// rather than imply the store has an opinion.
func LiveFromLocks(entries []StoreEntry, locks []Lock) (live, dead []StoreEntry) {
	rooted := map[string]bool{}
	for _, l := range locks {
		for _, p := range l.Pins {
			rooted[p.Project+"@"+p.Version] = true
		}
	}
	for _, e := range entries {
		if rooted[e.Project+"@"+e.Version] {
			live = append(live, e)
			continue
		}
		dead = append(dead, e)
	}
	return live, dead
}
