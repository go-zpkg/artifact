package artifact

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// Ordering the builds of one version.
//
// ⛔⛔ THERE IS NO BUILD DATE, AND THAT IS A DELIBERATE PROPERTY RATHER THAN A
// GAP TO FILL. A published artifact's timestamp is PINNED — `bk factory` stamps
// SOURCE_DATE_EPOCH, or its own fixed epoch when that is unset, never the
// wall clock — so that re-publishing the same artifact yields byte-identical
// attestations and the same referrer digests. Every artifact the factory
// publishes therefore carries the SAME instant, and sorting by it would order
// a list by a constant while looking like it ordered by time.
//
// Taking the wall clock instead would trade that for an ordering nobody
// needs: it would make every rebuild a new artefact and break the idempotent
// re-push. So the date is not recoverable from an artifact, by construction, and
// a reader asking "which is the newest" has to be answered with something
// that was actually written down.
//
// ⛔ AND ORDER IS A PRESENTATION QUESTION, NOT A RESOLUTION ONE. The resolver
// still refuses an ambiguous version: two builds of one version are siblings,
// and nothing here gives it permission to pick. What this orders is a LIST a
// person reads, and every key below is a recorded fact that the listing names
// out loud — never an inference dressed up as one.
type BuildOrder string

const (
	// ByStatus is the default: the builds that nothing is wrong with first,
	// the withdrawn ones last, each group by hash so the order is stable.
	//
	// It is the only key derived from a judgement, and the judgement was
	// made by a person and written in the withdrawal list — not by us.
	ByStatus BuildOrder = "status"
	// ByHash is the stable, meaningless order: what a script wants, and what
	// two runs are guaranteed to agree on.
	ByHash BuildOrder = "hash"
	// ByInstalled is most recently installed HERE first, then the ones that
	// are not installed at all.
	//
	// ⛔ IT IS A FACT ABOUT THIS MACHINE AND THE LISTING MUST SAY SO. It is
	// when you got the build, not when it was built, and the two are
	// unrelated: pulling a two-year-old artifact today puts it first.
	ByInstalled BuildOrder = "installed"
	// ByClosure is the order a reader actually means by "newer": a build made
	// against a later toolchain comes first.
	//
	// ⛔⛔ IT IS THE ONE ORDER THE ARTIFACTS THEMSELVES CARRY. There is no build
	// date (see above), but the closure IS recorded — so "built with go.dev
	// 1.27.4" against "built with go.dev 1.27.3" is a comparison of two facts
	// rather than an inference, and it is exactly the comparison a CVE
	// rebuild creates.
	//
	// ⛔ AND IT IS A PARTIAL ORDER, HONESTLY TOTALISED. See closureRank: one
	// build is later than another only when it is at least as new on EVERY
	// shared dependency and strictly newer on one. Two builds that each lead
	// on a different dependency are genuinely incomparable, and saying
	// otherwise would be the invented order this codebase keeps refusing.
	ByClosure BuildOrder = "closure"
)

// BuildOrders lists the keys, for a flag's help and for validating one.
var BuildOrders = []BuildOrder{ByStatus, ByClosure, ByHash, ByInstalled}

// ParseBuildOrder reads a sort key, naming the alternatives when it cannot.
func ParseBuildOrder(s string) (BuildOrder, error) {
	for _, o := range BuildOrders {
		if string(o) == s {
			return o, nil
		}
	}
	names := make([]string, 0, len(BuildOrders))
	for _, o := range BuildOrders {
		names = append(names, string(o))
	}
	return "", fmt.Errorf("%q is not a sort key (have: %s)", s, strings.Join(names, ", "))
}

// SortBuilds orders builds in place and returns them.
//
// ⛔ EVERY KEY FALLS BACK TO THE HASH. Without it two builds that tie on the
// key keep whatever order they arrived in, which is a map walk — so the same
// command would print a different list twice and a reader would stop
// believing either.
func SortBuilds(project string, builds []Build, by BuildOrder) []Build {
	// ⛔⛔ THE RANK IS COMPUTED ONCE, OUTSIDE THE COMPARATOR, AND THAT IS NOT
	// an optimisation. Dominance is a PARTIAL order, and a partial order used
	// directly as a `less` function is not a strict weak ordering: sort.Slice
	// may then produce a nonsensical permutation or panic, depending on the
	// input. Counting how many builds dominate each one turns it into a total
	// order over integers, which sort can be trusted with — and which is also
	// explainable to a reader: rank 0 is "nothing here is later than this".
	rank := map[string]int{}
	if by == ByClosure {
		rank = closureRank(builds)
	}
	sort.SliceStable(builds, func(i, j int) bool {
		a, b := builds[i], builds[j]
		switch by {
		case ByClosure:
			if ra, rb := rank[a.Hash()], rank[b.Hash()]; ra != rb {
				return ra < rb
			}
		case ByInstalled:
			if a.InstalledAt != b.InstalledAt {
				// Not installed sorts last, whatever the zero time would do.
				switch {
				case a.InstalledAt.IsZero():
					return false
				case b.InstalledAt.IsZero():
					return true
				}
				return a.InstalledAt.After(b.InstalledAt)
			}
		case ByStatus:
			aw, bw := isWithdrawn(project, a), isWithdrawn(project, b)
			if aw != bw {
				return bw
			}
		}
		return a.Hash() < b.Hash()
	})
	return builds
}

// closureRank counts, for each build, how many of the others are strictly
// LATER than it. Rank 0 means nothing listed here supersedes it.
//
// ⛔ A COUNT RATHER THAN A CHAIN, because dominance is partial: with three
// builds where A beats B, and C is incomparable with both, there is no chain
// to walk. The count orders what can be ordered and leaves the rest tied, and
// a tie falls back to the hash so the output is still stable.
func closureRank(builds []Build) map[string]int {
	rank := make(map[string]int, len(builds))
	for _, a := range builds {
		n := 0
		for _, b := range builds {
			if a.Hash() == b.Hash() {
				continue
			}
			if closureIsLater(b.Spec, a.Spec) {
				n++
			}
		}
		rank[a.Hash()] = n
	}
	return rank
}

// closureIsLater reports whether a was built against a strictly later closure
// than b: at least as new on every dependency they share, and newer on one.
//
// ⛔ ONLY THE SHARED DEPENDENCIES ARE COMPARED. A build that gained a
// dependency the other does not have is a different SHAPE, not a later
// version of it — treating an extra edge as "newer" would say the CUDA build
// supersedes the plain one, which is a statement about taste and not about
// time.
//
// ⛔ AND A SPEC THAT RECORDS NOTHING IS NEVER LATER AND NEVER EARLIER. Every
// artifact published before identities existed is one of those; ranking them
// against a described build would be comparing a fact with a blank.
func closureIsLater(a, b Concrete) bool {
	if a.IsZero() || b.IsZero() {
		return false
	}
	shared := 0
	better := false
	for _, da := range a.Deps {
		for _, db := range b.Deps {
			if da.Project != db.Project {
				continue
			}
			shared++
			switch cmpVer(ParseVer(da.Version), ParseVer(db.Version)) {
			case -1:
				return false // older on this one: not later overall
			case 1:
				better = true
			}
		}
	}
	return shared > 0 && better
}

func isWithdrawn(project string, b Build) bool {
	_, yes := WithdrawalOf(project, b.Version.Raw, b.Hash())
	return yes
}

// installedAt is when a build's directory appeared in this store, or the zero
// time when it is not installed.
//
// ⛔ THE DIRECTORY'S OWN MODIFICATION TIME, NOT A FILE INSIDE IT. An artifact's
// files carry the timestamps the archive recorded, which the publisher pinned
// for reproducibility — so reading one would report the pinned epoch and
// call it an install date.
func installedAt(path string) time.Time {
	if path == "" {
		return time.Time{}
	}
	fi, err := os.Stat(path)
	if err != nil {
		return time.Time{}
	}
	return fi.ModTime()
}

// WhyNoDate is the one line a command prints when a reader asks for an order
// by build date, so the absence is explained rather than looking like an
// oversight.
const WhyNoDate = "there is no build date: a published artifact's timestamp is pinned " +
	"(SOURCE_DATE_EPOCH) so that re-publishing it is byte-identical, which means every " +
	"artifact carries the same instant. --sort=installed orders by when THIS machine got them."
