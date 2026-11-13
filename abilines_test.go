package artifact

import (
	"fmt"
	"strings"
	"testing"
)

// fakePick answers from a list of available versions, honouring the
// constraints exactly as the real resolver does: newest that satisfies all.
func fakePick(avail ...string) func(string, []string, string, string) (Ver, error) {
	return func(_ string, cs []string, _, _ string) (Ver, error) {
		for i := len(avail) - 1; i >= 0; i-- {
			v := ParseVer(avail[i])
			if satisfiesAll(v, cs) {
				return v, nil
			}
		}
		return Ver{}, fmt.Errorf("no version satisfies %v", cs)
	}
}

func annotate(m map[string]string) func(string, string, string, string) map[string]string {
	return func(_, tag, _, _ string) map[string]string {
		if s, ok := m[tag]; ok {
			return map[string]string{ABIProvidesAnnotation: s}
		}
		return nil
	}
}

// The case the whole mechanism exists for. hwloc wants >=2.14 and gettext
// wants ~2.13; both are right, because libxml2 broke its ABI inside major 2
// and they are describing two different libraries.
func TestPickABILinesSplitsLibxml2(t *testing.T) {
	oldP, oldA := pickOne, abiAnnotations
	defer func() { pickOne, abiAnnotations = oldP, oldA }()
	pickOne = fakePick("2.12.0", "2.13.9", "2.15.4")
	abiAnnotations = annotate(map[string]string{
		"2.12.0": "libxml2.2.dylib",
		"2.13.9": "libxml2.2.dylib",
		"2.15.4": "libxml2.16.dylib",
	})

	got, err := pickABILines("gnome.org/libxml2", []string{">=2.14", "~2.13"}, "darwin", "aarch64")
	if err != nil {
		t.Fatalf("pickABILines: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d lines, want 2: %+v", len(got), got)
	}
	// Newest first: the leading line owns PATH, which is what `v*` means too.
	if got[0].Raw != "2.15.4" || got[1].Raw != "2.13.9" {
		t.Errorf("lines = %s, %s; want 2.15.4 then 2.13.9", got[0].Raw, got[1].Raw)
	}
}

// Two versions that ship the SAME soname are a real conflict: whichever the
// loader reached first would silently be the wrong one. Refuse, and let the
// caller report the original refusal.
func TestPickABILinesRefusesWhenSonamesOverlap(t *testing.T) {
	oldP, oldA := pickOne, abiAnnotations
	defer func() { pickOne, abiAnnotations = oldP, oldA }()
	pickOne = fakePick("1.0.0", "2.0.0")
	abiAnnotations = annotate(map[string]string{
		"1.0.0": "libthing.1.dylib",
		"2.0.0": "libthing.1.dylib", // same soname, different version
	})

	_, err := pickABILines("a.org", []string{"~1", "~2"}, "darwin", "aarch64")
	if err == nil {
		t.Fatal("two versions shipping one soname were allowed to coexist")
	}
	if !strings.Contains(err.Error(), "libthing.1.dylib") {
		t.Errorf("the refusal does not name the shared soname: %v", err)
	}
}

// An artifact that declares nothing is UNKNOWN, not empty. Guessing here would
// produce exactly the failure the mechanism exists to prevent, so the refusal
// stands — which also means an old artifact cannot be split until it is
// republished.
func TestPickABILinesRefusesAnUndeclaredArtifact(t *testing.T) {
	oldP, oldA := pickOne, abiAnnotations
	defer func() { pickOne, abiAnnotations = oldP, oldA }()
	pickOne = fakePick("1.0.0", "2.0.0")
	abiAnnotations = annotate(map[string]string{"1.0.0": "libthing.1.dylib"}) // 2.0.0 says nothing

	_, err := pickABILines("a.org", []string{"~1", "~2"}, "darwin", "aarch64")
	if err == nil || !strings.Contains(err.Error(), "declares no sonames") {
		t.Fatalf("err = %v, want a refusal naming the undeclared artifact", err)
	}
}

// Demands that DO intersect are one group, so there is nothing to split and
// the caller keeps its single answer.
func TestPickABILinesDoesNotSplitWhatAgrees(t *testing.T) {
	oldP := pickOne
	defer func() { pickOne = oldP }()
	pickOne = fakePick("2.13.9", "2.15.4")

	if _, err := pickABILines("a.org", []string{">=2.13", "<3"}, "darwin", "aarch64"); err == nil {
		t.Fatal("demands that agree were split")
	}
}

// A demand nothing satisfies on its own is a dead constraint, not a line: the
// partition gives up so the caller reports why ONE version could not be found,
// which is the part an operator can act on.
func TestPartitionGivesUpOnADeadConstraint(t *testing.T) {
	oldP := pickOne
	defer func() { pickOne = oldP }()
	pickOne = fakePick("1.0.0")

	if g := partitionConstraints("a.org", []string{"~1", "~9"}, "darwin", "aarch64"); g != nil {
		t.Errorf("partition = %v, want none", g)
	}
}

// Three demands, two lines: the group that already holds ~2.13 takes >=2.13
// too rather than opening a third. Greedy is not minimal in general, but it
// must not split what one version already answers.
func TestPartitionGroupsWhatOneVersionAnswers(t *testing.T) {
	oldP := pickOne
	defer func() { pickOne = oldP }()
	pickOne = fakePick("2.13.9", "2.15.4")

	g := partitionConstraints("a.org", []string{"~2.13", ">=2.13", ">=2.14"}, "darwin", "aarch64")
	if len(g) != 2 {
		t.Fatalf("partition = %v, want two groups", g)
	}
	if len(g[0]) != 2 || g[0][0] != "~2.13" || g[0][1] != ">=2.13" {
		t.Errorf("first group = %v, want the two demands 2.13.9 answers", g[0])
	}
}

// One demand cannot be split, and saying so costs nothing: the caller reaches
// here only after a refusal, and a refusal on one constraint is about the
// constraint, never about unification.
func TestPickABILinesNeedsMoreThanOneDemand(t *testing.T) {
	if _, err := pickABILines("a.org", []string{"~1"}, "darwin", "aarch64"); err == nil {
		t.Fatal("a single demand was treated as splittable")
	}
}
