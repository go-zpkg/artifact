package artifact

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SeedMarkerName is the file the installer writes at the root of every prefix
// it installed from the seed. A build that stages a prefix carrying it is
// built from seed bytes, and says so or is refused: the fact is written by the
// installer, in the prefix, where a build that never saw the seed flag cannot
// have left it out.
const SeedMarkerName = ".zpkg-seeded"

// markSeedPrefix writes the marker into a freshly extracted prefix, before it
// is renamed into place, so a seeded prefix is never visible unmarked.
func markSeedPrefix(prefix, digest string) error {
	p := filepath.Join(prefix, SeedMarkerName)
	if err := os.WriteFile(p, []byte(digest+"\n"), 0o444); err != nil {
		return fmt.Errorf("seed marker: %w", err)
	}
	return nil
}

// seedInForce reports whether an install running now is a seed install.
func seedInForce() bool {
	seedMu.Lock()
	defer seedMu.Unlock()
	return seedSource != ""
}

// IsSeedPrefix reports whether prefix was installed from the seed, and the
// digest recorded with it. A marker that is not a regular file (a symlink
// planted to look like one, a directory) is not trusted but IS reported as
// seeded: the question is whether the prefix may be believed unseeded.
func IsSeedPrefix(prefix string) (digest string, seeded bool, err error) {
	p := filepath.Join(prefix, SeedMarkerName)
	st, err := os.Lstat(p)
	if os.IsNotExist(err) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("seed marker: %w", err)
	}
	if !st.Mode().IsRegular() || st.Size() > 256 {
		return "", true, nil
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return "", false, fmt.Errorf("seed marker: %w", err)
	}
	return strings.TrimSpace(string(b)), true, nil
}
