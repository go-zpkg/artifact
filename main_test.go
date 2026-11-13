package artifact

import (
	"os"
	"testing"
)

// TestMain zeroes the publish settle DELAY for the whole suite — the delay, not
// the function, so the window's code still runs and is still covered. It exists to
// make a concurrent-writer clobber detectable in production (see
// mergePlatformIntoIndex), and two seconds per push would otherwise be paid by
// every test that publishes — several minutes of sleeping for nothing. Tests
// that care about the window install their own.
func TestMain(m *testing.M) {
	indexSettleDelay = 0
	os.Exit(m.Run())
}
