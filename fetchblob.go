package artifact

// fetchblob.go pulls an artifact's layer blob with retries and byte-range resume.
//
// A toolchain artifact is big — llvm.org's linux/aarch64 layer is 1.68 GiB — and a
// single interrupted transfer used to lose the whole download: ORAS fetches a
// blob in one shot, so a mid-stream cut surfaced as
//
//	read failed: expected content size of 1762228910, got 1247805440 … unexpected EOF
//
// and the install died after twenty minutes of progress. Registries, CDNs and
// container-VM networks all cut long transfers; a package manager that pulls
// gigabyte artefacts has to resume rather than restart.
//
// The transfer itself lives in blobfile.go, which stages it on DISK. This file
// keeps only the in-memory convenience over it: same retries, same resume, same
// digest check, one implementation.

import (
	"context"
	"time"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// blobRetries is how many times a cut transfer is resumed before giving up, and
// blobBackoff paces the attempts. Vars so tests need no real waiting.
var (
	blobRetries = 5
	blobBackoff = func(attempt int) { time.Sleep(time.Duration(attempt) * 500 * time.Millisecond) }
)

// fetchBlob downloads desc's content and returns it in memory. It stages the
// blob on disk first and reads it back, so the retry/resume/digest behaviour is
// the file path's — there is no second implementation to drift.
//
// For an artifact-sized blob, prefer fetchBlobFile: this one costs the blob's size
// in anonymous memory, which is what a 2 GiB micro-VM does not have when the
// blob is a 1.7 GiB compiler.
func (c *OCIClient) fetchBlob(ctx context.Context, project string, desc ocispec.Descriptor) ([]byte, error) {
	f, err := c.fetchBlobFile(ctx, project, desc)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ioReadAll(f)
}
