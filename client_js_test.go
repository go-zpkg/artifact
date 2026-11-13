//go:build js

package artifact

// The browser half of the wasm story. It lives under `js` alone because what it
// tests does: shortAcceptTransport and the Accept cap exist to satisfy the CORS
// safelist, and wasip1 has no fetch, no CORS and no network at all.
//
// It used to sit in exec_wasm_test.go, which is built for `js || wasip1`, while
// the symbols it uses are declared in client_js.go, which is `js`. Nothing
// noticed: a cross-COMPILE lane does not build _test.go files, so the wasip1
// build stayed green while `go test` there could not compile at all. The first
// wasip1 test lane found it in its first run.

import (
	"net/http"
	"strings"
	"testing"
)

// TestNewHTTPClientHasNoDialer is the fix, asserted where it matters. Under
// GOOS=js, net/http reaches the network through fetch only when the transport
// has no custom dialer — set one and every request falls back to Go's
// in-process fake network and a live registry answers "connection refused".
// Measured in headless Chrome, one field at a time.
func TestNewHTTPClientHasNoDialer(t *testing.T) {
	c := NewHTTPClient()
	// The browser chain, outermost first: cap Accept, then watch for stalls,
	// then the stock transport that reaches fetch.
	sa, ok := c.Transport.(*shortAcceptTransport)
	if !ok {
		t.Fatalf("transport = %T, want the Accept cap outermost", c.Transport)
	}
	st, ok := sa.base.(*stallTransport)
	if !ok {
		t.Fatalf("under the Accept cap: %T, want the stall watchdog", sa.base)
	}
	tr, ok := st.base.(*http.Transport)
	if !ok {
		t.Fatalf("base = %T", st.base)
	}
	if tr.DialContext != nil || tr.Dial != nil {
		t.Error("a custom dialer disables fetch: every browser request would fail")
	}
	if tr.TLSClientConfig != nil {
		t.Error("the browser owns TLS; a client config here is dead weight")
	}
}

// TestShortAcceptTransportCapsOnlyWhatIsTooLong: the rewrite is a browser
// workaround, so it must touch as little as possible — an Accept that is
// already safelisted goes through untouched, and everything else about the
// request is preserved.
func TestShortAcceptTransportCapsOnlyWhatIsTooLong(t *testing.T) {
	var seen *http.Request
	tr := &shortAcceptTransport{base: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		seen = r
		return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
	})}

	short := "application/vnd.oci.image.index.v1+json"
	req, _ := http.NewRequest("GET", "http://x.test/v2/p/manifests/1.0.0", nil)
	req.Header.Set("Accept", short)
	req.Header.Set("Authorization", "Bearer t")
	if _, err := tr.RoundTrip(req); err != nil {
		t.Fatal(err)
	}
	if got := seen.Header.Get("Accept"); got != short {
		t.Errorf("a safelisted Accept was rewritten: %q", got)
	}
	if seen.Header.Get("Authorization") != "Bearer t" {
		t.Error("another header was lost")
	}

	long := strings.Repeat("application/vnd.oci.image.index.v1+json,", 6)
	if len(long) <= acceptSafelistLimit {
		t.Fatalf("fixture is only %d bytes, not over the limit", len(long))
	}
	req2, _ := http.NewRequest("GET", "http://x.test/v2/p/manifests/1.0.0", nil)
	req2.Header.Set("Accept", long)
	if _, err := tr.RoundTrip(req2); err != nil {
		t.Fatal(err)
	}
	got := seen.Header.Get("Accept")
	if len(got) > acceptSafelistLimit {
		t.Errorf("still over the safelist limit at %d bytes: %q", len(got), got)
	}
	if got != browserAccept {
		t.Errorf("Accept = %q, want the published media types", got)
	}
	// The caller's own request object must not be mutated: oras reuses it.
	if req2.Header.Get("Accept") != long {
		t.Error("the caller's request was mutated instead of a clone")
	}
}
