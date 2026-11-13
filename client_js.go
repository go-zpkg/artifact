//go:build js

package artifact

import "net/http"

// NewHTTPClient builds the *http.Client used in a browser.
//
// It must NOT set DialContext, and that is the whole reason this file exists.
// Under GOOS=js there is no TCP: net/http reaches the network through the
// WHATWG Fetch API, and (*http.Transport).RoundTrip only takes that path when
// the transport has no custom dialer. Set one and every request falls back to
// Go's in-process fake network, so a page gets
//
//	Get "http://…/v2/": dial tcp …: connect: Connection refused
//
// for a registry that is up and answering. Measured in headless Chrome, one
// field at a time: an empty transport and one with TLSClientConfig both return
// 200; the same transport plus DialContext is the only one that fails.
//
// The rest of the native client's machinery has no meaning here either. The
// browser owns TLS and the trust store, so CertPool's embedded bundle is moot;
// and fetch exposes no dial or TLS-handshake phase to put a deadline on.
//
// The stall watchdog stays: it watches the response BODY for silence, which is
// transport-independent — and an artifact is exactly the kind of long download it
// exists for.
func NewHTTPClient() *http.Client {
	return &http.Client{
		Transport: &shortAcceptTransport{
			base: &stallTransport{
				idle: stallTimeout,
				base: &http.Transport{},
			},
		},
	}
}

// acceptSafelistLimit is the size beyond which CORS stops treating Accept as a
// safelisted request header (Fetch standard, "CORS-safelisted request-header":
// the value must be at most 128 bytes).
const acceptSafelistLimit = 128

// browserAccept is what a request asks for once its Accept is too long to stay
// safelisted. It names the two media types this registry actually serves, and
// fits under the limit.
const browserAccept = "application/vnd.oci.image.index.v1+json,application/vnd.oci.image.manifest.v1+json"

// shortAcceptTransport keeps Accept under the CORS safelist limit.
//
// oras-go asks for five media types when it resolves a reference — 243 bytes.
// Over 128, the browser stops treating Accept as safelisted and PREFLIGHTS the
// request; zot answers the preflight with
//
//	Access-Control-Allow-Headers: Authorization,content-type,X-ZOT-API-CLIENT
//
// which does not list accept, so the browser refuses to send the real request
// and fetch reports the opaque `TypeError: Failed to fetch`. Measured from a
// page against one URL, varying only this header: 39 bytes → 200, 128 → 200,
// 243 → TypeError.
//
// Rewriting a request header is the kind of quiet magic that bites later, so it
// happens ONLY in the browser build, ONLY when the value is over the limit, and
// it narrows to the types we publish rather than inventing one. If a registry
// ever answers a type outside that pair, the failure is a clean 406 rather than
// something subtle.
//
// The durable fix is to resolve manifests with this package's own HTTP instead
// of oras's — fetchBlobFile already does exactly that for blobs, and it would
// leave one client, one retry policy, one trust store. That touches manifest
// digest verification, so it is a change to make deliberately, not as a
// side effect of a browser workaround.
type shortAcceptTransport struct{ base http.RoundTripper }

func (t *shortAcceptTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if a := r.Header.Get("Accept"); len(a) > acceptSafelistLimit {
		r = r.Clone(r.Context())
		r.Header.Set("Accept", browserAccept)
	}
	return t.base.RoundTrip(r)
}
