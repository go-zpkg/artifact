//go:build !js

package artifact

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"
)

// NewHTTPClient builds an *http.Client that trusts CertPool.
func NewHTTPClient() *http.Client {
	pool := CertPool()
	// NO whole-request Timeout: it caps a transfer by TOTAL elapsed time, which
	// kills a healthy but slow download of a large artifact (llvm.org and gcc are
	// ~1 GB; five minutes is not enough on a modest link, and the failure looks
	// like "context deadline exceeded" rather than "too slow"). What must be
	// bounded is a STALL, so the connection setup and the response headers get
	// deadlines, and the body is watched for silence.
	return &http.Client{
		Transport: &stallTransport{
			idle: stallTimeout,
			base: &http.Transport{
				TLSClientConfig:       &tls.Config{RootCAs: pool},
				DialContext:           (&net.Dialer{Timeout: 30 * time.Second}).DialContext,
				TLSHandshakeTimeout:   30 * time.Second,
				ResponseHeaderTimeout: 60 * time.Second,
				// HTTP/1.1 deliberately (a custom TLSClientConfig already opts
				// out of automatic HTTP/2): forcing h2 made ghcr abort a ~1 GB
				// blob mid-stream with "stream error … PROTOCOL_ERROR", and a
				// artifact pull has nothing to gain from multiplexing.
			},
		},
	}
}
