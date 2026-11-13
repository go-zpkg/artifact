package artifact

import (
	"crypto/x509"
	_ "embed"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// cacert is the Mozilla CA bundle, compiled into the binary so TLS works on a
// bare `FROM scratch` image with no system trust store.
//
//go:embed cacert.pem
var cacert []byte

// HTTPClient is an HTTP client that trusts the embedded CA bundle (falling
// back to the system pool if, somehow, the embed is empty). It is overridable.
var HTTPClient = NewHTTPClient()

// systemCertPool is x509.SystemCertPool, swappable in tests so the
// no-system-trust-store fallback (an unusual platform, or a scratch image) is
// exercisable on a host that does have one.
var systemCertPool = x509.SystemCertPool

// CertPool is the trust store the go-zpkg tools use: the host's, plus the
// embedded Mozilla bundle. On a FROM-scratch image there is no system store at
// all, so the embedded bundle is the only thing standing between a tool and
// "x509: certificate signed by unknown authority" — which is exactly what bk hit
// when it tried to reach github from inside a scratch builder.
func CertPool() *x509.CertPool {
	pool, err := systemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	pool.AppendCertsFromPEM(cacert)
	return pool
}

// stallTimeout is how long a transfer may deliver nothing before it is treated
// as dead. Progress resets it, so a big artifact can take as long as it needs.
var stallTimeout = 60 * time.Second

// stallTransport guards every response body against a stalled transfer.
type stallTransport struct {
	base http.RoundTripper
	idle time.Duration
}

func (t *stallTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(r)
	if err != nil || resp.Body == nil {
		return resp, err
	}
	resp.Body = &stallReader{rc: resp.Body, idle: t.idle}
	return resp, nil
}

// stallReader fails a read that has gone quiet for idle, by closing the body
// from a timer (a blocked Read cannot be interrupted otherwise). Every byte
// received rearms the timer.
type stallReader struct {
	rc    io.ReadCloser
	idle  time.Duration
	timer *time.Timer
	mu    sync.Mutex
	dead  bool
}

func (s *stallReader) Read(p []byte) (int, error) {
	s.mu.Lock()
	if s.timer == nil {
		s.timer = time.AfterFunc(s.idle, func() {
			s.mu.Lock()
			s.dead = true
			s.mu.Unlock()
			s.rc.Close()
		})
	}
	s.mu.Unlock()

	n, err := s.rc.Read(p)
	if n > 0 {
		s.timer.Reset(s.idle)
	}
	if err != nil {
		s.mu.Lock()
		dead := s.dead
		s.mu.Unlock()
		if dead {
			return n, fmt.Errorf("transfer stalled for %s: %w", s.idle, err)
		}
	}
	return n, err
}

func (s *stallReader) Close() error {
	s.mu.Lock()
	if s.timer != nil {
		s.timer.Stop()
	}
	s.mu.Unlock()
	return s.rc.Close()
}
