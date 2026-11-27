package artifact

import (
	"errors"
	"io"
	"net/http"
	"syscall"
	"time"
)

// ociAttempts bounds how many times one idempotent registry request is tried.
const ociAttempts = 4

// ociRetrySleep is the pause between attempts; a seam for tests.
var ociRetrySleep = func(d time.Duration) { time.Sleep(d) }

// retryTransport retries a registry GET or HEAD that failed in transit (a
// timeout awaiting response headers, a reset connection) or that the registry
// answered 429/502/503/504. Blob downloads already retry on their own; the
// manifest and referrer requests did not, so one stalled response from ghcr.io
// failed a whole seed build ("timeout awaiting response headers").
// Writes (POST/PUT/PATCH/DELETE) are never retried: they are not idempotent
// and their bodies are streamed.
type retryTransport struct {
	base http.RoundTripper
}

func (t *retryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		return base.RoundTrip(req)
	}
	var (
		resp *http.Response
		err  error
	)
	for attempt := 1; ; attempt++ {
		if cerr := req.Context().Err(); cerr != nil {
			return nil, cerr
		}
		resp, err = base.RoundTrip(req)
		retryable := false
		switch {
		case err != nil:
			retryable = isTransient(err) && req.Context().Err() == nil
		default:
			switch resp.StatusCode {
			case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
				retryable = true
			}
		}
		if !retryable || attempt >= ociAttempts {
			return resp, err
		}
		var reason string
		if err != nil {
			reason = err.Error()
		} else {
			reason = "status " + resp.Status
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
			resp.Body.Close()
		}
		warn("registry %s %s failed (%s); retrying (%d/%d)", req.Method, req.URL.Redacted(), reason, attempt, ociAttempts-1)
		ociRetrySleep(time.Duration(attempt) * 2 * time.Second)
	}
}

// isTransient reports a failure worth retrying: a timeout, or a connection
// that was cut (EOF, reset, broken pipe). A refused connection or an unknown
// host is not transient: waiting does not change the answer, and retrying them
// would stall every caller pointed at a dead address.
func isTransient(err error) bool {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) {
		return true
	}
	var te interface{ Timeout() bool }
	return errors.As(err, &te) && te.Timeout()
}
