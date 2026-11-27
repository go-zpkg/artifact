package artifact

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// getWithin GETs under a deadline: an unbounded retry loop (the sleep is a
// no-op here) becomes a failing test, not a hung one.
func getWithin(c *http.Client, url string) (*http.Response, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	time.AfterFunc(4*time.Second, cancel)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	return c.Do(req)
}

func noRetrySleep(t *testing.T) {
	t.Helper()
	old := ociRetrySleep
	ociRetrySleep = func(time.Duration) {}
	t.Cleanup(func() { ociRetrySleep = old })
}

func TestRetryTransportRecoversFromTransientFailures(t *testing.T) {
	noRetrySleep(t)
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) <= 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	var logs []string
	oldWarn := Warn
	Warn = func(m string) { logs = append(logs, m) }
	defer func() { Warn = oldWarn }()

	c := &http.Client{Transport: &retryTransport{}}
	resp, err := getWithin(c, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 || n.Load() != 3 {
		t.Fatalf("status %d after %d requests, want 200 after 3", resp.StatusCode, n.Load())
	}
	if len(logs) != 2 || !strings.Contains(logs[0], "retrying (1/3)") {
		t.Fatalf("retries not logged: %q", logs)
	}
}

func TestRetryTransportRetriesDroppedConnection(t *testing.T) {
	noRetrySleep(t)
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) == 1 {
			conn, _, _ := w.(http.Hijacker).Hijack()
			conn.Close()
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	resp, err := getWithin(&http.Client{Transport: &retryTransport{}}, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if n.Load() != 2 {
		t.Fatalf("%d requests, want 2", n.Load())
	}
}

func TestRetryTransportIsBoundedAndSparesWrites(t *testing.T) {
	noRetrySleep(t)
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()
	c := &http.Client{Transport: &retryTransport{}}
	// A deadline turns an unbounded retry loop into a failure, not a hang.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%v after %d requests, want 502 after %d", err, n.Load(), ociAttempts)
	}
	resp.Body.Close()
	if resp.StatusCode != 502 || int(n.Load()) != ociAttempts {
		t.Fatalf("status %d after %d requests, want 502 after %d", resp.StatusCode, n.Load(), ociAttempts)
	}
	n.Store(0)
	resp, err = c.Post(srv.URL, "text/plain", strings.NewReader("x"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if n.Load() != 1 {
		t.Fatalf("a POST was tried %d times, want 1", n.Load())
	}
}

func TestRetryTransportSparesARefusedConnection(t *testing.T) {
	noRetrySleep(t)
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close() // nothing listens there now: connection refused
	var slept atomic.Int32
	ociRetrySleep = func(time.Duration) { slept.Add(1) }
	_, err := getWithin(&http.Client{Transport: &retryTransport{}}, url)
	if err == nil {
		t.Fatal("a closed port answered")
	}
	if slept.Load() != 0 {
		t.Fatalf("a refused connection was retried %d times, want 0", slept.Load())
	}
}

func TestIsTransient(t *testing.T) {
	for _, c := range []struct {
		err  error
		want bool
	}{
		{io.EOF, true},
		{io.ErrUnexpectedEOF, true},
		{syscall.ECONNRESET, true},
		{syscall.EPIPE, true},
		{syscall.ECONNREFUSED, false},
		{context.Canceled, false},
		{context.DeadlineExceeded, true},
		{errors.New("no such host"), false},
	} {
		if got := isTransient(c.err); got != c.want {
			t.Errorf("isTransient(%v) = %v, want %v", c.err, got, c.want)
		}
	}
}

func TestRetryTransportSparesNotFound(t *testing.T) {
	noRetrySleep(t)
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		http.NotFound(w, r)
	}))
	defer srv.Close()
	resp, err := getWithin(&http.Client{Transport: &retryTransport{}}, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if n.Load() != 1 {
		t.Fatalf("a 404 was tried %d times, want 1", n.Load())
	}
}

func TestOCIClientRetries(t *testing.T) {
	for name, env := range map[string]map[string]string{
		"anonymous":   {},
		"credentials": {"OCI_USERNAME": "u", "OCI_PASSWORD": "p"},
	} {
		t.Run(name, func(t *testing.T) {
			c, err := newOCIClientEnv("oci://127.0.0.1:5000/x", func(k string) string { return env[k] })
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := c.client.Client.Transport.(*retryTransport); !ok {
				t.Fatalf("OCI transport is %T, want *retryTransport", c.client.Client.Transport)
			}
		})
	}
}

type countingRT struct{ n int }

func (c *countingRT) RoundTrip(*http.Request) (*http.Response, error) {
	c.n++
	return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
}

func TestRetryTransportSendsNothingForACancelledRequest(t *testing.T) {
	base := &countingRT{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://example.test/", nil)
	if _, err := (&retryTransport{base: base}).RoundTrip(req); err == nil || base.n != 0 {
		t.Fatalf("err=%v after %d sends, want an error and none sent", err, base.n)
	}
}
