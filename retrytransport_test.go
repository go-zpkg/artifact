package artifact

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

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
	resp, err := c.Get(srv.URL)
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
	resp, err := (&http.Client{Transport: &retryTransport{}}).Get(srv.URL)
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
	if resp.StatusCode != 502|| int(n.Load()) != ociAttempts {
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

func TestRetryTransportSparesNotFound(t *testing.T) {
	noRetrySleep(t)
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		http.NotFound(w, r)
	}))
	defer srv.Close()
	resp, err := (&http.Client{Transport: &retryTransport{}}).Get(srv.URL)
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
