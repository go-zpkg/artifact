package artifact

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// A registry's challenge names a token endpoint; the credential belongs to the
// registry and must not follow the challenge to another host.
func TestCredentialsDoNotFollowATokenRealmToAnotherHost(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  map[string]string
	}{
		{"basic login", map[string]string{"OCI_USERNAME": "user", "OCI_PASSWORD": "secret"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var leaked atomic.Int32
			other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				leaked.Add(1)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"token":"t"}`))
			}))
			defer other.Close()
			// Same loopback address, another port: another host as far as a
			// credential is concerned.
			reg := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
					w.WriteHeader(http.StatusOK)
					return
				}
				w.Header().Set("Www-Authenticate", `Bearer realm="`+other.URL+`/token",service="x"`)
				w.WriteHeader(http.StatusUnauthorized)
			}))
			defer reg.Close()

			c, err := newOCIClientEnv("oci://"+strings.TrimPrefix(reg.URL, "http://")+"/o/r", func(k string) string { return tc.env[k] })
			if err != nil {
				t.Fatal(err)
			}
			req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, reg.URL+"/v2/", nil)
			resp, err := c.client.Do(req)
			if err == nil {
				resp.Body.Close()
				t.Error("the request was served although its token endpoint is another host")
			}
			if n := leaked.Load(); n != 0 {
				t.Errorf("the other host received %d request(s) from a client holding credentials", n)
			}
		})
	}
}

func TestCredentialGuardLetsTheRegistryAndAnonymousRequestsThrough(t *testing.T) {
	var got atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got.Add(1) }))
	defer srv.Close()
	g := &credentialGuard{host: strings.TrimPrefix(srv.URL, "http://")}
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	req.Header.Set("Authorization", "Basic x")
	resp, err := g.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	g.host = "elsewhere.example"
	req, _ = http.NewRequest(http.MethodGet, srv.URL, nil)
	resp, err = g.RoundTrip(req)
	if err != nil {
		t.Fatalf("an anonymous request was refused: %v", err)
	}
	resp.Body.Close()
	req, _ = http.NewRequest(http.MethodPost, srv.URL, strings.NewReader("password=p"))
	if _, err := g.RoundTrip(req); err == nil {
		t.Error("a token-request body was sent to another host")
	}
	if got.Load() != 2 {
		t.Errorf("server saw %d requests, want 2", got.Load())
	}
}
