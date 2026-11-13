package artifact

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func readServiceFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "service", name+".hcl"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The three daemons the shape was derived from, each read back field by field.
// What varies between them is exactly what the block holds.
func TestParseServiceTheThreeDaemons(t *testing.T) {
	want := map[string]*Service{
		"authnd": {
			Name: "authnd", Description: "authnd LDAP directory and Kerberos KDC",
			Documentation: "https://github.com/go-authn/authnd",
			Command:       "authnd", Args: []string{"--config", "/etc/authnd"}, User: "authnd",
			Capabilities: []string{"CAP_NET_BIND_SERVICE"},
			Restart:      "on-failure", Reload: "none", ProcSubset: "all",
			StateDirectory: &ServiceDirectory{Mode: "0700"},
		},
		"authn-bridge": {
			Name: "authn-bridge", Description: "authn-bridge, an OpenID Connect provider in front of a SAML federation",
			Documentation: "https://github.com/go-authn/bridge/blob/main/docs/install.md",
			Command:       "authn-bridge", Args: []string{"--config", "/etc/authn-bridge"}, User: "authn-bridge",
			Restart: "on-failure", Reload: "none", ProcSubset: "pid", StopTimeout: "20s",
			StateDirectory:         &ServiceDirectory{Mode: "0700"},
			RuntimeDirectory:       &ServiceDirectory{Mode: "0700"},
			ConfigurationDirectory: &ServiceDirectory{Mode: "0750"},
		},
		"authn-revokd": {
			Name: "authn-revokd", Description: "go-authn revocation list agent (SSH KRLs, X.509 CRLs)",
			Documentation: "https://github.com/go-authn/revocation",
			Command:       "authn-revokd", Args: []string{"-config", "/etc/authn-revokd/revokd.hcl"}, User: "authn-revokd",
			Restart: "always", Reload: "hup", ProcSubset: "pid",
			StateDirectory: &ServiceDirectory{Mode: "0755"},
		},
	}
	for name, w := range want {
		got, err := ParseService(readServiceFixture(t, name), name+".hcl")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !reflect.DeepEqual(got, w) {
			t.Errorf("%s:\n got %+v\nwant %+v", name, got, w)
		}
	}
}

func TestParseServiceDefaults(t *testing.T) {
	got, err := ParseService([]byte(`service "x" { command = "x" }`), "p.hcl")
	if err != nil {
		t.Fatal(err)
	}
	want := &Service{Name: "x", Description: "x", Command: "x", User: "x",
		Restart: "on-failure", Reload: "none", ProcSubset: "pid"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
	// Args and capabilities given as empty lists are empty, not absent.
	got, err = ParseService([]byte(`service "x" {
  command = "x"
  args = []
  capabilities = []
}`), "p.hcl")
	if err != nil || len(got.Args) != 0 || len(got.Capabilities) != 0 {
		t.Errorf("empty lists: %+v %v", got, err)
	}
}

func TestParseServiceNone(t *testing.T) {
	s, err := ParseService([]byte(`provides = ["bin/x"]`+"\nbuild {\n  script = \"x\"\n}\n"), "p.hcl")
	if s != nil || err != nil {
		t.Errorf("a recipe without a service: %+v, %v", s, err)
	}
}

// Every refusal names the problem, and a value that would let a recipe write
// a directive into a unit root loads is among them.
func TestParseServiceRefuses(t *testing.T) {
	cases := map[string]struct{ src, want string }{
		"two blocks":      {`service "a" { command = "a" }` + "\n" + `service "b" { command = "b" }`, "at most one"},
		"no label":        {`service { command = "a" }`, "exactly one label"},
		"two labels":      {`service "a" "b" { command = "a" }`, "exactly one label"},
		"bad name":        {`service "A b" { command = "a" }`, `name "A b"`},
		"name with @":     {`service "a@b" { command = "a" }`, "name"},
		"unknown attr":    {`service "a" {` + "\n" + `command = "a"` + "\n" + `capabilites = []` + "\n}", `unknown attribute "capabilites"`},
		"unknown block":   {`service "a" {` + "\n" + `command = "a"` + "\n" + `cache-directory { mode = "0700" }` + "\n}", `unknown block "cache-directory"`},
		"dir twice":       {`service "a" {` + "\n" + `command = "a"` + "\n" + `state-directory { mode = "0700" }` + "\n" + `state-directory { mode = "0700" }` + "\n}", "given twice"},
		"dir label":       {`service "a" {` + "\n" + `command = "a"` + "\n" + `state-directory "x" { mode = "0700" }` + "\n}", "takes no label"},
		"dir block":       {`service "a" {` + "\n" + `command = "a"` + "\n" + "state-directory {\nmode = \"0700\"\nx {}\n}\n}", "holds no block"},
		"dir attr":        {`service "a" {` + "\n" + `command = "a"` + "\n" + "state-directory {\nmode = \"0700\"\nowner = \"x\"\n}\n}", `unknown attribute "owner"`},
		"dir no mode":     {`service "a" {` + "\n" + `command = "a"` + "\n" + "state-directory {}\n}", "octal mode"},
		"dir bad mode":    {`service "a" {` + "\n" + `command = "a"` + "\n" + "state-directory { mode = \"777\" }\n}", "octal mode"},
		"dir mode number": {`service "a" {` + "\n" + `command = "a"` + "\n" + "state-directory { mode = 700 }\n}", "a string is required"},
		"dir mode eval":   {`service "a" {` + "\n" + `command = "a"` + "\n" + "state-directory { mode = nope }\n}", "mode"},
		"no command":      {`service "a" {}`, "command is required"},
		"path command":    {`service "a" { command = "/bin/sh" }`, "not a path"},
		"newline arg":     {`service "a" {` + "\n" + `command = "a"` + "\n" + `args = ["x\nUser=root"]` + "\n}", "args"},
		"space arg":       {`service "a" {` + "\n" + `command = "a"` + "\n" + `args = ["a b"]` + "\n}", "args"},
		"percent arg":     {`service "a" {` + "\n" + `command = "a"` + "\n" + `args = ["%i"]` + "\n}", "args"},
		"dollar arg":      {`service "a" {` + "\n" + `command = "a"` + "\n" + `args = ["$HOME"]` + "\n}", "args"},
		"semicolon arg":   {`service "a" {` + "\n" + `command = "a"` + "\n" + `args = [";"]` + "\n}", "args"},
		"quote arg":       {`service "a" {` + "\n" + `command = "a"` + "\n" + `args = ["\"x"]` + "\n}", "args"},
		"empty arg":       {`service "a" {` + "\n" + `command = "a"` + "\n" + `args = [""]` + "\n}", "args"},
		"args not list":   {`service "a" {` + "\n" + `command = "a"` + "\n" + `args = "x"` + "\n}", "list of strings"},
		"args of numbers": {`service "a" {` + "\n" + `command = "a"` + "\n" + `args = [1]` + "\n}", "a string is required"},
		"command number":  {`service "a" { command = 1 }`, "a string is required"},
		"eval error":      {`service "a" { command = nope }`, "command"},
		"bad user":        {`service "a" {` + "\n" + `command = "a"` + "\n" + `user = "Root"` + "\n}", "user"},
		"name not user":   {`service "1x" { command = "a" }`, "user"},
		"bad capability":  {`service "a" {` + "\n" + `command = "a"` + "\n" + `capabilities = ["NET_ADMIN"]` + "\n}", "capability"},
		"bad restart":     {`service "a" {` + "\n" + `command = "a"` + "\n" + `restart = "no"` + "\n}", "restart"},
		"bad reload":      {`service "a" {` + "\n" + `command = "a"` + "\n" + `reload = "usr1"` + "\n}", "reload"},
		"bad proc-subset": {`service "a" {` + "\n" + `command = "a"` + "\n" + `proc-subset = "none"` + "\n}", "proc-subset"},
		"bad timeout":     {`service "a" {` + "\n" + `command = "a"` + "\n" + `stop-timeout = "soon"` + "\n}", "stop-timeout"},
		"newline descr":   {`service "a" {` + "\n" + `command = "a"` + "\n" + `description = "x\nUser=root"` + "\n}", "description"},
		"quote descr":     {`service "a" {` + "\n" + `command = "a"` + "\n" + `description = "x\" y"` + "\n}", "description"},
		"bad doc":         {`service "a" {` + "\n" + `command = "a"` + "\n" + `documentation = "see the wiki"` + "\n}", "documentation"},
		"parse error":     {`service "a" {`, "hcl: parse"},
	}
	for name, c := range cases {
		s, err := ParseService([]byte(c.src), "p.hcl")
		if err == nil {
			t.Errorf("%s: accepted %+v", name, s)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want it to say %q", name, err, c.want)
		}
		if name != "parse error" && !strings.HasPrefix(name, "dir mode eval") && name != "eval error" && !errors.Is(err, ErrBadService) {
			t.Errorf("%s: %v does not wrap ErrBadService", name, err)
		}
	}
}

// ⛔ THE READER EVERY INSTALLED CLIENT CARRIES MUST NOT BREAK ON THE BLOCK.
//
// HCLToMap and recipeDoc are the code artifact v0.43.0 shipped, unchanged here,
// so this is that reader's behaviour: a recipe with one service block reads
// as the same recipe — same dependencies, same provides — as without it,
// through the whole consumer path (overlay over HTTP, merged over the base).
//
// It also pins the ONE thing that reader refuses, which is the reason for the
// one-block rule: two blocks are a duplicate key, and the whole recipe fails.
// If HCLToMap ever starts keeping labels, the second half fails and the rule
// can be reconsidered — for clients from that version on.
func TestOldReaderIgnoresOneServiceBlock(t *testing.T) {
	plain := "provides = [\"bin/authn-bridge\"]\ndependencies = { \"openssl.org\" = \"^3\" }\n"
	withOne := plain + string(readServiceFixture(t, "authn-bridge"))[strings.Index(string(readServiceFixture(t, "authn-bridge")), "service \""):]
	withTwo := withOne + "\nservice \"other\" {\n  command = \"other\"\n}\n"

	if _, err := HCLToMap([]byte(withOne), "package.hcl"); err != nil {
		t.Fatalf("one service block: %v", err)
	}
	if _, err := HCLToYAML([]byte(withOne), "package.hcl"); err != nil {
		t.Fatalf("one service block, through the YAML the builder's schema reads: %v", err)
	}
	if _, err := HCLToMap([]byte(withTwo), "package.hcl"); err == nil || !strings.Contains(err.Error(), `duplicate key "service"`) {
		t.Fatalf("two service blocks: %v — the one-block rule exists because this reader refuses them", err)
	}

	serve := func(recipe string) (map[string]string, []string, error) {
		mux := http.NewServeMux()
		mux.HandleFunc("/overlay/acme.org/d/package.hcl", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(recipe))
		})
		srv := httptest.NewServer(mux)
		defer srv.Close()
		o, p := PantryOverlay, PantryBase
		defer func() { PantryOverlay, PantryBase = o, p }()
		PantryOverlay, PantryBase = srv.URL+"/overlay", srv.URL+"/pantry"
		return FetchMetaFor("acme.org/d", "linux", "aarch64")
	}
	d0, p0, err := serve(plain)
	if err != nil {
		t.Fatal(err)
	}
	d1, p1, err := serve(withOne)
	if err != nil {
		t.Fatalf("FetchMeta with a service block: %v", err)
	}
	if !reflect.DeepEqual(d0, d1) || !reflect.DeepEqual(p0, p1) {
		t.Errorf("the block changed what an old reader sees: deps %v → %v, provides %v → %v", d0, d1, p0, p1)
	}
	if _, _, err := serve(withTwo); err == nil {
		t.Error("two blocks reached a consumer without error; the fixture no longer shows the hazard")
	}
	// And the new reader refuses two blocks itself, naming the reason.
	if _, err := ParseService([]byte(withTwo), "package.hcl"); err == nil || !strings.Contains(err.Error(), "duplicate key") {
		t.Errorf("ParseService on two blocks: %v", err)
	}
}

func TestFetchService(t *testing.T) {
	old := sleep
	sleep = func(time.Duration) {}
	defer func() { sleep = old }()
	bridge := readServiceFixture(t, "authn-bridge")
	files := map[string]string{
		"/overlay/acme.org/over/package.hcl":        string(bridge),
		"/pantry/acme.org/over/package.hcl":         `service "wrong" { command = "wrong" }`,
		"/pantry/acme.org/base/package.hcl":         string(bridge),
		"/overlay/acme.org/inherit/package.hcl":     `provides = ["bin/authn-bridge"]`,
		"/pantry/acme.org/inherit/package.hcl":      string(bridge),
		"/overlay/acme.org/none/package.hcl":        `provides = ["bin/x"]`,
		"/overlay/acme.org/bad/package.hcl":         `service "a" {}`,
		"/pantry/acme.org/yaml/package.yml":         "service:\n  command: x\n",
		"/overlay/acme.org/unreachable/package.hcl": "",
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "unreachable") {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		b, ok := files[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(b))
	}))
	defer srv.Close()
	o, p := PantryOverlay, PantryBase
	defer func() { PantryOverlay, PantryBase = o, p }()
	PantryOverlay, PantryBase = srv.URL+"/overlay", srv.URL+"/pantry"

	for project, want := range map[string]string{
		"acme.org/over":    "authn-bridge", // the overlay's block replaces the base's
		"acme.org/base":    "authn-bridge", // not in the overlay at all
		"acme.org/inherit": "authn-bridge", // in the overlay, without a block: inherited
	} {
		s, err := FetchService(project)
		if err != nil || s == nil || s.Name != want {
			t.Errorf("%s: %+v, %v; want %s", project, s, err, want)
		}
	}
	for _, project := range []string{"acme.org/none", "acme.org/yaml", "acme.org/absent"} {
		if s, err := FetchService(project); s != nil || err != nil {
			t.Errorf("%s: %+v, %v; want no service", project, s, err)
		}
	}
	if _, err := FetchService("acme.org/bad"); !errors.Is(err, ErrBadService) {
		t.Errorf("a bad block: %v", err)
	}
	if _, err := FetchService("acme.org/unreachable"); err == nil || errors.Is(err, ErrBadService) {
		t.Errorf("a pantry that cannot be asked must be an error, not \"no service\": %v", err)
	}
	if _, err := FetchService("../../etc"); err == nil {
		t.Error("a project name that is a path was fetched")
	}
	PantryOverlay = ""
	if s, err := FetchService("acme.org/base"); err != nil || s == nil {
		t.Errorf("no overlay: %+v, %v", s, err)
	}
}
