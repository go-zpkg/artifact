package artifact

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

// ⛔⛔ THE DEFAULT REGISTRY MUST HOLD ARTIFACTS, AND NOTHING CHECKED THAT.
//
// The go-pkgx → go-zpkg rename rewrote DistBase from `ghcr.io/go-pkgx/packages`
// to `ghcr.io/go-zpkg/packages`, and v0.64.0 through v0.68.0 shipped it.
// GitHub's container packages are org-scoped and do NOT follow a repository
// transfer: every repository moved, every artifact stayed. So the whole fleet
// pointed at an empty registry, `zpkx` could fetch nothing with its defaults,
// and the only thing that noticed was a container check in another repository
// whose message I first read as a path problem.
//
// A URL is a claim about where something is. This asks the registry.
//
// ⛔ AND IT TELLS "NO NETWORK" FROM "WRONG REGISTRY", WHICH IS THE WHOLE
// DIFFICULTY. The suite runs on qemu lanes and wasm lanes with no route out,
// and a test that read a transport failure as an empty registry would be red
// on nine platforms for a reason that has nothing to do with the registry.
// A test that read it as success would be the defect this exists to catch,
// surviving as a skip. So: a refusal from the registry FAILS, an answer we
// could not obtain SKIPS, and the two are never folded together.
//
// (unread answer ≠ negative answer — the lesson this repository has learnt
// more than once.)
func TestTheDefaultRegistryHoldsArtifacts(t *testing.T) {
	const probe = "gnu.org/bash" // in every build of the catalogue since the first

	reg, repo, ok := strings.Cut(strings.TrimPrefix(DistBase, "oci://"), "/")
	if !ok {
		t.Fatalf("DistBase %q is not <registry>/<namespace>", DistBase)
	}
	if reg != "ghcr.io" {
		t.Skipf("DistBase points at %s, and this check only knows ghcr.io's token endpoint", reg)
	}
	full := repo + "/" + probe

	c := &http.Client{Timeout: 20 * time.Second}
	resp, err := c.Get("https://ghcr.io/token?scope=repository%3A" +
		strings.ReplaceAll(full, "/", "%2F") + "%3Apull&service=ghcr.io")
	if err != nil {
		t.Skipf("no answer from ghcr.io (%v) — this says nothing about the registry", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusForbidden, http.StatusUnauthorized:
		t.Fatalf("ghcr.io refuses an anonymous pull token for %s — DistBase (%s) names a namespace that does not publish %s",
			full, DistBase, probe)
	default:
		t.Skipf("ghcr.io answered %s to the token request — not a verdict on the registry", resp.Status)
	}
	var tok struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil || tok.Token == "" {
		t.Skipf("unreadable token response (%v) — not a verdict on the registry", err)
	}

	req, err := http.NewRequest("GET", "https://ghcr.io/v2/"+full+"/tags/list?n=1", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tok.Token)
	tags, err := c.Do(req)
	if err != nil {
		t.Skipf("no answer listing tags (%v)", err)
	}
	defer tags.Body.Close()
	if tags.StatusCode == http.StatusNotFound {
		t.Fatalf("%s does not exist — DistBase (%s) names an empty namespace", full, DistBase)
	}
	if tags.StatusCode != http.StatusOK {
		t.Skipf("ghcr.io answered %s listing tags — not a verdict", tags.Status)
	}
	var body struct {
		Tags []string `json:"tags"`
	}
	if err := json.NewDecoder(tags.Body).Decode(&body); err != nil {
		t.Skipf("unreadable tag list (%v)", err)
	}
	if len(body.Tags) == 0 {
		t.Fatalf("%s has no tags — DistBase (%s) names a namespace with nothing in it", full, DistBase)
	}
}
