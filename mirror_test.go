package artifact

import "testing"

func TestVersionsForAndDownloadArtifact(t *testing.T) {
	t.Setenv("ZPKG_VERIFY", "0") // transport test: HTTP dist carries no signatures
	osn, arch := HostSlug()
	defer fakeServer(t, map[string]fakePkg{
		"acme.org/tool": {
			versions: []string{"1.0.0", "2.0.0"},
			yaml:     "provides:\n  - bin/tool\n",
			files:    map[string]string{"bin/tool": "x"},
		},
	})()
	vs, err := VersionsFor("acme.org/tool", osn, arch)
	if err != nil || len(vs) != 2 {
		t.Fatalf("VersionsFor n=%d err=%v", len(vs), err)
	}
	data, ext, err := DownloadArtifact("acme.org/tool", "2.0.0", osn, arch)
	if err != nil || ext != ".tar.gz" || len(data) == 0 {
		t.Fatalf("DownloadArtifact ext=%q n=%d err=%v", ext, len(data), err)
	}
	if _, _, err := DownloadArtifact("no.org/nope", "1.0.0", osn, arch); err == nil {
		t.Error("expected error for an unknown project (404)")
	}
}

func TestSatisfiesMethod(t *testing.T) {
	cases := []struct {
		v, c string
		want bool
	}{
		{"1.2.3", "^1.2", true},
		{"2.0.0", "^1", false},
		{"1.0.0", "*", true},
		{"1.2.3", ">=1.0", true},
	}
	for _, c := range cases {
		if got := ParseVer(c.v).Satisfies(c.c); got != c.want {
			t.Errorf("%s.Satisfies(%q)=%v want %v", c.v, c.c, got, c.want)
		}
	}
}

func TestApplyEnvOverride(t *testing.T) {
	d, p := DistBase, PantryBase
	defer func() { DistBase, PantryBase = d, p }()
	applyEnv(func(k string) string {
		switch k {
		case "ZPKG_DIST":
			return "https://mirror.example/"
		case "ZPKG_PANTRY":
			return "https://pantry.example/projects/"
		}
		return ""
	})
	if DistBase != "https://mirror.example" || PantryBase != "https://pantry.example/projects" {
		t.Errorf("override = %q / %q", DistBase, PantryBase)
	}
	// empty env leaves values unchanged
	applyEnv(func(string) string { return "" })
	if DistBase != "https://mirror.example" {
		t.Errorf("empty env should not clear DistBase, got %q", DistBase)
	}
}
