package artifact

import (
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"unicode/utf8"
)

// realNames are command names that real packages provide. The first rule that
// shipped (a list of permitted characters) refused `[`, which is coreutils'
// `test`, and a rootfs build stopped on it (go-zpkg/packages#440).
var realNames = []string{
	"[", "[[", "g++", "c++", "x86_64-linux-gnu-gcc", "python3.13", "2to3",
	"bash", "apu-1-config", "x_y", "a@b", "a:b", "-dash", "é", "a b", "*", "?", "~", "#", "%", "{}", "!",
}

func needSh(t *testing.T) {
	t.Helper()
	switch runtime.GOOS {
	case "windows", "js", "wasip1", "plan9":
		t.Skip("no /bin/sh to run a stub")
	}
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh to run a stub")
	}
}

// runStub writes the stub for `name` the way StubBinsStaged does, a target that
// echoes its arguments where the stub points, and runs the stub from a
// directory where a canary would be visible. It returns what the target saw
// and whether the canary was created.
func runStub(t *testing.T, name string, args ...string) (out string, canary bool) {
	t.Helper()
	root := t.TempDir()
	guestPrefix := filepath.Join(root, "store")
	target := filepath.Join(guestPrefix, "bin", name)
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("#!/bin/sh\nfor a in \"$@\"; do printf '<%s>' \"$a\"; done\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	stubDir := filepath.Join(root, "stubs")
	if err := os.MkdirAll(stubDir, 0o755); err != nil {
		t.Fatal(err)
	}
	stub := filepath.Join(stubDir, name)
	if err := os.WriteFile(stub, []byte(stubScript(filepath.Join(root, "lib"), guestPrefix, name)), 0o755); err != nil {
		t.Fatal(err)
	}
	work := filepath.Join(root, "work")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(stub, args...)
	cmd.Dir = work
	b, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("stub for %q failed: %v\n%s", name, err, b)
	}
	ents, _ := os.ReadDir(work)
	return string(b), len(ents) != 0
}

func TestSafeStubNameAcceptsEveryRealName(t *testing.T) {
	for _, n := range realNames {
		if why := stubNameProblem(n); why != "" {
			t.Errorf("%q refused: %s", n, why)
		}
	}
}

func TestStubOfARealNameRunsAndForwardsArguments(t *testing.T) {
	needSh(t)
	for _, n := range realNames {
		out, canary := runStub(t, n, "x y", "--flag", "$HOME", "")
		if want := "<x y><--flag><$HOME><>"; out != want {
			t.Errorf("stub %q printed %q, want %q", n, out, want)
		}
		if canary {
			t.Errorf("stub %q created a file", n)
		}
	}
}

// Every refused class is refused with the reason it is unsafe.
func TestStubNameRefusalsSayWhy(t *testing.T) {
	for _, c := range []struct{ name, why string }{
		{"", "empty"},
		{".", "directory reference"},
		{"..", "directory reference"},
		{"a/b", "path separator"},
		{"../x", "path separator"},
		{"/abs", "path separator"},
		{"a\x00b", "NUL"},
	} {
		got := stubNameProblem(c.name)
		if !strings.Contains(got, c.why) {
			t.Errorf("%q: reason %q, want one mentioning %q", c.name, got, c.why)
		}
		if safeStubName(c.name) {
			t.Errorf("%q accepted", c.name)
		}
	}
}

// A name that is not refused is written as the LITERAL name and nothing else:
// each hostile spelling is run, and the canary it tries to create must not
// exist while the target still receives the arguments untouched.
func TestHostileNamesStayLiteral(t *testing.T) {
	needSh(t)
	for _, n := range []string{
		"$(touch canary)", "`touch canary`", "a\"; touch canary; \"", `\`, `a\"b`,
		";touch canary", "a;touch canary", "a\ntouch canary", "a\"$(touch canary)\"",
		"${IFS}", "$HOME", "$1", "a\rb", "\t", "'; touch canary; '",
	} {
		if !safeStubName(n) {
			t.Fatalf("%q was refused; the rule is that it is written literally", n)
		}
		out, canary := runStub(t, n, "one", "two words")
		if canary {
			t.Errorf("name %q ran something: a canary file exists", n)
		}
		if want := "<one><two words>"; out != want {
			t.Errorf("name %q: target printed %q, want %q", n, out, want)
		}
	}
}

// Reading the generated script: the name occurs only inside the double-quoted
// exec word, escaped by shDQ, and the script has the same three statements
// whatever the name holds.
func TestStubScriptQuotesTheNameEverywhere(t *testing.T) {
	for _, n := range append([]string{"$(id)", "`id`", `a"b`, `a\b`, ";rm"}, realNames...) {
		got := stubScript("/lib", "/g/p", n)
		want := "#!/bin/sh\nexport LD_LIBRARY_PATH=\"/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}\"\nexec \"" +
			shDQ(filepath.Join("/g/p", "bin", n)) + "\" \"$@\"\n"
		if got != want {
			t.Errorf("name %q: script %q, want %q", n, got, want)
		}
	}
	// the library path is quoted the same way
	if got := stubScript("/a\"$(id)`x`\\", "/g", "b"); !strings.Contains(got, "\"/a\\\"\\$(id)\\`x\\`\\\\${LD_LIBRARY_PATH") {
		t.Errorf("lib path not escaped: %q", got)
	}
}

// THE REAL-DATA GATE. The two rules that shipped before this one were each
// written from the names their author thought of; this reads every `provides`
// entry of the real recipes. It runs where ZPKG_RECIPES_DIR names a checkout of
// go-zpkg/recipes (the `recipes-names` CI job) and is skipped without it,
// because a unit test must not need the network.
func TestEveryRecipeProvidesNameIsStubbable(t *testing.T) {
	dir := os.Getenv("ZPKG_RECIPES_DIR")
	if dir == "" {
		t.Skip("ZPKG_RECIPES_DIR not set: the recipes-names CI job runs this against go-zpkg/recipes main")
	}
	var recipes, names int
	err := filepath.WalkDir(filepath.Join(dir, "projects"), func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || d.Name() != "package.hcl" {
			return nil
		}
		src, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		doc, err := HCLToMap(src, p)
		if err != nil {
			t.Errorf("%s: %v", p, err)
			return nil
		}
		project, _ := filepath.Rel(filepath.Join(dir, "projects"), filepath.Dir(p))
		var lists [][]string
		switch v := doc["provides"].(type) {
		case []any:
			if l, ok := stringList(v); ok {
				lists = append(lists, l)
			}
		case map[string]any: // one list per platform
			for _, pv := range v {
				if l, ok := stringList(pv); ok {
					lists = append(lists, l)
				}
			}
		}
		if len(lists) != 0 {
			recipes++
		}
		for _, l := range lists {
			for _, n := range BinNamesFor(filepath.ToSlash(project), l, "1.2.3") {
				names++
				if !safeStubName(n) {
					t.Errorf("%s provides %q, which the stub rule refuses", project, n)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// A walk that found nothing must not read as "all accepted".
	if recipes < 200 || names < 700 {
		t.Fatalf("read %d recipes and %d names; a checkout of recipes main holds 273 and 973 (2026-11-22)", recipes, names)
	}
	t.Logf("%d recipes, %d names, all accepted", recipes, names)
}

// FuzzStubName: whatever the name, either it is refused with a reason, or the
// stub runs the literal name, forwards its arguments and creates nothing.
func FuzzStubName(f *testing.F) {
	for _, n := range append([]string{"", ".", "..", "a/b", "../x", "a\x00b", "$(touch canary)", "`touch canary`",
		"\"", `\`, ";rm", "a\ntouch canary"}, realNames...) {
		f.Add(n)
	}
	f.Fuzz(func(t *testing.T, name string) {
		why := stubNameProblem(name)
		if (why == "") != safeStubName(name) {
			t.Fatalf("%q: reason %q disagrees with safeStubName", name, why)
		}
		if why != "" {
			if strings.Contains(name, "/") || name == "" || name == "." || name == ".." || strings.ContainsRune(name, 0) {
				return
			}
			t.Fatalf("%q refused for %q, but it is none of the unsafe classes", name, why)
		}
		// Non-ASCII names are the file system's business (macOS refuses some
		// code points as file names); the shell quoting does not depend on them.
		ascii := true
		for i := 0; i < len(name); i++ {
			ascii = ascii && name[i] < utf8.RuneSelf
		}
		if len(name) > 200 || !ascii || !strings.HasPrefix(runtime.GOOS, "linux") && runtime.GOOS != "darwin" {
			return
		}
		needSh(t)
		out, canary := runStub(t, name, "p q")
		if canary || out != "<p q>" {
			t.Fatalf("name %q: out %q canary %v", name, out, canary)
		}
	})
}
