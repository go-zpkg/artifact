package artifact

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// convert is the only assertion that matters on the happy path: YAMLToHCL
// refuses anything that does not parse back into the same document, so a call
// that returns without an error has already been checked.
func convert(t *testing.T, yml string) string {
	t.Helper()
	out, err := YAMLToHCL([]byte(yml), "package.yml")
	if err != nil {
		t.Fatalf("YAMLToHCL refused:\n%s\n--- from ---\n%s", err, yml)
	}
	return string(out)
}

// The trap the whole conversion turns on. HCL reads ${…} as an interpolation
// and recipe scripts are full of shell expansions; left alone it either fails
// to parse or evaluates part of a build script.
func TestYAMLToHCLDefusesTemplateSyntax(t *testing.T) {
	got := convert(t, "build:\n  script: |\n    make PREFIX=${DEST} install\n")
	if !strings.Contains(got, "$${DEST}") {
		t.Errorf("the sigil must be doubled:\n%s", got)
	}
	// And it comes back out. The recipe the builder sees must hold the shell's
	// text, not HCL's escape of it.
	m, err := HCLToMap([]byte(got), "x.hcl")
	if err != nil {
		t.Fatal(err)
	}
	b := m["build"].(map[string]any)
	if s := b["script"].(string); !strings.Contains(s, "PREFIX=${DEST}") {
		t.Errorf("the shell must receive its own text, got %q", s)
	}
}

// TestYAMLToHCLKeepsVersionText is the compatibility rule in its sharpest
// form. docbook.org lists `5.0`, and the distributable interpolates
// {{version.raw}}: a candidate coerced to 5 fetches a tarball that is not
// there. A decode into `any` has already lost the ".0", so the text is read
// back off the YAML node.
func TestYAMLToHCLKeepsVersionText(t *testing.T) {
	got := convert(t, "versions:\n  - 5.0\n  - 4.5\ndistributable:\n  url: http://x/{{version.raw}}.tgz\n")
	if !strings.Contains(got, `"5.0"`) || !strings.Contains(got, `"4.5"`) {
		t.Errorf("a listed version must keep its text:\n%s", got)
	}
	m, err := HCLToMap([]byte(got), "x.hcl")
	if err != nil {
		t.Fatal(err)
	}
	if v := m["versions"].([]any); v[0] != "5.0" {
		t.Errorf("versions[0] = %#v, want the string \"5.0\"", v[0])
	}
}

// The OTHER half of the same rule, and the one that decides what builds.
//
// `MACOSX_DEPLOYMENT_TARGET: 11.0` reaches the shell as `11` today. Emitting
// it as the string "11.0" would be more faithful to what its author typed and
// would change what every macOS build is configured with. Fidelity to the
// author is not the requirement; fidelity to the build is.
func TestYAMLToHCLDoesNotPromoteNumbersToText(t *testing.T) {
	got := convert(t, "build:\n  env:\n    MACOSX_DEPLOYMENT_TARGET: 11.0\n  script: make\n")
	if strings.Contains(got, `"11.0"`) {
		t.Errorf("a number must not become text — the shell would receive 11.0 where it receives 11:\n%s", got)
	}
	m, err := HCLToMap([]byte(got), "x.hcl")
	if err != nil {
		t.Fatal(err)
	}
	env := m["build"].(map[string]any)["env"].(map[string]any)
	if _, isStr := env["MACOSX_DEPLOYMENT_TARGET"].(string); isStr {
		t.Errorf("want a number, got a string: %#v", env["MACOSX_DEPLOYMENT_TARGET"])
	}
}

// A `versions:` mapping is not a list, and its values are not version text.
// Recovering raw scalars from it would turn `strip: v` and a github reference
// into something else.
func TestRawListVersionsOnlyActsOnAList(t *testing.T) {
	got := convert(t, "versions:\n  github: x/y\n  strip: /^v/\n")
	if !strings.Contains(got, "github") || !strings.Contains(got, "strip") {
		t.Errorf("a mapping-form versions must survive:\n%s", got)
	}
	// And shapes rawListVersions must decline, reached directly: a sequence
	// holding a mapping is not a list of version texts.
	for name, src := range map[string]string{
		"not a mapping at all": "- a\n- b\n",
		"a sequence of maps":   "versions:\n  - {a: 1}\n",
		"no versions key":      "build:\n  script: make\n",
	} {
		var n yaml.Node
		if err := yaml.Unmarshal([]byte(src), &n); err != nil {
			t.Fatal(err)
		}
		if vs := rawListVersions(&n); vs != nil {
			t.Errorf("%s: want nil, got %#v", name, vs)
		}
	}
}

// docDiff is what makes a refusal actionable, and its one subtlety is the
// asymmetry between numbers and text.
func TestDocDiff(t *testing.T) {
	for name, c := range map[string]struct {
		a, b any
		want bool // want a difference
	}{
		"int and int64 render alike":   {1, int64(1), false},
		"float and int render alike":   {1.0, int64(1), false},
		"a string is never a number":   {"1", int64(1), true},
		"a number is never a string":   {int64(1), "1", true},
		"different numbers":            {int64(1), int64(2), true},
		"both absent":                  {nil, nil, false},
		"one absent":                   {nil, "x", true},
		"a map became a scalar":        {map[string]any{"a": 1}, "x", true},
		"a list became a scalar":       {[]any{1}, "x", true},
		"lists of different length":    {[]any{1}, []any{1, 2}, true},
		"a key on one side only":       {map[string]any{"a": 1}, map[string]any{"b": 1}, true},
		"an extra key on the far side": {map[string]any{}, map[string]any{"b": 1}, true},
		"equal nested":                 {map[string]any{"a": []any{1}}, map[string]any{"a": []any{int64(1)}}, false},
		"differing deep inside a list": {map[string]any{"a": []any{1}}, map[string]any{"a": []any{2}}, true},
		"differing deep inside a map":  {map[string]any{"a": map[string]any{"b": 1}}, map[string]any{"a": map[string]any{"b": 2}}, true},
	} {
		d := docDiff(c.a, c.b, "")
		if (d != "") != c.want {
			t.Errorf("%s: docDiff = %q, want a difference: %v", name, d, c.want)
		}
	}
	// The message names the PATH and the TYPES. %v renders int(1) and "1"
	// identically, so a message without them cannot be acted on.
	d := docDiff(map[string]any{"build": map[string]any{"v": 1}}, map[string]any{"build": map[string]any{"v": "1"}}, "")
	if !strings.Contains(d, ".build.v") || !strings.Contains(d, "string") {
		t.Errorf("the message must name the path and the types: %q", d)
	}
}

func TestYAMLToHCLRefusesBadInput(t *testing.T) {
	if _, err := YAMLToHCL([]byte("\tnot: yaml\n"), "bad.yml"); err == nil {
		t.Error("input that is not yaml must be refused")
	} else if !strings.Contains(err.Error(), "bad.yml") {
		t.Errorf("the refusal must name the file: %v", err)
	}
}

// The read-back guard, reached through the seam. Nothing a caller can pass
// triggers it while the renderer is correct — which is the point of having it.
func TestYAMLToHCLRefusesUnparseableOutput(t *testing.T) {
	old := emitFn
	t.Cleanup(func() { emitFn = old })
	emitFn = func(map[string]any) string { return "build { script = \n" }
	if _, err := YAMLToHCL([]byte("build:\n  script: make\n"), "x.yml"); err == nil ||
		!strings.Contains(err.Error(), "does not parse") {
		t.Errorf("want a refusal naming the parse failure, got %v", err)
	}
	// And a renderer that parses but says something ELSE is the worse case:
	// text that builds the wrong thing, silently. It must be refused too.
	emitFn = func(map[string]any) string { return "build { script = \"something else\" }\n" }
	if _, err := YAMLToHCL([]byte("build:\n  script: make\n"), "x.yml"); err == nil ||
		!strings.Contains(err.Error(), "DIFFERENT document") {
		t.Errorf("want a refusal naming the difference, got %v", err)
	}
}

func TestIdent(t *testing.T) {
	for _, s := range []string{"build", "strip-components", "_x", "a1"} {
		if !ident(s) {
			t.Errorf("ident(%q) = false", s)
		}
	}
	for _, s := range []string{"", "openssl.org", "linux/x86-64", "1abc", "-lead", "a b"} {
		if ident(s) {
			t.Errorf("ident(%q) = true", s)
		}
	}
}

func TestQuoteEscapes(t *testing.T) {
	got := quote("a\"b\\c\nd\te\rf")
	want := `"a\"b\\c\nd\te\rf"`
	if got != want {
		t.Errorf("quote = %s, want %s", got, want)
	}
}

// expr's fallback. A YAML decode yields only the shapes above it, so this arm
// exists for a caller passing something else — and it must render SOMETHING
// rather than an empty expression, which would not parse at all.
func TestExprFallback(t *testing.T) {
	type odd struct{ A int }
	if got := expr(odd{1}, ""); !strings.HasPrefix(got, `"`) {
		t.Errorf("an unknown shape must still render as a string, got %s", got)
	}
}

// Every value shape a recipe can hold, through the conversion. The renderer
// lives here now, so its shapes are exercised here rather than only from the
// suite of the command that used to own it.
func TestYAMLToHCLEveryValueShape(t *testing.T) {
	got := convert(t, `
s: text
b: true
n: 3
big: 20250127
f: 1.5
nul:
emptylist: []
emptymap: {}
list:
  - a
  - 1
  - true
quoted:
  "openssl.org": "^3"
block:
  inner: x
nested:
  - - a
    - b
build:
  script: make
`)
	for _, want := range []string{
		`s = "text"`, "b = true", "n = 3", "big = 20250127", "f = 1.5",
		"nul = null", "emptylist = []", "emptymap = {}",
		`"openssl.org" = "^3"`, "block {", `inner = "x"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("want %q in:\n%s", want, got)
		}
	}
	// `inner = x` must NOT appear bare — a string is quoted, and a renderer
	// that dropped the quotes would emit a reference to an undefined name.
	if strings.Contains(got, "inner = x\n") {
		t.Errorf("a string must be quoted:\n%s", got)
	}
}

// A map becomes a BLOCK only when every key is a bare-writable HCL identifier.
// `openssl.org` cannot be an attribute name, so its map has to stay an object.
func TestAsBlockNeedsIdentifiersThroughout(t *testing.T) {
	for name, c := range map[string]struct {
		k    string
		v    any
		want bool
	}{
		"all identifiers":     {"build", map[string]any{"script": "make"}, true},
		"a key that is not":   {"deps", map[string]any{"openssl.org": "^3"}, false},
		"the name is not":     {"openssl.org", map[string]any{"a": 1}, false},
		"empty":               {"build", map[string]any{}, false},
		"not a map at all":    {"build", "x", false},
		"a list is not a map": {"build", []any{1}, false},
	} {
		if got := asBlock(c.k, c.v); got != c.want {
			t.Errorf("%s: asBlock = %v, want %v", name, got, c.want)
		}
	}
}

// A script whose own text contains the terminator would end the heredoc early,
// and the rest of the recipe would be read as HCL. The tag grows until no line
// of the body is exactly it.
func TestHeredocTagAvoidsTheScriptsOwnText(t *testing.T) {
	if tag := heredocTag("a\nb\n"); tag != "EOT" {
		t.Errorf("an ordinary body keeps EOT, got %s", tag)
	}
	if tag := heredocTag("cat <<EOT\nx\nEOT\n"); tag != "EOT_" {
		t.Errorf("a body containing EOT must move on, got %s", tag)
	}
	// Twice over, and trailing whitespace does not hide a terminator: HCL
	// ignores it when matching one, so a line of "EOT " ends the heredoc.
	if tag := heredocTag("EOT\nEOT_  \n"); tag != "EOT__" {
		t.Errorf("got %s", tag)
	}
	// And through the whole conversion, which is where it has to hold.
	got := convert(t, "build:\n  script: |\n    cat <<EOT\n    x\n    EOT\n")
	if !strings.Contains(got, "<<EOT_\n") {
		t.Errorf("the heredoc must pick a tag the script does not use:\n%s", got)
	}
}

// A heredoc's terminator must be alone on its line, so in a list the comma
// goes on the next one. `EOT,` refused 15 recipes with "Unterminated template
// string" — the parser reads it as a different word and never finds the end.
func TestHeredocInsideAList(t *testing.T) {
	got := convert(t, "test:\n  script:\n    - |\n      line one\n      line two\n    - echo done\n")
	if strings.Contains(got, "EOT,") {
		t.Errorf("the comma must not follow the terminator:\n%s", got)
	}
}

// A string with no final newline cannot be a heredoc — a heredoc always ends
// with one — so it has to be quoted, however many lines it has.
func TestStringWithoutAFinalNewline(t *testing.T) {
	got := convert(t, "build:\n  script: make install\n")
	if !strings.Contains(got, `script = "make install"`) {
		t.Errorf("want a quoted string:\n%s", got)
	}
}

// Indentation inside a script is the script's own. `<<-` would strip the
// common prefix and change what runs.
func TestIndentationInsideAScriptSurvives(t *testing.T) {
	got := convert(t, "build:\n  script: |\n    if true; then\n      echo nested\n    fi\n")
	m, err := HCLToMap([]byte(got), "x.hcl")
	if err != nil {
		t.Fatal(err)
	}
	if s := m["build"].(map[string]any)["script"].(string); !strings.Contains(s, "\n  echo nested\n") {
		t.Errorf("the script's own indentation must survive, got %q", s)
	}
}

// A recipe that is not a mapping at all. The document parses as YAML, so the
// refusal has to come from the decode into a document — and it must name the
// file, because the caller is converting a whole pantry and "is not a mapping"
// on its own says nothing about which recipe.
func TestYAMLToHCLRefusesANonMapping(t *testing.T) {
	_, err := YAMLToHCL([]byte("- a\n- b\n"), "list.yml")
	if err == nil {
		t.Fatal("a sequence is not a recipe")
	}
	if !strings.Contains(err.Error(), "list.yml") || !strings.Contains(err.Error(), "mapping") {
		t.Errorf("the refusal must name the file and the cause: %v", err)
	}
}

// DocDiff is the exported face of docDiff, for a caller that has to name the
// key rather than only report that two recipes differ.
func TestDocDiffIsExported(t *testing.T) {
	if d := DocDiff(map[string]any{"a": 1}, map[string]any{"a": 1}); d != "" {
		t.Errorf("equal documents: %q", d)
	}
	d := DocDiff(map[string]any{"build": map[string]any{"script": "make"}},
		map[string]any{"build": map[string]any{"script": "gmake"}})
	if !strings.Contains(d, ".build.script") {
		t.Errorf("the path must be named: %q", d)
	}
}

// WHICH side, not "one side". Comparing the overlay recipe a consumer resolves
// from against the pantry recipe the factory builds, a key the overlay ADDS is
// the overlay doing its job and a key it has LOST is drift — and a report that
// spells those the same way is a report somebody has to open 25 files to read.
func TestDocDiffSaysWhichSideAKeyIsOn(t *testing.T) {
	for _, tc := range []struct {
		name string
		a, b map[string]any
		want string
	}{
		{"gone from the second", map[string]any{"dependencies": 1}, map[string]any{}, "..dependencies: dropped"},
		{"new in the second", map[string]any{}, map[string]any{"dependencies": 1}, "..dependencies: added"},
		{"nested", map[string]any{"build": map[string]any{"env": 1}}, map[string]any{"build": map[string]any{}}, "..build.env: dropped"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := DocDiff(tc.a, tc.b); got != tc.want {
				t.Errorf("DocDiff = %q, want %q", got, tc.want)
			}
		})
	}
}
