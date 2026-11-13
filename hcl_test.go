package artifact

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// TestHCLToYAMLMatchesTheYAMLItReplaces: the two formats must reach the same
// document, or a recipe would behave differently for having been rewritten.
func TestHCLToYAMLMatchesTheYAMLItReplaces(t *testing.T) {
	got, err := HCLToYAML([]byte(`
dependencies = { "openssl.org" = "^3" }
provides     = ["bin/x"]

build {
  script = <<EOT
make PREFIX=$${DEST} install
EOT
}
`), "x.hcl")
	if err != nil {
		t.Fatal(err)
	}
	s := string(got)
	for _, want := range []string{"openssl.org: ^3", "bin/x", "make PREFIX=${DEST} install"} {
		if !strings.Contains(s, want) {
			t.Errorf("want %q in the yaml:\n%s", want, s)
		}
	}
	// The doubled sigil is HCL's way of spelling a literal one, and it must be
	// gone by the time the script reaches a shell.
	if strings.Contains(s, "$${") {
		t.Errorf("the escape must not survive into the yaml:\n%s", s)
	}
}

// Every value shape a recipe can hold, through the converter.
func TestHCLToMapValueShapes(t *testing.T) {
	m, err := HCLToMap([]byte(`
s = "text"
b = true
n = 3
f = 1.5
nul = null
list = ["a", 1]
obj = { "a.b" = "v" }

blk {
  inner = "x"
}
`), "x.hcl")
	if err != nil {
		t.Fatal(err)
	}
	// n is an int64 and f a float64: an integral number keeps its integerness,
	// because yaml.Marshal renders a large float64 in exponent form and a
	// version pinned to 20250127 must not become 2.0250127e+07.
	if m["s"] != "text" || m["b"] != true || m["n"] != int64(3) || m["f"] != 1.5 || m["nul"] != nil {
		t.Errorf("scalars: %#v", m)
	}
	if l, ok := m["list"].([]any); !ok || len(l) != 2 {
		t.Errorf("list: %#v", m["list"])
	}
	if o, ok := m["obj"].(map[string]any); !ok || o["a.b"] != "v" {
		t.Errorf("object: %#v", m["obj"])
	}
	if blk, ok := m["blk"].(map[string]any); !ok || blk["inner"] != "x" {
		t.Errorf("block: %#v", m["blk"])
	}
}

// A block and an attribute of the same name are two answers to one question.
// Picking either silently would build something the file does not say.
func TestHCLDuplicateKeyRefused(t *testing.T) {
	_, err := HCLToMap([]byte("build = \"x\"\nbuild {\n  y = 1\n}\n"), "x.hcl")
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("want a duplicate-key refusal, got %v", err)
	}
}

func TestHCLErrors(t *testing.T) {
	if _, err := HCLToMap([]byte("build { script = "), "x.hcl"); err == nil {
		t.Error("a syntax error must be reported")
	}
	if _, err := HCLToMap([]byte("x = undefined_ref\n"), "x.hcl"); err == nil {
		t.Error("an unresolvable reference must be reported")
	}
	if _, err := HCLToYAML([]byte("x = {"), "x.hcl"); err == nil {
		t.Error("HCLToYAML must surface a parse failure")
	}
}

// A cty value with no Go equivalent must be REFUSED rather than guessed at:
// putting something in a recipe the file never said is worse than failing.
//
// Reached directly. A `for` expression looked like a candidate and is not —
// it evaluates to an ordinary tuple — so the arm is not reachable from HCL
// text with no evaluation context, which is exactly why it needs a test of
// its own rather than a plausible-looking input.
func TestHCLUnsupportedValue(t *testing.T) {
	capsule := cty.Capsule("thing", reflect.TypeOf(struct{}{}))
	bad := cty.CapsuleVal(capsule, &struct{}{})
	if _, err := hclCtyToGo(bad); err == nil {
		t.Error("an unconvertible value must be refused")
	}
	// And from inside a container. An element the converter cannot render is
	// not a container it can render with a hole in it, so the failure has to
	// travel outward rather than be dropped where it was found.
	if _, err := hclCtyToGo(cty.TupleVal([]cty.Value{bad})); err == nil {
		t.Error("an unconvertible list element must be refused")
	}
	if _, err := hclCtyToGo(cty.ObjectVal(map[string]cty.Value{"k": bad})); err == nil {
		t.Error("an unconvertible object value must be refused")
	}
}

// TestFetchRecipePrefersHCL.
//
// Our own overlay is written in HCL; upstream's pantry is YAML. Asking only
// for the yaml is how an override silently stops applying: the overlay 404s,
// resolution falls through to upstream, and the recipe that builds is the one
// the overlay exists to replace. Nothing fails — the wrong thing is built.
func TestFetchRecipePrefersHCL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/overlay/a.org/package.hcl":
			fmt.Fprint(w, "dependencies = { \"openssl.org\" = \"^3\" }\n")
		case "/pantry/a.org/package.yml":
			fmt.Fprint(w, "dependencies:\n  openssl.org: ^1.1\n")
		case "/pantry/b.org/package.yml":
			fmt.Fprint(w, "dependencies:\n  zlib.net: 1\n")
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	o, p := PantryOverlay, PantryBase
	defer func() { PantryOverlay, PantryBase = o, p }()
	PantryOverlay, PantryBase = srv.URL+"/overlay", srv.URL+"/pantry"

	// The overlay's HCL wins over the pantry's YAML for the same project.
	body, err := fetchRecipe("a.org")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "^3") {
		t.Errorf("the overlay's hcl must win:\n%s", body)
	}
	// A project the overlay does not carry falls through to the pantry.
	body, err = fetchRecipe("b.org")
	if err != nil || !strings.Contains(string(body), "zlib.net") {
		t.Errorf("fall through to the pantry: %s, %v", body, err)
	}
	// Neither has it: an error naming both places, rather than an empty recipe.
	if _, err := fetchRecipe("nowhere.org"); err == nil {
		t.Error("a project in neither tree must be an error")
	}
}

// An error inside a nested structure must carry outward rather than being
// swallowed at the level that found it — a recipe half-read is not a recipe.
func TestHCLNestedErrorsSurface(t *testing.T) {
	for name, src := range map[string]string{
		"inside a block":   "blk {\n  x = undefined_ref\n}\n",
		"inside a list":    "x = [undefined_ref]\n",
		"inside an object": "x = { k = undefined_ref }\n",
	} {
		if _, err := HCLToMap([]byte(src), "x.hcl"); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

// The attribute conversion error, reached through the REAL function.
//
// No HCL text can produce it: with no evaluation context, a value an attribute
// holds is always one hclCtyToGo renders. A hand-built body can, and that is
// the difference between exercising this branch and writing a copy of it —
// which is what a first attempt did, and a copy agrees with itself whatever
// it says.
func TestHCLAttributeConvertError(t *testing.T) {
	capsule := cty.Capsule("thing", reflect.TypeOf(struct{}{}))
	body := &hclsyntax.Body{
		Attributes: hclsyntax.Attributes{
			"x": &hclsyntax.Attribute{Name: "x", Expr: &hclsyntax.LiteralValueExpr{Val: cty.CapsuleVal(capsule, &struct{}{})}},
		},
	}
	if _, err := hclBodyToMap(body); err == nil {
		t.Error("an attribute whose value cannot be rendered must be refused")
	} else if !strings.Contains(err.Error(), "x") {
		t.Errorf("the message must name the attribute: %v", err)
	}
}

// A large integer must stay an integer. cty has one number type, so the choice
// of Go type is ours, and float64 was the wrong one: yaml.Marshal writes
// float64(20250127) as 2.0250127e+07, so a recipe pinning abseil.io to
// 20250127 would have been handed 2.0250127e+07 at INSTALL time — a client
// bug, not a conversion one. Found by converting all 1907 upstream recipes and
// comparing each against itself.
func TestHCLIntegersDoNotBecomeFloats(t *testing.T) {
	y, err := HCLToYAML([]byte("build { dependencies = { \"abseil.io\" = 20250127 } }\n"), "x.hcl")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(y), "20250127") || strings.Contains(string(y), "e+07") {
		t.Errorf("a large integer must survive:\n%s", y)
	}
	// And a genuine fraction stays one.
	y, err = HCLToYAML([]byte("x = 1.5\n"), "x.hcl")
	if err != nil || !strings.Contains(string(y), "1.5") {
		t.Errorf("a fraction must survive: %s, %v", y, err)
	}
	// A number too large for an int64 falls back to a float rather than
	// silently truncating.
	m, err := HCLToMap([]byte("x = 99999999999999999999999\n"), "x.hcl")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := m["x"].(float64); !ok {
		t.Errorf("an out-of-range integer must fall back to float, got %T", m["x"])
	}
}

// A recipe the client cannot read is an ERROR naming the project.
//
// The overlay is HCL and upstream is converted to HCL on the way in, so this
// is the one place a malformed recipe surfaces — and it has to say which
// project, because the caller is resolving a closure and "parse error" alone
// names none of the dozen recipes it just fetched.
func TestRecipeDocRefusesUnreadableHCL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/pantry/broken.org/package.hcl":
			fmt.Fprint(w, "build { script = \n")
		case "/pantry/notyaml.org/package.yml":
			fmt.Fprint(w, "\tthis is not yaml\n")
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	o, p := PantryOverlay, PantryBase
	defer func() { PantryOverlay, PantryBase = o, p }()
	PantryOverlay, PantryBase = "", srv.URL+"/pantry"

	if _, _, err := FetchMetaFor("broken.org", "linux", "x86-64"); err == nil {
		t.Error("hcl that does not parse must be an error")
	} else if !strings.Contains(err.Error(), "broken.org") {
		t.Errorf("the error must name the project: %v", err)
	}
	// And upstream YAML that does not convert fails the same way, at the same
	// place — which is the point of converting on the way in.
	if _, _, err := FetchMetaFor("notyaml.org", "linux", "x86-64"); err == nil {
		t.Error("yaml that does not convert must be an error")
	} else if !strings.Contains(err.Error(), "notyaml.org") {
		t.Errorf("the error must name the project: %v", err)
	}
}

// AN ATTRIBUTE NAME IS UNTRUSTED, and we were the ones printing it raw.
//
// Found by FuzzParseLock in seven seconds, on `"\xe4\x040=0/0"`: the name
// reached the terminal through our own `fmt.Errorf("hcl: %s: %s", name, …)`
// before any field validation could run — a shorter path than the three
// that had just been closed, because it needs nothing to be well formed.
func TestAnAttributeNameCannotCarryAnEscape(t *testing.T) {
	// Division by zero makes the ATTRIBUTE path fail (not the parse path),
	// which is what puts the name in the message.
	_, err := HCLToMap([]byte("a\x1b[2K\rb = 0/0\n"), "evil.hcl")
	if err == nil {
		t.Fatal("an invalid expression parsed")
	}
	for _, bad := range []rune{0x1b, '\r', 0x00, 0x7f} {
		if strings.ContainsRune(err.Error(), bad) {
			t.Errorf("%q reached the message: %q", bad, err.Error())
		}
	}
	// The name is still RECOGNISABLE: cleaning is not censoring, and a
	// reader needs to know which attribute was wrong.
	if !strings.Contains(err.Error(), "ab") && !strings.Contains(err.Error(), "a") {
		t.Errorf("the attribute was lost with the escapes: %q", err.Error())
	}
}

// A LEGAL HCL RECIPE IS NOT REFUSED FOR A YAML QUIRK.
//
// yaml.v3 picks a literal block scalar for a multi-line string and, when the
// first line is indented, emits an indentation indicator that does not match
// the body — YAML it cannot itself re-read. priver.dev/geni's package.yml
// does not survive yaml.Unmarshal → yaml.Marshal → yaml.Unmarshal, with no
// HCL involved at all.
//
// The previous answer was to detect that and REFUSE the recipe. But the
// recipe is legal HCL; what cannot express it is the YAML hop in the middle,
// and refusing a valid input because of an intermediate format is the wrong
// way round. The string is now written double-quoted, which carries any
// string there is.
func TestAnIndentedFirstLineSurvivesTheYAMLHop(t *testing.T) {
	src := "test {\n  script = [\n    { fixture = <<EOT\n    indented first line\nsecond\nEOT\n    },\n  ]\n}\n"
	out, err := HCLToYAML([]byte(src), "geni.hcl")
	if err != nil {
		t.Fatalf("a legal HCL recipe was refused: %v", err)
	}
	// IT READS BACK, which is the property the refusal was protecting.
	var back map[string]any
	if err := yaml.Unmarshal(out, &back); err != nil {
		t.Fatalf("the YAML does not parse: %v\n%s", err, out)
	}
	// AND THE STRING IS INTACT — a style that round-trips is worth nothing if
	// it round-trips something else. The leading spaces are the whole point.
	got := back["test"].(map[string]any)["script"].([]any)[0].(map[string]any)["fixture"]
	want := "    indented first line\nsecond\n"
	if got != want {
		t.Errorf("fixture = %q, want %q", got, want)
	}
}

// AND THE ORDINARY SHAPES ARE UNTOUCHED. This conversion feeds a schema
// validator over the whole pantry; restyling every scalar for tidiness would
// make the change unreviewable, so only the unsafe shape moves.
func TestOrdinaryScalarsKeepTheirStyle(t *testing.T) {
	out, err := HCLToYAML([]byte("build {\n  script = <<EOT\nmake install\nmake check\nEOT\n}\n"), "x.hcl")
	if err != nil {
		t.Fatal(err)
	}
	// A block scalar, as before: the first line is not indented, so nothing
	// was unsafe about it.
	if !strings.Contains(string(out), "|") {
		t.Errorf("a safe multi-line string stopped being a block scalar:\n%s", out)
	}
}

// KEYS COME OUT SORTED, which yaml.Marshal did for a map and this hand-built
// node tree has to keep doing.
//
// Nothing downstream depends on the order — the schema validator reads the
// document, not the bytes — so the reason is REVIEWABILITY: this conversion
// is run over the whole pantry, and a reshuffle would turn a one-line change
// into a diff nobody can read. A claim like that in a comment is worth
// nothing unless something checks it; mutate reversed the sort and the suite
// did not notice.
func TestConvertedKeysComeOutSorted(t *testing.T) {
	out, err := HCLToYAML([]byte("zebra = 1\nalpha = 2\nmiddle = 3\n"), "x.hcl")
	if err != nil {
		t.Fatal(err)
	}
	var order []string
	for _, line := range strings.Split(string(out), "\n") {
		if k, _, ok := strings.Cut(line, ":"); ok && !strings.HasPrefix(line, " ") {
			order = append(order, k)
		}
	}
	if !reflect.DeepEqual(order, []string{"alpha", "middle", "zebra"}) {
		t.Errorf("keys came out %v, want them sorted:\n%s", order, out)
	}
}

// THE SHAPES YAML MANGLES, measured rather than predicted — and this is the
// test that pins the whole retry, because every rule anybody wrote about it
// was wrong.
//
// Marshalled with yaml.v3 and read back, no HCL involved:
//
//	"    first\nsecond\n"  round-trips       ← the rule in the code said it failed
//	"\tfirst\nsecond\n"    cannot be read back
//	"\nsecond\n"           comes back one line SHORTER, and parses fine
//
// The last is priver.dev/geni's `fixture: |`. And the same string round-trips
// at the top of a document but NOT three levels down, which is why a probe of
// the string alone could not decide either. HCLToYAML therefore verifies the
// whole document and retries quoted.
func TestTheShapesTheRetryIsFor(t *testing.T) {
	for name, src := range map[string]string{
		"a leading blank line, nested deep": "test {\n  script = [\n    { fixture = <<EOT\n\n    CREATE TABLE x (\n        y int\n    )\nEOT\n    },\n  ]\n}\n",
		"an indented first line, nested":    "test {\n  script = [\n    { fixture = <<EOT\n    indented first line\nsecond\nEOT\n    },\n  ]\n}\n",
		"a tab-indented first line":         "build {\n  script = <<EOT\n\tfirst\nsecond\nEOT\n}\n",
	} {
		out, err := HCLToYAML([]byte(src), "shape.hcl")
		if err != nil {
			t.Errorf("%s: a legal HCL recipe was refused: %v", name, err)
			continue
		}
		want, err := HCLToMap([]byte(src), "shape.hcl")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var back any
		if err := yaml.Unmarshal(out, &back); err != nil {
			t.Errorf("%s: the YAML does not parse: %v\n%s", name, err, out)
			continue
		}
		// THE DOCUMENT, not just "it parses": the leading-blank-line case
		// parses perfectly and is a line short, which is the whole reason
		// the comparison exists.
		if !sameDocument(want, back) {
			t.Errorf("%s: the document changed through the YAML hop\n%s", name, out)
		}
	}
}
