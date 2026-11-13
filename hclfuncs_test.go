package artifact

import (
	"strings"
	"testing"
)

// A recipe can compute, the way a Terraform file can.
func TestRecipeFunctionsEvaluate(t *testing.T) {
	m, err := HCLToMap([]byte(`
underscored = replace("1.2.3", ".", "_")
shouty      = upper("clang")
major       = element(split(".", "14.4.0"), 0)
args        = concat(["--prefix=/x"], formatlist("--with-%s", ["zlib", "ssl"]))
joined      = join(" ", sort(["b", "a"]))
n           = max(3, 7, 5)
padded      = format("%04d", 42)
built       = try(tonumber("nope"), 0)
`), "x.hcl")
	if err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]any{
		"underscored": "1_2_3",
		"shouty":      "CLANG",
		"major":       "14",
		"joined":      "a b",
		"n":           int64(7),
		"padded":      "0042",
		"built":       int64(0),
	} {
		if m[k] != want {
			t.Errorf("%s = %#v, want %#v", k, m[k], want)
		}
	}
	args, _ := m["args"].([]any)
	if len(args) != 3 || args[1] != "--with-zlib" || args[2] != "--with-ssl" {
		t.Errorf("args = %#v", m["args"])
	}
}

// THE security property, and the reason this is a subset rather than
// Terraform's whole catalogue.
//
// A recipe is fetched over HTTP from a pantry and evaluated by every consumer
// resolving a closure, so a function that reads the filesystem reads the
// machine of whoever ran `pkgx +that-package`. A function that reads a clock
// makes the same recipe resolve differently twice.
//
// Asserted as ABSENCE from the evaluator, not merely as absence from a list:
// a name that is not in the table is an "unknown function" at parse time.
func TestImpureFunctionsAreNotAvailableToARecipe(t *testing.T) {
	for name, call := range map[string]string{
		"reads the consumer's filesystem": `x = file("/etc/passwd")`,
		"probes the consumer's files":     `x = fileexists("/etc/passwd")`,
		"globs the consumer's disk":       `x = fileset("/", "*")`,
		"renders a file as a template":    `x = templatefile("/tmp/t", {})`,
		"reads a clock":                   `x = timestamp()`,
		"is random":                       `x = uuid()`,
		"is random too":                   `x = bcrypt("x")`,
		"holds a private key":             `x = rsadecrypt("a", "b")`,
	} {
		_, err := HCLToMap([]byte(call+"\n"), "x.hcl")
		if err == nil {
			t.Errorf("%s: %s was evaluated — a recipe must not be able to", name, call)
			continue
		}
		if !strings.Contains(err.Error(), "unction") {
			t.Errorf("%s: want a missing-function error, got %v", name, err)
		}
	}
	// And the table itself carries none of them, so a future `MakeToFunc`-style
	// addition cannot smuggle one in under a different spelling.
	for _, bad := range []string{"file", "fileexists", "fileset", "filebase64", "templatefile",
		"timestamp", "plantimestamp", "uuid", "uuidv5", "bcrypt", "rsadecrypt", "pathexpand", "abspath"} {
		if _, in := recipeFunctions[bad]; in {
			t.Errorf("%q must not be a recipe function", bad)
		}
	}
}

// A recipe's {{moustaches}} are NOT HCL. They are substituted by the builder
// once the version is resolved and the dependency prefixes are known, so they
// must reach it as literal text — a client evaluating a recipe knows none of
// those values.
func TestMoustachesSurviveEvaluation(t *testing.T) {
	m, err := HCLToMap([]byte(`
url    = "https://x/{{version}}.tgz"
script = "make PREFIX={{prefix}} -j{{hw.concurrency}}"
mixed  = upper("gnu") == "GNU" ? "{{deps.zlib.net.prefix}}" : ""
`), "x.hcl")
	if err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]string{
		"url":    "https://x/{{version}}.tgz",
		"script": "make PREFIX={{prefix}} -j{{hw.concurrency}}",
		"mixed":  "{{deps.zlib.net.prefix}}",
	} {
		if m[k] != want {
			t.Errorf("%s = %#v, want %#v", k, m[k], want)
		}
	}
}

// A function that fails says so, naming the attribute. Silence here would be a
// recipe that resolved to nothing and installed nothing.
func TestAFailingFunctionIsAnError(t *testing.T) {
	if _, err := HCLToMap([]byte(`x = element([], 0)`+"\n"), "x.hcl"); err == nil {
		t.Error("indexing an empty list must be an error")
	}
	if _, err := HCLToMap([]byte(`x = nosuchfunction(1)`+"\n"), "x.hcl"); err == nil {
		t.Error("an unknown function must be an error")
	} else if !strings.Contains(err.Error(), "x") {
		t.Errorf("the error must name the attribute: %v", err)
	}
}
