package artifact

// config.go loads user defaults for the go-zpkg tools from ~/.zpkg/config.hcl2.
//
// The file is an HCL2 top-level-attribute settings file: a flat list of
// `NAME = <value>` attributes (no blocks), where <value> is a string, bool, or
// number. Any ZPKG_* / OCI_* variable the tools read can be given a default
// here. It is parsed with the real HCL2 library (github.com/hashicorp/hcl/v2)
// via the generic JustAttributes API, so every attribute is handled uniformly
// and the standard HCL2 comment/quoting/escape rules apply.
//
// Precedence (see Env): a real process environment variable — present AND
// non-empty — always wins; otherwise the value from config.hcl2 is used;
// otherwise the empty string. This lets the file set defaults that a live
// environment variable can still override.

import (
	"os"
	"path/filepath"
	"sync"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/zclconf/go-cty/cty"
)

// lookupEnv is os.LookupEnv, swappable in tests.
var lookupEnv = os.LookupEnv

// configPathFn resolves the config file path. It is a var so tests can point it
// at a temporary file (or make it fail). It is deliberately based on the user
// home directory — always ~/.zpkg/config.hcl2 — and NOT on ZPKG_DIR, both to
// avoid a circular dependency (ZPKG_DIR is itself resolved through Env) and
// because the location is a fixed, well-known settings path.
//
// ⛔ `.zpkg`, for the reason Dir() gives at length: upstream pkgx owns
// ~/.pkgx and can be installed alongside us. A config file of ours in their
// directory is a file they may reasonably delete.
var configPathFn = func() (string, error) {
	home, err := os.UserHomeDir()
	return filepath.Join(home, ".zpkg", "config.hcl2"), err
}

var (
	configOnce sync.Once
	configMap  map[string]string
	configErr  error
)

// loadConfig reads and parses ~/.zpkg/config.hcl2 exactly once. It is tolerant:
// a missing file yields an empty map and no error; a path or parse failure
// yields an empty map and a stored error (see ConfigError). Reads therefore
// always fall back cleanly to environment variables / built-in defaults.
func loadConfig() {
	configOnce.Do(func() {
		configMap = map[string]string{}
		path, err := configPathFn()
		if err != nil {
			configErr = err
			return
		}
		if _, err := os.Stat(path); err != nil {
			if os.IsNotExist(err) {
				return // absent file → empty map, no error
			}
			configErr = err
			return
		}
		m, err := parseConfigFile(path)
		if err != nil {
			configErr = err
			return // keep the empty map so reads fall back
		}
		configMap = m
	})
}

// parseConfigFile parses an HCL2 top-level-attribute file into a string map.
func parseConfigFile(path string) (map[string]string, error) {
	f, diags := hclparse.NewParser().ParseHCLFile(path)
	if diags.HasErrors() {
		return nil, diags
	}
	attrs, diags := f.Body.JustAttributes()
	if diags.HasErrors() {
		return nil, diags // blocks or other non-attribute content
	}
	out := make(map[string]string, len(attrs))
	for name, a := range attrs {
		v, d := a.Expr.Value(nil)
		if d.HasErrors() {
			return nil, d
		}
		s, err := ctyToString(v)
		if err != nil {
			return nil, err
		}
		out[name] = s
	}
	return out, nil
}

// ctyToString renders a scalar cty value as the string form the tools consume:
// a string as-is, a bool as "true"/"false", and a number without trailing
// zeros (so `ZPKG_VERIFY = true` → "true" and a port stays clean). Any other
// type (list, object, null, …) is rejected — the settings file is scalar-only.
func ctyToString(v cty.Value) (string, error) {
	switch v.Type() {
	case cty.String:
		return v.AsString(), nil
	case cty.Bool:
		if v.True() {
			return "true", nil
		}
		return "false", nil
	case cty.Number:
		return v.AsBigFloat().Text('f', -1), nil
	default:
		return "", &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "unsupported config value",
			Detail:   "config attributes must be a string, bool, or number",
		}
	}
}

// Env resolves a variable for the go-zpkg tools. A real process environment
// variable that is set AND non-empty wins; otherwise the value from
// ~/.zpkg/config.hcl2 is returned; otherwise the empty string.
func Env(name string) string {
	if v, ok := lookupEnv(name); ok && v != "" {
		return v
	}
	loadConfig()
	return configMap[name]
}

// ConfigError returns the error, if any, from loading ~/.zpkg/config.hcl2. It is
// nil when the file parsed cleanly or is simply absent, and non-nil only on a
// real path or parse failure (in which case reads fall back to the environment).
func ConfigError() error {
	loadConfig()
	return configErr
}

// reloadConfig resets the one-shot loader so tests can re-read the file after
// swapping the configPathFn / lookupEnv seams.
func reloadConfig() {
	configOnce = sync.Once{}
	configMap = nil
	configErr = nil
}
