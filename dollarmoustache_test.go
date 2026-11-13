package artifact

import "testing"

// TestExpandRecipeVarsDollarGluedToBraces: `${{prefix}}` is the pantry's own
// spelling in 338 recipes, and the `$` is part of the placeholder. Leaving it
// behind produced paths that exist nowhere:
//
//	SSL_CERT_FILE=$/…/curl.se/ca-certs/v2026.8.13/ssl/cert.pem
//
// which google.com/gcloud's build reported as
// "curl: (77) error adding trust anchors from file: $/…" — and which every
// other consumer simply failed to find, in silence.
func TestExpandRecipeVarsDollarGluedToBraces(t *testing.T) {
	const prefix = "/pkgx/curl.se/ca-certs/v2026.8.13"
	for _, tc := range []struct{ in, want string }{
		{"${{prefix}}/ssl/cert.pem", prefix + "/ssl/cert.pem"},
		{"${{ prefix }}/ssl/cert.pem", prefix + "/ssl/cert.pem"},
		{"{{prefix}}/ssl/cert.pem", prefix + "/ssl/cert.pem"},
		// A real shell variable next to a placeholder must survive: only the
		// `$` glued to the braces belongs to the placeholder.
		{"$PYTHONPATH:${{prefix}}/lib", "$PYTHONPATH:" + prefix + "/lib"},
		{"${{prefix}}/lib:$PYTHONPATH", prefix + "/lib:$PYTHONPATH"},
		// A `$` on its own, and a `$` followed by a brace that is not a
		// placeholder, are left alone.
		{"cost is $5", "cost is $5"},
		// An unknown placeholder is dropped, and its `$` with it — exporting
		// `${{hw.concurrency}}` verbatim would be worse than exporting nothing.
		{"${{hw.concurrency}}", ""},
		{"a${{nope}}b", "ab"},
	} {
		if got := expandRecipeVars(tc.in, prefix, "2026.8.13"); got != tc.want {
			t.Errorf("expandRecipeVars(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	// The version placeholders keep working through the same path.
	if got := expandRecipeVars("${{version.marketing}}", prefix, "3.11.9"); got != "3.11" {
		t.Errorf("version.marketing = %q", got)
	}
}
