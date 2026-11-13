package artifact

// yamltohcl.go renders a recipe document as package.hcl text, and converts an
// upstream package.yml into one ON THE WAY IN.
//
// It lives in the CLIENT because that is where upstream YAML arrives. Nothing
// downstream of fetchRecipe then has to know that two formats exist: the
// overlay is HCL on disk, upstream is HCL by the time anyone reads it, and the
// one YAML parser left in the tree is the one below.
//
// There is one renderer, here, and bk's converter calls it. A second copy
// would drift, and the two would disagree about a recipe on the day it
// mattered.

import (
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Emit renders a recipe document as package.hcl text.
//
// It is the inverse of ToMap, and the only thing that makes it trustworthy is
// that the two are checked against each other: Convert parses what this
// produces and refuses to hand it back unless the result is the document it
// started from. A converter nobody checks is a rewrite.
//
// Shape follows this package's own convention. A map whose keys are all HCL
// identifiers becomes a BLOCK, because `build { script = … }` is what a reader
// expects; a map with a key like "openssl.org" cannot — an attribute name must
// be an identifier — so it becomes an object attribute with quoted keys.
func EmitHCL(doc map[string]any) string {
	var b strings.Builder
	emitBody(&b, doc, "")
	return b.String()
}

func emitBody(b *strings.Builder, m map[string]any, indent string) {
	// Blocks last, so the short attributes a reader scans first are not buried
	// under a build script.
	var attrs, blocks []string
	for k, v := range m {
		if asBlock(k, v) {
			blocks = append(blocks, k)
		} else {
			attrs = append(attrs, k)
		}
	}
	sort.Strings(attrs)
	sort.Strings(blocks)
	for _, k := range attrs {
		fmt.Fprintf(b, "%s%s = %s\n", indent, k, expr(m[k], indent))
	}
	for _, k := range blocks {
		fmt.Fprintf(b, "\n%s%s {\n", indent, k)
		emitBody(b, m[k].(map[string]any), indent+"  ")
		fmt.Fprintf(b, "%s}\n", indent)
	}
}

// asBlock decides between `k { … }` and `k = { … }`.
//
// Only a map can be a block, only under an identifier name, and only when
// every key inside is an identifier too — otherwise the body would need an
// attribute called "openssl.org", which HCL cannot express.
func asBlock(k string, v any) bool {
	m, ok := v.(map[string]any)
	if !ok || len(m) == 0 || !ident(k) {
		return false
	}
	for kk := range m {
		if !ident(kk) {
			return false
		}
	}
	return true
}

// ident reports whether a name can be written bare in HCL.
func ident(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r == '_':
		case (r >= '0' && r <= '9' || r == '-') && i > 0:
		default:
			return false
		}
	}
	return true
}

func expr(v any, indent string) string {
	switch x := v.(type) {
	case nil:
		return "null"
	case bool:
		return fmt.Sprintf("%t", x)
	case int:
		return fmt.Sprintf("%d", x)
	case float64:
		if x == float64(int64(x)) {
			return fmt.Sprintf("%d", int64(x))
		}
		return fmt.Sprintf("%g", x)
	case string:
		return str(x, indent)
	case []any:
		if len(x) == 0 {
			return "[]"
		}
		var b strings.Builder
		b.WriteString("[\n")
		for _, e := range x {
			rendered := expr(e, indent+"  ")
			b.WriteString(indent + "  " + rendered)
			// A heredoc's terminator must be alone on its line, so the comma
			// that separates list items cannot follow it. `EOT,` is where the
			// first run of this refused 15 recipes with "Unterminated template
			// string" — the parser reads EOT, as a different word and never
			// finds the end.
			if isHeredoc(rendered) {
				b.WriteString("\n,\n")
				continue
			}
			b.WriteString(",\n")
		}
		b.WriteString(indent + "]")
		return b.String()
	case map[string]any:
		if len(x) == 0 {
			return "{}"
		}
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var parts []string
		for _, k := range keys {
			name := k
			if !ident(k) {
				name = quote(k)
			}
			parts = append(parts, fmt.Sprintf("%s  %s = %s", indent, name, expr(x[k], indent+"  ")))
		}
		return "{\n" + strings.Join(parts, "\n") + "\n" + indent + "}"
	default:
		// A YAML decode yields only the shapes above. Anything else means the
		// document holds something this converter has never seen, and guessing
		// at it would produce HCL that parses into something different.
		return quote(fmt.Sprint(v))
	}
}

// str renders a string, as a heredoc when it has newlines.
//
// A recipe's script is the reason: rendered as one escaped line it is
// unreadable, and the point of the conversion is a file people edit.
func str(s, indent string) string {
	// A heredoc can carry exactly one shape of string: one that ends with a
	// newline, written verbatim. Anything else has to be quoted.
	//
	// The first version used <<- and indented the body to match its
	// surroundings, which reads far better and is wrong: <<- strips the
	// COMMON leading whitespace, so a fixture whose own C code is indented
	// comes back with that indentation removed. Twenty-eight recipes were
	// refused for it, every one a script or a fixture, and the refusal is the
	// only reason none of them shipped altered.
	//
	// So the body sits at column 0 and the terminator with it. It is uglier
	// than an indented heredoc and it is the same bytes.
	if !strings.HasSuffix(s, "\n") || !strings.Contains(s, "\n") {
		return quote(s)
	}
	tag := heredocTag(s)
	var b strings.Builder
	b.WriteString("<<" + tag + "\n")
	for _, line := range strings.Split(strings.TrimSuffix(s, "\n"), "\n") {
		b.WriteString(escapeTemplate(line) + "\n")
	}
	b.WriteString(tag)
	return b.String()
}

// heredocTag picks a terminator the body does not contain.
//
// A heredoc ends at the first line equal to its tag, so a script with a line
// reading exactly EOT would end it early and the rest of the script would be
// read as HCL. Found by covering Convert's "does not parse" guard, which
// needed an input that breaks the emitter — and this was one.
func heredocTag(body string) string {
	tag := "EOT"
	for lineIs(body, tag) {
		tag += "_"
	}
	return tag
}

// lineIs reports whether any line of s is exactly tag, ignoring the trailing
// whitespace HCL also ignores when matching a terminator.
func lineIs(s, tag string) bool {
	for _, line := range strings.Split(s, "\n") {
		if strings.TrimRight(line, " \t") == tag {
			return true
		}
	}
	return false
}

// heredocEnd is what a rendered heredoc ends with, so a list can tell one
// apart from an ordinary expression and put its comma on the next line.
const heredocEnd = "EOT"

// isHeredoc reports whether a rendered expression is a heredoc, whatever
// terminator it had to choose.
func isHeredoc(rendered string) bool {
	return strings.HasPrefix(rendered, "<<"+heredocEnd)
}

func quote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\t':
			b.WriteString(`\t`)
		case '\r':
			b.WriteString(`\r`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return escapeTemplate(b.String())
}

// escapeTemplate defuses HCL's template syntax.
//
// This is the trap the whole conversion turns on. HCL reads `${…}` as an
// interpolation and `%{…}` as a directive, and a recipe's script is FULL of
// shell expansions — `${prefix}`, `${LDFLAGS}`, `$(…)` is safe but `${…}` is
// not. Left alone, HCL either fails to parse or, worse, evaluates something
// and silently changes the script. Doubling the sigil is how HCL spells a
// literal one.
func escapeTemplate(s string) string {
	s = strings.ReplaceAll(s, "${", "$${")
	return strings.ReplaceAll(s, "%{", "%%{")
}

// YAMLToHCL converts an upstream package.yml into package.hcl text.
//
// This is the whole reason the renderer lives in the client. Upstream's pantry
// is YAML and will stay YAML; converting it AS IT ARRIVES is what lets
// everything past this point support one format. Nothing is written to disk:
// the conversion is a step in fetchRecipe, not a migration of upstream.
//
// It must not change what a recipe MEANS. Two places decide that:
//
//   - a list-form `versions:` carries TEXT. Decoding it into a map coerces
//     `5.0` to the number 5, and the distributable URL interpolates
//     {{version.raw}} — a coerced candidate fetches a tarball that does not
//     exist. The raw scalars are read back off the YAML node, which is the
//     only place that text still exists after a decode.
//   - every other number stays a NUMBER. `MACOSX_DEPLOYMENT_TARGET: 11.0`
//     reaches the shell as `11` today; emitting it as the string "11.0" would
//     be more faithful to what its author typed and would change what builds.
//     Fidelity to the author is not the requirement here — fidelity to the
//     build is.
func YAMLToHCL(src []byte, name string) ([]byte, error) {
	// Parsed ONCE, into a node, and decoded from there. Two passes over the
	// same bytes would give a second failure arm that cannot be reached when
	// the first pass succeeded — an untestable branch standing in for nothing.
	var node yaml.Node
	if err := yaml.Unmarshal(src, &node); err != nil {
		return nil, fmt.Errorf("%s does not decode as yaml: %w", name, err)
	}
	var doc map[string]any
	if err := node.Decode(&doc); err != nil {
		return nil, fmt.Errorf("%s is not a yaml mapping: %w", name, err)
	}
	if vs := rawListVersions(&node); vs != nil {
		doc["versions"] = vs
	}
	out := []byte(emitFn(doc))
	// Read it back. The renderer is hand-written, with heredocs, quoted keys
	// and a template syntax that has to be defused; a mistake in it is a
	// recipe that builds something else, silently. So no caller sees text that
	// has not been parsed back into the document it came from.
	got, err := HCLToMap(out, name)
	if err != nil {
		return nil, fmt.Errorf("the hcl converted from %s does not parse: %w", name, err)
	}
	if d := docDiff(doc, got, ""); d != "" {
		return nil, fmt.Errorf("the hcl converted from %s is a DIFFERENT document: %s", name, d)
	}
	return out, nil
}

// rawListVersions recovers the SOURCE TEXT of a list-form `versions:`.
//
// A scalar node keeps what the file said, which a decode into `any` does not:
// `5.0` decodes to float64(5) and renders back as "5". docbook.org and
// info-zip.org/zip are the two that noticed.
//
// Returns nil for every other shape — a `versions:` block with `github:` and
// `strip:` is a mapping, not a list, and the decoded form is right for it.
func rawListVersions(root *yaml.Node) []any {
	if root.Kind == yaml.DocumentNode && len(root.Content) == 1 {
		root = root.Content[0]
	}
	if root.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value != "versions" {
			continue
		}
		seq := root.Content[i+1]
		if seq.Kind != yaml.SequenceNode {
			return nil
		}
		out := make([]any, 0, len(seq.Content))
		for _, item := range seq.Content {
			if item.Kind != yaml.ScalarNode {
				return nil
			}
			out = append(out, item.Value)
		}
		return out
	}
	return nil
}

// DocDiff is docDiff, exported: a caller comparing two recipes needs to say
// WHICH key parted, and a second implementation of this walk would be a second
// opinion about what a recipe means.
func DocDiff(a, b any) string { return docDiff(a, b, "") }

// docDiff describes the first place two decoded documents part.
//
// Numbers are compared by what they RENDER, because the two decoders disagree
// about Go types for the same text and nothing downstream can tell int(1) from
// int64(1). A string is never equal to a number, though, however alike they
// print: "1" becoming 1 is precisely the coercion this conversion exists to
// avoid, and a comparison that tolerated it would be blind to its own subject.
func docDiff(a, b any, path string) string {
	if path == "" {
		path = "."
	}
	if a == nil || b == nil {
		if a == nil && b == nil {
			return ""
		}
		return fmt.Sprintf("%s: one side is absent (%v vs %v)", path, a, b)
	}
	switch av := a.(type) {
	case map[string]any:
		bv, ok := b.(map[string]any)
		if !ok {
			return fmt.Sprintf("%s: %T became %T", path, a, b)
		}
		keys := make([]string, 0, len(av))
		for k := range av {
			keys = append(keys, k)
		}
		for k := range bv {
			if _, in := av[k]; !in {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		for _, k := range keys {
			x, inA := av[k]
			y, inB := bv[k]
			if inA != inB {
				// WHICH side, not "one side". Both arguments are named
				// documents to whoever called DocDiff, and for the caller this
				// was written for the direction IS the answer: comparing the
				// overlay recipe a consumer resolves from against the pantry
				// recipe the factory builds, a key the overlay ADDS is the
				// overlay doing its job, and a key the overlay has LOST is
				// drift. "Present on one side only" made those two read the
				// same, and 25 projects had to be opened by hand to tell them
				// apart.
				//
				// The wording follows "%v became %v" elsewhere here: the first
				// argument is the before, the second the after.
				if inA {
					return fmt.Sprintf("%s.%s: dropped", path, k)
				}
				return fmt.Sprintf("%s.%s: added", path, k)
			}
			if d := docDiff(x, y, path+"."+k); d != "" {
				return d
			}
		}
		return ""
	case []any:
		bv, ok := b.([]any)
		if !ok {
			return fmt.Sprintf("%s: %T became %T", path, a, b)
		}
		if len(av) != len(bv) {
			return fmt.Sprintf("%s: %d items became %d", path, len(av), len(bv))
		}
		for i := range av {
			if d := docDiff(av[i], bv[i], fmt.Sprintf("%s[%d]", path, i)); d != "" {
				return d
			}
		}
		return ""
	}
	_, aStr := a.(string)
	_, bStr := b.(string)
	if aStr != bStr {
		return fmt.Sprintf("%s: %T(%v) became %T(%v)", path, a, a, b, b)
	}
	if fmt.Sprint(a) != fmt.Sprint(b) {
		return fmt.Sprintf("%s: %v became %v", path, a, b)
	}
	return ""
}

// emitFn is a seam. The read-back guard above protects against a defect in the
// renderer, so nothing reachable through the public API can trigger it while
// the renderer is correct — and it is the check that caught the heredoc
// terminator colliding with a script's own EOT line, so it stays. A test
// reaches it by substituting a renderer that is wrong on purpose.
var emitFn = EmitHCL
