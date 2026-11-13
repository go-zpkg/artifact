package artifact

import (
	"fmt"
	"math/big"
	"reflect"
	"sort"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	"gopkg.in/yaml.v3"
)

// HCLToYAML turns a package.hcl into the package.yml bytes the rest of this
// package already knows how to read.
//
// It lives here, and not in bk where the HCL front-end was written, because
// the CLIENT has to read these files: the pantry overlay is fetched at install
// time, and a recipe written in HCL is unreadable to a pkgx that cannot parse
// it. bk imports artifact, so the parser cannot live in bk without a cycle — and
// two copies of it would drift.
//
// Converting to YAML rather than decoding straight into a recipe keeps ONE
// parse path: whatever validation and quirk-handling the YAML side has is
// applied to both formats, and a recipe written either way cannot behave
// differently.
//
// Cost, measured before it was added: pkgx goes from 8.81 MB to 9.45 MB.
func HCLToYAML(src []byte, filename string) ([]byte, error) {
	doc, err := HCLToMap(src, filename)
	if err != nil {
		return nil, err
	}
	// VERIFY, THEN RETRY — because every attempt to PREDICT which strings
	// yaml.v3 mangles was wrong, twice.
	//
	// The comment this replaces said the cause was "a string whose first line
	// is indented". Measured against yaml.v3, with no HCL involved:
	//
	//	"    first\nsecond\n"  round-trips fine   ← the stated cause does not fail
	//	"\tfirst\nsecond\n"    cannot be read back
	//	"\nsecond\n"           comes back as "second\n" — one line SHORTER
	//
	// The last is priver.dev/geni's `fixture: |`, which begins with a blank
	// line: the one recipe in 1899 that `bk tohcl` refused. And it is the
	// dangerous shape, because losing a leading blank line is not a parse
	// error — a guard asking only "does it still parse" lets it through.
	//
	// A per-string probe replaced that rule and was ALSO wrong: the same
	// string round-trips at the top of a document and not three levels down,
	// so the outcome depends on nesting depth, which no probe of the string
	// alone can see.
	//
	// So nothing here predicts. The document is marshalled, read back and
	// COMPARED; if it changed, it is marshalled again with every multi-line
	// string double-quoted, a style that carries any string there is. The
	// second pass costs one extra marshal on the rare document that needs it
	// and nothing on the rest, and it is right by construction rather than by
	// a rule that has to be maintained against a library's quirks.
	for _, quoteMultiline := range []bool{false, true} {
		out, err := yaml.Marshal(yamlNodeFor(doc, quoteMultiline))
		if err != nil {
			// Unreachable: HCLToMap yields only string, bool, int64, float64,
			// nil, []any and map[string]any. Kept because the two can drift —
			// a new cty case added above would arrive here first.
			return nil, err
		}
		var check any
		if err := yaml.Unmarshal(out, &check); err != nil {
			continue // the quoted pass will not have this problem
		}
		if sameDocument(doc, check) {
			return out, nil
		}
	}
	return nil, fmt.Errorf("hcl: %s: the YAML it converts to does not read back as the same document, "+
		"even with every multi-line string quoted", filename)
}

// HCLToMap parses package.hcl into the generic document shape a package.yml
// decodes to.
func HCLToMap(src []byte, filename string) (map[string]any, error) {
	f, diags := hclsyntax.ParseConfig(src, filename, hcl.InitialPos)
	if diags.HasErrors() {
		return nil, hclDiag("hcl: parse", diags)
	}
	return hclBodyToMap(f.Body.(*hclsyntax.Body))
}

// hclBodyToMap converts a body's attributes and nested blocks into a map.
func hclBodyToMap(body *hclsyntax.Body) (map[string]any, error) {
	out := make(map[string]any, len(body.Attributes)+len(body.Blocks))
	for name, attr := range body.Attributes {
		v, diags := attr.Expr.Value(recipeEvalContext())
		if diags.HasErrors() {
			return nil, hclDiag("hcl: "+displayText(name, maxProjectName), diags)
		}
		g, err := hclCtyToGo(v)
		if err != nil {
			// Not reachable from HCL TEXT — with no evaluation context, every
			// value an attribute can hold is one hclCtyToGo renders — but
			// reachable from a body, which is how the test gets here. It
			// matters because the two functions can drift: a future cty type
			// would arrive here first.
			return nil, fmt.Errorf("hcl: %s: %w", name, err)
		}
		out[name] = g
	}
	for _, block := range body.Blocks {
		if _, exists := out[block.Type]; exists {
			// A block and an attribute of the same name are two answers to one
			// question, and picking either silently would build something the
			// file does not say.
			return nil, fmt.Errorf("hcl: duplicate key %q (block and/or attribute)", block.Type)
		}
		m, err := hclBodyToMap(block.Body)
		if err != nil {
			return nil, err
		}
		out[block.Type] = m
	}
	return out, nil
}

// hclCtyToGo converts a cty.Value into the plain Go value a YAML decode would
// yield: string, float64, bool, nil, []any, map[string]any.
func hclCtyToGo(v cty.Value) (any, error) {
	if v.IsNull() {
		return nil, nil
	}
	t := v.Type()
	switch {
	case t == cty.String:
		return v.AsString(), nil
	case t == cty.Bool:
		return v.True(), nil
	case t == cty.Number:
		// An integral number comes back as an int, not a float.
		//
		// cty has one number type, so the choice is ours — and float64 was the
		// wrong one. yaml.Marshal writes float64(20250127) as 2.0250127e+07,
		// which decodes as a float, and a recipe asking for abseil.io at
		// version 20250127 would have been handed 2.0250127e+07 at INSTALL
		// time. Found by converting the whole upstream pantry and comparing
		// each recipe against itself; dozzle.dev is the one that has it.
		//
		// A whole number that was written 11.0 still arrives as 11, because
		// HCL cannot tell the two apart. That is a limit of the format, and
		// the four recipes it affects keep their YAML.
		bf := v.AsBigFloat()
		if bf.IsInt() {
			if i, acc := bf.Int64(); acc == big.Exact {
				return i, nil
			}
		}
		f, _ := bf.Float64()
		return f, nil
	case t.IsTupleType(), t.IsListType(), t.IsSetType():
		var out []any
		for _, e := range v.AsValueSlice() {
			g, err := hclCtyToGo(e)
			if err != nil {
				return nil, err
			}
			out = append(out, g)
		}
		return out, nil
	case t.IsObjectType(), t.IsMapType():
		out := make(map[string]any)
		for k, e := range v.AsValueMap() {
			g, err := hclCtyToGo(e)
			if err != nil {
				return nil, err
			}
			out[k] = g
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unsupported HCL value type %s", t.FriendlyName())
	}
}

// hclDiag renders a diagnostic as something SAFE TO PRINT.
//
// # FOUND BY FUZZING, IN SEVEN SECONDS, AND IT WAS OUR OWN SENTENCE
//
// Three channels were closed so that no version string reaches a terminal
// unvalidated — a lock, a catalogue, a registry tag. A REFUSAL was not one
// of them, and it is the path taken before any of that validation can run:
//
//	hcl: \xe4\x040: fuzz.lock.hcl:1,5-8: Operation failed; …
//
// The control bytes are the ATTRIBUTE NAME, and we interpolated it
// ourselves with `fmt.Errorf("hcl: %s: %s", name, …)`. A lock that does not
// even hold a valid attribute could still write on the screen of whoever
// ran it — a shorter path than the one that was fixed, since it needs
// nothing to be well formed. The name is cleaned at each call site, which
// is where it is known to be untrusted.
//
// Probed afterwards and worth stating: HCL's own parse diagnostics did NOT
// quote raw source in any of twelve crafted inputs. Wrapping them here is
// therefore defence in depth against a future version that does, not a
// reproduced defect — said plainly, because a comment that claims a fix for
// something nobody demonstrated is how an unverified belief becomes
// documentation.
//
// The text goes through the same displayText a summary does: a message is
// prose for a reader, not a key, so it is cleaned rather than refused. The
// limit is generous because a diagnostic names a file, a position and a
// cause, and losing the cause would trade one unreadable message for
// another.
func hclDiag(prefix string, diags interface{ Error() string }) error {
	return fmt.Errorf("%s: %s", prefix, displayText(diags.Error(), hclDiagLimit))
}

const hclDiagLimit = 500

// yamlNodeFor builds the YAML node tree for a document, so the STYLE of each
// scalar is ours to choose rather than yaml.v3's.
//
// quoteMultiline is the second pass of HCLToYAML: with it, every string
// containing a newline is written double-quoted, a style that carries any
// string there is. It is not the default because this conversion feeds a
// schema validator over the whole pantry, and restyling every script block
// would turn a one-line change into a diff nobody can read.
func yamlNodeFor(v any, quoteMultiline bool) *yaml.Node {
	switch x := v.(type) {
	case nil:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!null", Value: "null"}
	case string:
		n := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: x}
		if quoteMultiline && strings.Contains(x, "\n") {
			n.Style = yaml.DoubleQuotedStyle
		}
		return n
	case bool:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: fmt.Sprint(x)}
	case int64:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: fmt.Sprint(x)}
	case float64:
		n := &yaml.Node{}
		_ = n.Encode(x) // yaml.v3's own float formatting, not ours
		return n
	case []any:
		n := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		for _, e := range x {
			n.Content = append(n.Content, yamlNodeFor(e, quoteMultiline))
		}
		return n
	case map[string]any:
		n := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		// SORTED, because yaml.Marshal sorts a map's keys and this replaces
		// it. Nothing downstream depends on the order — the schema validator
		// reads the document, not the bytes — but this conversion is run over
		// the whole pantry, and a reshuffle would make every change
		// unreviewable.
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			n.Content = append(n.Content,
				&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: k},
				yamlNodeFor(x[k], quoteMultiline))
		}
		return n
	default:
		// Unreachable from hclCtyToGo, which yields exactly the cases above.
		// Encode rather than panic: a new cty case added upstream arrives
		// here, and a wrong style is better than a crash in an installer.
		n := &yaml.Node{}
		_ = n.Encode(x)
		return n
	}
}

// looked for.
func sameDocument(in map[string]any, out any) bool {
	return reflect.DeepEqual(normNums(in), normNums(out))
}

func normNums(v any) any {
	switch x := v.(type) {
	case int64:
		return int(x)
	case []any:
		o := make([]any, len(x))
		for i, e := range x {
			o[i] = normNums(e)
		}
		return o
	case map[string]any:
		o := make(map[string]any, len(x))
		for k, e := range x {
			o[k] = normNums(e)
		}
		return o
	}
	return v
}
