package artifact

// hclfuncs.go gives a recipe the function set Terraform has, minus every
// function that would make a recipe unreproducible or let it read the machine
// evaluating it.
//
// WHY A SUBSET, and why this one.
//
// Terraform's catalogue is two halves. Roughly fifty of its functions are
// go-cty's `function/stdlib` under Terraform's names — `upper`, `join`,
// `regex`, `formatdate` — and the rest live in Terraform's own `internal/lang/
// funcs`. The split is not cosmetic: stdlib is PURE by construction. It has no
// `file`, no `timestamp`, no `uuid`; `formatdate` and `timeadd` take the time
// as an argument rather than reading a clock.
//
// Every function Terraform adds on top is where the impurity is — `file`,
// `fileexists`, `fileset`, `templatefile`, `timestamp`, `uuid`, `bcrypt`,
// `rsadecrypt`. Terraform can afford them; a recipe cannot, for two reasons
// that are properties of THIS system rather than opinions:
//
//   - a recipe is fetched over HTTP from a pantry and evaluated by every
//     consumer resolving a closure. `file("/etc/shadow")` in a recipe would be
//     read on the machine of whoever ran `pkgx +that-package`.
//   - a build must be reproducible. Terraform's own docs say of `timestamp`:
//     "The result of this function will change every second". A recipe whose
//     dependencies depend on the clock is a recipe that resolves differently
//     twice.
//
// So the line is drawn at purity, and it happens to fall exactly where
// upstream already drew it — which is why this file needs no allow-list of its
// own to maintain. Anything go-cty's stdlib gains, a recipe may have.
//
// `try` and `can` come from hcl's own tryfunc extension and are pure: they
// evaluate an expression and report whether it worked.

import (
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/ext/tryfunc"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
	"github.com/zclconf/go-cty/cty/function/stdlib"
)

// recipeFunctions is the function table a recipe is evaluated with.
//
// Named as TERRAFORM names them, not as go-cty exports them: a recipe author
// who knows `trimprefix` should not have to learn `TrimPrefixFunc`, and the
// names are the part people carry between languages.
var recipeFunctions = map[string]function.Function{
	// numbers
	"abs":      stdlib.AbsoluteFunc,
	"ceil":     stdlib.CeilFunc,
	"floor":    stdlib.FloorFunc,
	"log":      stdlib.LogFunc,
	"max":      stdlib.MaxFunc,
	"min":      stdlib.MinFunc,
	"parseint": stdlib.ParseIntFunc,
	"pow":      stdlib.PowFunc,
	"signum":   stdlib.SignumFunc,

	// strings
	"chomp":      stdlib.ChompFunc,
	"format":     stdlib.FormatFunc,
	"formatlist": stdlib.FormatListFunc,
	"indent":     stdlib.IndentFunc,
	"join":       stdlib.JoinFunc,
	"lower":      stdlib.LowerFunc,
	"regex":      stdlib.RegexFunc,
	"regexall":   stdlib.RegexAllFunc,
	"replace":    stdlib.ReplaceFunc,
	"split":      stdlib.SplitFunc,
	"strrev":     stdlib.ReverseFunc,
	"substr":     stdlib.SubstrFunc,
	"title":      stdlib.TitleFunc,
	"trim":       stdlib.TrimFunc,
	"trimprefix": stdlib.TrimPrefixFunc,
	"trimspace":  stdlib.TrimSpaceFunc,
	"trimsuffix": stdlib.TrimSuffixFunc,
	"upper":      stdlib.UpperFunc,

	// collections
	"chunklist":    stdlib.ChunklistFunc,
	"coalesce":     stdlib.CoalesceFunc,
	"coalescelist": stdlib.CoalesceListFunc,
	"compact":      stdlib.CompactFunc,
	"concat":       stdlib.ConcatFunc,
	"contains":     stdlib.ContainsFunc,
	"distinct":     stdlib.DistinctFunc,
	"element":      stdlib.ElementFunc,
	"flatten":      stdlib.FlattenFunc,
	"index":        stdlib.IndexFunc,
	"keys":         stdlib.KeysFunc,
	"length":       stdlib.LengthFunc,
	"lookup":       stdlib.LookupFunc,
	"merge":        stdlib.MergeFunc,
	"range":        stdlib.RangeFunc,
	"reverse":      stdlib.ReverseListFunc,
	"slice":        stdlib.SliceFunc,
	"sort":         stdlib.SortFunc,
	"values":       stdlib.ValuesFunc,
	"zipmap":       stdlib.ZipmapFunc,

	// sets
	"setintersection": stdlib.SetIntersectionFunc,
	"setproduct":      stdlib.SetProductFunc,
	"setsubtract":     stdlib.SetSubtractFunc,
	"setunion":        stdlib.SetUnionFunc,

	// encoding — decode only for csv, as Terraform has it
	"csvdecode":  stdlib.CSVDecodeFunc,
	"jsondecode": stdlib.JSONDecodeFunc,
	"jsonencode": stdlib.JSONEncodeFunc,

	// time, both of which take the instant as an ARGUMENT and read no clock
	"formatdate": stdlib.FormatDateFunc,
	"timeadd":    stdlib.TimeAddFunc,

	// conversions
	"tobool":   stdlib.MakeToFunc(cty.Bool),
	"tolist":   stdlib.MakeToFunc(cty.List(cty.DynamicPseudoType)),
	"tomap":    stdlib.MakeToFunc(cty.Map(cty.DynamicPseudoType)),
	"tonumber": stdlib.MakeToFunc(cty.Number),
	"toset":    stdlib.MakeToFunc(cty.Set(cty.DynamicPseudoType)),
	"tostring": stdlib.MakeToFunc(cty.String),

	// error handling, from hcl's own extension
	"can": tryfunc.CanFunc,
	"try": tryfunc.TryFunc,
}

// recipeEvalContext is what a recipe's expressions are evaluated against.
//
// Functions and no variables. A recipe's {{moustaches}} — `{{version}}`,
// `{{prefix}}`, `{{deps.X.prefix}}` — are substituted LATER, by the builder,
// once the version is resolved and the dependency prefixes are known; they are
// not HCL at all and must survive this evaluation as literal text. Putting
// them here as variables would resolve them at parse time, in a client that
// knows none of their values.
func recipeEvalContext() *hcl.EvalContext {
	return &hcl.EvalContext{Functions: recipeFunctions}
}
