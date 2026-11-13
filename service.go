package artifact

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// Service is a recipe's `service "<name>" { … }` block: what a supervisor needs
// to know to run one of the package's programs as a daemon.
//
// It is DATA, not a unit file. The installer (pkgm) renders the systemd unit
// from it, so the hardening every service shares is written once, in the
// renderer, and a recipe states only what VARIES between daemons. The fields
// are the ones that varied between the three daemons this was derived from —
// authnd, authn-bridge and authn-revokd, whose hand-written units were checked
// with `systemd-analyze security` — and nothing else: a field nobody needed is
// a field nobody tested.
//
//	service "authn-bridge" {
//	  description   = "authn-bridge, an OpenID Connect provider in front of a SAML federation"
//	  documentation = "https://github.com/go-authn/bridge/blob/main/docs/install.md"
//	  command       = "authn-bridge"
//	  args          = ["--config", "/etc/authn-bridge"]
//	  restart       = "on-failure"
//	  stop-timeout  = "20s"
//	  state-directory { mode = "0700" }
//	  runtime-directory { mode = "0700" }
//	  configuration-directory { mode = "0750" }
//	}
//
// # WHERE IT LIVES, AND WHY OLD READERS DO NOT BREAK ON IT
//
// In package.hcl, beside the rest of the recipe. That was decided by
// measurement against artifact v0.43.0, the reader every installed pkgm and
// pkgx carries: HCLToMap is a generic reader, not a schema-checked decode, so
// a block it has never heard of is read as one more map key and ignored by
// every consumer — FetchMeta returns the same deps and provides with the block
// as without it, and `bk lint` (top-level additionalProperties: true) passes.
//
// It DROPS THE LABEL, though, and that has one consequence a recipe must
// respect: two `service` blocks are two values for the key "service", which
// that reader refuses as a duplicate key — and the whole recipe with it, so
// every install of the project fails for every old client. Hence ONE service
// per recipe, refused here too so the rule holds before a client sees it.
//
// It is read from the HCL source, not from the merged document recipeDoc
// builds, because that document is HCLToMap's and has already lost the name.
type Service struct {
	// Name is the block's label: the unit is <Name>@.service, and it is the
	// default account and the name of the state, runtime and configuration
	// directories.
	Name string
	// Description is the unit's Description= and the account's GECOS.
	Description string
	// Documentation is the unit's Documentation=, or "".
	Documentation string
	// Command is the program to run: the base name of one of the recipe's
	// `provides`, found in the installed version's bin/.
	Command string
	// Args follow Command on the command line.
	Args []string
	// User is the static account the service runs as (systemd-sysusers). It
	// defaults to Name.
	User string
	// Capabilities are the only capabilities the service holds, e.g.
	// CAP_NET_BIND_SERVICE for a port below 1024. Usually none.
	Capabilities []string
	// Restart is systemd's Restart=: "on-failure" (the default) or "always".
	Restart string
	// Reload is what `systemctl reload` does: "none" (refused, the default) or
	// "hup" (SIGHUP to the main process).
	Reload string
	// ProcSubset is "pid" (the default: /proc shows only processes) or "all",
	// for a program that reads /proc/sys — Go reads net.core.somaxconn there,
	// and without it every listener's backlog falls from 4096 to 128.
	ProcSubset string
	// StopTimeout is TimeoutStopSec=, or "" for systemd's default.
	StopTimeout string
	// StateDirectory, RuntimeDirectory and ConfigurationDirectory are the
	// versionless directories systemd creates for the service under
	// /var/lib, /run and /etc, named after it. Nil means none.
	StateDirectory         *ServiceDirectory
	RuntimeDirectory       *ServiceDirectory
	ConfigurationDirectory *ServiceDirectory
}

// ServiceDirectory is one of the directories systemd makes for a service.
type ServiceDirectory struct {
	// Mode is its octal mode, e.g. "0700".
	Mode string
}

// ErrBadService is wrapped by every refusal of a service block's contents.
var ErrBadService = errors.New("service block")

var (
	// A unit name is <name>@<version>.service. '@' would end the prefix and
	// anything outside this set would have to be escaped, which the label
	// would then not round-trip through.
	serviceNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,62}$`)
	// The account name systemd-sysusers and useradd both accept everywhere.
	serviceUserRE = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,30}$`)
	// A program in bin/: a base name, never a path.
	serviceCommandRE = regexp.MustCompile(`^[A-Za-z0-9_.+-]{1,128}$`)
	// ARGUMENTS ARE A CLOSED ALPHABET, because they are written into a unit
	// that root loads. A newline would be a new directive (User=root), a
	// quote or a backslash changes how systemd splits the line, `%` is a
	// specifier and `$` an environment expansion, and a lone `;` separates
	// commands. Each could be escaped; none of the daemons needs any of them,
	// so they are refused rather than escaped by rules nobody has tested.
	serviceArgRE         = regexp.MustCompile(`^[A-Za-z0-9_./:=,@+-]{1,512}$`)
	serviceCapabilityRE  = regexp.MustCompile(`^CAP_[A-Z_]{1,40}$`)
	serviceModeRE        = regexp.MustCompile(`^0[0-7]{3}$`)
	serviceTimeSpanRE    = regexp.MustCompile(`^[0-9]{1,6}(ms|s|min|h)?$`)
	serviceDocumentionRE = regexp.MustCompile(`^(https?|file|man|info):[^\s"\\]{1,500}$`)
)

// serviceAttrs are the attributes a service block may hold. The block is
// STRICT, unlike the recipe around it: an attribute this reader does not know
// is a misspelling — `capabilites` would otherwise yield a unit without the
// capability — or a field from a newer recipe whose meaning this version
// cannot honour. Either way, rendering a unit without it would run a
// different service from the one the recipe describes. The strictness is
// confined to ParseService: FetchMeta and every other recipe reader never
// call it, so it cannot make a recipe unreadable.
var serviceAttrs = map[string]bool{
	"description": true, "documentation": true, "command": true, "args": true,
	"user": true, "capabilities": true, "restart": true, "reload": true,
	"proc-subset": true, "stop-timeout": true,
}

var serviceDirBlocks = []string{"state-directory", "runtime-directory", "configuration-directory"}

// ParseService reads the `service` block of a package.hcl. A recipe with no
// such block returns (nil, nil): most packages are not daemons.
func ParseService(src []byte, filename string) (*Service, error) {
	f, diags := hclsyntax.ParseConfig(src, filename, hcl.InitialPos)
	if diags.HasErrors() {
		return nil, hclDiag("hcl: parse", diags)
	}
	var blocks []*hclsyntax.Block
	for _, b := range f.Body.(*hclsyntax.Body).Blocks {
		if b.Type == "service" {
			blocks = append(blocks, b)
		}
	}
	switch len(blocks) {
	case 0:
		return nil, nil
	case 1:
	default:
		return nil, fmt.Errorf("%w: %s has %d service blocks; a recipe holds at most one, "+
			"because a reader before artifact v0.44.0 reads two as a duplicate key and refuses the whole recipe",
			ErrBadService, filename, len(blocks))
	}
	return decodeService(blocks[0])
}

func decodeService(b *hclsyntax.Block) (*Service, error) {
	if len(b.Labels) != 1 {
		return nil, fmt.Errorf("%w: needs exactly one label, its name: service \"<name>\" { … }", ErrBadService)
	}
	s := &Service{Name: b.Labels[0], Restart: "on-failure", Reload: "none", ProcSubset: "pid"}
	if !serviceNameRE.MatchString(s.Name) {
		return nil, fmt.Errorf("%w: name %q: lowercase letters, digits, '_', '.' and '-', starting with a letter or digit",
			ErrBadService, displayText(s.Name, 80))
	}
	where := "service " + s.Name
	names := make([]string, 0, len(b.Body.Attributes))
	for n := range b.Body.Attributes {
		names = append(names, n)
	}
	sort.Strings(names) // the FIRST problem reported must not depend on map order
	for _, n := range names {
		if !serviceAttrs[n] {
			return nil, fmt.Errorf("%w: %s: unknown attribute %q", ErrBadService, where, displayText(n, 80))
		}
		v, diags := b.Body.Attributes[n].Expr.Value(recipeEvalContext())
		if diags.HasErrors() {
			return nil, hclDiag("hcl: "+where+": "+n, diags)
		}
		var err error
		switch n {
		case "args":
			s.Args, err = serviceStrings(v)
		case "capabilities":
			s.Capabilities, err = serviceStrings(v)
		default:
			var str string
			str, err = serviceString(v)
			switch n {
			case "description":
				s.Description = str
			case "documentation":
				s.Documentation = str
			case "command":
				s.Command = str
			case "user":
				s.User = str
			case "restart":
				s.Restart = str
			case "reload":
				s.Reload = str
			case "proc-subset":
				s.ProcSubset = str
			case "stop-timeout":
				s.StopTimeout = str
			}
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %s: %v", ErrBadService, where, n, err)
		}
	}
	seen := map[string]bool{}
	for _, blk := range b.Body.Blocks {
		known := false
		for _, d := range serviceDirBlocks {
			known = known || blk.Type == d
		}
		if !known {
			return nil, fmt.Errorf("%w: %s: unknown block %q", ErrBadService, where, displayText(blk.Type, 80))
		}
		if seen[blk.Type] {
			return nil, fmt.Errorf("%w: %s: %s given twice", ErrBadService, where, blk.Type)
		}
		seen[blk.Type] = true
		d, err := decodeServiceDir(blk)
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %s: %v", ErrBadService, where, blk.Type, err)
		}
		switch blk.Type {
		case "state-directory":
			s.StateDirectory = d
		case "runtime-directory":
			s.RuntimeDirectory = d
		case "configuration-directory":
			s.ConfigurationDirectory = d
		}
	}
	if s.User == "" {
		s.User = s.Name
	}
	if s.Description == "" {
		s.Description = s.Name
	}
	if err := s.validate(); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrBadService, where, err)
	}
	return s, nil
}

func decodeServiceDir(blk *hclsyntax.Block) (*ServiceDirectory, error) {
	if len(blk.Labels) != 0 {
		return nil, errors.New("takes no label")
	}
	if len(blk.Body.Blocks) != 0 {
		return nil, errors.New("holds no block")
	}
	d := &ServiceDirectory{}
	for n, a := range blk.Body.Attributes {
		if n != "mode" {
			return nil, fmt.Errorf("unknown attribute %q", displayText(n, 80))
		}
		v, diags := a.Expr.Value(recipeEvalContext())
		if diags.HasErrors() {
			return nil, hclDiag("hcl: mode", diags)
		}
		m, err := serviceString(v)
		if err != nil {
			return nil, fmt.Errorf("mode: %v", err)
		}
		d.Mode = m
	}
	if !serviceModeRE.MatchString(d.Mode) {
		return nil, fmt.Errorf("mode %q: an octal mode such as \"0700\" is required", displayText(d.Mode, 20))
	}
	return d, nil
}

func (s *Service) validate() error {
	if s.Command == "" {
		return errors.New("command is required: the name of the program in bin/ to run")
	}
	if !serviceCommandRE.MatchString(s.Command) {
		return fmt.Errorf("command %q: a program name in bin/, not a path", displayText(s.Command, 80))
	}
	for _, a := range s.Args {
		if !serviceArgRE.MatchString(a) {
			return fmt.Errorf("args: %q: an argument may hold only letters, digits and _ . / : = , @ + -", displayText(a, 80))
		}
	}
	if !serviceUserRE.MatchString(s.User) {
		return fmt.Errorf("user %q: not an account name systemd-sysusers accepts; name one with user = \"…\"", displayText(s.User, 80))
	}
	for _, c := range s.Capabilities {
		if !serviceCapabilityRE.MatchString(c) {
			return fmt.Errorf("capabilities: %q is not a capability name (CAP_…)", displayText(c, 80))
		}
	}
	if err := oneOf("restart", s.Restart, "on-failure", "always"); err != nil {
		return err
	}
	if err := oneOf("reload", s.Reload, "none", "hup"); err != nil {
		return err
	}
	if err := oneOf("proc-subset", s.ProcSubset, "pid", "all"); err != nil {
		return err
	}
	if s.StopTimeout != "" && !serviceTimeSpanRE.MatchString(s.StopTimeout) {
		return fmt.Errorf("stop-timeout %q: a time span such as \"20s\"", displayText(s.StopTimeout, 20))
	}
	// The description is one line of a unit AND the quoted GECOS field of a
	// sysusers line: a newline would start a directive, a quote would end
	// the field. `%` is escaped by the renderer, not refused — it is prose.
	if displayText(s.Description, 200) != s.Description || strings.ContainsAny(s.Description, "\"\\") {
		return errors.New("description: one line of at most 200 characters, without control characters, quotes or backslashes")
	}
	if s.Documentation != "" && !serviceDocumentionRE.MatchString(s.Documentation) {
		return fmt.Errorf("documentation %q: one URL (https:, http:, file:, man: or info:)", displayText(s.Documentation, 80))
	}
	return nil
}

func oneOf(field, v string, allowed ...string) error {
	for _, a := range allowed {
		if v == a {
			return nil
		}
	}
	return fmt.Errorf("%s %q: one of %s", field, displayText(v, 40), strings.Join(allowed, ", "))
}

func serviceString(v cty.Value) (string, error) {
	if v.IsNull() || !v.IsKnown() || v.Type() != cty.String {
		return "", fmt.Errorf("a string is required, not %s", v.Type().FriendlyName())
	}
	return v.AsString(), nil
}

func serviceStrings(v cty.Value) ([]string, error) {
	t := v.Type()
	if v.IsNull() || !v.IsKnown() || !(t.IsTupleType() || t.IsListType()) {
		return nil, fmt.Errorf("a list of strings is required, not %s", t.FriendlyName())
	}
	out := []string{}
	for _, e := range v.AsValueSlice() {
		s, err := serviceString(e)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

// FetchService returns a project's service block, or (nil, nil) when its
// recipe declares none.
//
// It reads the package.hcl of the overlay first and of the base pantry
// second, following recipeDoc's rule that a key the overlay states replaces
// that key and a key it omits is inherited. A package.yml is never consulted:
// YAML has no labelled block, so it cannot spell a service.
func FetchService(project string) (*Service, error) {
	if err := ValidateProjectName(project); err != nil {
		return nil, err
	}
	for _, base := range []string{PantryOverlay, PantryBase} {
		if base == "" {
			continue
		}
		body, err := httpGet(fmt.Sprintf("%s/%s/package.hcl", base, project))
		if isNotFound(err) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", project, err)
		}
		s, err := ParseService(body, project+"/package.hcl")
		if err != nil {
			return nil, fmt.Errorf("%s: %w", project, err)
		}
		if s != nil {
			return s, nil
		}
	}
	return nil, nil
}
