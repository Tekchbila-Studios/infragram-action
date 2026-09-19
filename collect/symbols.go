package collect

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

// Symbol extraction.
//
// Terraform's JSON plan does not contain locals. Not omitted here — absent from
// the format: a plan records that an attribute references `local.vpc_id` and
// never says what `local.vpc_id` is. The name is dangling, and no amount of
// reading the plan will resolve it.
//
// That matters because the modules people actually use are built on locals. The
// registry's VPC module writes `vpc_id = local.vpc_id`, so every subnet, route
// table, gateway and network ACL in it loses its link to the VPC. Measured
// across this project's fixtures, 85 of 95 unrecoverable references are
// `local.*`, and every one of them is in a module-based configuration. A
// hand-written configuration loses nothing.
//
// So the collector reads the configuration's .tf files. What it takes from them
// is deliberately narrow:
//
//   - only `locals` blocks, and only the names and the references inside them
//   - never an attribute's value, never file contents, never anything else
//
// A local holding a literal — `locals { db_password = "..." }` — contributes an
// entry with no references and is dropped. There is no path by which a value
// reaches the bundle.
//
// What is emitted is raw material, not conclusions. The bundle carries the
// symbol table and the references that could not be resolved against it, and
// the renderer decides what they mean. That split is the point: interpretation
// belongs to the thing drawing the diagram, and keeping it there means new
// diagramming rules never require a new collector.

// LocalSymbol is the name a local is published under, qualified by the module it
// is declared in. Exported because the renderer resolves against these names and
// must not carry its own spelling of them.
func LocalSymbol(modulePrefix, name string) string {
	return modulePrefix + "local." + name
}

// VarSymbol is the name a module input variable is published under, qualified by
// the module it is declared in — the counterpart of LocalSymbol for the other
// dangling name a plan carries.
//
// A plan records that a resource references `var.vpc_id` and never says what
// was passed for it, exactly as it never says what a local holds. The call site
// does say, and it is in the plan: `module_calls.<name>.expressions`. So a
// variable resolves the same way a local does, one symbol hop further.
func VarSymbol(modulePrefix, name string) string {
	return modulePrefix + "var." + name
}

type moduleManifest struct {
	Modules []moduleManifestRecord `json:"Modules"`
}

type moduleManifestRecord struct {
	Key string `json:"Key"`
	Dir string `json:"Dir"`
}

type symbolScanner struct {
	rootPath   string
	moduleDirs map[string]string
	symbols    map[string][]string
	visited    map[string]bool
}

func newSymbolScanner(rootPath string) *symbolScanner {
	absolute, err := filepath.Abs(rootPath)
	if err != nil {
		absolute = rootPath
	}
	return &symbolScanner{
		rootPath:   absolute,
		moduleDirs: loadModuleDirs(absolute),
		symbols:    make(map[string][]string),
		visited:    make(map[string]bool),
	}
}

// scan walks the configuration tree and the directories behind it in step, so
// that a local declared inside a module is published under that module's prefix.
//
// The two have to be walked together: the configuration says which modules exist
// and what they are called, and only the filesystem says where their source
// lives. Neither alone can name `module.vpc.local.vpc_id`.
func (s *symbolScanner) scan(module *configModule, modulePath, modulePrefix string) {
	if module == nil {
		return
	}
	// A module used twice reaches this with two different prefixes, which is
	// correct and must not be collapsed. Only an identical pair is a cycle.
	key := modulePrefix + "|" + modulePath
	if s.visited[key] {
		return
	}
	s.visited[key] = true

	s.scanLocals(modulePath, modulePrefix)

	for name, call := range module.ModuleCalls {
		childPrefix := modulePrefix + "module." + name + "."
		childPath := s.moduleCallPath(modulePath, modulePrefix, name, call.Source)
		s.scan(call.Module, childPath, childPrefix)
	}
}

func (s *symbolScanner) scanLocals(modulePath, modulePrefix string) {
	forEachTerraformBody(modulePath, func(body *hclsyntax.Body) {
		for _, block := range body.Blocks {
			if block.Type != "locals" {
				continue
			}
			for name, attribute := range block.Body.Attributes {
				refs := expressionRefs(modulePrefix, attribute.Expr)
				if len(refs) == 0 {
					// A local with no references names a literal. It cannot
					// contribute an edge, and carrying it would put a value's
					// name in the bundle for nothing.
					continue
				}
				symbol := LocalSymbol(modulePrefix, name)
				s.symbols[symbol] = appendUnique(s.symbols[symbol], refs...)
			}
		}
	})
}

// moduleCallPath locates a module call's source directory.
//
// The manifest terraform writes during init is authoritative and covers registry
// and remote modules. A local path module may not appear there, so a relative
// source is resolved against the calling module instead.
func (s *symbolScanner) moduleCallPath(modulePath, modulePrefix, moduleName, source string) string {
	if dir := s.moduleDirs[moduleCallKey(modulePrefix, moduleName)]; dir != "" {
		return dir
	}
	if modulePath == "" || source == "" {
		return ""
	}
	if strings.HasPrefix(source, "./") || strings.HasPrefix(source, "../") {
		return filepath.Clean(filepath.Join(modulePath, source))
	}
	return ""
}

// moduleCallKey mirrors the keys terraform writes into its module manifest:
// dot-joined call names with no "module." segments.
func moduleCallKey(modulePrefix, moduleName string) string {
	trimmed := strings.ReplaceAll(modulePrefix, "module.", "")
	trimmed = strings.Trim(trimmed, ".")
	if trimmed == "" {
		return moduleName
	}
	return trimmed + "." + moduleName
}

func loadModuleDirs(rootPath string) map[string]string {
	dirs := make(map[string]string)
	if rootPath == "" {
		return dirs
	}
	data, err := os.ReadFile(filepath.Join(rootPath, ".terraform", "modules", "modules.json"))
	if err != nil {
		return dirs
	}
	var manifest moduleManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return dirs
	}
	for _, record := range manifest.Modules {
		if record.Key == "" || record.Dir == "" {
			continue
		}
		dir := record.Dir
		if !filepath.IsAbs(dir) {
			dir = filepath.Join(rootPath, dir)
		}
		dirs[record.Key] = filepath.Clean(dir)
	}
	return dirs
}

// forEachTerraformBody parses every .tf file directly inside modulePath.
//
// Not recursive: terraform does not descend into subdirectories for a module's
// own configuration, and a nested directory is a different module reached
// through its own call. A file that will not parse is skipped rather than
// failing the run — a plan already succeeded against this configuration, so a
// parse error here is this parser's problem and must not cost the customer their
// build.
func forEachTerraformBody(modulePath string, visit func(*hclsyntax.Body)) {
	if modulePath == "" {
		return
	}
	entries, err := os.ReadDir(modulePath)
	if err != nil {
		return
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".tf") {
			names = append(names, entry.Name())
		}
	}
	// Sorted so the emitted bundle is byte-identical for identical input.
	sort.Strings(names)

	for _, name := range names {
		source, err := os.ReadFile(filepath.Join(modulePath, name))
		if err != nil {
			continue
		}
		file, diagnostics := hclsyntax.ParseConfig(source, name, hcl.Pos{Line: 1, Column: 1})
		if diagnostics.HasErrors() || file == nil {
			continue
		}
		if body, ok := file.Body.(*hclsyntax.Body); ok && body != nil {
			visit(body)
		}
	}
}

// expressionRefs reports what an expression names, qualified by the module it
// was written in.
//
// Only the traversal roots are read — `aws_vpc.this[0].id` yields the resource,
// not the attribute — so nothing about the expression's value survives.
func expressionRefs(modulePrefix string, expr hcl.Expression) []string {
	if expr == nil {
		return nil
	}
	var refs []string
	for _, traversal := range expr.Variables() {
		if ref := traversalRef(modulePrefix, traversal); ref != "" {
			refs = append(refs, ref)
		}
	}
	return refs
}

func traversalRef(modulePrefix string, traversal hcl.Traversal) string {
	if len(traversal) == 0 {
		return ""
	}
	root, ok := traversal[0].(hcl.TraverseRoot)
	if !ok {
		return ""
	}
	segments := []string{root.Name}
	for _, step := range traversal[1:] {
		attribute, ok := step.(hcl.TraverseAttr)
		if !ok {
			// An index stops the walk. `local.subnets[0].id` names the local,
			// and what it selects out of it is not knowable here.
			break
		}
		segments = append(segments, attribute.Name)
	}
	return qualifyRef(modulePrefix, segments)
}

// qualifyRef turns a traversal's segments into a reference the renderer can
// resolve, prefixing anything module-scoped with the module it was written in.
//
// count, each, var, path, terraform and self name nothing that can become an
// edge, and are dropped here rather than travelling to be dropped there.
func qualifyRef(modulePrefix string, segments []string) string {
	if len(segments) == 0 {
		return ""
	}
	// Two callers, two spellings of the same prefix: the scanner walks with a
	// trailing dot ("module.vpc."), the relationship walk without it
	// ("module.vpc"). Normalising here rather than at each call site is what
	// keeps a symbol emitted by one findable by the other — they disagreed once,
	// and the result was a table keyed "module.vpc.local.vpc_id" against
	// references reading "module.vpclocal.vpc_id".
	if modulePrefix != "" && !strings.HasSuffix(modulePrefix, ".") {
		modulePrefix += "."
	}
	switch segments[0] {
	case "count", "each", "path", "terraform", "self":
		return ""
	case "var":
		// A variable names whatever the call site passed. That is a symbol, not
		// a resource, so it resolves through the table like a local rather than
		// being dropped here — dropping it cost every module-wired resource its
		// link to the things it was handed (cleo #62).
		if len(segments) < 2 {
			return ""
		}
		return VarSymbol(modulePrefix, segments[1])
	case "local":
		if len(segments) < 2 {
			return ""
		}
		return LocalSymbol(modulePrefix, segments[1])
	case "module":
		// A module output is already addressed relative to this module, so the
		// prefix still applies.
		if len(segments) < 3 {
			return ""
		}
		return modulePrefix + strings.Join(segments[:3], ".")
	case "data":
		if len(segments) < 3 {
			return ""
		}
		return modulePrefix + strings.Join(segments[:3], ".")
	default:
		if len(segments) < 2 {
			return ""
		}
		return modulePrefix + strings.Join(segments[:2], ".")
	}
}

func appendUnique(existing []string, values ...string) []string {
	seen := make(map[string]bool, len(existing))
	for _, value := range existing {
		seen[value] = true
	}
	for _, value := range values {
		if !seen[value] {
			existing = append(existing, value)
			seen[value] = true
		}
	}
	return existing
}

// BareAddress strips count and for_each subscripts from an address, giving the
// form the configuration writes it in.
//
// Exported because the renderer expands this bundle's addresses against the
// resources it carries, and must use this package's spelling of "same resource,
// different instance" rather than its own.
func BareAddress(address string) string { return bareAddress(address) }

// collectWiringSymbols reports what a module's inputs and outputs name.
//
// Locals are not the only dangling name in a plan. A module-wired resource
// writes `vpc_id = var.vpc_id`, and the plan says nothing about what var.vpc_id
// was; the caller writes `module.vpc_endpoints { vpc_id = module.vpc.vpc_id }`,
// and says nothing about what that output is. Each half is recorded somewhere
// in the configuration, and neither alone reaches a resource. Joining them is
// what lets a reference cross a module boundary at all.
//
// Two entries per hop, in the spellings qualifyRef produces so a reference
// written in either module finds them:
//
//	module.vpc.vpc_id              -> module.vpc.aws_vpc.this
//	module.vpc_endpoints.var.vpc_id -> module.vpc.vpc_id
//
// Only reference lists are read. An argument or output holding a literal
// contributes nothing, so no value reaches the bundle — the same rule the
// locals scanner follows.
func collectWiringSymbols(configuration *config) map[string][]string {
	symbols := make(map[string][]string)
	if configuration == nil || configuration.RootModule == nil {
		return symbols
	}
	collectModuleWiring(configuration.RootModule, "", symbols)
	return symbols
}

// collectModuleWiring walks the module tree. prefix is the path of the body
// being walked, so a call inside it is prefix + "module.<name>.".
func collectModuleWiring(module *configModule, prefix string, symbols map[string][]string) {
	if module == nil {
		return
	}
	for name, call := range module.ModuleCalls {
		callee := prefix + "module." + name + "."

		// What the caller reads. The output's expression is written inside the
		// callee, so it is the callee's prefix that qualifies it.
		if call.Module != nil {
			for output, expression := range call.Module.Outputs {
				addWiringSymbol(symbols, callee+output, callee, expression.Expression)
			}
		}

		// What the callee reads. The argument is written at the call site, so it
		// is this module's prefix that qualifies it.
		for argument, expression := range call.Expressions {
			addWiringSymbol(symbols, VarSymbol(callee, argument), prefix, expression)
		}

		collectModuleWiring(call.Module, callee, symbols)
	}
}

// addWiringSymbol records every reference in expression under key, qualified by
// the module the expression was written in. A self-reference is dropped: it
// would make resolution loop without ever naming a resource.
//
// Targets are stored without count subscripts. An output referencing both
// `aws_vpc.this[0].id` and `aws_vpc.this` names one resource twice, and the
// subscript carries nothing: a symbol is resolved against the bare address, and
// which instance a reference pairs with is decided later, from the addresses of
// the resources the bundle actually carries.
func addWiringSymbol(symbols map[string][]string, key, refPrefix string, expression any) {
	for _, reference := range expressionReferences(expression) {
		target := bareAddress(qualifyRef(refPrefix, strings.Split(reference, ".")))
		if target == "" || target == key {
			continue
		}
		symbols[key] = append(symbols[key], target)
	}
}

// sortedUnique orders a symbol's targets and drops duplicates, so the emitted
// bundle is byte-identical for identical input.
func sortedUnique(values []string) []string {
	if len(values) < 2 {
		return values
	}
	sort.Strings(values)
	unique := values[:1]
	for _, value := range values[1:] {
		if value != unique[len(unique)-1] {
			unique = append(unique, value)
		}
	}
	return unique
}

// pruneDanglingNames drops symbol names that lead nowhere, and the references
// that name them.
//
// This is not the resolution version 3 moved to the renderer, and it is
// deliberately narrower than it could be. A reference naming a resource is kept
// whatever the plan contains — a module declares resources for every optional
// feature and instantiates a few, and whether an uninstantiated one may still
// appear in a diagram is the renderer's call, exactly as version 3 intends.
//
// What goes is a name that is not a resource and reaches none: `var.region`
// handed a literal at the call site, an output nothing reads, a local holding a
// constant. Version 2 dropped `local.*` because it could not see what a local
// held; with the whole symbol table in hand, such a name cannot become an edge
// under any interpretation, and carrying it only costs bytes.
//
// Without this the table grew 4.5x on a registry VPC module, nearly all of it
// the module's own inputs and its hundred-odd unread outputs.
func pruneDanglingNames(bundle *Bundle) {
	resources := make(map[string]bool, len(bundle.Resources))
	for _, resource := range bundle.Resources {
		resources[bareAddress(resource.Address)] = true
	}

	// A symbol resolves when any target is a resource or a symbol that resolves.
	// Iterating to a fixpoint terminates on cycles, which a malformed bundle can
	// contain, where following the chain would not.
	resolvable := make(map[string]bool, len(bundle.Symbols))
	for changed := true; changed; {
		changed = false
		for name, targets := range bundle.Symbols {
			if resolvable[name] {
				continue
			}
			for _, target := range targets {
				if resources[bareAddress(target)] || resolvable[target] {
					resolvable[name] = true
					changed = true
					break
				}
			}
		}
	}

	kept := bundle.References[:0]
	for _, reference := range bundle.References {
		if isSymbolRef(bundle, reference.Ref) && !resolvable[reference.Ref] {
			continue
		}
		kept = append(kept, reference)
	}
	bundle.References = kept

	// Keep only the symbols some surviving reference can still walk through.
	needed := make(map[string]bool, len(bundle.Symbols))
	var mark func(string)
	mark = func(name string) {
		if needed[name] {
			return
		}
		targets, ok := bundle.Symbols[name]
		if !ok {
			return
		}
		needed[name] = true
		for _, target := range targets {
			mark(target)
		}
	}
	for _, reference := range bundle.References {
		mark(reference.Ref)
	}
	for name := range bundle.Symbols {
		if !needed[name] {
			delete(bundle.Symbols, name)
		}
	}
	if len(bundle.Symbols) == 0 {
		bundle.Symbols = nil
	}
}

// isSymbolRef reports whether a reference names something the symbol table has
// to resolve rather than a resource. Being a key is the direct answer; a var or
// local that never made it into the table is the case that matters, since that
// is precisely a name leading nowhere.
func isSymbolRef(bundle *Bundle, reference string) bool {
	if _, ok := bundle.Symbols[reference]; ok {
		return true
	}
	segments := strings.Split(reference, ".")
	start := 0
	for start+1 < len(segments) && segments[start] == "module" {
		start += 2
	}
	if start >= len(segments) {
		return false
	}
	switch segments[start] {
	case "var", "local":
		return true
	}
	return false
}
