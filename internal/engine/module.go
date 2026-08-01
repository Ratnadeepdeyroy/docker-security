package engine

import "context"

// Module is a self-contained capability (a scanner, linter, analyzer). Modules
// depend only on the engine package and know nothing about CLI or HTTP.
type Module interface {
	// Name is the stable identifier used to select the module.
	Name() string
	// Description is a one-line human summary.
	Description() string
	// Domains lists the CAPABILITY_SPEC domain numbers this module addresses.
	Domains() []string
	// Supports reports whether the module can analyze the given target type.
	Supports(TargetType) bool
	// Analyze inspects the target and returns findings.
	Analyze(ctx context.Context, t *Target) ([]Finding, error)
}

// Registry holds the set of available modules in registration order.
type Registry struct {
	modules map[string]Module
	order   []string
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{modules: map[string]Module{}}
}

// Register adds (or replaces) a module by name, preserving first-seen order.
func (r *Registry) Register(m Module) {
	if _, ok := r.modules[m.Name()]; !ok {
		r.order = append(r.order, m.Name())
	}
	r.modules[m.Name()] = m
}

// Get returns a module by name.
func (r *Registry) Get(name string) (Module, bool) {
	m, ok := r.modules[name]
	return m, ok
}

// All returns every registered module in registration order.
func (r *Registry) All() []Module {
	out := make([]Module, 0, len(r.order))
	for _, n := range r.order {
		out = append(out, r.modules[n])
	}
	return out
}

// Names returns registered module names in registration order.
func (r *Registry) Names() []string {
	out := make([]string, len(r.order))
	copy(out, r.order)
	return out
}
