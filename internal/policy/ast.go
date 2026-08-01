package policy

import "fmt"

// --- Abstract syntax tree --------------------------------------------------
//
// The parser produces a tree of these nodes; Eval walks it against an evalEnv
// (the Input plus its cached regexes). Evaluation is a pure function of the
// tree and the environment — no globals, no clock, no randomness — which is
// what makes a policy decision reproducible for the same inputs.

// node is one expression AST node.
type node interface {
	// eval computes this node's value in env.
	eval(env *evalEnv) (Value, error)
	// walk visits this node's children, used for compile-time validation.
	walk(fn func(node) error) error
}

// litNode is a literal bool/number/string.
type litNode struct{ v Value }

func (n litNode) eval(*evalEnv) (Value, error) { return n.v, nil }
func (n litNode) walk(func(node) error) error  { return nil }

// listNode is a list literal like ["a", "b", "c"].
type listNode struct{ elems []node }

func (n listNode) eval(env *evalEnv) (Value, error) {
	vs := make([]Value, len(n.elems))
	for i, e := range n.elems {
		v, err := e.eval(env)
		if err != nil {
			return Value{}, err
		}
		vs[i] = v
	}
	return List(vs), nil
}

func (n listNode) walk(fn func(node) error) error {
	for _, e := range n.elems {
		if err := fn(e); err != nil {
			return err
		}
	}
	return nil
}

// identNode is a bare identifier resolving to a nullary variable binding.
type identNode struct{ name string }

func (n identNode) eval(env *evalEnv) (Value, error) {
	v, ok := variables[n.name]
	if !ok {
		return Value{}, fmt.Errorf("unknown identifier %q", n.name)
	}
	return v.fn(env)
}

func (n identNode) walk(func(node) error) error { return nil }

// callNode is a function invocation.
type callNode struct {
	name string
	args []node
}

func (n callNode) eval(env *evalEnv) (Value, error) {
	b, ok := functions[n.name]
	if !ok {
		return Value{}, fmt.Errorf("unknown function %q", n.name)
	}
	args := make([]Value, len(n.args))
	for i, a := range n.args {
		v, err := a.eval(env)
		if err != nil {
			return Value{}, err
		}
		args[i] = v
	}
	return b.fn(env, args)
}

func (n callNode) walk(fn func(node) error) error {
	for _, a := range n.args {
		if err := fn(a); err != nil {
			return err
		}
	}
	return nil
}

// unaryNode is `!x` or unary `-x`.
type unaryNode struct {
	op tokenKind
	x  node
}

func (n unaryNode) eval(env *evalEnv) (Value, error) {
	v, err := n.x.eval(env)
	if err != nil {
		return Value{}, err
	}
	switch n.op {
	case tokNot:
		b, err := v.AsBool()
		if err != nil {
			return Value{}, fmt.Errorf("operator !: %w", err)
		}
		return Bool(!b), nil
	case tokMinus:
		if v.Kind != KindNum {
			return Value{}, fmt.Errorf("operator -: expected number, got %s", v.Kind)
		}
		return Num(-v.n), nil
	}
	return Value{}, fmt.Errorf("unknown unary operator")
}

func (n unaryNode) walk(fn func(node) error) error { return fn(n.x) }

// binaryNode is any infix operator. Logical && and || short-circuit.
type binaryNode struct {
	op   tokenKind
	l, r node
}

func (n binaryNode) eval(env *evalEnv) (Value, error) {
	// Short-circuit boolean operators before touching the right side, so a
	// cheap left operand can gate an expensive one (e.g. `signed && verified(...)`).
	if n.op == tokAnd || n.op == tokOr {
		return n.evalLogical(env)
	}

	lv, err := n.l.eval(env)
	if err != nil {
		return Value{}, err
	}
	rv, err := n.r.eval(env)
	if err != nil {
		return Value{}, err
	}

	switch n.op {
	case tokEq:
		return Bool(lv.Equal(rv)), nil
	case tokNe:
		return Bool(!lv.Equal(rv)), nil
	case tokLt, tokLe, tokGt, tokGe:
		return n.evalOrder(lv, rv)
	case tokPlus, tokMinus:
		if lv.Kind != KindNum || rv.Kind != KindNum {
			return Value{}, fmt.Errorf("arithmetic requires numbers, got %s and %s", lv.Kind, rv.Kind)
		}
		if n.op == tokPlus {
			return Num(lv.n + rv.n), nil
		}
		return Num(lv.n - rv.n), nil
	}
	return Value{}, fmt.Errorf("unknown binary operator")
}

// evalLogical implements short-circuiting && / ||.
func (n binaryNode) evalLogical(env *evalEnv) (Value, error) {
	lv, err := n.l.eval(env)
	if err != nil {
		return Value{}, err
	}
	lb, err := lv.AsBool()
	if err != nil {
		return Value{}, fmt.Errorf("operator %s: %w", opName(n.op), err)
	}
	if n.op == tokAnd && !lb {
		return Bool(false), nil
	}
	if n.op == tokOr && lb {
		return Bool(true), nil
	}
	rv, err := n.r.eval(env)
	if err != nil {
		return Value{}, err
	}
	rb, err := rv.AsBool()
	if err != nil {
		return Value{}, fmt.Errorf("operator %s: %w", opName(n.op), err)
	}
	return Bool(rb), nil
}

// evalOrder implements <, <=, >, >= via Value.Less.
func (n binaryNode) evalOrder(lv, rv Value) (Value, error) {
	switch n.op {
	case tokLt:
		lt, err := lv.Less(rv)
		return Bool(lt), err
	case tokGt:
		gt, err := rv.Less(lv)
		return Bool(gt), err
	case tokLe:
		gt, err := rv.Less(lv)
		return Bool(!gt), err
	case tokGe:
		lt, err := lv.Less(rv)
		return Bool(!lt), err
	}
	return Value{}, fmt.Errorf("unknown ordering operator")
}

func (n binaryNode) walk(fn func(node) error) error {
	if err := fn(n.l); err != nil {
		return err
	}
	return fn(n.r)
}

// opName renders an operator token for error messages.
func opName(k tokenKind) string {
	switch k {
	case tokAnd:
		return "&&"
	case tokOr:
		return "||"
	default:
		return "operator"
	}
}
