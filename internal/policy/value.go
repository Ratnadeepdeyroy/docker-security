package policy

import (
	"fmt"
	"strconv"
	"strings"
)

// --- Dynamic values --------------------------------------------------------
//
// The policy expression language is dynamically typed but deliberately small:
// a value is one of bool, number, string, or list. We use a tagged struct
// rather than `any` so comparisons and type errors are explicit and total —
// a hostile or sloppy policy can never trigger a Go panic during evaluation,
// only a clean, reported error. Numbers are float64 so integer counts and
// thresholds share one type without surprising truncation.

// Kind is the runtime type tag of a Value.
type Kind uint8

const (
	KindBool Kind = iota
	KindNum
	KindStr
	KindList
)

func (k Kind) String() string {
	switch k {
	case KindBool:
		return "bool"
	case KindNum:
		return "number"
	case KindStr:
		return "string"
	case KindList:
		return "list"
	default:
		return "unknown"
	}
}

// Value is a single dynamically-typed policy value.
type Value struct {
	Kind Kind
	b    bool
	n    float64
	s    string
	list []Value
}

// Constructors keep the internal fields unexported so a Value is always
// well-formed (its Kind matches the populated field).

func Bool(b bool) Value     { return Value{Kind: KindBool, b: b} }
func Num(n float64) Value   { return Value{Kind: KindNum, n: n} }
func Str(s string) Value    { return Value{Kind: KindStr, s: s} }
func List(vs []Value) Value { return Value{Kind: KindList, list: vs} }

// AsBool returns the boolean value, or an error if the value is not a bool.
// The final result of a rule's match expression must be a bool; using a
// number or string in a boolean position is a policy error, not a coercion,
// so mistakes surface at evaluation rather than silently passing a gate.
func (v Value) AsBool() (bool, error) {
	if v.Kind != KindBool {
		return false, fmt.Errorf("expected bool, got %s", v.Kind)
	}
	return v.b, nil
}

// Equal reports value equality. Cross-kind comparison is defined (and false)
// rather than an error, so `registry == 5` is simply false instead of aborting
// a whole policy evaluation. Lists compare element-wise.
func (v Value) Equal(o Value) bool {
	if v.Kind != o.Kind {
		return false
	}
	switch v.Kind {
	case KindBool:
		return v.b == o.b
	case KindNum:
		return v.n == o.n
	case KindStr:
		return v.s == o.s
	case KindList:
		if len(v.list) != len(o.list) {
			return false
		}
		for i := range v.list {
			if !v.list[i].Equal(o.list[i]) {
				return false
			}
		}
		return true
	}
	return false
}

// Less orders two values for the <, <=, >, >= operators. Ordering is only
// defined for two numbers or two strings; anything else is a typed error so an
// author cannot accidentally compare a bool against a number and get a
// meaningless answer that flips a gate.
func (v Value) Less(o Value) (bool, error) {
	if v.Kind != o.Kind {
		return false, fmt.Errorf("cannot order %s against %s", v.Kind, o.Kind)
	}
	switch v.Kind {
	case KindNum:
		return v.n < o.n, nil
	case KindStr:
		return v.s < o.s, nil
	default:
		return false, fmt.Errorf("cannot order values of type %s", v.Kind)
	}
}

// Contains reports whether a list value contains x. It is the backing for the
// in(x, list) builtin and returns an error if the receiver is not a list.
func (v Value) Contains(x Value) (bool, error) {
	if v.Kind != KindList {
		return false, fmt.Errorf("in: second argument must be a list, got %s", v.Kind)
	}
	for _, e := range v.list {
		if e.Equal(x) {
			return true, nil
		}
	}
	return false, nil
}

// Display renders a value for human-readable messages and explanations.
func (v Value) Display() string {
	switch v.Kind {
	case KindBool:
		return strconv.FormatBool(v.b)
	case KindNum:
		// Render whole numbers without a trailing ".0" so counts read cleanly.
		if v.n == float64(int64(v.n)) {
			return strconv.FormatInt(int64(v.n), 10)
		}
		return strconv.FormatFloat(v.n, 'g', -1, 64)
	case KindStr:
		return v.s
	case KindList:
		parts := make([]string, len(v.list))
		for i, e := range v.list {
			parts[i] = e.Display()
		}
		return "[" + strings.Join(parts, ", ") + "]"
	}
	return ""
}
