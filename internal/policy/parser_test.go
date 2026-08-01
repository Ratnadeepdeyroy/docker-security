package policy

import "testing"

// evalString parses and evaluates an expression against in, returning the
// value's display form. It is a compact way to assert language semantics.
func evalString(t *testing.T, expr string, in *Input) Value {
	t.Helper()
	n, err := parseExpr(expr)
	if err != nil {
		t.Fatalf("parse %q: %v", expr, err)
	}
	v, err := n.eval(newEvalEnv(in))
	if err != nil {
		t.Fatalf("eval %q: %v", expr, err)
	}
	return v
}

func TestParsePrecedence(t *testing.T) {
	// && binds tighter than ||: false || true && false  ==  false || (true && false)  == false
	if v := evalString(t, `false || true && false`, &Input{}); v.b != false {
		t.Errorf("precedence: got %v, want false", v.b)
	}
	// Parentheses override: (false || true) && false == false
	if v := evalString(t, `(false || true) && false`, &Input{}); v.b != false {
		t.Errorf("paren: got %v", v.b)
	}
	// Arithmetic then comparison: 1 + 2 > 2 == true
	if v := evalString(t, `1 + 2 > 2`, &Input{}); v.b != true {
		t.Errorf("arith/compare: got %v", v.b)
	}
}

func TestParseListAndIn(t *testing.T) {
	in := &Input{Image: Image{Registry: "docker.io"}}
	if v := evalString(t, `in(registry, ["gcr.io", "docker.io"])`, in); v.b != true {
		t.Errorf("in-list: got %v, want true", v.b)
	}
	if v := evalString(t, `in(registry, ["gcr.io"])`, in); v.b != false {
		t.Errorf("in-list negative: got %v", v.b)
	}
}

func TestParseErrors(t *testing.T) {
	cases := []string{
		`(1 + 2`,                  // unclosed paren
		`severity_atleast("high"`, // unclosed call
		`1 < 2 < 3`,               // non-associative comparison
		`[1, 2`,                   // unclosed list
		`&& x`,                    // leading operator
		`1 2`,                     // trailing input
	}
	for _, in := range cases {
		if _, err := parseExpr(in); err == nil {
			t.Errorf("parseExpr(%q): expected error, got nil", in)
		}
	}
}

func TestParseDepthLimit(t *testing.T) {
	// Deeply nested parentheses must be rejected rather than overflowing.
	expr := ""
	for i := 0; i < maxDepth+5; i++ {
		expr += "("
	}
	expr += "true"
	for i := 0; i < maxDepth+5; i++ {
		expr += ")"
	}
	if _, err := parseExpr(expr); err == nil {
		t.Fatal("expected depth-limit error")
	}
}

func TestUnaryOps(t *testing.T) {
	if v := evalString(t, `!false`, &Input{}); v.b != true {
		t.Errorf("!false: got %v", v.b)
	}
	if v := evalString(t, `-3 < -2`, &Input{}); v.b != true {
		t.Errorf("unary minus: got %v", v.b)
	}
}
