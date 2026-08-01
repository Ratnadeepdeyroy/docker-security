package policy

import "fmt"

// --- Parser ----------------------------------------------------------------
//
// A hand-written recursive-descent parser turns the token stream into an AST.
// The grammar (lowest-binding first, so unary binds tightest) is:
//
//	expr        := or
//	or          := and        ( "||" and )*
//	and         := comparison ( "&&" comparison )*
//	comparison  := additive   ( ("=="|"!="|"<"|"<="|">"|">=") additive )?
//	additive    := unary      ( ("+"|"-") unary )*
//	unary       := ("!" | "-") unary | primary
//	primary     := NUMBER | STRING | "true" | "false"
//	             | "[" (expr ("," expr)*)? "]"
//	             | IDENT ( "(" (expr ("," expr)*)? ")" )?
//	             | "(" expr ")"
//
// Unary sits below the binary operators so a negated operand like `x < -2` and
// `!privileged && ...` parse the way an author expects. Comparisons are
// non-associative (a single optional operator) because `a < b < c` has no useful
// meaning in a policy and is almost always a mistake.

// maxDepth bounds recursion so a deeply-nested or adversarial expression cannot
// blow the stack. Real policies nest a handful of levels; 128 is plenty.
const maxDepth = 128

type parser struct {
	toks  []token
	pos   int
	depth int
}

// parseExpr parses a complete expression string into an AST.
func parseExpr(input string) (node, error) {
	toks, err := lex(input)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks}
	n, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.peek().kind != tokEOF {
		return nil, fmt.Errorf("unexpected trailing input at column %d", p.peek().col)
	}
	return n, nil
}

func (p *parser) peek() token { return p.toks[p.pos] }

func (p *parser) next() token {
	t := p.toks[p.pos]
	if p.pos < len(p.toks)-1 {
		p.pos++
	}
	return t
}

func (p *parser) enter() error {
	p.depth++
	if p.depth > maxDepth {
		return fmt.Errorf("expression nested too deeply (over %d levels)", maxDepth)
	}
	return nil
}

func (p *parser) leave() { p.depth-- }

func (p *parser) parseOr() (node, error) {
	if err := p.enter(); err != nil {
		return nil, err
	}
	defer p.leave()
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.peek().kind == tokOr {
		p.next()
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = binaryNode{op: tokOr, l: left, r: right}
	}
	return left, nil
}

func (p *parser) parseAnd() (node, error) {
	left, err := p.parseComparison()
	if err != nil {
		return nil, err
	}
	for p.peek().kind == tokAnd {
		p.next()
		right, err := p.parseComparison()
		if err != nil {
			return nil, err
		}
		left = binaryNode{op: tokAnd, l: left, r: right}
	}
	return left, nil
}

func (p *parser) parseComparison() (node, error) {
	left, err := p.parseAdditive()
	if err != nil {
		return nil, err
	}
	switch p.peek().kind {
	case tokEq, tokNe, tokLt, tokLe, tokGt, tokGe:
		op := p.next().kind
		right, err := p.parseAdditive()
		if err != nil {
			return nil, err
		}
		return binaryNode{op: op, l: left, r: right}, nil
	}
	return left, nil
}

func (p *parser) parseAdditive() (node, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for k := p.peek().kind; k == tokPlus || k == tokMinus; k = p.peek().kind {
		op := p.next().kind
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		left = binaryNode{op: op, l: left, r: right}
	}
	return left, nil
}

// parseUnary handles prefix ! and - and then falls through to a primary. It
// sits below the binary levels so unary binds tightest.
func (p *parser) parseUnary() (node, error) {
	if k := p.peek().kind; k == tokNot || k == tokMinus {
		if err := p.enter(); err != nil {
			return nil, err
		}
		defer p.leave()
		op := p.next().kind
		x, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return unaryNode{op: op, x: x}, nil
	}
	return p.parsePrimary()
}

func (p *parser) parsePrimary() (node, error) {
	if err := p.enter(); err != nil {
		return nil, err
	}
	defer p.leave()

	t := p.peek()
	switch t.kind {
	case tokNumber:
		p.next()
		return litNode{v: Num(t.num)}, nil
	case tokString:
		p.next()
		return litNode{v: Str(t.str)}, nil
	case tokTrue:
		p.next()
		return litNode{v: Bool(true)}, nil
	case tokFalse:
		p.next()
		return litNode{v: Bool(false)}, nil
	case tokLBracket:
		return p.parseList()
	case tokLParen:
		p.next()
		inner, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if p.peek().kind != tokRParen {
			return nil, fmt.Errorf("expected ) at column %d", p.peek().col)
		}
		p.next()
		return inner, nil
	case tokIdent:
		return p.parseIdentOrCall()
	default:
		return nil, fmt.Errorf("unexpected token at column %d", t.col)
	}
}

// parseList parses a "[" elem, elem, ... "]" list literal.
func (p *parser) parseList() (node, error) {
	p.next() // consume '['
	var elems []node
	if p.peek().kind != tokRBracket {
		for {
			e, err := p.parseOr()
			if err != nil {
				return nil, err
			}
			elems = append(elems, e)
			if p.peek().kind == tokComma {
				p.next()
				continue
			}
			break
		}
	}
	if p.peek().kind != tokRBracket {
		return nil, fmt.Errorf("expected ] at column %d", p.peek().col)
	}
	p.next()
	return listNode{elems: elems}, nil
}

// parseIdentOrCall parses a bare identifier or a function call `name(args...)`.
func (p *parser) parseIdentOrCall() (node, error) {
	name := p.next().text
	if p.peek().kind != tokLParen {
		return identNode{name: name}, nil
	}
	p.next() // consume '('
	var args []node
	if p.peek().kind != tokRParen {
		for {
			a, err := p.parseOr()
			if err != nil {
				return nil, err
			}
			args = append(args, a)
			if p.peek().kind == tokComma {
				p.next()
				continue
			}
			break
		}
	}
	if p.peek().kind != tokRParen {
		return nil, fmt.Errorf("expected ) to close call to %s at column %d", name, p.peek().col)
	}
	p.next()
	return callNode{name: name, args: args}, nil
}
