package policy

import "testing"

func TestLexBasicTokens(t *testing.T) {
	toks, err := lex(`severity_atleast("high") > 0 && signed`)
	if err != nil {
		t.Fatalf("lex: %v", err)
	}
	want := []tokenKind{
		tokIdent, tokLParen, tokString, tokRParen, tokGt, tokNumber, tokAnd, tokIdent, tokEOF,
	}
	if len(toks) != len(want) {
		t.Fatalf("got %d tokens, want %d: %+v", len(toks), len(want), toks)
	}
	for i, w := range want {
		if toks[i].kind != w {
			t.Errorf("token %d: got kind %d, want %d", i, toks[i].kind, w)
		}
	}
}

func TestLexStringEscapes(t *testing.T) {
	toks, err := lex(`"a\"b" 'c'`)
	if err != nil {
		t.Fatalf("lex: %v", err)
	}
	if toks[0].str != `a"b` {
		t.Errorf("double-quote escape: got %q", toks[0].str)
	}
	if toks[1].str != "c" {
		t.Errorf("single-quote: got %q", toks[1].str)
	}
}

func TestLexNumbers(t *testing.T) {
	toks, err := lex(`3 4.5`)
	if err != nil {
		t.Fatalf("lex: %v", err)
	}
	if toks[0].num != 3 || toks[1].num != 4.5 {
		t.Errorf("numbers: got %v, %v", toks[0].num, toks[1].num)
	}
}

func TestLexErrors(t *testing.T) {
	cases := []string{
		`"unterminated`,
		`a & b`, // single ampersand is rejected
		`a @ b`, // unknown character
		`"bad\escape"`,
	}
	for _, in := range cases {
		if _, err := lex(in); err == nil {
			t.Errorf("lex(%q): expected error, got nil", in)
		}
	}
}

func TestLexTokenLimit(t *testing.T) {
	// A string of many "+" tokens should be rejected past the ceiling rather
	// than accepted unbounded.
	var b []byte
	for i := 0; i < maxTokens+10; i++ {
		b = append(b, '+')
	}
	if _, err := lex(string(b)); err == nil {
		t.Fatal("expected token-limit error")
	}
}
