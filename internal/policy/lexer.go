package policy

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// --- Lexer -----------------------------------------------------------------
//
// The condition language is tokenized here before the parser builds an AST.
// The grammar is small on purpose (comparisons, boolean logic, calls, list
// literals), so the lexer is a single left-to-right scan with no lookahead
// beyond one rune. Every error carries the column so a policy author sees
// exactly where their expression went wrong.

// tokenKind enumerates the lexical categories of the expression language.
type tokenKind uint8

const (
	tokEOF tokenKind = iota
	tokNumber
	tokString
	tokIdent
	tokLParen
	tokRParen
	tokLBracket
	tokRBracket
	tokComma
	tokAnd // &&
	tokOr  // ||
	tokNot // !
	tokEq  // ==
	tokNe  // !=
	tokLt  // <
	tokLe  // <=
	tokGt  // >
	tokGe  // >=
	tokPlus
	tokMinus
	tokTrue
	tokFalse
)

// token is a lexeme with its source position (0-based column).
type token struct {
	kind tokenKind
	text string  // identifier name / raw number text
	str  string  // decoded string literal (for tokString)
	num  float64 // parsed value (for tokNumber)
	col  int
}

// maxTokens bounds a single expression so a pathologically long policy string
// cannot exhaust memory or CPU during compilation. Real rules are a few dozen
// tokens; 4096 is generous headroom while still a hard ceiling.
const maxTokens = 4096

// lex tokenizes an expression. It returns all tokens including a trailing EOF.
func lex(input string) ([]token, error) {
	var toks []token
	i := 0
	for i < len(input) {
		r, size := utf8.DecodeRuneInString(input[i:])
		switch {
		case unicode.IsSpace(r):
			i += size
			continue
		case r == '(':
			toks = append(toks, token{kind: tokLParen, col: i})
			i += size
		case r == ')':
			toks = append(toks, token{kind: tokRParen, col: i})
			i += size
		case r == '[':
			toks = append(toks, token{kind: tokLBracket, col: i})
			i += size
		case r == ']':
			toks = append(toks, token{kind: tokRBracket, col: i})
			i += size
		case r == ',':
			toks = append(toks, token{kind: tokComma, col: i})
			i += size
		case r == '+':
			toks = append(toks, token{kind: tokPlus, col: i})
			i += size
		case r == '-':
			toks = append(toks, token{kind: tokMinus, col: i})
			i += size
		case r == '"' || r == '\'':
			tok, next, err := lexString(input, i, r)
			if err != nil {
				return nil, err
			}
			toks = append(toks, tok)
			i = next
		case r == '&' || r == '|' || r == '=' || r == '!' || r == '<' || r == '>':
			tok, next, err := lexOperator(input, i)
			if err != nil {
				return nil, err
			}
			toks = append(toks, tok)
			i = next
		case r >= '0' && r <= '9':
			tok, next, err := lexNumber(input, i)
			if err != nil {
				return nil, err
			}
			toks = append(toks, tok)
			i = next
		case isIdentStart(r):
			tok, next := lexIdent(input, i)
			toks = append(toks, tok)
			i = next
		default:
			return nil, fmt.Errorf("unexpected character %q at column %d", string(r), i)
		}
		if len(toks) > maxTokens {
			return nil, fmt.Errorf("expression too long (over %d tokens)", maxTokens)
		}
	}
	toks = append(toks, token{kind: tokEOF, col: len(input)})
	return toks, nil
}

// lexOperator scans the multi-character operators. Bare `&` and `|` are
// rejected: the language has no bitwise operators, so a single one is almost
// certainly a typo for the boolean form.
func lexOperator(input string, i int) (token, int, error) {
	two := ""
	if i+1 < len(input) {
		two = input[i : i+2]
	}
	switch two {
	case "&&":
		return token{kind: tokAnd, col: i}, i + 2, nil
	case "||":
		return token{kind: tokOr, col: i}, i + 2, nil
	case "==":
		return token{kind: tokEq, col: i}, i + 2, nil
	case "!=":
		return token{kind: tokNe, col: i}, i + 2, nil
	case "<=":
		return token{kind: tokLe, col: i}, i + 2, nil
	case ">=":
		return token{kind: tokGe, col: i}, i + 2, nil
	}
	switch input[i] {
	case '!':
		return token{kind: tokNot, col: i}, i + 1, nil
	case '<':
		return token{kind: tokLt, col: i}, i + 1, nil
	case '>':
		return token{kind: tokGt, col: i}, i + 1, nil
	}
	return token{}, i, fmt.Errorf("unexpected operator %q at column %d (did you mean && or ||?)", string(input[i]), i)
}

// lexString scans a quoted string literal with C-style escapes. Both single
// and double quotes are accepted so authors can embed the other quote freely.
func lexString(input string, start int, quote rune) (token, int, error) {
	var sb strings.Builder
	i := start + 1
	for i < len(input) {
		c := input[i]
		if rune(c) == quote {
			return token{kind: tokString, str: sb.String(), col: start}, i + 1, nil
		}
		if c == '\\' {
			if i+1 >= len(input) {
				break
			}
			switch input[i+1] {
			case 'n':
				sb.WriteByte('\n')
			case 't':
				sb.WriteByte('\t')
			case '\\':
				sb.WriteByte('\\')
			case '"':
				sb.WriteByte('"')
			case '\'':
				sb.WriteByte('\'')
			default:
				return token{}, i, fmt.Errorf("invalid escape %q at column %d", "\\"+string(input[i+1]), i)
			}
			i += 2
			continue
		}
		sb.WriteByte(c)
		i++
	}
	return token{}, start, fmt.Errorf("unterminated string starting at column %d", start)
}

// lexNumber scans an integer or decimal number.
func lexNumber(input string, start int) (token, int, error) {
	i := start
	seenDot := false
	for i < len(input) {
		c := input[i]
		if c >= '0' && c <= '9' {
			i++
			continue
		}
		if c == '.' && !seenDot {
			seenDot = true
			i++
			continue
		}
		break
	}
	text := input[start:i]
	n, err := strconv.ParseFloat(text, 64)
	if err != nil {
		return token{}, start, fmt.Errorf("invalid number %q at column %d", text, start)
	}
	return token{kind: tokNumber, text: text, num: n, col: start}, i, nil
}

// lexIdent scans an identifier and folds the boolean keywords into their own
// token kinds so the parser can treat them as literals.
func lexIdent(input string, start int) (token, int) {
	i := start
	for i < len(input) {
		r, size := utf8.DecodeRuneInString(input[i:])
		if !isIdentPart(r) {
			break
		}
		i += size
	}
	text := input[start:i]
	switch text {
	case "true":
		return token{kind: tokTrue, text: text, col: start}, i
	case "false":
		return token{kind: tokFalse, text: text, col: start}, i
	}
	return token{kind: tokIdent, text: text, col: start}, i
}

func isIdentStart(r rune) bool {
	return r == '_' || unicode.IsLetter(r)
}

func isIdentPart(r rune) bool {
	return r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r)
}
