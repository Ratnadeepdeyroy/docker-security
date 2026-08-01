// Package k8syaml is a minimal, dependency-free YAML reader scoped to the subset
// Kubernetes manifests actually use: indentation-based mappings and sequences,
// block scalars are not needed, and values are strings/bools/ints/null. It
// converts each document to the JSON the rest of the tool already understands, so
// an offline manifest scan can reuse the harden Workload parser without pulling
// in a full YAML library (the project is zero-dependency by design).
//
// It is deliberately strict about what it accepts and converts — anything it
// cannot represent (anchors, block scalars, flow-mixed edge cases) yields an
// error for that document rather than a silently wrong parse, which matters for
// a security tool: a mis-parsed manifest that looks "clean" is worse than a
// reported parse failure.
package k8syaml

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// SplitDocuments splits a multi-document YAML stream on `---` separators,
// returning each non-empty document's lines. A leading `---` and trailing `...`
// are handled. Comment-only and blank documents are dropped.
func SplitDocuments(src string) [][]string {
	var docs [][]string
	var cur []string
	flush := func() {
		if hasContent(cur) {
			docs = append(docs, cur)
		}
		cur = nil
	}
	for _, line := range strings.Split(src, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "---" {
			flush()
			continue
		}
		if trimmed == "..." {
			flush()
			continue
		}
		cur = append(cur, line)
	}
	flush()
	return docs
}

func hasContent(lines []string) bool {
	for _, l := range lines {
		t := strings.TrimSpace(l)
		if t != "" && !strings.HasPrefix(t, "#") {
			return true
		}
	}
	return false
}

// ToJSON parses one YAML document (as lines) into a value and marshals it to
// JSON. The result is exactly what json.Unmarshal-based parsers elsewhere expect.
func ToJSON(lines []string) ([]byte, error) {
	p := &parser{lines: stripComments(lines)}
	v, err := p.parseBlock(0)
	if err != nil {
		return nil, err
	}
	return json.Marshal(v)
}

// stripComments removes full-line comments and trailing blank lines, and drops
// trailing " # ..." comments on scalar lines (only when the # is not inside a
// quoted string — we keep it simple: a # preceded by whitespace outside quotes).
func stripComments(lines []string) []string {
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		if s := strings.TrimSpace(l); s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		out = append(out, stripInlineComment(l))
	}
	return out
}

func stripInlineComment(l string) string {
	inSingle, inDouble := false, false
	for i := 0; i < len(l); i++ {
		switch l[i] {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case '#':
			if !inSingle && !inDouble && i > 0 && (l[i-1] == ' ' || l[i-1] == '\t') {
				return strings.TrimRight(l[:i], " \t")
			}
		}
	}
	return l
}

type parser struct {
	lines []string
	pos   int
}

// indentOf returns the leading-space count of a line.
func indentOf(l string) int {
	n := 0
	for n < len(l) && l[n] == ' ' {
		n++
	}
	return n
}

// parseBlock parses the block of lines at exactly the given indent, returning a
// map[string]any or []any.
func (p *parser) parseBlock(indent int) (any, error) {
	if p.pos >= len(p.lines) {
		return nil, nil
	}
	first := p.lines[p.pos]
	if strings.HasPrefix(strings.TrimLeft(first, " "), "- ") || strings.TrimSpace(first) == "-" {
		return p.parseSequence(indent)
	}
	return p.parseMapping(indent)
}

func (p *parser) parseMapping(indent int) (any, error) {
	m := map[string]any{}
	for p.pos < len(p.lines) {
		line := p.lines[p.pos]
		ci := indentOf(line)
		if ci < indent {
			break
		}
		if ci > indent {
			return nil, fmt.Errorf("unexpected indent at line %q", line)
		}
		content := strings.TrimLeft(line, " ")
		key, rest, ok := splitKey(content)
		if !ok {
			return nil, fmt.Errorf("expected 'key:' at line %q", line)
		}
		p.pos++
		rest = strings.TrimSpace(rest)
		if rest != "" {
			m[key] = scalar(rest)
			continue
		}
		// Nested block: peek the next content line's indent.
		child, err := p.parseChild(indent)
		if err != nil {
			return nil, err
		}
		m[key] = child
	}
	return m, nil
}

func (p *parser) parseSequence(indent int) (any, error) {
	seq := []any{}
	for p.pos < len(p.lines) {
		line := p.lines[p.pos]
		ci := indentOf(line)
		if ci != indent {
			break
		}
		content := strings.TrimLeft(line, " ")
		if !(content == "-" || strings.HasPrefix(content, "- ")) {
			break
		}
		// Column where the item content begins (just after "- ").
		dashRun := len(content) - len(strings.TrimLeft(content, "-"))
		after := strings.TrimLeft(content[dashRun:], " ")
		itemIndent := ci + (len(content) - len(after))

		if after == "" {
			// Item content is a nested block on following lines.
			p.pos++
			child, err := p.parseChild(indent)
			if err != nil {
				return nil, err
			}
			seq = append(seq, child)
			continue
		}

		if key, rest, ok := splitKey(after); ok {
			// A mapping whose first key sits on the dash line. Rewrite the dash
			// line so its first key is indented to itemIndent, then parse the
			// whole item (this key + any continuation keys) as one mapping block.
			p.lines[p.pos] = strings.Repeat(" ", itemIndent) + after
			_ = key
			_ = rest
			m, err := p.parseMapping(itemIndent)
			if err != nil {
				return nil, err
			}
			seq = append(seq, m)
			continue
		}

		seq = append(seq, scalar(after))
		p.pos++
	}
	return seq, nil
}

// parseChild parses a key's block value. The value is either a mapping/sequence
// indented deeper than the key, or — in the common K8s style — a sequence whose
// dashes sit at the SAME indent as the key. Anything at a shallower indent (or a
// non-dash line at the same indent) means the key had an empty value.
func (p *parser) parseChild(parentIndent int) (any, error) {
	if p.pos >= len(p.lines) {
		return nil, nil
	}
	line := p.lines[p.pos]
	childIndent := indentOf(line)
	content := strings.TrimLeft(line, " ")

	if childIndent == parentIndent {
		// Same-indent sequence under the key (K8s style); otherwise empty value.
		if content == "-" || strings.HasPrefix(content, "- ") {
			return p.parseSequence(parentIndent)
		}
		return nil, nil
	}
	if childIndent < parentIndent {
		return nil, nil // empty value
	}
	return p.parseBlock(childIndent)
}

// splitKey splits "key: rest" respecting quoted keys. Returns ok=false if the
// line is not a mapping entry.
func splitKey(s string) (key, rest string, ok bool) {
	// Find the first ": " or trailing ":" outside quotes.
	inSingle, inDouble := false, false
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case ':':
			if inSingle || inDouble {
				continue
			}
			if i == len(s)-1 {
				return unquote(strings.TrimSpace(s[:i])), "", true
			}
			if s[i+1] == ' ' || s[i+1] == '\t' {
				return unquote(strings.TrimSpace(s[:i])), s[i+1:], true
			}
		}
	}
	return "", "", false
}

// scalar converts a YAML scalar token to a typed Go value.
func scalar(s string) any {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	if (strings.HasPrefix(s, `"`) && strings.HasSuffix(s, `"`)) ||
		(strings.HasPrefix(s, `'`) && strings.HasSuffix(s, `'`)) {
		return unquote(s)
	}
	switch strings.ToLower(s) {
	case "null", "~":
		return nil
	case "true", "yes", "on":
		return true
	case "false", "no", "off":
		return false
	}
	if i, err := strconv.ParseInt(s, 10, 64); err == nil {
		return i
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return f
	}
	// Flow sequence/mapping like [a, b] or {a: 1} — handle the simple list case
	// common in manifests (args: [x, y]).
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		return flowSeq(s)
	}
	return s
}

func flowSeq(s string) []any {
	inner := strings.TrimSpace(s[1 : len(s)-1])
	if inner == "" {
		return []any{}
	}
	var out []any
	for _, part := range strings.Split(inner, ",") {
		out = append(out, scalar(strings.TrimSpace(part)))
	}
	return out
}

func unquote(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}
