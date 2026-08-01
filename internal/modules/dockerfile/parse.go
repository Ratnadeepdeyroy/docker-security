// Package dockerfile implements static analysis and linting of Dockerfiles.
// It is the first capability module (CAPABILITY_SPEC domain 3). The parser is
// intentionally small: it splits a Dockerfile into logical instructions,
// honoring comments and backslash line-continuations, and records line spans
// so findings can point at exact locations.
package dockerfile

import "strings"

// Instruction is one logical Dockerfile instruction (a command plus its
// arguments), possibly spanning multiple physical lines.
type Instruction struct {
	Cmd       string // upper-cased command, e.g. "FROM", "RUN"
	Args      string // everything after the command, continuations joined
	StartLine int    // 1-based first physical line
	EndLine   int    // 1-based last physical line
	Raw       string // normalized "CMD args" text
}

// Dockerfile is a parsed Dockerfile.
type Dockerfile struct {
	Instructions []Instruction
	Lines        []string
}

// Parse turns Dockerfile text into a Dockerfile. It never errors; malformed
// input simply yields whatever instructions could be recognized.
func Parse(content string) *Dockerfile {
	raw := strings.Split(content, "\n")
	df := &Dockerfile{Lines: raw}

	i, n := 0, len(raw)
	for i < n {
		trimmed := strings.TrimSpace(raw[i])
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			i++
			continue
		}

		start := i
		var b strings.Builder
		for {
			cur := strings.TrimRight(raw[i], " \t\r")
			if strings.HasSuffix(cur, "\\") {
				b.WriteString(strings.TrimSuffix(cur, "\\"))
				b.WriteString(" ")
				i++
				// Skip comment lines embedded inside a continuation.
				for i < n && strings.HasPrefix(strings.TrimSpace(raw[i]), "#") {
					i++
				}
				if i >= n {
					break
				}
				continue
			}
			b.WriteString(cur)
			break
		}
		end := i

		full := strings.TrimSpace(b.String())
		fields := strings.Fields(full)
		if len(fields) == 0 {
			i++
			continue
		}
		cmd := strings.ToUpper(fields[0])
		args := strings.TrimSpace(strings.TrimPrefix(full, fields[0]))
		df.Instructions = append(df.Instructions, Instruction{
			Cmd:       cmd,
			Args:      args,
			StartLine: start + 1,
			EndLine:   end + 1,
			Raw:       cmd + " " + args,
		})
		i++
	}
	return df
}

// From returns all FROM instructions.
func (d *Dockerfile) From() []Instruction { return d.byCmd("FROM") }

func (d *Dockerfile) byCmd(cmd string) []Instruction {
	var out []Instruction
	for _, ins := range d.Instructions {
		if ins.Cmd == cmd {
			out = append(out, ins)
		}
	}
	return out
}

// Has reports whether any instruction with the given command exists.
func (d *Dockerfile) Has(cmd string) bool {
	for _, ins := range d.Instructions {
		if ins.Cmd == cmd {
			return true
		}
	}
	return false
}
