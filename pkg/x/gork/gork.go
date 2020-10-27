package gork

import (
	"bufio"
	"fmt"
	"github.com/pkg/errors"
	"github.com/valyala/fasttemplate"
	"io"
	"regexp"
	"strings"
)

const (
	startDelimiter = "%{"
	endDelimiter   = "}"
)

type Pattern struct {
	src   string
	expr  *regexp.Regexp
	names []string
}

func (p *Pattern) Regexp() string {
	return p.expr.String()
}

func (p *Pattern) String() string {
	return p.src
}

func (p *Pattern) MatchString(dst []string, src string) ([]string, error) {
	matches := p.expr.FindStringSubmatchIndex(src)
	if matches == nil {
		return nil, nil
	}
	if len(matches) > 2 {
		// Regexp always sets first match to full string
		matches = matches[2:]
		var start, end int
		for i := 0; 0 <= i && i < len(p.names) && len(matches) >= 2; i++ {
			name := p.names[i]
			// We skip unnamed groups
			if name == "" {
				continue
			}
			start, end, matches = matches[0], matches[1], matches[2:]
			dst = append(dst, name, src[start:end])
		}
	}
	return dst, nil
}

func (p *Pattern) FieldName(i int) string {
	return p.names[i]
}

type Env struct {
	patterns map[string]*Pattern
}

func New() *Env {
	return defaultEnv.Clone()
}

func (e *Env) Clone() *Env {
	patterns := make(map[string]*Pattern, len(e.patterns))
	for name, pattern := range e.patterns {
		patterns[name] = pattern
	}
	return &Env{
		patterns: patterns,
	}
}

func (e *Env) lookup(name string) *Pattern {
	if p, ok := e.patterns[name]; ok {
		return p
	}
	return nil
}

func (e *Env) MustSet(name string, pattern string) {
	if err := e.Set(name, pattern); err != nil {
		panic(err)
	}
}

func (e *Env) Set(name string, pattern string) error {
	if err := e.checkDuplicate(name); err != nil {
		return err
	}
	expr, err := e.compile(name, pattern, nil, nil)
	if err != nil {
		return err
	}
	e.set(name, expr)
	return nil
}

func (e *Env) Compile(pattern string) (*Pattern, error) {
	return e.compile(pattern, pattern, nil, nil)
}

var (
	validPatternName = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
	validFieldName = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*`)
)
func (e *Env) compile(root, src string, patterns map[string]string, visited []string) (*Pattern, error) {
	tpl := fasttemplate.New(src, startDelimiter, endDelimiter)
	s := strings.Builder{}
	_, err := tpl.ExecuteFunc(&s, func(w io.Writer, tag string) (int, error) {
		// TODO: Allow arbitrary field names by switching named groups with auto-incrementing name
		// To achieve this we need to build the 'names' slice as we render the template
		name, field := splitTag(tag)
		if !validPatternName.MatchString(name) {
			return 0, errors.Errorf("invalid pattern name %q in tag %q of pattern %q", name, tag, root)
		}
		if field != "" && !validFieldName.MatchString(field) {
			return 0, errors.Errorf("invalid field name %q in tag %q of pattern %q", field, tag, root)
		}
		for _, visited := range visited {
			if visited == name {
				return 0, errors.Errorf("recursive pattern %q %v", root, visited)
			}
		}
		expr := e.lookup(name)
		if expr == nil {
			// Try to compile the pattern
			if src, ok := patterns[name]; ok {
				subexpr, err := e.compile(name, src, patterns, append(visited, name))
				if err != nil {
					return 0, err
				}
				// Avoid duplicate compilations
				e.set(name, subexpr)
				expr = subexpr
			} else {
				return 0, errors.Errorf("unresolved pattern %q", name)
			}
		}
		var group string
		if field == "" {
			group = fmt.Sprintf("(?:%s)", expr.Regexp())
		} else {
			group = fmt.Sprintf("(?P<%s>%s)", field, expr.Regexp())
		}
		return w.Write([]byte(group))
	})
	if err != nil {
		return nil, errors.Wrapf(err, "failed to expand pattern %q", root)
	}

	expr, err := regexp.Compile(s.String())
	if err != nil {
		return nil, errors.Wrapf(err, "failed to compile pattern %q", root)
	}
	return &Pattern{
		src:   src,
		expr:  expr,
		names: expr.SubexpNames()[1:],
	}, nil
}

func (e *Env) set(name string, expr *Pattern) {
	if e.patterns == nil {
		e.patterns = make(map[string]*Pattern)
	}
	e.patterns[name] = expr

}
func (e *Env) checkDuplicate(name string) error {
	if duplicate := e.lookup(name); duplicate != nil {
		return errors.Errorf("expresion %q already defined as %q", name, duplicate.String())
	}
	return nil
}

func splitTag(tag string) (pattern, field string) {
	tag = strings.TrimSpace(tag)
	if pos := strings.IndexByte(tag, ':'); 0 <= pos && pos < len(tag) {
		return tag[:pos], tag[pos+1:]
	}
	return tag, ""
}

var defaultEnv = mustDefaultEnv()

func mustDefaultEnv() *Env {
	env := Env{}
	r := strings.NewReader(BuiltinPatterns)
	if err := env.ReadPatterns(r); err != nil {
		panic(err)
	}
	return &env
}

func (e *Env) ReadPatterns(r io.Reader) error {
	patterns, err := ReadPatterns(r)
	if err != nil {
		return err
	}
	if err := e.SetMap(patterns); err != nil {
		return err
	}
	return nil
}

func (e *Env) SetMap(patterns map[string]string) error {
	child := e.Clone()
	for name, pattern := range patterns {
		// We check for duplicate only in the parent environment.
		if err := e.checkDuplicate(name); err != nil {
			return err
		}
		// Compilation is recursive so we might have compiled this already
		if _, skip := child.patterns[name]; skip {
			continue
		}
		expr, err := child.compile(name, pattern, patterns, nil)
		if err != nil {
			return err
		}
		e.set(name, expr)
	}
	for name, pattern := range child.patterns {
		e.set(name, pattern)
	}
	return nil
}

func ReadPatterns(r io.Reader) (map[string]string, error) {
	patterns := make(map[string]string)
	scanner := bufio.NewScanner(r)
	numLines := 0
	for scanner.Scan() {
		numLines++
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		match := patternDef.FindStringSubmatch(line)
		if match == nil {
			return nil, errors.Errorf("invalid pattern definition at line #%d", numLines)
		}
		name, src := match[1], match[2]
		patterns[name] = src
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return patterns, nil
}

var patternDef = regexp.MustCompile(`^(\w+)\s+(.*)`)
