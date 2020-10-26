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

type Expression struct {
	src   string
	expr  *regexp.Regexp
	names []string
}

func (e *Expression) Regexp() string {
	return e.expr.String()
}

func (e *Expression) String() string {
	return e.src
}

func (e *Expression) MatchString(dst []string, src string) ([]string, error) {
	matches := e.expr.FindStringSubmatchIndex(src)
	if matches == nil {
		return nil, nil
	}
	if len(matches) > 2 {
		matches = matches[2:]
		var start, end int
		for i := 0; 0<= i && i < len(e.names) && len(matches) >= 2; i++ {
			name := e.names[i]
			if name == "" {
				continue
			}
			start, end, matches = matches[0], matches[1], matches[2:]
			dst = append(dst, name)
			dst = append(dst, src[start:end])
		}
	}
	return dst, nil
}

func (e *Expression) FieldName(i int) string {
	return e.names[i]
}

func (e *Expression) NumFields() int {
	return len(e.names)
}

type Env struct {
	parent   *Env
	compiled map[string]*Expression
}

func New() *Env {
	return defaultEnv.NewChild()
}

func (e *Env) NewChild() *Env {
	return &Env{
		parent: e,
	}
}

func (e *Env) lookup(name string) *Expression {
	expr, ok := e.compiled[name]
	if ok {
		return expr
	}
	if e.parent != nil {
		return e.parent.lookup(name)
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

func (e *Env) Compile(pattern string) (*Expression, error) {
	return e.compile(pattern, pattern, nil, nil)
}

func (e *Env) compile(root, src string, patterns map[string]string, visited []string) (*Expression, error) {
	tpl := fasttemplate.New(src, startDelimiter, endDelimiter)
	s := strings.Builder{}
	_, err := tpl.ExecuteFunc(&s, func(w io.Writer, tag string) (int, error) {
		name, field := splitTag(tag)
		for _, visited := range visited {
			if visited == name {
				return 0, errors.Errorf("recursive pattern %q %v", root, visited)
			}
		}
		expr := e.lookup(name)
		if expr == nil {
			if src, ok := patterns[name]; ok {
				e, err := e.compile(name, src, patterns, append(visited, name))
				if err != nil {
					return 0, err
				}
				expr = e
			}
		}
		if expr == nil {
			return 0, errors.Errorf("unresolved pattern %q", name)
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
	return &Expression{
		src:   src,
		expr:  expr,
		names: expr.SubexpNames()[1:],
	}, nil
}

func (e *Env) set(name string, expr *Expression) {
	if e.compiled == nil {
		e.compiled = make(map[string]*Expression)
	}
	e.compiled[name] = expr

}
func (e *Env) checkDuplicate(name string) error {
	if duplicate := e.lookup(name); duplicate != nil {
		return errors.Errorf("expresion %q already defined as %q", name, duplicate.String())
	}
	return nil
}


func splitTag(tag string) (pattern, field string) {
	if pos := strings.IndexByte(tag, ':'); 0 <= pos && pos < len(tag) {
		return tag[:pos], tag[pos+1:]
	}
	return tag, ""
}

var defaultEnv = mustDefaultEnv()

func mustDefaultEnv() *Env {
	env := Env{}
	r := strings.NewReader(corePatterns)
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
	child := e.NewChild()
	for name, pattern := range patterns {
		if err := e.checkDuplicate(name); err != nil {
			return err
		}
		expr, err := child.compile(name, pattern, patterns, nil)
		if err != nil {
			return err
		}
		e.set(name, expr)
	}
	for name, pattern := range child.compiled {
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
