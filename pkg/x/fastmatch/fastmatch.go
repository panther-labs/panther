package fastmatch

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

type Pattern struct {
	prefix     string
	delimiters []delimiter
	fields     []string
}
type delimiter struct {
	match string
	name  string
}

var splitFields = regexp.MustCompile(`%\{\s*(?P<field>[^\}]*)\s*\}`)

func New(pattern string) (*Pattern, error) {
	matchFields := splitFields.FindAllStringSubmatch(pattern, -1)
	if matchFields == nil {
		return nil, errInvalidPattern
	}
	matchDelimiters := splitFields.Split(pattern, -1)
	prefix, matchDelimiters := matchDelimiters[0], matchDelimiters[1:]
	delimiters := make([]delimiter, 0, len(matchFields))
	fields := make([]string, 0, len(matchFields))
	last := len(matchDelimiters) - 1
	for i, m := range matchDelimiters {
		if i < last && m == "" {
			return nil, errInvalidPattern
		}
		name := matchFields[i][1]
		delimiters = append(delimiters, delimiter{
			match: m,
			name:  name,
		})
		if name != "" {
			fields = append(fields, name)
		}
	}
	return &Pattern{
		prefix:     prefix,
		delimiters: delimiters,
		fields:     fields,
	}, nil
}

func (p *Pattern) NumFields() int {
	return len(p.fields)
}
func (p *Pattern) FieldName(i int) string {
	return p.fields[i]
}

var errMatch = errors.New("match failed")
var errInvalidPattern = errors.New("invalid pattern")

type matchError struct {
	field string
	delim string
}

func (e *matchError) Error() string {
	return fmt.Sprintf("failed to match %q after field %q", e.delim, e.field)
}

func (p *Pattern) MatchString(dst []string, src string) ([]string, bool) {
	tail := src
	if prefix := p.prefix; len(prefix) <= len(tail) && tail[:len(prefix)] == prefix {
		tail = tail[len(prefix):]
	} else {
		return dst, false
	}
	var match string
	matches := dst
	delimiters := p.delimiters
	for i := range delimiters {
		d := &delimiters[i]
		m := d.match
		if m == "" {
			if d.name != "" {
				matches = append(matches, tail)
			}
			return matches, true
		}
		end := strings.Index(tail, m)
		if 0 <= end && end < len(tail) {
			match, tail = tail[:end], tail[end:]
			if d.name != "" {
				matches = append(matches, match)
			}
			tail = tail[len(m):]
		} else {
			return dst, false
		}
	}
	return matches, true
}