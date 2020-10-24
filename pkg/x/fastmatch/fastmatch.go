package fastmatch

import (
	"errors"
	"regexp"
	"strconv"
	"strings"
)

type Pattern struct {
	prefix     string
	delimiters []delimiter
	fields     []string
	scratch    []rune
}

type delimiter struct {
	match string
	name  string
	quote byte
}

func (d *delimiter) reset(tag, match, prev string) {
	quote := prevQuote(prev)
	if quote != nextQuote(match) {
		quote = 0
	}
	d.name = tag
	d.quote = quote
	d.match = match
}

var splitFields = regexp.MustCompile(`%\{\s*(?P<tag>[^\}]*)\s*\}`)

func Compile(pattern string) (*Pattern, error) {
	tags := splitFields.FindAllStringSubmatch(pattern, -1)
	if tags == nil {
		return nil, errInvalidPattern
	}
	matchDelimiters := splitFields.Split(pattern, -1)
	prefix, matchDelimiters := matchDelimiters[0], matchDelimiters[1:]
	delimiters := make([]delimiter, 0, len(tags))
	fields := make([]string, 0, len(tags))
	last := len(matchDelimiters) - 1
	prev := prefix
	for i, m := range matchDelimiters {
		if i < last && m == "" {
			return nil, errInvalidPattern
		}
		tag := tags[i][1]
		d := delimiter{}
		d.reset(tag, m, prev)
		prev = m
		delimiters = append(delimiters, d)
		if d.name != "" {
			fields = append(fields, d.name)
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

func (p *Pattern) MatchString(dst []string, src string) ([]string, error) {
	tail := src
	if prefix := p.prefix; len(prefix) <= len(tail) && tail[:len(prefix)] == prefix {
		tail = tail[len(prefix):]
	} else {
		return dst, errMatch
	}
	matches := dst
	delimiters := p.delimiters
	for i := range delimiters {
		d := &delimiters[i]
		switch seek := d.match; seek {
		case "":
			if d.name == "" {
				return matches, nil
			}
			return append(matches, tail), nil
		default:
			match, ss, err := p.match(tail, seek, d.quote)
			if err != nil {
				return dst, err
			}
			if d.name != "" {
				matches = append(matches, match)
			}
			tail = ss
		}
	}
	return matches, nil
}

func (p *Pattern) match(src, delim string, quote byte) (match, tail string, err error) {
	if (quote == '"' || quote == '\'') && strings.IndexByte(src, '\\') != -1 {
		return p.matchQuoted(src, delim, quote)
	}
	if pos := strings.Index(src, delim); 0 <= pos && pos < len(src) {
		match, tail = src[:pos], src[pos:]
		tail = tail[len(delim):]
		return match, tail, nil
	}
	return "", src, errMatch
}

func (p *Pattern) matchQuoted(src, delim string, quote byte) (match, tail string, err error) {
	tail = src
	scratch := p.scratch[:0]
	for len(tail) > 0 && tail[0] != quote {
		c, _, ss, err := strconv.UnquoteChar(tail, quote)
		if err != nil {
			p.scratch = scratch
			return "", src, err
		}
		scratch = append(scratch, c)
		tail = ss
	}
	p.scratch = scratch
	if strings.HasPrefix(tail, delim) {
		return string(scratch), strings.TrimPrefix(tail, delim), nil
	}
	return "", src, errMatch
}

func prevQuote(s string) byte {
	if n := len(s) - 1; 0 <= n && n < len(s) {
		switch q := s[n]; q {
		case '"', '\'':
			return q
		}
	}
	return 0
}

func nextQuote(s string) byte {
	if len(s) > 0 {
		switch q := s[0]; q {
		case '"', '\'':
			return q
		}
	}
	return 0
}