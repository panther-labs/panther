package fastmatch

/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2020 Panther Labs Inc
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

import (
	"errors"
	"regexp"
	"strconv"
	"strings"
)

// Pattern matches a string and extracts key/value pairs.
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

var splitFields = regexp.MustCompile(`%{\s*(?P<tag>[^}]*)\s*}`)

// Compile compiles a pattern.
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

func (d *delimiter) reset(tag, match, prev string) {
	quote := prevQuote(prev)
	if quote != nextQuote(match) {
		quote = 0
	}
	d.name = tag
	d.quote = quote
	d.match = match
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

var (
	errMatch          = errors.New("match failed")
	errInvalidPattern = errors.New("invalid pattern")
)

// MatchString matches src and appends key/value pairs to dst
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
			if name := d.name; name != "" {
				matches = append(matches, name, tail)
			}
			return matches, nil
		default:
			match, ss, err := p.match(tail, seek, d.quote)
			if err != nil {
				return dst, err
			}
			if name := d.name; name != "" {
				matches = append(matches, name, match)
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
