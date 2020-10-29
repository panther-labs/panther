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
	// text to match at start of input
	prefix string
	// the rest of the fields
	delimiters []delimiter
	// non-empty field names
	fields []string
	// reusable buffer for unquoting stings
	scratch []rune
}

type delimiter struct {
	// delimiter to match at end of field
	match string
	// name of the field
	name string
	// if set to `'` or `"` we should look out for escaping quotes
	quote byte
}

var splitFields = regexp.MustCompile(`%{\s*(?P<tag>[^}]*)\s*}`)

// Compile compiles a pattern.
// Patterns use `%{` and `}` delimiters to define the placing of fields in a string.
// Two consecutive fields *must* have some delimiter text between them for the pattern to be valid.
// For example:
// `%{foo} %{bar}` is valid
// `%{foo}%{bar}` is not valid
// Pattern names currently have no restrictions apart from that they cannot contain `}`.
// Please be conservative with your field names as that might change in the future...
func Compile(pattern string) (*Pattern, error) {
	tags := splitFields.FindAllStringSubmatch(pattern, -1)
	if tags == nil {
		// pattern contains no fields
		return nil, errInvalidPattern
	}
	matchDelimiters := splitFields.Split(pattern, -1)
	// First delimiter is a prefix at the start of text.
	prefix, matchDelimiters := matchDelimiters[0], matchDelimiters[1:]
	delimiters := make([]delimiter, 0, len(tags))
	fields := make([]string, 0, len(tags))
	last := len(matchDelimiters) - 1
	// Keep not of the previous delimiter for auto detecting quotes
	prev := prefix
	for i, m := range matchDelimiters {
		// Do not allow empty delimiters unless it's the last field
		if i < last && m == "" {
			return nil, errInvalidPattern
		}
		tag := tags[i][1]
		d := delimiter{}
		// Autodetects quotes
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

// Returns the number of non-empty field names
func (p *Pattern) NumFields() int {
	return len(p.fields)
}

// Returns a non-empty field name by index.
// Panics if index is out of range.
// Use in conjunction with NumFields to check the range
func (p *Pattern) FieldName(i int) string {
	return p.fields[i]
}

var (
	errMatch          = errors.New("match failed")
	errInvalidPattern = errors.New("invalid pattern")
)

// MatchString matches src and appends key/value pairs to dst.
// Note that if an error occurs the original slice is returned.
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
		// Only trigger quoted match if there is an escaping slash (`\\`) somewhere ahead
		return p.matchQuoted(src, delim, quote)
	}
	// Fast match case
	if pos := strings.Index(src, delim); 0 <= pos && pos < len(src) {
		// Split match part from rest of text
		match, tail = src[:pos], src[pos:]
		// Consume the delimiter
		tail = tail[len(delim):]
		return match, tail, nil
	}
	return "", src, errMatch
}

// matchQuoted matches fields while escaping quotes in a single pass.
// It properly handles unicode multibytes so it is much slower than non-quoted match.
func (p *Pattern) matchQuoted(src, delim string, quote byte) (match, tail string, err error) {
	tail = src
	// Copy and reset scratch slice header to stack
	scratch := p.scratch[:0]
	// Go over each unicode character in src until we reach the quote
	for len(tail) > 0 && tail[0] != quote {
		// This reads a unicode character properly handling `\\` escapes
		c, _, ss, err := strconv.UnquoteChar(tail, quote)
		if err != nil {
			p.scratch = scratch // Restore scratch buffer
			return "", src, err
		}
		// Gather all characters
		scratch = append(scratch, c)
		// Advance the loop
		tail = ss
	}
	p.scratch = scratch // Restore scratch buffer
	// Check that the rest for the text starts with delimiter
	if strings.HasPrefix(tail, delim) {
		// Match found, consume the delimiter and return
		return string(scratch), strings.TrimPrefix(tail, delim), nil
	}
	return "", src, errMatch
}
