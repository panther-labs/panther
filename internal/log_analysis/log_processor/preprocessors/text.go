package preprocessors

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
	"io"
	"strings"

	jsoniter "github.com/json-iterator/go"
	"github.com/valyala/fasttemplate"
)

type stringMatcher func(dst []string, src string) ([]string, error)

type matchTextPreprocessor struct {
	match        stringMatcher
	skipLines    int
	skipPrefix   string
	expandFields map[string]*fasttemplate.Template
	emptyValues  []string
	matches      []string
	buffer       []byte
	stream       *jsoniter.Stream
	trimSpace    bool
}

func (p *matchTextPreprocessor) PreProcessLog(log string) (string, error) {
	if p.skipLines > 0 {
		p.skipLines--
		return "", nil
	}
	if prefix := p.skipPrefix; prefix != "" && len(prefix) <= len(log) && log[:len(prefix)] == prefix {
		return "", nil
	}
	matches, err := p.match(p.matches[:0], log)
	if err != nil {
		return "", err
	}
	// trim spaces before we omit empty values
	if p.trimSpace {
		trimSpacesInPlace(matches)
	}
	// omit empty values before we expand fields
	if len(p.emptyValues) > 0 {
		matches = omitValues(matches[:0], matches, p.emptyValues)
	}
	if p.expandFields != nil {
		for key, tpl := range p.expandFields {
			p.buffer = expandFieldTemplate(p.buffer[:0], matches, tpl)
			if value := string(p.buffer); value != "" && !contains(p.emptyValues, value) {
				matches = append(matches, key, string(p.buffer))
			}
		}
	}
	writeFieldsJSON(p.stream, matches)
	// Reuse buffer
	p.matches = matches
	// allocation unavoidable here as long as we use string for log entries
	return string(p.stream.Buffer()), nil
}

// writes key/value pairs as JSON to stream
func writeFieldsJSON(stream *jsoniter.Stream, fields []string) {
	var key, value string
	stream.WriteObjectStart()
	// we use an if for the first pair to handle `,` in JSON efficiently
	if len(fields) >= 2 {
		// `len(fields) >= 2` elides bounds checks in the compiler if the assignment is in a single line
		key, value, fields = fields[0], fields[1], fields[2:]
		stream.WriteObjectField(key)
		stream.WriteString(value)
		// this is the fastest way to go through the slice in pairs.
		for len(fields) >= 2 {
			// `len(fields) >= 2` elides bounds checks in the compiler if the assignment is in a single line
			key, value, fields = fields[0], fields[1], fields[2:]
			// writes `,`
			stream.WriteMore()
			stream.WriteObjectField(key)
			stream.WriteString(value)
		}
	}
	stream.WriteObjectEnd()
}

// appends key/value pairs to dst, reading from src and skipping the ones where value is omit
// to omit fields 'in-place' use src[:0] as dst
func omitValues(dst, src, omit []string) []string {
	var key, value string
	// this is the fastest way to go through the slice in pairs.
loopPairs:
	for len(src) >= 2 {
		// `len(fields) >= 2` elides bounds checks in the compiler if the assignment is in a single line
		key, value, src = src[0], src[1], src[2:]
		for _, omit := range omit {
			if value == omit {
				continue loopPairs
			}
		}
		dst = append(dst, key, value)
	}
	return dst
}

func contains(values []string, seek string) bool {
	for _, value := range values {
		if seek == value {
			return true
		}
	}
	return false
}

type appendWriter struct {
	buffer []byte
}

func (w *appendWriter) Write(p []byte) (int, error) {
	w.buffer = append(w.buffer, p...)
	return len(p), nil
}

// expands a template using key/value pairs
// missing keys are replaced with empty string
// the template tags must have no space surrounding them (use normalizeTemplate)
func expandFieldTemplate(dst []byte, fields []string, tpl *fasttemplate.Template) []byte {
	w := appendWriter{
		buffer: dst,
	}
	_, _ = tpl.ExecuteFunc(&w, func(_ io.Writer, tag string) (int, error) {
		if value, ok := seekFieldValue(fields, tag); ok {
			// skip w writing directly onto the buffer
			w.buffer = append(w.buffer, value...)
			return len(value), nil
		}
		return 0, nil
	})
	return w.buffer
}

// finds a value in a key/value pairs slice
func seekFieldValue(fields []string, seek string) (string, bool) {
	var key, value string
	// this is the fastest way to go through the slice in pairs.
	for len(fields) >= 2 {
		// `len(fields) >= 2` elides bounds check in the compiler if the assignment is in a single line
		key, value, fields = fields[0], fields[1], fields[2:]
		if key == seek {
			return value, true
		}
	}
	return "", false
}

// trims space surrounding values in a key/value pairs slice in-place
func trimSpacesInPlace(fields []string) {
	for i := 1; 1 <= i && i < len(fields); i += 2 {
		fields[i] = strings.TrimSpace(fields[i])
	}
}

// compiles templates removing space surrounding tags
func compileFieldTemplates(src map[string]string) map[string]*fasttemplate.Template {
	if len(src) == 0 {
		return nil
	}
	out := make(map[string]*fasttemplate.Template, len(src))
	for name, src := range src {
		tpl := fasttemplate.New(src, "%{", "}")
		// trim spaces in template tags
		tpl = normalizeTemplate("%{", "%}", tpl)
		out[name] = tpl
	}
	return out
}

// trim spaces in template tags
func normalizeTemplate(start, end string, tpl *fasttemplate.Template) *fasttemplate.Template {
	normalized := tpl.ExecuteFuncString(func(w io.Writer, tag string) (int, error) {
		tag = start + strings.TrimSpace(tag) + end
		return w.Write([]byte(tag))
	})
	return fasttemplate.New(normalized, start, end)
}

func buildJSONStream() *jsoniter.Stream {
	return jsoniter.NewStream(jsoniter.ConfigDefault, nil, 4096)
}
