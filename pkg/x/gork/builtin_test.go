package gork

import (
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
)

var patternTests = [][]string{
	{"DATA", "", ""},
	{"WORD", " foo_bar.", "foo_bar"},
	{"WORD", " "},
	{"NOTSPACE", "foo ", "foo"},
	{"NOTSPACE", " foo", "foo"},
	{"NOTSPACE", "foo\t", "foo"},
	{"NOTSPACE", "\tfoo", "foo"},
	{"NOTSPACE", "\t  foo", "foo"},
	{"QUOTEDSTRING", `"foo"`, `"foo"`},
	{"QS", `"foo"`, `"foo"`},
	{"QS", `"foo" "`, `"foo"`},
	{"QS", `"foo \"bar\""`, `"foo \"bar\""`},
	{"QUOTEDSTRING", `'foo'`, `'foo'`},
	{"QS", `'foo'`, `'foo'`},
	{"QS", `'foo' '`, `'foo'`},
	{"QS", `'foo \'bar\''`, `'foo \'bar\''`},
	{"SPACE", "  foo", "  "},
	{"SPACE", "\tfoo", "\t"},
	{"SPACE", ".foo", ""},
	{"INT", "42", "42"},
	{"INT", "+42", "+42"},
	{"INT", "-42", "-42"},
	{"INT", "-42.0", "-42"},
	{"INT", "0", "0"},
	{"INT", "01", "01"},
	{"INT", "001", "001"},
	{"IP", "127.0.0.1", "127.0.0.1"},
	{"IP", "0.0.0.0", "0.0.0.0"},
	{"IP", "300.0.0.0"},
	{"IP", "255.0.0.0", "255.0.0.0"},
	{"IP", "255.255.255.255", "255.255.255.255"},
	{"IP", "255.2555.255.255"},
	{"IP", "300.0"},
	{"IP", "2001:0db8:0000:0000:0000:8a2e:0370:7334", "2001:0db8:0000:0000:0000:8a2e:0370:7334"},
	{"IP", "2001:db8::8a2e:370:7334", "2001:db8::8a2e:370:7334"},
	{"MONTHDAY", "01", "01"},
	{"MONTHDAY", "31", "31"},
	{"MONTHDAY", "10", "10"},
	{"MONTH", "/Oct", "Oct"},
	{"YEAR", "2000", "2000"},
	{"TIME", "13:55:36", "13:55:36"},
	{"TZOFFSET", "-0700", "-0700"},
	{"HTTPDATE", "10/Oct/2000:13:55:36 -0700", "10/Oct/2000:13:55:36 -0700"},

}
func TestBuiltinPatterns(t *testing.T) {
	assert := require.New(t)
	env := Env{}
	patterns, err := ReadPatterns(strings.NewReader(BuiltinPatterns))
	assert.NoError(err)
	assert.NoError(env.SetMap(patterns))
	numTests := map[string]int{}
	for _, tc := range patternTests {
		name, input, expect := tc[0], tc[1], tc[2:]
		t.Run(name + "_" + input, func (t *testing.T) {
			assert := require.New(t)
			src := name
			if !strings.Contains(src, "%{") {
				src = "%{" + src + ":actual}"
				if len(expect) == 1 {
					expect = []string{"actual", expect[0]}
				}
			}
			pattern, err := env.Compile(src)
			assert.NoError(err)
			matches, err := pattern.MatchString(nil, input)
			assert.NoError(err)
			if len(expect) == 0 {
				expect = nil
			}
			assert.Equal(expect, matches, "match %q failed", name)
			numTests[name] += 1
		})
	}
	for name := range patterns {
		if numTests[name] == 0 {
			t.Logf("no tests for pattern %q", name)
		}
	}

}
