package fastmatch

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestMatchString(t *testing.T) {
	type testCase struct {
		Name    string
		Input   string
		Pattern string
		Matches []string
	}
	for _, tc := range []testCase{
		{"two fields", "foo bar", "%{foo} %{bar}", []string{"foo", "bar"}},
		{"two fields prefix", "LOG: foo bar", "LOG: %{foo} %{bar}", []string{"foo", "bar"}},
		{"no match", "foo", "%{foo} %{bar}", nil},
		{"two fields empty last", "foo ", "%{foo} %{bar}", []string{"foo", ""}},
		{"two fields empty first", " bar", "%{foo} %{bar}", []string{"", "bar"}},
		{"two fields quoted first", `"\"foo\" bar" baz`, `"%{foo}" %{bar}`, []string{`"foo" bar`, "baz"}},
		{"two fields quoted last", `foo "\"bar\"baz"`, `%{foo} "%{bar}"`, []string{`foo`, `"bar"baz`}},
		{"two fields one empty", "foo bar", "%{foo} %{}", []string{"foo"}},
		{"common log",
			"127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] \"GET /apache_pb.gif HTTP/1.0\" 200 2326",
			`%{remote_ip} %{identity} %{user} [%{timestamp}] "%{method} %{request_uri} %{protocol}" %{status} %{bytes_sent}`,
			[]string{"127.0.0.1", "-", "frank", "10/Oct/2000:13:55:36 -0700", "GET", "/apache_pb.gif", "HTTP/1.0", "200", "2326"},
		},
	} {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			assert := require.New(t)
			p, err := Compile(tc.Pattern)
			assert.NoError(err)
			match, err := p.MatchString(nil, tc.Input)
			assert.Equal(tc.Matches != nil, err == nil)
			assert.Equal(tc.Matches, match, "invalid match\nexpect: %v\nactual: %v", tc.Matches, match)
		})
	}
}

func TestPattern_match(t *testing.T) {
	type testCase struct {
		Name      string
		Input     string
		Delimiter string
		Quote     byte
		Tail      string
		Match     string
		WantErr   bool
	}
	for _, tc := range []testCase{
		{"simple", "foo ", " ", 0, "", "foo", false},
		{"double quote", `foo \"bar\"" `, "\" ", '"', "", `foo "bar"`, false},
		{"single quote", `foo \'bar\'' `, "' ", '\'', "", `foo 'bar'`, false},
	} {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			assert := require.New(t)
			p := Pattern{}
			match, tail, err := p.match(tc.Input, tc.Delimiter, tc.Quote)
			if tc.WantErr {
				assert.Error(err)
				assert.Empty(match)
				assert.Equal(tc.Input, tail)
				return
			}
			assert.NoError(err)
			assert.Equal(tc.Match, match)
			assert.Equal(tc.Tail, tail)
		})
	}
}
