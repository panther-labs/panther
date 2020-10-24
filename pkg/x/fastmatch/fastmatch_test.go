package fastmatch

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestMatchString(t *testing.T) {
	type testCase struct {
		Name string
		Input string
		Pattern string
		Matches []string
	}
	for _, tc := range []testCase{
		{"two fields", "foo bar", "%{foo} %{bar}", []string{"foo", "bar"}},
		{"no match", "foo", "%{foo} %{bar}", nil},
		{"two fields", "foo ", "%{foo} %{bar}", []string{"foo", ""}},
		{"two fields", " bar", "%{foo} %{bar}", []string{"", "bar"}},
	}{
		tc := tc
		t.Run(tc.Name, func (t *testing.T) {
			assert := require.New(t)
			p, err := New(tc.Pattern)
			assert.NoError(err)
			match, ok := p.MatchString(nil, tc.Input)
			assert.Equal(tc.Matches != nil, ok)
			assert.Equal(tc.Matches, match, "invalid match\nexpect: %v\nactual: %v", tc.Matches, match)
		})
	}
}
