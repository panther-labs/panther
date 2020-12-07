package logstream

import (
	"bytes"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestLineStream(t *testing.T) {
	type testCase struct {
		Name    string
		Input   []byte
		Expect  []string
		WantErr bool
	}
	for _, tc := range []testCase{
		{
			Name:    "Binary data",
			Input:   []byte{0, 0, 0, 0, 0, 0, 0, 0},
			Expect:  nil,
			WantErr: true,
		},
		{
			Name:  "Single line",
			Input: []byte("foo bar baz"),
			Expect: []string{
				"foo bar baz",
			},
			WantErr: false,
		},
		{
			Name: "Two lines",
			Input: []byte(`foo bar baz
foo bar baz`),
			Expect: []string{
				"foo bar baz",
				"foo bar baz",
			},
			WantErr: false,
		},
		{
			Name:    "Long Line",
			Input:   []byte(longLine),
			Expect:  []string{longLine},
			WantErr: false,
		},
	} {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			r := bytes.NewReader(tc.Input)
			s := NewLineStream(r, 16)
			var result []string
			for {
				entry := s.Next()
				if entry == nil {
					break
				}
				result = append(result, string(entry))
			}
			err := s.Err()
			if tc.WantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.Expect, result)
		})

	}

}

const longLine = "foo bar baz foo bar baz foo bar baz foo bar baz foo bar baz foo bar baz foo bar baz foo bar baz " +
	"foo bar baz foo bar baz foo bar baz foo bar baz foo bar baz foo bar baz foo bar baz foo bar baz " +
	"foo bar baz foo bar baz foo bar baz foo bar baz foo bar baz foo bar baz foo bar baz foo bar baz " +
	"foo bar baz foo bar baz foo bar baz foo bar baz foo bar baz foo bar baz foo bar baz foo bar baz " +
	"foo bar baz foo bar baz foo bar baz foo bar baz foo bar baz foo bar baz foo bar baz foo bar baz " +
	"foo bar baz foo bar baz foo bar baz foo bar baz foo bar baz foo bar baz foo bar baz foo bar baz "
