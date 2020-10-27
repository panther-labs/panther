package gork

import (
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
)

func TestMatchString(t *testing.T) {
	assert := require.New(t)
	env := New()
	src := `%{DATA:remote_ip} %{DATA:identity} %{DATA:user} \[%{HTTPDATE:timestamp}\] "%{DATA:method} %{DATA:request_uri} %{DATA:protocol}" %{DATA:status} %{DATA:bytes_sent}$`
	pattern, err := env.Compile(src)
	assert.NoError(err)
	input := "127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] \"GET /apache_pb.gif HTTP/1.0\" 200 2326"
	matches, err := pattern.MatchString(nil, input)
	assert.NoError(err)
	assert.Equal([]string{
		"remote_ip", "127.0.0.1",
		"identity", "-",
		"user", "frank",
		"timestamp", "10/Oct/2000:13:55:36 -0700",
		"method", "GET",
		"request_uri", "/apache_pb.gif",
		"protocol", "HTTP/1.0",
		"status", "200",
		"bytes_sent", "2326",
	}, matches)
}

func TestRecursive(t *testing.T) {
	assert := require.New(t)
	{
		env := Env{}
		patterns := `FOO %{FOO}`
		err := env.ReadPatterns(strings.NewReader(patterns))
		assert.Error(err)
		assert.Contains(err.Error(), "recursive")
	}
	{
		env := Env{}
		patterns := `
FOO %{BAR}
BAR %{FOO}`
		err := env.ReadPatterns(strings.NewReader(patterns))
		assert.Error(err)
		assert.Contains(err.Error(), "recursive")
	}
}

