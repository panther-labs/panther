package gork_test

import (
	"github.com/panther-labs/panther/pkg/x/gork"
	"testing"
)

func BenchmarkMatchString(b *testing.B) {

	env := gork.New()
	pattern := `%{NS:remote_ip} %{NS:identity} %{NS:user} \[%{HTTPDATE:timestamp}\] "%{NS:method} %{NS:request_uri} %{NS:protocol}" %{NS:status} %{NS:bytes_sent}`
	expr, err := env.Compile(pattern)
	if err != nil {
		b.Fatal(err)
	}
	input := "127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] \"GET /apache_pb.gif HTTP/1.0\" 200 2326"
	matches := make([]string, 10)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		matches, err = expr.MatchString(matches[:0], input)
		if err != nil {
			b.Fatal(err)
		}
		if len(matches) != 18 {
			b.Error(matches)
		}
	}

}
