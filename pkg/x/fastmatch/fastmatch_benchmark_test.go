package fastmatch_test

import (
	"github.com/panther-labs/panther/pkg/x/fastmatch"
	"testing"
)

func BenchmarkPattern_MatchString(b *testing.B) {
	input := "127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] \"GET /apache_pb.gif HTTP/1.0\" 200 2326"
	pattern := `%{remote_ip} %{identity} %{user} [%{timestamp}] "%{method} %{request_uri} %{protocol}" %{status} %{bytes_sent}`
	pat, err := fastmatch.Compile(pattern)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	matches := make([]string, 10)
	for i := 0; i < b.N; i++ {
		matches, err = pat.MatchString(matches[:0], input)
		if err != nil {
			b.Fatal(err)
		}
		if len(matches) != 18 {
			b.Fatal(matches)
		}
	}
}