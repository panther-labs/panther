package awsglue

import (
	jsoniter "github.com/json-iterator/go"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog/tcodec"
	"strings"
	"time"
)

// TODO: [awsglue] Add more mappings of invalid Athena field name characters here
// NOTE: The mapping should be easy to remember (so no ASCII code etc) and complex enough
// to avoid possible conflicts with other fields.
var fieldNameReplacer = strings.NewReplacer(
	"@", "_at_sign_",
	",", "_comma_",
	"`", "_backtick_",
	"'", "_apostrophe_",
)

func RewriteFieldName(name string) string {
	result := fieldNameReplacer.Replace(name)
	if result == name {
		return name
	}
	return strings.Trim(result, "_")
}

const (
	TimestampLayout     = `2006-01-02 15:04:05.000000000`
	TimestampLayoutJSON = `"` + TimestampLayout + `"`
)

func NewTimestampEncoder() tcodec.TimeEncoder {
	return &timestampEncoder{}
}

var _ tcodec.TimeEncoder = (*timestampEncoder)(nil)

type timestampEncoder struct{}

func (*timestampEncoder) EncodeTime(tm time.Time, stream *jsoniter.Stream) {
	if tm.IsZero() {
		stream.WriteNil()
		return
	}
	buf := stream.Buffer()
	buf = tm.UTC().AppendFormat(buf, TimestampLayoutJSON)
	stream.SetBuffer(buf)
}
