package fluentdsysloglogs

import (
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/testutil"
	"github.com/stretchr/testify/require"
)

func TestRFC5424(t *testing.T) {
	// nolint:lll
	log := `{"pri": 16, "host": "192.168.0.1", "ident": "fluentd", "pid": "11111", "msgid": "ID24224", "extradata": "[exampleSDID@20224 iut=\"3\" eventSource=\"Application\" eventID=\"11211\"]","message": "[error] Syslog test"}`

	expectedRFC5424 := &RFC5424{
		Priority:  aws.Uint8(16),
		Hostname:  aws.String("192.168.0.1"),
		Ident:     aws.String("fluentd"),
		ProcID:    aws.String("11111"),
		MsgID:     aws.String("ID24224"),
		ExtraData: aws.String("[exampleSDID@20224 iut=\"3\" eventSource=\"Application\" eventID=\"11211\"]"),
		Message:   aws.String("[error] Syslog test"),
	}

	// panther fields
	expectedRFC5424.PantherLogType = aws.String("Fluentd.Syslog5424")
	checkRFC5424(t, log, expectedRFC5424)
}

func TestRFC5424TypeType(t *testing.T) {
	parser := &RFC5424Parser{}
	require.Equal(t, "Fluentd.Syslog5424", parser.LogType())
}

func checkRFC5424(t *testing.T, log string, expectedRFC5424 *RFC5424) {
	parser := &RFC5424Parser{}
	testutil.EqualPantherLog(t, expectedRFC5424.Log(), parser.Parse(log))
}
