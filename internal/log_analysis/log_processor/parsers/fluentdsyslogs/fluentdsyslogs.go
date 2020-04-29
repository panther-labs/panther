package fluentdsyslogs

import "github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"

func init() {
	parsers.MustRegister(LogTypeRFC3164, LogTypeRFC5424)
}
