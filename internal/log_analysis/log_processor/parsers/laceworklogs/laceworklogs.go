package laceworklogs

import (
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logtypes"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
)

func init() {
	logtypes.MustRegister(logtypes.Config{
		Name:         "Lacework.Events",
		Description:  LaceworkDesc,
		ReferenceURL: `https://www.lacework.com/platform-overview/`,
		Schema:       Lacework{},
		NewParser:    parsers.AdapterFactory(&LaceworkParser{}),
	})
}
