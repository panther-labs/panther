package slacklogs

import "github.com/panther-labs/panther/internal/log_analysis/log_processor/logtypes"

func LogTypes() logtypes.Group {
	return logTypes
}

// We use an immediately called function to register the time decoder before building the logtype entries.
var logTypes = func() logtypes.Group {
	return logtypes.Must("Slack",
		logtypes.ConfigJSON{
			Name: TypeAuditLogs,
			// nolint:lll
			Description:  "Slack audit logs provide a view of the actions users perform in an Enterprise Grid organization.",
			ReferenceURL: "https://api.slack.com/enterprise/audit-logs",
			NewEvent: func() interface{} {
				return &AuditLog{}
			},
		},

		logtypes.ConfigJSON{
			Name: TypeAccessLogs,
			// nolint:lll
			Description:  "Access logs for users on a Slack workspace.",
			ReferenceURL: "https://api.slack.com/methods/team.accessLogs",
			NewEvent: func() interface{} {
				return &AccessLog{}
			},
		},
	)
}()
