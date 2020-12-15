package slacklogs

import "github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"

const TypeAccessLogs = "Slack.AccessLogs"

//nolint:lll
type AccessLog struct {
	UserID pantherlog.String `json:"user_id" validate:"required" description:"The id of the user accessing Slack."`
	UserName pantherlog.String `json:"username" description:"The username of the user accessing Slack."`
	DateFirst pantherlog.Time `json:"date_first" validate:"required" tcodec:"unix" description:"Unix timestamp of the first access log entry for this user, IP address, and user agent combination."`
	DateLast pantherlog.Time `json:"date_last" validate:"required" tcodec:"unix" event_time:"true" description:"Unix timestamp of the most recent access log entry for this user, IP address, and user agent combination."`
	Count pantherlog.Int32 `json:"count" validate:"required" description:"The total number of access log entries for that combination."`
	IP pantherlog.String `json:"ip" validate:"required" panther:"ip" description:"The IP address of the device used to access Slack."`
	UserAgent pantherlog.String `json:"user_agent" description:"The reported user agent string from the browser or client application."`
	ISP pantherlog.String `json:"isp" description:"Best guess at the internet service provider owning the IP address."`
	Country pantherlog.String `json:"country" description:"Best guesses on where the access originated, based on the IP address."`
	Region pantherlog.String `json:"region" description:"Best guesses on where the access originated, based on the IP address."`
}