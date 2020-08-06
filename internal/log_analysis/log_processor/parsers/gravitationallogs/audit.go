package gravitationallogs

/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2020 Panther Labs Inc
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

import (
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logtypes"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog/null"
)

const LogTypePrefix = "Gravitational"

// TypeTeleportAudit registers and exports the logtype entry for Gravitational.TeleportAudit logs
var TypeTeleportAudit = logtypes.MustRegisterJSON(logtypes.Desc{
	Name:         LogTypePrefix + ".TeleportAudit",
	Description:  `Teleport logs events like successful user logins along with the metadata like remote IP address, time and the session ID.`,
	ReferenceURL: `https://gravitational.com/teleport/docs/admin-guide/#audit-log`,
}, func() interface{} {
	return &TeleportAudit{}
})

// TeleportAudit is a log event in a Teleport audit log file.
// NOTE: Each event type has a different mix of fields.
// nolint:lll,maligned
type TeleportAudit struct {
	// A (non-exhaustive) list of event types is:
	//
	//   * auth - Authentication attempt.
	//   * session.start - Started an interactive shell session.
	//   * session.end - An interactive shell session has ended.
	//   * session.join - A new user has joined the existing interactive shell session.
	//   * session.leave - A user has left the session.
	//   * session.disk - A list of files opened during the session. Requires Enhanced Session Recording.
	//   * session.network - A list of network connections made during the session. Requires Enhanced Session Recording.
	//   * session.data - A list of data transferred in a session
	//   * session.command - A list of commands ran during the session. Requires Enhanced Session Recording.
	//   * resize - Terminal has been resized.
	//   * user.create - A new user was created
	//   * user.login - A user logged into web UI or via tsh.
	//   * user.update - A user was updated
	//   * github.create - A user was created via github
	Event null.String `json:"event" validate:"required" description:"Event type"`
	Code  null.String `json:"code" validate:"required" description:"Event code"`
	Time  time.Time   `json:"time" tcodec:"rfc3339" validate:"required" panther:"event_time" description:"Event timestamp"`
	UID   null.String `json:"uid" validate:"required" description:"Event unique id"`

	User      null.String `json:"user" description:"Teleport user name (event type is 'user.login')"`
	Namespace null.String `json:"namespace" description:"Server namespace. This field is reserved for future use."`
	ServerID  null.String `json:"server_id" description:"Unique server ID."`
	SessionID null.String `json:"sid" panther:"trace_id" description:"Session ID. Can be used to replay the session."`
	EventID   null.Int32  `json:"ei" description:"Event numeric id"`

	Login         null.String `json:"login" description:"OS login"`
	AddressLocal  null.String `json:"addr.local" panther:"net_addr" description:"Address of the SSH node"`
	AddressRemote null.String `json:"addr.remote" panther:"net_addr" description:"Address of the connecting client (user)"`
	TerminalSize  null.String `json:"size" description:"Size of terminal"`

	// auth event type fields
	Success null.Bool   `json:"success" description:"Authentication success (if event type is 'auth')"`
	Error   null.String `json:"error" description:"Authentication error (event type is 'auth')"`

	// exec event type fields
	Command   null.String `json:"command" description:"Command that was executed (event type is 'exec')"`
	ExitCode  null.Int32  `json:"exitCode" description:"Exit code of the command (event type is 'exec')"`
	ExitError null.String `json:"exitError" description:"Exit error of the command (event type is 'exec')"`

	// session.command type fields
	PID        null.Int64  `json:"pid" description:"Process id of command"`
	ParentPID  null.Int64  `json:"ppid" description:"Process id of the parent process"`
	CGroupID   null.Int64  `json:"cgroup_id" description:"Control group id"`
	ReturnCode null.Int32  `json:"return_code" description:"Return code of the command"`
	Program    null.String `json:"program" description:"Name of the command"`
	ArgV       []string    `json:"argv" description:"Arguments passed to command"`

	// scp event type fields
	Path   null.String `json:"path" description:"Executable path or SCP action target file path (scp, session.command)"`
	Len    null.Int64  `json:"len" description:"SCP target file size (scp)"`
	Action null.String `json:"action" description:"SCP action (scp)"`

	// user.login event type fields
	Method     null.String          `json:"method" description:"Login method used (user.login)"`
	Attributes *jsoniter.RawMessage `json:"attributes" description:"User login attributes (user.login)"`

	// user.create event type fields
	Roles     []string    `json:"roles" description:"Roles for the new user (user.create)"`
	Connector null.String `json:"connector" description:"Connector that created the user (user.create)"`
	Expires   time.Time   `json:"expires" tcodec:"rfc3339" description:"Expiration date "`

	// user.create, user.update, github.create
	Name null.String `json:"name" description:"Name of user or service (github.created, user.create, user.update)"`

	// session.data
	BytesSent     null.Int64 `json:"tx" description:"Number of bytes sent"`
	BytesReceived null.Int64 `json:"rx" description:"Number of bytes received"`

	// session.start
	ServerLabels   map[string]string `json:"server_labels" description:"Sever labels"`
	ServerHostname null.String       `json:"server_hostname" panther:"hostname" description:"Server hostname"`
	ServerAddress  null.String       `json:"server_addr" panther:"net_addr" description:"Server hostname"`

	// session.end
	SessionStart      time.Time `json:"session_start" tcodec:"rfc3339" description:"Timestamp of session start"`
	SessionStop       time.Time `json:"session_stop" tcodec:"rfc3339" description:"Timestamp of session end"`
	Interactive       null.Bool `json:"interactive" description:"Whether the session was interactive"`
	EnhancedRecording null.Bool `json:"enhanced_recording" description:"Whether enhanced recording is enabled"`
	Participants      []string  `json:"participants" description:"Users that participated in the session"`
}
