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
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"
)

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
	Event pantherlog.String `json:"event" validate:"required" description:"Event type"`
	Code  pantherlog.String `json:"code" validate:"required" description:"Event code"`
	Time  pantherlog.Time   `json:"time" tcodec:"rfc3339" validate:"required" event_time:"true" description:"Event timestamp"`
	UID   pantherlog.String `json:"uid" validate:"required" description:"Event unique id"`

	User      pantherlog.String `json:"user" description:"Teleport user name (event type is 'user.login')"`
	Namespace pantherlog.String `json:"namespace" description:"Server namespace. This field is reserved for future use."`
	ServerID  pantherlog.String `json:"server_id" description:"Unique server ID."`
	SessionID pantherlog.String `json:"sid" panther:"trace_id" description:"Session ID. Can be used to replay the session."`
	EventID   pantherlog.Int32  `json:"ei" description:"Event numeric id"`

	Login         pantherlog.String `json:"login" description:"OS login"`
	AddressLocal  pantherlog.String `json:"addr.local" panther:"net_addr" description:"Address of the SSH node"`
	AddressRemote pantherlog.String `json:"addr.remote" panther:"net_addr" description:"Address of the connecting client (user)"`
	TerminalSize  pantherlog.String `json:"size" description:"Size of terminal"`

	// auth event type fields
	Success pantherlog.Bool   `json:"success" description:"Authentication success (if event type is 'auth')"`
	Error   pantherlog.String `json:"error" description:"Authentication error (event type is 'auth')"`

	// exec event type fields
	Command   pantherlog.String `json:"command" description:"Command that was executed (event type is 'exec')"`
	ExitCode  pantherlog.Int32  `json:"exitCode" description:"Exit code of the command (event type is 'exec')"`
	ExitError pantherlog.String `json:"exitError" description:"Exit error of the command (event type is 'exec')"`

	// session.command type fields
	PID        pantherlog.Int64  `json:"pid" description:"Process id of command"`
	ParentPID  pantherlog.Int64  `json:"ppid" description:"Process id of the parent process"`
	CGroupID   pantherlog.Int64  `json:"cgroup_id" description:"Control group id"`
	ReturnCode pantherlog.Int32  `json:"return_code" description:"Return code of the command"`
	Program    pantherlog.String `json:"program" description:"Name of the command"`
	ArgV       []string          `json:"argv" description:"Arguments passed to command"`

	// scp event type fields
	Path   pantherlog.String `json:"path" description:"Executable path or SCP action target file path (scp, session.command)"`
	Len    pantherlog.Int64  `json:"len" description:"SCP target file size (scp)"`
	Action pantherlog.String `json:"action" description:"SCP action (scp)"`

	// user.login event type fields
	Method     pantherlog.String      `json:"method" description:"Login method used (user.login)"`
	Attributes *pantherlog.RawMessage `json:"attributes" description:"User login attributes (user.login)"`

	// user.create event type fields
	Roles     []string          `json:"roles" description:"Roles for the new user (user.create)"`
	Connector pantherlog.String `json:"connector" description:"Connector that created the user (user.create)"`
	Expires   pantherlog.Time   `json:"expires" tcodec:"rfc3339" description:"Expiration date "`

	// user.create, user.update, github.create
	Name pantherlog.String `json:"name" description:"Name of user or service (github.created, user.create, user.update)"`

	// session.data
	BytesSent     pantherlog.Int64 `json:"tx" description:"Number of bytes sent"`
	BytesReceived pantherlog.Int64 `json:"rx" description:"Number of bytes received"`

	// session.start
	ServerLabels   map[string]string `json:"server_labels" description:"Server labels"`
	ServerHostname pantherlog.String `json:"server_hostname" panther:"hostname" description:"Server hostname"`
	ServerAddress  pantherlog.String `json:"server_addr" panther:"net_addr" description:"Server hostname"`

	// session.end
	SessionStart      pantherlog.Time `json:"session_start" tcodec:"rfc3339" description:"Timestamp of session start"`
	SessionStop       pantherlog.Time `json:"session_stop" tcodec:"rfc3339" description:"Timestamp of session end"`
	Interactive       pantherlog.Bool `json:"interactive" description:"Whether the session was interactive"`
	EnhancedRecording pantherlog.Bool `json:"enhanced_recording" description:"Whether enhanced recording is enabled"`
	Participants      []string        `json:"participants" description:"Users that participated in the session"`

	// session.network
	DestinationAddress pantherlog.String `json:"dst_addr" panther:"ip" description:"Destination IP address"`
	SourceAddress      pantherlog.String `json:"src_addr" panther:"ip" description:"Source IP address"`
	DestinationPort    pantherlog.Uint16 `json:"dst_port" description:"Destination port"`
	Version            pantherlog.Int32  `json:"version" description:"Event version"`
}
