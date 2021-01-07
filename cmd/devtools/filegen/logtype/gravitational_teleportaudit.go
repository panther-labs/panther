package logtype

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
	"io"
	"time"

	"github.com/google/uuid"
	jsoniter "github.com/json-iterator/go"

	"github.com/panther-labs/panther/cmd/devtools/filegen"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/gravitationallogs"
)

const (
	GravitationalTeleportAuditName = "Gravitational.TeleportAudit"
)

type GravitationalTeleportAudit struct {
	filegen.JSON
}

func NewGravitationalTeleportAudit() *GravitationalTeleportAudit {
	return &GravitationalTeleportAudit{
		JSON: *filegen.NewJSON(),
	}
}

func (ga *GravitationalTeleportAudit) LogType() string {
	return GravitationalTeleportAuditName
}

func (ga *GravitationalTeleportAudit) Filename(_ time.Time) string {
	return uuid.New().String()
}

func (ga *GravitationalTeleportAudit) NewFile(hour time.Time) *filegen.File {
	f := filegen.NewFile(ga, hour)
	var event gravitationallogs.TeleportAudit
	for i := 0; i < ga.Rows(); i++ {
		ga.fillEvent(&event, hour)
		ga.writeEvent(&event, f)
	}
	f.Close()
	return f
}

func (*GravitationalTeleportAudit) fillEvent(event *gravitationallogs.TeleportAudit, hour time.Time) {
	event.Event = filegen.ToPantherString(filegen.StringChoice(gravitationalTeleportAuditEventTypes))
	event.Code = filegen.ToPantherString(filegen.String(8))
	event.Time = hour
	event.UID = filegen.ToPantherString(filegen.String(16))

	event.User = filegen.ToPantherString(filegen.String(8))
	event.Namespace = filegen.ToPantherString(filegen.String(8))
	event.ServerID = filegen.ToPantherString(filegen.String(8))
	event.SessionID = filegen.ToPantherString(filegen.String(16))
	event.EventID = filegen.ToPantherInt32(filegen.Int32())

	event.Login = filegen.ToPantherString(filegen.String(8))
	event.AddressLocal = filegen.ToPantherString(filegen.IP())
	event.AddressRemote = filegen.ToPantherString(filegen.IP())
	event.TerminalSize = filegen.ToPantherString(filegen.String(8))

	switch event.Event.Value {
	case "auth":
		event.Success = filegen.ToPantherBool(filegen.Bool())
		if !event.Success.Value {
			event.Error = filegen.ToPantherString(filegen.String(8))
		}
	case "exec":
		event.Command = filegen.ToPantherString(filegen.String(16))
		event.ExitCode = filegen.ToPantherInt32(filegen.Int32())
		event.ExitError = filegen.ToPantherString(filegen.String(8))
	case "session.command":
		event.PID = filegen.ToPantherInt64(filegen.Int64())
		event.ParentPID = filegen.ToPantherInt64(filegen.Int64())
		event.CGroupID = filegen.ToPantherInt64(filegen.Int64())
		event.ReturnCode = filegen.ToPantherInt32(filegen.Int32())
		event.Program = filegen.ToPantherString(filegen.String(16))
		event.ArgV = filegen.StringSlice(8, 3)
	case "scp":
		event.Path = filegen.ToPantherString(filegen.String(16))
		event.Len = filegen.ToPantherInt64(filegen.Int64())
		event.Action = filegen.ToPantherString(filegen.String(8))
	case "user.login":
		// event.Attributes *pantherlog.RawMessage `json:"attributes" description:"User login attributes (user.login)"`
		event.Method = filegen.ToPantherString(filegen.String(8))
	case "user.create":
		event.Roles = filegen.StringSlice(8, 3)
		event.Connector = filegen.ToPantherString(filegen.String(8))
		event.Expires = hour.Add(time.Minute * time.Duration(filegen.Intn(30)))
		event.Name = filegen.ToPantherString(filegen.String(8))
	case "user.update", "github.create":
		event.Name = filegen.ToPantherString(filegen.String(8))
	}

	// session.data
	event.BytesSent = filegen.ToPantherInt64(filegen.Int64())
	event.BytesReceived = filegen.ToPantherInt64(filegen.Int64())

	// session.start
	// event.ServerLabels   map[string]string `json:"server_labels" description:"Server labels"`
	event.ServerHostname = filegen.ToPantherString(filegen.String(8))
	event.ServerAddress = filegen.ToPantherString(filegen.IP())

	// session.end
	event.SessionStart = hour.Add(time.Minute * time.Duration(filegen.Intn(30)))
	event.SessionStop = event.SessionStart.Add(time.Second)
	event.Interactive = filegen.ToPantherBool(filegen.Bool())
	event.EnhancedRecording = filegen.ToPantherBool(filegen.Bool())
	event.Participants = filegen.StringSlice(8, 3)

	// session.network
	event.DestinationAddress = filegen.ToPantherString(filegen.IP())
	event.SourceAddress = filegen.ToPantherString(filegen.IP())
	event.DestinationPort = filegen.ToPantherUint16(filegen.Uint16())
	event.Version = filegen.ToPantherInt32(filegen.Int32())
}

func (ga *GravitationalTeleportAudit) writeEvent(event *gravitationallogs.TeleportAudit, w io.Writer) {
	eventJSON, err := jsoniter.Marshal(event)
	if err != nil {
		panic(err)
	}
	_, err = w.Write(eventJSON)
	if err != nil {
		panic(err)
	}
	_, err = w.Write(ga.EndOfLine())
	if err != nil {
		panic(err)
	}
}

var (
	gravitationalTeleportAuditEventTypes = []string{
		"auth", //   * auth - Authentication attempt.
		"exec",
		"scp",
		"session.start",   //   * session.start - Started an interactive shell session.
		"session.end",     //   * session.end - An interactive shell session has ended.
		"session.join",    //   * session.join - A new user has joined the existing interactive shell session.
		"session.leave",   //   * session.leave - A user has left the session.
		"session.disk",    //   * session.disk - A list of files opened during the session. Requires Enhanced Session Recording.
		"session.network", //   * session.network - A list of network connections made during the session. Requires Enhanced Session Recording.
		"session.data",    //   * session.data - A list of data transferred in a session
		"session.command", //   * session.command - A list of commands ran during the session. Requires Enhanced Session Recording.
		"resize",          //   * resize - Terminal has been resized.
		"user.create",     //   * user.create - A new user was created
		"user.login",      //   * user.login - A user logged into web UI or via tsh.
		"user.update",     //   * user.update - A user was updated
		"github.create",   //   * github.create - A user was created via github
	}
)
