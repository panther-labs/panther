package crowdstrikelogs

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

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logtypes"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog/null"
)

// nolint:lll
var (
	TypeProcessRollup2 = mustBuild(logtypes.ConfigJSON{
		Name:         TypePrefix + ".ProcessRollup2",
		Description:  `This event (often called "PR2" for short) is generated for a process that is running or has finished running on a host and contains information about that process.`,
		ReferenceURL: `-`,
		NewEvent:     func() interface{} { return &ProcessRollup2{} },
	})

	TypeSyntheticProcessRollup2 = mustBuild(logtypes.ConfigJSON{
		Name: TypePrefix + ".SyntheticProcessRollup2",
		// TODO - what should this description be?
		Description:  `A synthetic version of the process rollup (PR2) event`,
		ReferenceURL: `-`,
		NewEvent:     func() interface{} { return &SyntheticProcessRollup2{} },
	})
)

// nolint:lll
type ProcessRollup2 struct {
	EventSimpleName null.String `json:"event_simpleName" validate:"required,eq=ProcessRollup2" description:"Event name"`

	BaseEvent

	TargetProcessID  null.Int64  `json:"TargetProcessId" description:"The unique ID of a target process"`
	SourceProcessID  null.Int64  `json:"SourceProcessId" description:"The unique ID of creating process."`
	SourceThreadID   null.Int64  `json:"SourceThreadId" description:"The unique ID of thread from creating process."`
	ParentProcessID  null.Int64  `json:"ParentProcessId" description:"The unique ID of the parent process."`
	ImageFileName    null.String `json:"ImageFileName" description:"The full path to an executable (PE) file. The context of this field provides more information as to its meaning. For ProcessRollup2 events, this is the full path to the main executable for the created process"`
	CommandLine      null.String `json:"CommandLine" description:"The command line used to create this process. May be empty in some circumstances"`
	RawProcessID     null.Int64  `json:"RawProcessId" description:"The operating system’s internal PID. For matching, use the UPID fields which guarantee a unique process identifier"`
	ProcessStartTime time.Time   `json:"ProcessStartTime" tcodec:"unix" description:"The time the process began in UNIX epoch time (in decimal, non-hex format)."`
	ProcessEndTime   time.Time   `json:"ProcessEndTime" tcodec:"unix" description:"The time the process finished (in decimal, non-hex format)."`
	SHA256HashData   null.String `json:"SHA256HashData" panther:"sha256" description:"The SHA256 hash of a file. In most cases, the hash of the file referred to by the ImageFileName field."`
	SHA1HashData     null.String `json:"SHA1HashData" panther:"sha1" description:"The SHA1 hash of a file"`
	MD5HashData      null.String `json:"MD5HashData" panther:"md5" description:"The MD5 hash of a file"`

	// Windows only
	ImageSubsystem                     null.String `json:"ImageSubsystem" description:"Subsystem of the image filename (Windows only)"`
	UserSID                            null.String `json:"UserSid" description:"The User Security Identifier (UserSID) of the user who executed the command. A UserSID uniquely identifies a user in a system. (Windows only)"`
	AuthenticationID                   null.String `json:"AuthenticationId" description:"The authentication identifier (Windows only)" `
	IntegrityLevel                     null.String `json:"IntegrityLevel" description:"The integrity level (Windows only)" `
	ProcessCreateFlags                 null.String `json:"ProcessCreateFlags" description:"Captured flags from original process create. This is a bitfield. (Windows only)"`
	ProcessParameterFlags              null.String `json:"ProcessParameterFlags" description:"Flags from the ‘NtCreateUserProcess’ API. This bitfield includes data like if DLL redirection is enabled. (Windows only)"`
	ProcessSXSFlags                    null.String `json:"ProcessSxsFlags" description:"Flags from the communications path with the Windows Subsystem Process. This bitfield includes data like if there’s a manifest and if it’s local or not. (Windows only)"`
	ParentAuthenticationID             null.String `json:"ParentAuthenticationId" description:"The authentication identifier for the parent process (Windows only)" `
	TokenType                          null.String `json:"TokenType" description:"The token type (Windows only)"`
	SessionID                          null.String `json:"SessionId" description:"The id of the session (Windows only)"`
	WindowFlags                        null.String `json:"WindowFlags" description:"Flags from the window (Windows only)"`
	ShowWindowFlags                    null.String `json:"ShowWindowFlags" description:"Window visibility flags (Windows only)"`
	WindowStartingPositionHorizontal   null.Int64  `json:"WindowStartingPositionHorizontal" description:"Start horizontal position of the process window (Windows only)"`
	WindowStartingPositionVertical     null.Int64  `json:"WindowStartingPositionVertical" description:"Start vertical position of the process window (Windows only)"`
	WindowStartingWidth                null.Int64  `json:"WindowStartingWidth" description:"Start width of the process window (Windows only)"`
	WindowStartingHeight               null.Int64  `json:"WindowStartingHeight" description:"Start height of the process window (Windows only)"`
	Desktop                            null.String `json:"Desktop" description:"The desktop of the process window (Windows only)"`
	WindowStation                      null.String `json:"WindowStation" description:"The  process window station (Windows only)"`
	WindowTitle                        null.String `json:"WindowTitle" description:"The title of the process window (WindowsOnly)"`
	LinkName                           null.String `json:"LinkName" description:"Link name (Windows only)"`
	ApplicationUserModelID             null.String `json:"ApplicationUserModelId" description:"Application user model id (WindowsOnly)"`
	CallStackModuleNames               null.String `json:"CallStackModuleNames" description:"Call stack module names (Windows only)"`
	CallStackModuleNamesVersion        null.String `json:"CallStackModuleNamesVersion" description:"Call stack module names version (Windows only)"`
	RPCClientProcessID                 null.String `json:"RpcClientProcessId" description:"RPC client process id (Windows only)"`
	CSAProcessDataCollectionInstanceID null.String `json:"CsaProcessDataCollectionInstanceId" description:"CSA process data collection instance id (Windows only)"`
	OriginalCommandLine                null.String `json:"OriginalCommandLine" description:"The original command line used to create this process (Windows only)"`
	CreateProcessType                  null.String `json:"CreateProcessType" description:"Create process type (Windows only)"`
	ZoneIdentifier                     null.String `json:"ZoneIdentifier" description:"Zone identifier (Windows only)"`
	HostURL                            null.String `json:"HostUrl" description:"Host URL (Windows only)"`
	ReferrerURL                        null.String `json:"ReferrerUrl" panther:"url" description:"Referrer URL (Windows only)"`
	GrandParent                        null.String `json:"GrandParent" description:"Grant parent (Windows only)"`
	BaseFileName                       null.String `json:"BaseFileName" description:"Base file name (Windows only)"`

	Tags               null.String `json:"Tags" description:"Process tags comma separated list (Windows, Mac)"`
	ParentBaseFileName null.String `json:"ParentBaseFileName" description:"Parent process base file name (Windows, Mac)"`
	ProcessGroupID     null.Int64  `json:"ProcessGroupId" description:"Process group id (Windows, Mac)"`
	UID                null.Int64  `json:"UID" description:"UID (Mac, Linux, Android)"`
	RUID               null.Int64  `json:"RUID" description:"RUID (Mac, Linux, Android)"`
	SVUID              null.Int64  `json:"SVUID" description:"SVUID (Mac, Linux, Android)"`
	GID                null.Int64  `json:"GID" description:"GID (Mac, Linux, Android)"`
	RGID               null.Int64  `json:"RGID" description:"RGID (Mac, Linux, Android)"`
	SVGID              null.Int64  `json:"SVGID" description:"SVGID (Mac, Linux, Android)"`

	SessionProcessID null.Int64  `json:"SessionProcessId" description:"Session process id (Mac, Linux)"`
	MachOSubType     null.String `json:"MachOSubType" description:"MachOSubType (Mac only)"`

	TTYName        null.String `json:"TtyName" description:"TTY name (Linux only)"`
	OCIContainerID null.String `json:"OciContainerId" description:"OCI Container id (Linux only)"`

	// Android only
	SourceAndroidComponentName null.String `json:"SourceAndroidComponentName" description:"Source component name (Android only)"`
	TargetAndroidComponentName null.String `json:"TargetAndroidComponentName" description:"Target component name (Android only)"`
	TargetAndroidComponentType null.String `json:"TargetAndroidComponentType" description:"Target component type (Android only)"`
}

// nolint:lll
type SyntheticProcessRollup2 struct {
	EventSimpleName null.String `json:"event_simpleName" validate:"required,eq=SyntheticProcessRollup2" description:"event name"`

	ContextEvent
	TargetProcessID   null.Int64  `json:"TargetProcessId" description:"The unique ID of a target process"`
	SourceProcessID   null.Int64  `json:"SourceProcessId" description:"The unique ID of creating process."`
	SourceThreadID    null.Int64  `json:"SourceThreadId" description:"The unique ID of thread from creating process."`
	ParentProcessID   null.Int64  `json:"ParentProcessId" description:"The unique ID of the parent process."`
	ImageFileName     null.String `json:"ImageFileName" description:"The full path to an executable (PE) file. The context of this field provides more information as to its meaning. For ProcessRollup2 events, this is the full path to the main executable for the created process"`
	CommandLine       null.String `json:"CommandLine" description:"The command line used to create this process. May be empty in some circumstances"`
	RawProcessID      null.Int64  `json:"RawProcessId" description:"The operating system’s internal PID. For matching, use the UPID fields which guarantee a unique process identifier"`
	ProcessStartTime  time.Time   `json:"ProcessStartTime" tcodec:"unix" description:"The time the process began in UNIX epoch time (in decimal, non-hex format)."`
	ProcessEndTime    time.Time   `json:"ProcessEndTime" tcodec:"unix" description:"The time the process finished (in decimal, non-hex format)."`
	SHA256HashData    null.String `json:"SHA256HashData" panther:"sha256" description:"The SHA256 hash of a file. In most cases, the hash of the file referred to by the ImageFileName field."`
	SHA1HashData      null.String `json:"SHA1HashData" panther:"sha1" description:"The SHA1 hash of a file"`
	MD5HashData       null.String `json:"MD5HashData" panther:"md5" description:"The MD5 hash of a file"`
	SyntheticPR2Flags null.Uint16 `json:"SyntheticPR2Flags" description:"PR2 flags (PROCESS_RUNDOWN = 0, PROCESS_HOLLOWED = 1, IMAGEHASH_FAILURE = 4, FILE_PATH_EXCLUDED = 8, PROCESS_FORK_FOLDING = 16, APP_MONITORING = 2)"`

	// Windows only
	ImageSubsystem   null.String `json:"ImageSubsystem" description:"Subsystem of the image filename (Windows only)"`
	UserSID          null.String `json:"UserSid" description:"The User Security Identifier (UserSID) of the user who executed the command. A UserSID uniquely identifies a user in a system. (Windows only)"`
	AuthenticationID null.String `json:"AuthenticationId" description:"The authentication identifier (Windows only)" `
	IntegrityLevel   null.String `json:"IntegrityLevel" description:"The integrity level (Windows only)" `

	// Mac only
	ProcessGroupID   null.Int64 `json:"ProcessGroupId" description:"Process group id (Mac)"`
	UID              null.Int64 `json:"UID" description:"UID (Mac)"`
	RUID             null.Int64 `json:"RUID" description:"RUID (Mac)"`
	SVUID            null.Int64 `json:"SVUID" description:"SVUID (Mac)"`
	GID              null.Int64 `json:"GID" description:"GID (Mac)"`
	RGID             null.Int64 `json:"RGID" description:"RGID (Mac)"`
	SVGID            null.Int64 `json:"SVGID" description:"SVGID (Mac)"`
	SessionProcessID null.Int64 `json:"SessionProcessId" description:"Session process id (Mac)"`
}
