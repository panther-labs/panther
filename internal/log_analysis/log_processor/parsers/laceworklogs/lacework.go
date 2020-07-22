package laceworklogs

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
	jsoniter "github.com/json-iterator/go"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/numerics"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

// LaceworkDesc is the lacework description
var LaceworkDesc = `Lacework.Events represents the content of an exported Lacework Alert S3 Object.`

// Lacework struct for Events
type Lacework struct {
	EventCategory *string                      `json:"EVENT_CATEGORY" validate:"required" description:"The category the event falls into"`
	EventDetails  *LaceworkDataArray           `json:"EVENT_DETAILS" validate:"required" description:"The event details"`
	Severity      *numerics.Integer            `json:"SEVERITY" validate:"required" description:"The severity level of the alert"`
	StartTime     *timestamp.LaceworkTimestamp `json:"START_TIME" validate:"required" description:"The event start time."`
	Summary       *string                      `json:"SUMMARY" validate:"required" description:"The alert title and quick summary"`
	EventType     *string                      `json:"EVENT_TYPE" validate:"required" description:"The type of event"`
	EventName     *string                      `json:"EVENT_NAME" validate:"required" description:"The event name"`
	Link          *string                      `json:"LINK" validate:"required" description:"A link to the Lacework dashboard for the event"`
	EventID       *numerics.Integer            `json:"EVENT_ID" validate:"required" description:"The eventID reference"`
	Account       *string                      `json:"ACCOUNT" validate:"required" description:"The Lacework tenent that created the event"`
	Source        *string                      `json:"SOURCE" validate:"required" description:"The data source the event triggered on"`

	// NOTE: added to end of struct to allow expansion later
	parsers.PantherLog
}

//LaceworkDataArray s
type LaceworkDataArray struct {
	Data []LaceworkData `json:"data" description:"The array of event data"`
}

// LaceworkData is the main level data
type LaceworkData struct {
	StartTime  *timestamp.RFC3339 `json:"START_TIME"  description:"The event start time."`
	EndTime    *timestamp.RFC3339 `json:"END_TIME"  description:"The event end time."`
	EventType  *string            `json:"EVENT_TYPE"  description:"The event type description eg - launched new binary."`
	EventID    *string            `json:"EVENT_ID"  description:"The event alert ID."`
	EventActor *string            `json:"EVENT_ACTOR"  description:"The origin of the event eg - AWS, User."`
	EventModel *string            `json:"EVENT_MODEL"  description:"The model that triggered an alert."`
	EntityMap  *LaceworkEntityMap `json:"ENTITY_MAP"  description:"The map of related fields to the detection alert."`
}

// LaceworkEntityMap is the raw event details
type LaceworkEntityMap struct {
	User            []LaceworkUser            `json:"User,omitempty" description:"Any user based info involved in an alert."`
	Application     []LaceworkApplication     `json:"Application,omitempty" description:"Any application based info involved in an alert."`
	Machine         []LaceworkMachine         `json:"Machine,omitempty" description:"Any machine based info involved in an alert."`
	Container       []LaceworkContainer       `json:"Container,omitempty" description:"Any container based info involved in an alert."`
	DNSName         []LaceworkDNSName         `json:"DnsName,omitempty" description:"Any dns based info involved in an alert."`
	IPAddress       []LaceworkIPAddress       `json:"IpAddress,omitempty" description:"Any ip based info involved in an alert."`
	Process         []LaceworkProcess         `json:"Process,omitempty" description:"Any process based info involved in an alert."`
	FileDataHash    []LaceworkFileDataHash    `json:"FileDataHash,omitempty" description:"Any filehash based info involved in an alert."`
	FileExePath     []LaceworkFileExePath     `json:"FileExePath,omitempty" description:"Any executable filepath information."`
	SourceIPAddress []LaceworkSourceIPAddress `json:"SourceIpAddress,omitempty" description:"Source IP based information."`
	API             []LaceworkAPI             `json:"API,omitempty" description:"The service and endpoint."`
	Region          []LaceworkRegion          `json:"Region,omitempty" description:"Regional based information."`
	CTUser          []LaceworkCTUser          `json:"CT_User,omitempty" description:"Cloudtrail user information."`
	Resource        []LaceworkResource        `json:"Resource,omitempty" description:"Resource values."`
	RecID           []LaceworkRecID           `json:"RecId,omitempty" description:"Receiver account info."`
	CustomRule      []LaceworkCustomRule      `json:"CustomRule,omitempty" description:"Custom Rule info."`
	NewViolation    []LaceworkNewViolation    `json:"NewViolation,omitempty" description:"Violation Ref."`
	ViolationReason []LaceworkViolationReason `json:"ViolationReason,omitempty" description:"A reason for the violation."`
}

// LaceworkUser is user info
type LaceworkUser struct {
	Hostname *string `json:"MACHINE_HOSTNAME,omitempty"`
	Username *string `json:"USERNAME,omitempty"`
}

// LaceworkApplication is the app info
type LaceworkApplication struct {
	Application       *string            `json:"APPLICATION,omitempty"`
	HasExternalConns  *numerics.Integer  `json:"HAS_EXTERNAL_CONNS,omitempty"`
	IsClient          *numerics.Integer  `json:"IS_CLIENT,omitempty"`
	IsServer          *numerics.Integer  `json:"IS_SERVER,omitempty"`
	EarliestKnownTime *timestamp.RFC3339 `json:"EARLIEST_KNOWN_TIME,omitempty"`
}

//LaceworkMachine contains machine datas
type LaceworkMachine struct {
	Hostname          *string           `json:"HOSTNAME,omitempty"`
	ExternalIP        *string           `json:"EXTERNAL_IP,omitempty"`
	InstanceID        *string           `json:"INSTANCE_ID,omitempty"`
	InstanceName      *string           `json:"INSTANCE_NAME,omitempty"`
	CPUPercentage     *float32          `json:"CPU_PERCENTAGE,omitempty"`
	InternalIPAddress *string           `json:"INTERNAL_IP_ADDR,omitempty"`
	IsExternal        *numerics.Integer `json:"IS_EXTERNAL,omitempty"`
}

// LaceworkContainer is container info
type LaceworkContainer struct {
	ImageRepo        *string            `json:"IMAGE_REPO,omitempty"`
	ImageTag         *string            `json:"IMAGE_TAG,omitempty"`
	HasExternalConns *numerics.Integer  `json:"HAS_EXTERNAL_CONNS,omitempty"`
	IsClient         *numerics.Integer  `json:"IS_CLIENT,omitempty"`
	IsServer         *numerics.Integer  `json:"IS_SERVER,omitempty"`
	FirstSeenTime    *timestamp.RFC3339 `json:"FIRST_SEEN_TIME,omitempty"`
	PodNamespace     *string            `json:"POD_NAMESPACE,omitempty"`
	PodIPAddress     *string            `json:"POD_IP_ADDR,omitempty"`
}

// LaceworkDNSName is DNS info
type LaceworkDNSName struct {
	Hostname      *string  `json:"HOSTNAME,omitempty"`
	PortList      []int32  `json:"PORT_LIST,omitempty"`
	TotalINBytes  *float32 `json:"TOTAL_IN_BYTES,omitempty"`
	TotalOUTBytes *float32 `json:"TOTAL_OUT_BYTES,omitempty"`
}

//LaceworkIPAddress is IP info
type LaceworkIPAddress struct {
	SourceIPAddress *string              `json:"IP_ADDRESS,omitempty"`
	TotalINBytes    *float32             `json:"TOTAL_IN_BYTES,omitempty"`
	TotalOUTBytes   *float32             `json:"TOTAL_OUT_BYTES,omitempty"`
	ThreatTags      []string             `json:"THREAT_TAGS,omitempty"`
	ThreatSource    *jsoniter.RawMessage `json:"THREAT_SOURCE,omitempty"`
	Country         *string              `json:"COUNTRY,omitempty"`
	Region          *string              `json:"REGION,omitempty"`
	PortList        []int32              `json:"PORT_LIST,omitempty"`
	FirstSeenTime   *string              `json:"FIRST_SEEN_TIME,omitempty"`
}

//LaceworkProcess contains Proc info
type LaceworkProcess struct {
	Hostname         *string            `json:"HOSTNAME,omitempty"`
	ProcessID        *numerics.Integer  `json:"PROCESS_ID,omitempty"`
	ProcessStartTime *timestamp.RFC3339 `json:"PROCESS_START_TIME,omitempty"`
	CommandLine      *string            `json:"CMDLINE,omitempty"`
	CPUPercentage    *float32           `json:"CPU_PERCENTAGE,omitempty"`
}

// LaceworkFileDataHash contains hash data
type LaceworkFileDataHash struct {
	FiledataHash  *string            `json:"FILEDATA_HASH,omitempty"`
	MachineCount  *numerics.Integer  `json:"MACHINE_COUNT,omitempty"`
	EXEPathList   []string           `json:"EXE_PATH_LIST,omitempty"`
	FirstSeenTime *timestamp.RFC3339 `json:"FIRST_SEEN_TIME,omitempty"`
	ISKnownBad    *numerics.Integer  `json:"IS_KNOWN_BAD,omitempty"`
}

//LaceworkFileExePath contains exe path info
type LaceworkFileExePath struct {
	EXEPath          *string            `json:"EXE_PATH,omitempty"`
	FirstSeenTime    *timestamp.RFC3339 `json:"FIRST_SEEN_TIME,omitempty"`
	LastFileDataHash *string            `json:"LAST_FILEDATA_HASH,omitempty"`
	LastPackageName  *string            `json:"LAST_PACKAGE_NAME,omitempty"`
	LastVersion      *string            `json:"LAST_VERSION,omitempty"`
	LastFileOwner    *string            `json:"LAST_FILE_OWNER,omitempty"`
}

// LaceworkSourceIPAddress contains ip info
type LaceworkSourceIPAddress struct {
	SourceIPAddress *string `json:"IP_ADDRESS,omitempty"`
	Region          *string `json:"REGION,omitempty"`
	Country         *string `json:"COUNTRY,omitempty"`
}

// LaceworkAPI contains aip based info for AWS
type LaceworkAPI struct {
	EventSource *string `json:"SERVICE,omitempty"`
	EventName   *string `json:"API,omitempty"`
}

//LaceworkRegion contatins regional info
type LaceworkRegion struct {
	Region             *string  `json:"REGION,omitempty"`
	RecipientAccountID []string `json:"ACCOUNT_LIST,omitempty"`
}

// LaceworkCTUser contains user info
type LaceworkCTUser struct {
	Username    *string           `json:"USERNAME,omitempty"`
	AccountID   *string           `json:"ACCOUNT_ID,omitempty"`
	MFA         *numerics.Integer `json:"MFA,omitempty"`
	APIList     []string          `json:"API_LIST,omitempty"`
	RegionList  []string          `json:"REGION_LIST,omitempty"`
	AccessKeyID *string           `json:"PRINCIPAL_ID,omitempty"`
}

// LaceworkResource contains resource info
type LaceworkResource struct {
	Name  *string `json:"NAME,omitempty"`
	Value *string `json:"VALUE,omitempty"`
}

//LaceworkRecID contains the receiver account Id infor
type LaceworkRecID struct {
	RECID              *string `json:"REC_ID,omitempty"`
	RecipientAccountID *string `json:"ACCOUNT_ID,omitempty"`
	AccountAlias       *string `json:"ACCOUNT_ALIAS,omitempty"`
	Title              *string `json:"TITLE,omitempty"`
	Status             *string `json:"STATUS,omitempty"`
	EVALType           *string `json:"EVAL_TYPE,omitempty"`
	EVALGUID           *string `json:"EVAL_GUID,omitempty"`
}

//LaceworkCustomRule contains custom created rule info
type LaceworkCustomRule struct {
	LastUpdatedTime *timestamp.RFC3339 `json:"LAST_UPDATED_TIME,omitempty"`
	LastUpdatedUser *string            `json:"LAST_UPDATED_USER,omitempty"`
	DisplayFilter   *string            `json:"DISPLAY_FILTER,omitempty"`
	RuleGUID        *string            `json:"RULE_GUID,omitempty"`
}

// LaceworkNewViolation contains violation info
type LaceworkNewViolation struct {
	RECID    *string `json:"REC_ID,omitempty"`
	Reason   *string `json:"REASON,omitempty"`
	Resource *string `json:"RESOURCE,omitempty"`
}

//LaceworkViolationReason is violation details
type LaceworkViolationReason struct {
	RECID  *string `json:"REC_ID,omitempty"`
	Reason *string `json:"REASON,omitempty"`
}

// LaceworkParser parses Lacework Alert logs
type LaceworkParser struct{}

var _ parsers.LogParser = (*LaceworkParser)(nil)

//New LaceworkParser parses the data
func (p *LaceworkParser) New() parsers.LogParser {
	return &LaceworkParser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *LaceworkParser) Parse(log string) ([]*parsers.PantherLog, error) {
	event := &Lacework{}
	err := jsoniter.UnmarshalFromString(log, event)
	if err != nil {
		return nil, err
	}

	event.updatePantherFields(p)

	if err := parsers.Validator.Struct(event); err != nil {
		return nil, err
	}

	return event.Logs(), nil
}

// LogType returns the log type supported by this parser
func (p *LaceworkParser) LogType() string {
	return "Lacework.Events"
}

// Update schema defs and align to the fields below
func (event *Lacework) updatePantherFields(p *LaceworkParser) {
	event.SetCoreFields(p.LogType(), (*timestamp.RFC3339)(event.StartTime), event)

	for _, data := range event.EventDetails.Data {
		for _, address := range data.EntityMap.IPAddress {
			event.AppendAnyIPAddressPtr(address.SourceIPAddress)
		}

		for _, address := range data.EntityMap.SourceIPAddress {
			event.AppendAnyIPAddressPtr(address.SourceIPAddress)
		}
	}
}
