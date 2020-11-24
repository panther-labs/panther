package oktalogs

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
	"gopkg.in/go-playground/validator.v9"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

const TypeSystemLog = "Okta.SystemLog"

var valid = validator.New()

type SystemLogParser struct{}

var _ parsers.LogParser = (*SystemLogParser)(nil)

func (*SystemLogParser) Parse(log string) ([]*parsers.PantherLog, error) {
	event := LogEvent{}
	if err := jsoniter.UnmarshalFromString(log, &event); err != nil {
		return nil, err
	}
	event.updatePantherLog()
	if err := valid.Struct(&event); err != nil {
		return nil, err
	}
	return event.Logs(), nil
}

func NewSystemLogParser() parsers.LogParser {
	return &SystemLogParser{}
}

func (*SystemLogParser) New() parsers.LogParser {
	return NewSystemLogParser()
}
func (*SystemLogParser) LogType() string {
	return TypeSystemLog
}

// nolint:lll
type LogEvent struct {
	UUID                  *string                `json:"uuid" validate:"required" description:"Unique identifier for an individual event"`
	Published             *timestamp.RFC3339     `json:"published" validate:"required" description:"Timestamp when event was published"`
	EventType             *string                `json:"eventType" validate:"required" description:"Type of event that was published"`
	Version               *string                `json:"version" validate:"required" description:"Versioning indicator"`
	Severity              *string                `json:"severity" validate:"required" description:"Indicates how severe the event is: DEBUG, INFO, WARN, ERROR"`
	LegacyEventType       *string                `json:"legacyEventType,omitempty" description:"Associated Events API Action objectType attribute value"`
	DisplayMessage        *string                `json:"displayMessage,omitempty" description:"The display message for an event"`
	Actor                 *Actor                 `json:"actor,omitempty" description:"Describes the entity that performed an action"`
	Client                *Client                `json:"client,omitempty" description:"The client that requested an action"`
	Request               *Request               `json:"request,omitempty" description:"The request that initiated an action"`
	Outcome               *Outcome               `json:"outcome,omitempty" description:"The outcome of an action"`
	Target                []Target               `json:"target,omitempty" description:"Zero or more targets of an action"`
	Transaction           *Transaction           `json:"transaction,omitempty" description:"The transaction details of an action"`
	DebugContext          *DebugContext          `json:"debugContext,omitempty" description:"The debug request data of an action"`
	AuthenticationContext *AuthenticationContext `json:"authenticationContext,omitempty" description:"The authentication data of an action"`
	SecurityContext       *SecurityContext       `json:"securityContext,omitempty" description:"The security data of an action"`

	parsers.PantherLog
}

func (event *LogEvent) updatePantherLog() {
	event.SetCoreFields(TypeSystemLog, event.Published, event)
	if event.Request != nil {
		for _, ip := range event.Request.IPChain {
			event.AppendAnyIPAddressPtr(ip.IP)
		}
	}
	if event.SecurityContext != nil {
		event.AppendAnyDomainNamePtrs(event.SecurityContext.Domain)
	}
	if event.Client != nil {
		event.AppendAnyIPAddressPtr(event.Client.IPAddress)
	}
}

type Actor struct {
	ID          *string             `json:"id" validate:"required" description:"ID of actor"`
	Type        *string             `json:"type" validate:"required" description:"Type of actor"`
	AlternateID *string             `json:"alternateId,omitempty"  description:"Alternative id of the actor"`
	DisplayName *string             `json:"displayName,omitempty"  description:"Display name of the actor"`
	Details     jsoniter.RawMessage `json:"details,omitempty" description:"Details about the actor"`
}

// nolint:lll
type Client struct {
	ID                  *string              `json:"id,omitempty" description:"For OAuth requests this is the id of the OAuth client making the request. For SSWS token requests, this is the id of the agent making the request."`
	UserAgent           *UserAgent           `json:"userAgent,omitempty" description:"The user agent used by an actor to perform an action"`
	GeographicalContext *GeographicalContext `json:"geographicalContext,omitempty" description:"The physical location where the client made its request from"`
	Zone                *string              `json:"zone,omitempty" description:"The name of the Zone that the client's location is mapped to"`
	IPAddress           *string              `json:"ipAddress,omitempty" description:"Ip address that the client made its request from"`
	Device              *string              `json:"device,omitempty" description:"Type of device that the client operated from (e.g. Computer)"`
}

// nolint:lll
type UserAgent struct {
	Browser      *string `json:"browser,omitempty" description:"If the client is a web browser, this field identifies the type of web browser (e.g. CHROME, FIREFOX)"`
	OS           *string `json:"os,omitempty" description:"The Operating System the client runs on (e.g. Windows 10)"`
	RawUserAgent *string `json:"rawUserAgent,omitempty" description:"A raw string representation of the user agent, formatted according to section 5.5.3 of HTTP/1.1 Semantics and Content. Both the browser and the OS fields can be derived from this field."`
}

// nolint:lll
type GeographicalContext struct {
	GeoLocation *GeoLocation `json:"geolocation,omitempty" description:"Contains the geolocation coordinates (latitude, longitude)"`
	City        *string      `json:"city,omitempty" description:"The city encompassing the area containing the geolocation coordinates, if available (e.g. Seattle, San Francisco)"`
	State       *string      `json:"state,omitempty" description:"Full name of the state/province encompassing the area containing the geolocation coordinates (e.g. Montana, Incheon)"`
	Country     *string      `json:"country,omitempty" description:"Full name of the country encompassing the area containing the geolocation coordinates (e.g. France, Uganda)"`
	PostalCode  *string      `json:"postalCode,omitempty" description:"Full name of the country encompassing the area containing the geolocation coordinates (e.g. France, Uganda)"`
}
type GeoLocation struct {
	Latitude  *float64 `json:"lat" description:"Latitude"`
	Longitude *float64 `json:"lon" description:"Longitude"`
}
type Target struct {
	ID          *string             `json:"id" validate:"required" description:"ID of target"`
	Type        *string             `json:"type" validate:"required" description:"Type of target"`
	AlternateID *string             `json:"alternateId,omitempty"  description:"Alternative id of the target"`
	DisplayName *string             `json:"displayName,omitempty"  description:"Display name of the target"`
	Details     jsoniter.RawMessage `json:"details,omitempty" description:"Details about the target"`
}

// nolint:lll
type Request struct {
	IPChain []IPAddress `json:"ipChain,omitempty" description:"If the incoming request passes through any proxies, the IP addresses of those proxies will be stored here in the format (clientIp, proxy1, proxy2, ...)."`
}

type IPAddress struct {
	IP                  *string              `json:"ip,omitempty" description:"IP address"`
	GeographicalContext *GeographicalContext `json:"geographicalContext,omitempty" description:"Geographical context of the IP address"`
	Version             *string              `json:"version,omitempty" description:"IP version"`
	Source              *string              `json:"source,omitempty" description:"Details regarding the source"`
}

type Outcome struct {
	Result *string `json:"result,omitempty" description:"Result of the action: SUCCESS, FAILURE, SKIPPED, ALLOW, DENY, CHALLENGE, UNKNOWN"`
	Reason *string `json:"reason,omitempty" description:"Reason for the result, for example INVALID_CREDENTIALS"`
}

// nolint:lll
type Transaction struct {
	ID     *string             `json:"id,omitempty" description:"Unique identifier for this transaction."`
	Type   *string             `json:"type,omitempty" description:"Describes the kind of transaction. WEB indicates a web request. JOB indicates an asynchronous task."`
	Detail jsoniter.RawMessage `json:"detail,omitempty" description:"Details for this transaction."`
}

// nolint:lll
type DebugContext struct {
	DebugData jsoniter.RawMessage `json:"debugData,omitempty" description:"Dynamic field containing miscellaneous information dependent on the event type."`
}

// nolint:lll
type AuthenticationContext struct {
	// Possible values OKTA_AUTHENTICATION_PROVIDER, ACTIVE_DIRECTORY, LDAP, FEDERATION, SOCIAL, FACTOR_PROVIDER
	AuthenticationProvider *string `json:"authenticatorProvider,omitempty" description:"The system that proves the identity of an actor using the credentials provided to it"`
	AuthenticationStep     *int32  `json:"authenticationStep,omitempty" description:"The zero-based step number in the authentication pipeline. Currently unused and always set to 0."`
	// Possible values OKTA_CREDENTIAL_PROVIDER, RSA, SYMANTEC, GOOGLE, DUO, YUBIKEY
	CredentialProvider *string `json:"credentialProvider,omitempty" description:"A credential provider is a software service that manages identities and their associated credentials. When authentication occurs via credentials provided by a credential provider, that credential provider will be recorded here."`
	// Possible values OTP, SMS, PASSWORD, ASSERTION, IWA, EMAIL, OAUTH2, JWT, CERTIFICATE, PRE_SHARED_SYMMETRIC_KEY, OKTA_CLIENT_SESSION, DEVICE_UDID
	CredentialType    *string `json:"credentialType,omitempty" description:"The underlying technology/scheme used in the credential"`
	Issuer            *Issuer `json:"issuer,omitempty"  description:"The specific software entity that created and issued the credential."`
	ExternalSessionID *string `json:"externalSessionId,omitempty" description:"A proxy for the actor's session ID"`
	Interface         *string `json:"interface,omitempty" description:"The third party user interface that the actor authenticates through, if any."`
}

// nolint:lll
type Issuer struct {
	ID   *string `json:"id,omitempty" description:"Varies depending on the type of authentication. If authentication is SAML 2.0, id is the issuer in the SAML assertion. For social login, id is the issuer of the token."`
	Type *string `json:"type,omitempty" description:"Information regarding issuer and source of the SAML assertion or token."`
}

// nolint:lll
type SecurityContext struct {
	AutonomousSystemNumber       *int64  `json:"asNumber,omitempty" description:"Autonomous system number associated with the autonomous system that the event request was sourced to"`
	AutonomousSystemOrganization *string `json:"asOrg,omitempty" description:"Organization associated with the autonomous system that the event request was sourced to"`
	ISP                          *string `json:"isp,omitempty" description:"Internet service provider used to sent the event's request"`
	Domain                       *string `json:"domain,omitempty" description:"The domain name associated with the IP address of the inbound event request"`
	IsProxy                      *bool   `json:"isProxy,omitempty" description:"Specifies whether an event's request is from a known proxy"`
}
