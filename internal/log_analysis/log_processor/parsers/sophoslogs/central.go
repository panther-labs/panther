package sophoslogs

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

// SophosCentralEvent -- full details at https://support.sophos.com/support/s/article/KB-000038307?language=en_US
// Event types and descriptions: https://support.sophos.com/support/s/article/KB-000038309?language=en_US
// Event structure can vary depending on the Type and Category fields
//nolint:lll
type SophosCentralEvent struct {
	// common fields belonging to all groups
	EndpointID   pantherlog.String `json:"endpoint_id" validate:"required" description:"Endpoint ID associated with the event"`
	EndpointType pantherlog.String `json:"endpoint_type" validate:"required" description:"Type of endpoint"`
	CustomerID   pantherlog.String `json:"customer_id" description:"Customer ID"`
	Severity     pantherlog.String `json:"severity" description:"Severity of the event"`
	Source       *Source           `json:"source_info" description:"Source IP of the endpoint"`
	Name         pantherlog.String `json:"name"  description:"Name of threat, or other event details"`
	ID           pantherlog.String `json:"id" validate:"required" description:"Unique identifier for the event"`
	Type         pantherlog.String `json:"type" validate:"required" description:"Type of event"`
	Category     pantherlog.String `json:"group" validate:"required" description:"Category of event"`
	Time         pantherlog.Time   `json:"end" validate:"required" event_time:"true" tcodec:"rfc3339" description:"Time the event occurred on the endpoint"`
	UploadTime   pantherlog.Time   `json:"rt" description:"Time the event was uploaded to Sophos Central"`
	Host         pantherlog.String `json:"dhost" description:"Source host of the event"`
	User         pantherlog.String `json:"suser" panther:"username" description:"Logged in user"`
	Datastream   pantherlog.String `json:"datastream" description:"Alert, or Event, to distinguish between event types"`
	DUID         pantherlog.String `json:"duid" description:"Undocumented field"`

	// MALWARE group additional fields
	Threat        pantherlog.String `json:"threat" description:"Name of the threat"`
	DetectionName pantherlog.String `json:"detection_identity_name" description:"Name of the detection"`
	FilePath      pantherlog.String `json:"filePath" description:"Path to the threat"`

	// DATA_LOSS_PREVENTION group additional fields
	DLPUser        pantherlog.String `json:"user" description:"Undocumented field, but should be same as User"`
	DLPRule        pantherlog.String `json:"rule" description:"DLP rule"`
	DLPUserAction  pantherlog.String `json:"user_action" description:"DLP user action"`
	DLPApplication pantherlog.String `json:"app_name" description:"DLP application name"`
	DLPAction      pantherlog.String `json:"action" description:"DLP action"`
	DLPFileType    pantherlog.String `json:"file_type" description:"DLP file type"`
	DLPFileSize    pantherlog.Int64  `json:"file_size" description:"DLP file size"`
	DLPFilePath    pantherlog.String `json:"file_path" description:"DLP file path"`

	// PUA group additional fields
	PUASHA256      pantherlog.String `json:"appSha256" panther:"sha256" description:"SHA 256 hash of the application associated with the threat, if available"`
	PUAAppCerts    []AppCert         `json:"appCerts" description:"Certificate information for the application associated with the threat, if available"`
	PUAOrigin      pantherlog.String `json:"origin" description:"Originating component of a detection"`
	PUARemedyItems *CoreRemedyItems  `json:"core_remedy_items" description:"Details of the items cleaned or restored"`

	// No additional fields for groups PERIPHERALS / DENC / UPDATING / RUNTIME_DETECTIONS / WEB / ENDPOINT_FIREWALL / PROTECTION / APPLICATION_CONTROL / POLICY
	// WIRELESS group could not be tested due to lack of example data
}

// Source contains the endpoint source IP
type Source struct {
	IP pantherlog.String `json:"ip" panther:"ip" description:"First IPv4 address of the endpoint"`
}

// AppCert contains the PUA certificate details
type AppCert struct {
	Signer     pantherlog.String `json:"signer" description:"PUA app certificate signer"`
	Thumbprint pantherlog.String `json:"thumbprint" description:"PUA app certificate thumbprint"`
}

// CoreRemedyItems contains the PUA remediation list
type CoreRemedyItems struct {
	Items      []RemedyItem     `json:"items" description:"List of remediations"`
	TotalItems pantherlog.Int32 `json:"totalItems" description:"Remediation count"`
}

// RemedyItem is a PUA remediation
type RemedyItem struct {
	Type        pantherlog.String `json:"type" description:"Type of item"`
	Result      pantherlog.String `json:"result" description:"Remedy outcome"`
	Descriptor  pantherlog.String `json:"descriptor" description:"Path to file"`
	ProcessPath pantherlog.String `json:"processPath" description:"Undocumented field"`
}
