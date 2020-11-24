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
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logtypes"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog/null"
)

// TypeDNSRequest is the logtype entry for Crowdstrike DNS request events.
// nolint:lll
var TypeDNSRequest = mustBuild(logtypes.ConfigJSON{
	Name:         TypePrefix + ".DNSRequest",
	Description:  `This event is generated for every attempted DNS name resolution on a host.`,
	ReferenceURL: `-`,
	NewEvent:     func() interface{} { return &DNSRequest{} },
})

// nolint:lll
type DNSRequest struct {
	EventSimpleName null.String `json:"event_simpleName" validate:"required,eq=DnsRequest" description:"Event name"`

	ContextEvent

	EffectiveTransmissionClass null.Int64 `json:"EffectiveTransmissionClass" description:"Effective transmission class"`

	DomainName      null.String `json:"DomainName" panther:"domain" description:"The domain name requested"`
	InterfaceIndex  null.Int64  `json:"InterfaceIndex" description:"The network interface index (Windows only)"`
	DualRequest     null.Int64  `json:"DualRequest" description:"If the event is dual request (Windows only)"`
	DNSRequestCount null.Int64  `json:"DnsRequestCount" description:"The number of DNS requests (Windows only)"`
	AppIdentifier   null.String `json:"AppIdentifier" description:"The identifier of the app that made the request (Android, iOS)"`
	IPAddress       null.String `json:"IpAddress" panther:"ip" description:"The device ip address (Android, iOS)"`
	RequestType     null.String `json:"RequestType" description:"The DNS request type"`
}
