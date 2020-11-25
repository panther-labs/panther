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

// nolint:lll
var (
	TypeNetworkConnect = mustBuild(logtypes.ConfigJSON{
		Name:         TypePrefix + ".NetworkConnect",
		Description:  `This event is generated when an application attempts a remote connection on an interface`,
		ReferenceURL: `-`,
		NewEvent:     func() interface{} { return &NetworkConnect{} },
	})

	TypeNetworkListen = mustBuild(logtypes.ConfigJSON{
		Name:         TypePrefix + ".NetworkListen",
		Description:  `This event is generated when an application establishes a socket in listening mode`,
		ReferenceURL: `-`,
		NewEvent:     func() interface{} { return &NetworkListen{} },
	})
)

// nolint:lll
type NetworkConnect struct {
	EventSimpleName null.String `json:"event_simpleName" validate:"required,oneof=NetworkConnectIP4 NetworkConnectIP6" description:"Event name"`
	ContextEvent
	LocalAddressIP4     null.String `json:"LocalAddressIP4" panther:"ip" description:"Local IPv4 address for the connection"`
	LocalAddressIP6     null.String `json:"LocalAddressIP6" panther:"ip" description:"Local IPv6 address for the connection"`
	RemoteAddressIP4    null.String `json:"RemoteAddressIP4" panther:"ip"  description:"Remote IPv4 address for the connection"`
	RemoteAddressIP6    null.String `json:"RemoteAddressIP6" panther:"ip" description:"Remote IPv6 address for the connection"`
	ConnectionFlags     null.Uint16 `json:"ConnectionFlags" description:"Connection flags (PROMISCUOUS_MODE_SIO_RCVALL = 2, RAW_SOCKET = 1, PROMISCUOUS_MODE_SIO_RCVALL_IGMPMCAST = 4, PROMISCUOUS_MODE_SIO_RCVALL_MCAST = 8)"`
	Protocol            null.Uint16 `json:"Protocol" description:"IP Protocol (ICMP = 1, TCP = 6, UDP = 17)"`
	LocalPort           null.Uint16 `json:"LocalPort" description:"Connection local port"`
	RemotePort          null.Uint16 `json:"RemotePort" description:"Connection remote port"`
	ConnectionDirection null.Uint16 `json:"ConnectionDirection" description:"Direction of the connection (OUTBOUND = 0, INBOUND = 1, NEITHER = 2, BOTH = 3)"`
	ICMPType            null.String `json:"IcmpType" description:"ICMP type (N/A on iOS)"`
	ICMPCode            null.String `json:"IcmpCode" description:"ICMP code (N/A on iOS)"`
}

// nolint:lll
type NetworkListen struct {
	EventSimpleName null.String `json:"event_simpleName" validate:"required,oneof=NetworkListenIP4 NetworkListenIP6" description:"event name"`
	ContextEvent
	LocalAddressIP4     null.String `json:"LocalAddressIP4" panther:"ip" description:"Local IPv4 address for the connection"`
	LocalAddressIP6     null.String `json:"LocalAddressIP6" panther:"ip"  description:"Local IPv6 address for the connection"`
	RemoteAddressIP4    null.String `json:"RemoteAddressIP4" panther:"ip" description:"Remote IPv4 address for the connection"`
	RemoteAddressIP6    null.String `json:"RemoteAddressIP6" panther:"ip" description:"Remote IPv6 address for the connection"`
	ConnectionFlags     null.Uint16 `json:"ConnectionFlags" description:"Connection flags (PROMISCUOUS_MODE_SIO_RCVALL = 2, RAW_SOCKET = 1, PROMISCUOUS_MODE_SIO_RCVALL_IGMPMCAST = 4, PROMISCUOUS_MODE_SIO_RCVALL_MCAST = 8)"`
	Protocol            null.Uint16 `json:"Protocol" description:"IP Protocol (ICMP = 1, TCP = 6, UDP = 17)"`
	LocalPort           null.Uint16 `json:"LocalPort" description:"Connection local port"`
	RemotePort          null.Uint16 `json:"RemotePort" description:"Connection remote port"`
	ConnectionDirection null.Uint16 `json:"ConnectionDirection" description:"Direction of the connection (OUTBOUND = 0, INBOUND = 1, NEITHER = 2, BOTH = 3)"`
}
