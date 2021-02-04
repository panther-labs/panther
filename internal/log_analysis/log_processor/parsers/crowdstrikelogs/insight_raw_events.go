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
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"
)

// nolint:lll
var (
	TypeAIDMaster = logtypes.MustBuild(logtypes.ConfigJSON{
		Name:         TypePrefix + ".AIDMaster",
		Description:  "Sensor and Host information provided by Falcon Insight",
		ReferenceURL: "https://developer.crowdstrike.com/crowdstrike/docs/falcon-data-replicator-guide#section-aid-master",
		NewEvent:     func() interface{} { return &AIDMaster{} },
	})

	TypeManagedAssets = logtypes.MustBuild(logtypes.ConfigJSON{
		Name:         TypePrefix + ".ManagedAssets",
		Description:  "Sensor and Host information provided by Falcon Insight (Network Information: IP Address, LAN/Ethernet Interface, Gateway Address, MAC Address)",
		ReferenceURL: "https://developer.crowdstrike.com/crowdstrike/docs/falcon-data-replicator-guide#section-managedassets",
		NewEvent:     func() interface{} { return &ManagedAssets{} },
	})

	TypeNotManagedAssets = logtypes.MustBuild(logtypes.ConfigJSON{
		Name:         TypePrefix + ".NotManagedAssets",
		Description:  "Unmanaged Host discovery information provided by Falcon Insight",
		ReferenceURL: "https://developer.crowdstrike.com/crowdstrike/docs/falcon-data-replicator-guide#section-notmanaged",
		NewEvent:     func() interface{} { return &NotManagedAssets{} },
	})
)

// nolint:lll
type AIDMaster struct {
	Time               pantherlog.Time    `json:"Time" validate:"required" tcodec:"unix" event_time:"true" description:"Timestamp of when the event was received by the CrowdStrike cloud. This is not to be confused with the time the event was generated locally on the system (the _timeevent). This is the timestamp of the event from the cloud's point of view. This value can be converted to any time format and can be used for calculations."`
	AgentLoadFlags     pantherlog.Int32   `json:"AgentLoadFlags" validate:"required" description:"Whether the sensor loaded during or after the Windows host's boot process. Example values: 0, 1"`
	AgentLocalTime     pantherlog.Time    `json:"AgentLocalTime" tcodec:"unix" validate:"required" description:"The local time for the sensor in epoch format."`
	AgentTimeOffset    pantherlog.Float64 `json:"AgentTimeOffset" validate:"required" description:"The time since the last reboot in epoch format."`
	AgentVersion       pantherlog.String  `json:"AgentVersion" validate:"required" description:"The version of the sensor running on a host."`
	AID                pantherlog.String  `json:"aid" validate:"required" description:"The sensor ID. This value is unique to each installation of a Falcon sensor. When a sensor is updated or reinstalled, the host gets a new aid. In those situations, a single host could have multiple aid values over time."`
	CID                pantherlog.String  `json:"cid" validate:"required" description:"The customer ID."`
	AIP                pantherlog.String  `json:"aip" validate:"required" panther:"ip" description:"The sensor’s IP, as seen from the CrowdStrike cloud. This is typically the public IP of the sensor. This helps determine the location of a computer, depending on your network."`
	BiosManufacturer   pantherlog.String  `json:"BiosManufacturer" description:"The manufacturer of the host's BIOS."`
	BiosVersion        pantherlog.String  `json:"BiosVersion" description:"The version of the host's BIOS."`
	ChassisType        pantherlog.String  `json:"ChassisType" description:"Type of system chassis, as defined in SMBIOS Standard."`
	City               pantherlog.String  `json:"City" description:"The system's city of origin."`
	Country            pantherlog.String  `json:"Country" description:"The system's country of origin."`
	Continent          pantherlog.String  `json:"Continent" description:"The sensor's continent, as seen from the CrowdStrike cloud."`
	ComputerName       pantherlog.String  `json:"ComputerName" description:"The name of the host."`
	ConfigIDBuild      pantherlog.String  `json:"ConfigIDBuild" description:"Build number used as part of the ConfigID."`
	EventPlatform      pantherlog.String  `json:"event_platform" description:"The platform the sensor is running on. Example values: 'Win', 'Lin', 'Mac'."`
	FirstSeen          pantherlog.Time    `json:"FirstSeen" tcodec:"unix" description:"The first time the sensor was seen by the CrowdStrike cloud in epoch format."`
	MachineDomain      pantherlog.String  `json:"MachineDomain" description:"The Windows domain name to which the host is currently joined."`
	OU                 pantherlog.String  `json:"OU" description:"The organizational unit of the host as seen by the sensor (defined by system admin)."`
	PointerSize        pantherlog.String  `json:"PointerSize" description:"The processor architecture (in decimal, non-hex format): '4' for 32-bit, '8' for 64-bit, or 'none' for unknown."`
	ProductType        pantherlog.String  `json:"ProductType" description:"The type of product (in decimal, non-hex format). Example values: '1' (Workstation), '2' (Domain Controller), '3' (Server)."`
	ServicePackMajor   pantherlog.String  `json:"ServicePackMajor" description:"The major version # of the OS Service Pack (in decimal, non-hex format)."`
	SiteName           pantherlog.String  `json:"SiteName" description:"The site name of the domain to which the host is joined (defined by system admin)."`
	SystemManufacturer pantherlog.String  `json:"SystemManufacturer" description:"The host's system manufacturer."`
	SystemProductName  pantherlog.String  `json:"SystemProductName" description:"The host's product name."`
	Timezone           pantherlog.String  `json:"Timezone" description:"The sensor's time zone, as seen from the CrowdStrike cloud."`
	Version            pantherlog.String  `json:"Version" description:"The host's system version."`
	HostHiddenStatus   pantherlog.String  `json:"HostHiddenStatus" description:"Whether the host is visible or not."`
}

// nolint:lll
type ManagedAssets struct {
	Time                 pantherlog.Time   `json:"_time" tcodec:"unix" validate:"required" event_time:"true" description:"The host's local time in epoch format."`
	AID                  pantherlog.String `json:"aid" validate:"required" description:"The sensor ID. This value is unique to each installation of a Falcon sensor. When a sensor is updated or reinstalled, the host gets a new aid. In those situations, a single host could have multiple aid values over time."`
	CID                  pantherlog.String `json:"cid" validate:"required" description:"The customer ID."`
	GatewayIP            pantherlog.String `json:"GatewayIP" validate:"required" panther:"ip" description:"The gateway of the system where the sensor is installed."`
	GatewayMAC           pantherlog.String `json:"GatewayMAC" validate:"required" description:"The MAC address of the gateway."`
	MacPrefix            pantherlog.String `json:"MacPrefix" validate:"required" description:"An identifier unique to the organization."`
	MAC                  pantherlog.String `json:"MAC" validate:"required" description:"The MAC address of the system."`
	LocalAddressIP4      pantherlog.String `json:"LocalAddressIP4" validate:"required" panther:"ip" description:"The device's local IP address in IPv4 format."`
	InterfaceAlias       pantherlog.String `json:"InterfaceAlias" description:"The user-friendly name of the IP interface."`
	InterfaceDescription pantherlog.String `json:"InterfaceDescription" description:"The network adapter used for the IP interface."`
}

// nolint:lll
type NotManagedAssets struct {
	Time                 pantherlog.Time     `json:"_time" validate:"required" tcodec:"unix" event_time:"true" description:"The host's local time in epoch format."`
	AIP                  pantherlog.String   `json:"aip" validate:"required" panther:"ip" description:"The sensor’s IP, as seen from the CrowdStrike cloud. This is typically the public IP of the sensor. This helps determine the location of a computer, depending on your network."`
	AIPCount             pantherlog.Int64    `json:"aipcount" validate:"required" description:"The number of public-facing IP addresses."`
	LocalIPCount         pantherlog.Int64    `json:"localipCount" validate:"required" description:"The number of local IP addresses."`
	CID                  pantherlog.String   `json:"cid" validate:"required" description:"The customer ID."`
	CurrentLocalIP       pantherlog.String   `json:"CurrentLocalIP" validate:"required" panther:"ip" description:"The current local IP address of the machine, found via the IPv4 network discovery protocol."`
	Subnet               pantherlog.String   `json:"subnet" description:"The subnet of the system."`
	MAC                  pantherlog.String   `json:"MAC" validate:"required" description:"The MAC address of the system."`
	MacPrefix            pantherlog.String   `json:"MacPrefix" validate:"required" description:"An identifier unique to the organization."`
	DiscovererCount      pantherlog.Int64    `json:"discovererCount" validate:"required" description:"The number of aid's that have discovered this system."`
	DiscovererAID        []pantherlog.String `json:"discoverer_aid" description:"The agent IDs that have discovered this system."`
	DiscovererDeviceType pantherlog.String   `json:"discoverer_devicetype" description:"The type of device that discovered this system ('VM' or 'Server')."`
	FirstDiscoveredDate  pantherlog.Time     `json:"FirstDiscoveredDate" tcodec:"unix" description:"The first time the system was discovered in epoch format."`
	LastDiscoveredBy     pantherlog.Time     `json:"LastDiscoveredBy" tcodec:"unix" description:"The most recent time the system was discovered in epoch format."`
	LocalAddressIP4      pantherlog.String   `json:"LocalAddressIP4" panther:"ip" description:"The device's local IP address in IPv4 format."`
	ComputerName         pantherlog.String   `json:"ComputerName" description:"The name of the host that discovered the neighbor."`
	NeighborName         pantherlog.String   `json:"NeighborName" description:"The neighbor's host name."`
}
