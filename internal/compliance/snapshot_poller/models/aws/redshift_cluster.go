package aws

/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2021 Panther Labs Inc
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

import "github.com/aws/aws-sdk-go/service/redshift"

const (
	RedshiftClusterSchema = "AWS.Redshift.Cluster"
)

// RedshiftCluseter contains all the information about a Redshift cluster
type RedshiftCluster struct {
	// Generic resource fields
	GenericAWSResource
	GenericResource

	// Fields embedded from redshift.cluster
	AllowVersionUpgrade              *bool
	AutomatedSnapshotRetentionPeriod *int64
	AvailabilityZone                 *string
	ClusterAvailabilityStatus        *string
	ClusterNodes                     []*redshift.ClusterNode
	ClusterParameterGroups           []*redshift.ClusterParameterGroupStatus
	ClusterPublicKey                 *string
	ClusterRevisionNumber            *string
	ClusterSecurityGroups            []*redshift.ClusterSecurityGroupMembership
	ClusterSnapshotCopyStatus        *redshift.ClusterSnapshotCopyStatus
	ClusterStatus                    *string
	ClusterSubnetGroupName           *string
	ClusterVersion                   *string
	DataTransferProgress             *redshift.DataTransferProgress
	DeferredMaintenanceWindows       []*redshift.DeferredMaintenanceWindow
	ElasticIpStatus                  *redshift.ElasticIpStatus
	ElasticResizeNumberOfNodeOptions *string
	Encrypted                        *bool
	Endpoint                         *redshift.Endpoint
	EnhancedVpcRouting               *bool
	HsmStatus                        *redshift.HsmStatus
	IamRoles                         []*redshift.ClusterIamRole
	KmsKeyId                         *string
	MaintenanceTrackName             *string
	ManualSnapshotRetentionPeriod    *int64
	MasterUsername                   *string
	ModifyStatus                     *string
	NodeType                         *string
	NumberOfNodes                    *int64
	PendingActions                   []*string
	PendingModifiedValues            *redshift.PendingModifiedValues
	PreferredMaintenanceWindow       *string
	PubliclyAccessible               *bool
	ResizeInfo                       *redshift.ResizeInfo
	RestoreStatus                    *redshift.RestoreStatus
	SnapshotScheduleIdentifier       *string
	SnapshotScheduleState            *string
	VpcId                            *string
	VpcSecurityGroups                []*redshift.VpcSecurityGroupMembership

	// Additional fields
	LoggingStatus *redshift.LoggingStatus
}
