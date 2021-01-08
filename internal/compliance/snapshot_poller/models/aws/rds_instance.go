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

import (
	"time"

	"github.com/aws/aws-sdk-go/service/rds"
)

const (
	RDSInstanceSchema = "AWS.RDS.Instance"
)

// RDSInstance contains all the information about an RDS DB instance
type RDSInstance struct {
	// Generic resource fields
	GenericAWSResource
	GenericResource

	// Fields embedded from rds.DBInstance
	AllocatedStorage                      *int64
	AssociatedRoles                       []*rds.DBInstanceRole
	AutoMinorVersionUpgrade               *bool
	AvailabilityZone                      *string
	BackupRetentionPeriod                 *int64
	CACertificateIdentifier               *string
	CharacterSetName                      *string
	CopyTagsToSnapshot                    *bool
	DBClusterIdentifier                   *string
	DBInstanceClass                       *string
	DBInstanceStatus                      *string
	DBParameterGroups                     []*rds.DBParameterGroupStatus
	DBSecurityGroups                      []*rds.DBSecurityGroupMembership
	DBSubnetGroup                         *rds.DBSubnetGroup
	DbInstancePort                        *int64
	DbiResourceId                         *string
	DeletionProtection                    *bool
	DomainMemberships                     []*rds.DomainMembership
	EnabledCloudwatchLogsExports          []*string
	Endpoint                              *rds.Endpoint
	Engine                                *string
	EngineVersion                         *string
	EnhancedMonitoringResourceArn         *string
	IAMDatabaseAuthenticationEnabled      *bool
	Iops                                  *int64
	KmsKeyId                              *string
	LatestRestorableTime                  *time.Time
	LicenseModel                          *string
	ListenerEndpoint                      *rds.Endpoint
	MasterUsername                        *string
	MaxAllocatedStorage                   *int64
	MonitoringInterval                    *int64
	MonitoringRoleArn                     *string
	MultiAZ                               *bool
	OptionGroupMemberships                []*rds.OptionGroupMembership
	PendingModifiedValues                 *rds.PendingModifiedValues
	PerformanceInsightsEnabled            *bool
	PerformanceInsightsKMSKeyId           *string
	PerformanceInsightsRetentionPeriod    *int64
	PreferredBackupWindow                 *string
	PreferredMaintenanceWindow            *string
	ProcessorFeatures                     []*rds.ProcessorFeature
	PromotionTier                         *int64
	PubliclyAccessible                    *bool
	ReadReplicaDBClusterIdentifiers       []*string
	ReadReplicaDBInstanceIdentifiers      []*string
	ReadReplicaSourceDBInstanceIdentifier *string
	SecondaryAvailabilityZone             *string
	StatusInfos                           []*rds.DBInstanceStatusInfo
	StorageEncrypted                      *bool
	StorageType                           *string
	TdeCredentialArn                      *string
	Timezone                              *string
	VpcSecurityGroups                     []*rds.VpcSecurityGroupMembership

	// Additional fields
	SnapshotAttributes []*rds.DBSnapshotAttributesResult
}
