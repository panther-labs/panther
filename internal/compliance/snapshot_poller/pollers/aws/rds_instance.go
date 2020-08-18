package aws

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
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/rds"
	"github.com/aws/aws-sdk-go/service/rds/rdsiface"
	"go.uber.org/zap"

	apimodels "github.com/panther-labs/panther/api/gateway/resources/models"
	awsmodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
	pollermodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/poller"
	"github.com/panther-labs/panther/internal/compliance/snapshot_poller/pollers/utils"
)

// Set as variables to be overridden in testing
var (
	RDSClientFunc = setupRDSClient
)

func setupRDSClient(sess *session.Session, cfg *aws.Config) interface{} {
	return rds.New(sess, cfg)
}

func getRDSClient(pollerResourceInput *awsmodels.ResourcePollerInput, region string) (rdsiface.RDSAPI, error) {
	client, err := getClient(pollerResourceInput, RDSClientFunc, "rds", region)
	if err != nil {
		return nil, err // error is logged in getClient()
	}

	return client.(rdsiface.RDSAPI), nil
}

// PollRDSInstance polls a single RDS DB Instance resource
func PollRDSInstance(
	pollerResourceInput *awsmodels.ResourcePollerInput,
	resourceARN arn.ARN,
	scanRequest *pollermodels.ScanEntry,
) (interface{}, error) {

	rdsClient, err := getRDSClient(pollerResourceInput, resourceARN.Region)
	if err != nil {
		return nil, err
	}

	rdsInstance := getRDSInstance(rdsClient, scanRequest.ResourceID)

	snapshot := buildRDSInstanceSnapshot(rdsClient, rdsInstance)
	if snapshot == nil {
		return nil, nil
	}
	snapshot.AccountID = aws.String(resourceARN.AccountID)
	snapshot.Region = aws.String(resourceARN.Region)
	return snapshot, nil
}

// getRDSInstance returns a specific RDS instance
func getRDSInstance(svc rdsiface.RDSAPI, instanceARN *string) *rds.DBInstance {
	instance, err := svc.DescribeDBInstances(&rds.DescribeDBInstancesInput{
		Filters: []*rds.Filter{
			{
				Name:   aws.String("db-instance-id"),
				Values: []*string{instanceARN},
			},
		},
	})
	if err != nil {
		utils.LogAWSError("RDS.DescribeDBInstances", err)
		return nil
	}

	if len(instance.DBInstances) == 0 {
		zap.L().Warn("tried to scan non-existent resource",
			zap.String("resource", *instanceARN),
			zap.String("resourceType", awsmodels.RDSInstanceSchema))
		return nil
	}
	return instance.DBInstances[0]
}

// describeDbInstance returns a list of all RDS Instances in the account
func describeDBInstances(rdsSvc rdsiface.RDSAPI, nextMarker *string) (instances []*rds.DBInstance, marker *string, err error) {
	err = rdsSvc.DescribeDBInstancesPages(&rds.DescribeDBInstancesInput{
		Marker: nextMarker,
	},
		func(page *rds.DescribeDBInstancesOutput, lastPage bool) bool {
			instances = append(instances, page.DBInstances...)
			if len(instances) >= defaultBatchSize {
				if !lastPage {
					marker = page.Marker
				}
				return false
			}
			return true
		})
	return
}

// describeDBSnapshots provides information about the snapshots of an RDS instance
func describeDBSnapshots(rdsSvc rdsiface.RDSAPI, dbID *string) (snapshots []*rds.DBSnapshot, err error) {
	err = rdsSvc.DescribeDBSnapshotsPages(&rds.DescribeDBSnapshotsInput{DBInstanceIdentifier: dbID},
		func(page *rds.DescribeDBSnapshotsOutput, lastPage bool) bool {
			snapshots = append(snapshots, page.DBSnapshots...)
			return true
		})
	if err != nil {
		return nil, err
	}
	return
}

// describeDBSnapshot Attributes provides information about a given RDS Instance snapshot
func describeDBSnapshotAttributes(rdsSvc rdsiface.RDSAPI, snapshotID *string) (*rds.DBSnapshotAttributesResult, error) {
	out, err := rdsSvc.DescribeDBSnapshotAttributes(
		&rds.DescribeDBSnapshotAttributesInput{DBSnapshotIdentifier: snapshotID},
	)
	if err != nil {
		utils.LogAWSError("RDS.DescribeDBSnapshots", err)
		return nil, err
	}
	return out.DBSnapshotAttributesResult, nil
}

// listTagsForResource returns all the tags for the given RDS instance
func listTagsForResourceRds(svc rdsiface.RDSAPI, arn *string) ([]*rds.Tag, error) {
	tags, err := svc.ListTagsForResource(&rds.ListTagsForResourceInput{ResourceName: arn})
	if err != nil {
		utils.LogAWSError("RDS.ListTagsForResource", err)
		return nil, err
	}

	return tags.TagList, nil
}

// buildRDSInstanceSnapshot makes all the calls to build up a snapshot of a given RDS DB instance
func buildRDSInstanceSnapshot(rdsSvc rdsiface.RDSAPI, instance *rds.DBInstance) *awsmodels.RDSInstance {
	if instance == nil {
		return nil
	}

	instanceSnapshot := &awsmodels.RDSInstance{
		GenericResource: awsmodels.GenericResource{
			ResourceID:   instance.DBInstanceArn,
			TimeCreated:  utils.DateTimeFormat(*instance.InstanceCreateTime),
			ResourceType: aws.String(awsmodels.RDSInstanceSchema),
		},
		GenericAWSResource: awsmodels.GenericAWSResource{
			ARN:  instance.DBInstanceArn,
			ID:   instance.DBInstanceIdentifier,
			Name: instance.DBName,
		},
		AllocatedStorage:                      instance.AllocatedStorage,
		AssociatedRoles:                       instance.AssociatedRoles,
		AutoMinorVersionUpgrade:               instance.AutoMinorVersionUpgrade,
		AvailabilityZone:                      instance.AvailabilityZone,
		BackupRetentionPeriod:                 instance.BackupRetentionPeriod,
		CACertificateIdentifier:               instance.CACertificateIdentifier,
		CharacterSetName:                      instance.CharacterSetName,
		CopyTagsToSnapshot:                    instance.CopyTagsToSnapshot,
		DBClusterIdentifier:                   instance.DBClusterIdentifier,
		DBInstanceClass:                       instance.DBInstanceClass,
		DBInstanceStatus:                      instance.DBInstanceStatus,
		DBParameterGroups:                     instance.DBParameterGroups,
		DBSecurityGroups:                      instance.DBSecurityGroups,
		DBSubnetGroup:                         instance.DBSubnetGroup,
		DbInstancePort:                        instance.DbInstancePort,
		DbiResourceId:                         instance.DbiResourceId,
		DeletionProtection:                    instance.DeletionProtection,
		DomainMemberships:                     instance.DomainMemberships,
		EnabledCloudwatchLogsExports:          instance.EnabledCloudwatchLogsExports,
		Endpoint:                              instance.Endpoint,
		Engine:                                instance.Engine,
		EngineVersion:                         instance.EngineVersion,
		EnhancedMonitoringResourceArn:         instance.EnhancedMonitoringResourceArn,
		IAMDatabaseAuthenticationEnabled:      instance.IAMDatabaseAuthenticationEnabled,
		Iops:                                  instance.Iops,
		KmsKeyId:                              instance.KmsKeyId,
		LatestRestorableTime:                  instance.LatestRestorableTime,
		LicenseModel:                          instance.LicenseModel,
		ListenerEndpoint:                      instance.ListenerEndpoint,
		MasterUsername:                        instance.MasterUsername,
		MaxAllocatedStorage:                   instance.MaxAllocatedStorage,
		MonitoringInterval:                    instance.MonitoringInterval,
		MonitoringRoleArn:                     instance.MonitoringRoleArn,
		MultiAZ:                               instance.MultiAZ,
		OptionGroupMemberships:                instance.OptionGroupMemberships,
		PendingModifiedValues:                 instance.PendingModifiedValues,
		PerformanceInsightsEnabled:            instance.PerformanceInsightsEnabled,
		PerformanceInsightsKMSKeyId:           instance.PerformanceInsightsKMSKeyId,
		PerformanceInsightsRetentionPeriod:    instance.PerformanceInsightsRetentionPeriod,
		PreferredBackupWindow:                 instance.PreferredBackupWindow,
		PreferredMaintenanceWindow:            instance.PreferredMaintenanceWindow,
		ProcessorFeatures:                     instance.ProcessorFeatures,
		PromotionTier:                         instance.PromotionTier,
		PubliclyAccessible:                    instance.PubliclyAccessible,
		ReadReplicaDBClusterIdentifiers:       instance.ReadReplicaDBClusterIdentifiers,
		ReadReplicaDBInstanceIdentifiers:      instance.ReadReplicaDBInstanceIdentifiers,
		ReadReplicaSourceDBInstanceIdentifier: instance.ReadReplicaSourceDBInstanceIdentifier,
		SecondaryAvailabilityZone:             instance.SecondaryAvailabilityZone,
		StatusInfos:                           instance.StatusInfos,
		StorageEncrypted:                      instance.StorageEncrypted,
		StorageType:                           instance.StorageType,
		TdeCredentialArn:                      instance.TdeCredentialArn,
		Timezone:                              instance.Timezone,
		VpcSecurityGroups:                     instance.VpcSecurityGroups,
	}

	tags, err := listTagsForResourceRds(rdsSvc, instance.DBInstanceArn)
	if err == nil {
		instanceSnapshot.Tags = utils.ParseTagSlice(tags)
	}

	dbSnapshots, err := describeDBSnapshots(rdsSvc, instance.DBInstanceIdentifier)
	if err != nil {
		utils.LogAWSError("RDS.DescribeDBSnapshots", err)
	} else {
		for _, dbSnapshot := range dbSnapshots {
			attributes, err := describeDBSnapshotAttributes(rdsSvc, dbSnapshot.DBSnapshotIdentifier)
			if err == nil {
				instanceSnapshot.SnapshotAttributes = append(instanceSnapshot.SnapshotAttributes, attributes)
			}
		}
	}

	return instanceSnapshot
}

// PollRDSInstances gathers information on each RDS DB Instance for an AWS account.
func PollRDSInstances(pollerInput *awsmodels.ResourcePollerInput) ([]*apimodels.AddResourceEntry, *string, error) {
	zap.L().Debug("starting RDS Instance resource poller")
	rdsInstanceSnapshots := make(map[string]*awsmodels.RDSInstance)

	rdsSvc, err := getRDSClient(pollerInput, *pollerInput.Region)
	if err != nil {
		return nil, nil, err
	}

	// Start with generating a list of all instances
	instances, marker, err := describeDBInstances(rdsSvc, pollerInput.NextPageToken)
	if err != nil {
		return nil, nil, err
	}
	if len(instances) == 0 {
		zap.L().Debug("No RDS instances found.", zap.String("region", *pollerInput.Region))
		return nil, nil, nil
	}

	for _, instance := range instances {
		rdsInstanceSnapshot := buildRDSInstanceSnapshot(rdsSvc, instance)
		if rdsInstanceSnapshot == nil {
			continue
		}
		rdsInstanceSnapshot.AccountID = aws.String(pollerInput.AuthSourceParsedARN.AccountID)
		rdsInstanceSnapshot.Region = pollerInput.Region
		if _, ok := rdsInstanceSnapshots[*rdsInstanceSnapshot.ARN]; !ok {
			rdsInstanceSnapshots[*rdsInstanceSnapshot.ARN] = rdsInstanceSnapshot
		} else {
			zap.L().Info(
				"overwriting existing RDS Instance snapshot",
				zap.String("resourceID", *rdsInstanceSnapshot.ARN),
			)
			rdsInstanceSnapshots[*rdsInstanceSnapshot.ARN] = rdsInstanceSnapshot
		}
	}

	resources := make([]*apimodels.AddResourceEntry, 0, len(rdsInstanceSnapshots))
	for resourceID, instanceSnapshot := range rdsInstanceSnapshots {
		resources = append(resources, &apimodels.AddResourceEntry{
			Attributes:      instanceSnapshot,
			ID:              apimodels.ResourceID(resourceID),
			IntegrationID:   apimodels.IntegrationID(*pollerInput.IntegrationID),
			IntegrationType: apimodels.IntegrationTypeAws,
			Type:            awsmodels.RDSInstanceSchema,
		})
	}

	return resources, marker, nil
}
