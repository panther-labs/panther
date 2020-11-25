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
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/rds"
	"github.com/aws/aws-sdk-go/service/rds/rdsiface"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	apimodels "github.com/panther-labs/panther/api/lambda/resources/models"
	awsmodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
	pollermodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/poller"
	"github.com/panther-labs/panther/internal/compliance/snapshot_poller/pollers/utils"
)

// RDS scanning regularly gets rate limited on the following API calls (in order of most to least
// likely to be rate limited):
//
//  - DescribeDBSnapshotAttributes
//  - DescribeDBSnapshots
//  - ListTagsForResource
//  - DescribeDBInstances
//
// By default though, RDS has a limit of 40 instances per region. For this reason, setting the batch
// size very low should not adversely affecting scanning times much and will hopefully avoid rate
// limits in most cases.
const rdsMaxBatchSize = 20

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
		return nil, err
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

	// If a snapshot was updated, the aws-event-processor is unable to determine which instance was
	// updated. In this case, the aws-event-processor forwards the snapshot ID instead of the instance
	// ID. So if we have received a snapshot ID, we must lookup the corresponding instance ID.
	//
	// Remember we must overwrite scanRequest.ResourceID, as this field is referenced in the calling
	// function when forwarding the resource snapshot.
	if strings.HasPrefix(resourceARN.Resource, "snapshot:") {
		zap.L().Debug("received snapshot ID, looking up corresponding instance", zap.String("snapshotID", resourceARN.String()))
		scanRequest.ResourceID, err = getRDSInstanceFromSnapshotID(rdsClient, resourceARN)
		if err != nil {
			return nil, err
		}
		zap.L().Debug("looked up instance ID for snapshot", zap.String("instanceID", aws.StringValue(scanRequest.ResourceID)))
	}

	rdsInstance, err := getRDSInstance(rdsClient, scanRequest.ResourceID)
	if err != nil || rdsInstance == nil {
		return nil, err
	}

	snapshot, err := buildRDSInstanceSnapshot(rdsClient, rdsInstance)
	if err != nil {
		return nil, err
	}
	snapshot.AccountID = aws.String(resourceARN.AccountID)
	snapshot.Region = aws.String(resourceARN.Region)
	return snapshot, nil
}

func getRDSInstanceFromSnapshotID(svc rdsiface.RDSAPI, snapshotARN arn.ARN) (*string, error) {
	snapshot, err := svc.DescribeDBSnapshots(&rds.DescribeDBSnapshotsInput{
		DBSnapshotIdentifier: aws.String(snapshotARN.String()),
	})
	if err != nil {
		return nil, err
	}
	snapshotARN.Resource = "db:" + aws.StringValue(snapshot.DBSnapshots[0].DBInstanceIdentifier)
	return aws.String(snapshotARN.String()), nil
}

// getRDSInstance returns a specific RDS instance
func getRDSInstance(svc rdsiface.RDSAPI, instanceARN *string) (*rds.DBInstance, error) {
	instance, err := svc.DescribeDBInstances(&rds.DescribeDBInstancesInput{
		Filters: []*rds.Filter{
			{
				Name:   aws.String("db-instance-id"),
				Values: []*string{instanceARN},
			},
		},
	})
	if err != nil {
		return nil, errors.Wrapf(err, "RDS.DescribeDBInstances: %s", aws.StringValue(instanceARN))
	}

	if len(instance.DBInstances) == 0 {
		zap.L().Warn("tried to scan non-existent resource",
			zap.String("resource", *instanceARN),
			zap.String("resourceType", awsmodels.RDSInstanceSchema))
		return nil, nil
	}
	if len(instance.DBInstances) != 1 {
		return nil, errors.WithMessagef(
			errors.New("RDS.DescribeDBInstances"),
			"expected exactly 1 DB Instance from RDS.DescribeDBInstances when describing %s, found %d DB instances",
			aws.StringValue(instanceARN),
			len(instance.DBInstances),
		)
	}
	return instance.DBInstances[0], nil
}

// describeDbInstance returns a list of all RDS Instances in the account
func describeDBInstances(rdsSvc rdsiface.RDSAPI, nextMarker *string) (instances []*rds.DBInstance, marker *string, err error) {
	err = rdsSvc.DescribeDBInstancesPages(&rds.DescribeDBInstancesInput{
		Marker:     nextMarker,
		MaxRecords: aws.Int64(int64(rdsMaxBatchSize)),
	},
		func(page *rds.DescribeDBInstancesOutput, lastPage bool) bool {
			return rdsInstanceIterator(page, &instances, &marker)
		})
	if err != nil {
		return nil, nil, errors.Wrap(err, "RDS.DescribeDBInstancesPages")
	}
	return
}

func rdsInstanceIterator(page *rds.DescribeDBInstancesOutput, instances *[]*rds.DBInstance, marker **string) bool {
	*instances = append(*instances, page.DBInstances...)
	*marker = page.Marker
	return len(*instances) < rdsMaxBatchSize
}

// describeDBSnapshots provides information about the snapshots of an RDS instance
func describeDBSnapshots(rdsSvc rdsiface.RDSAPI, dbID *string) (snapshots []*rds.DBSnapshot, err error) {
	err = rdsSvc.DescribeDBSnapshotsPages(&rds.DescribeDBSnapshotsInput{DBInstanceIdentifier: dbID},
		func(page *rds.DescribeDBSnapshotsOutput, lastPage bool) bool {
			snapshots = append(snapshots, page.DBSnapshots...)
			return true
		})
	if err != nil {
		return nil, errors.Wrapf(err, "RDS.DescribeDBSnapshotsPages: %s", aws.StringValue(dbID))
	}
	return
}

// describeDBSnapshot Attributes provides information about a given RDS Instance snapshot
func describeDBSnapshotAttributes(rdsSvc rdsiface.RDSAPI, snapshotID *string) (*rds.DBSnapshotAttributesResult, error) {
	out, err := rdsSvc.DescribeDBSnapshotAttributes(
		&rds.DescribeDBSnapshotAttributesInput{DBSnapshotIdentifier: snapshotID},
	)
	if err != nil {
		return nil, errors.Wrapf(err, "RDS.DescribeDBSnapshots: %s", aws.StringValue(snapshotID))
	}
	return out.DBSnapshotAttributesResult, nil
}

// listTagsForResource returns all the tags for the given RDS instance
func listTagsForResourceRds(svc rdsiface.RDSAPI, arn *string) ([]*rds.Tag, error) {
	tags, err := svc.ListTagsForResource(&rds.ListTagsForResourceInput{ResourceName: arn})
	if err != nil {
		return nil, errors.Wrapf(err, "RDS.ListTagsForResource: %s", aws.StringValue(arn))
	}

	return tags.TagList, nil
}

// buildRDSInstanceSnapshot makes all the calls to build up a snapshot of a given RDS DB instance
func buildRDSInstanceSnapshot(rdsSvc rdsiface.RDSAPI, instance *rds.DBInstance) (*awsmodels.RDSInstance, error) {
	instanceSnapshot := &awsmodels.RDSInstance{
		GenericResource: awsmodels.GenericResource{
			ResourceID:   instance.DBInstanceArn,
			TimeCreated:  instance.InstanceCreateTime,
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
	if err != nil {
		return nil, err
	}
	instanceSnapshot.Tags = utils.ParseTagSlice(tags)

	dbSnapshots, err := describeDBSnapshots(rdsSvc, instance.DBInstanceIdentifier)
	if err != nil {
		return nil, err
	}
	for _, dbSnapshot := range dbSnapshots {
		attributes, err := describeDBSnapshotAttributes(rdsSvc, dbSnapshot.DBSnapshotIdentifier)
		if err != nil {
			return nil, err
		}
		instanceSnapshot.SnapshotAttributes = append(instanceSnapshot.SnapshotAttributes, attributes)
	}

	return instanceSnapshot, nil
}

// PollRDSInstances gathers information on each RDS DB Instance for an AWS account.
func PollRDSInstances(pollerInput *awsmodels.ResourcePollerInput) ([]apimodels.AddResourceEntry, *string, error) {
	zap.L().Debug("starting RDS Instance resource poller")

	rdsSvc, err := getRDSClient(pollerInput, *pollerInput.Region)
	if err != nil {
		return nil, nil, err
	}

	// Start with generating a list of all instances
	instances, marker, err := describeDBInstances(rdsSvc, pollerInput.NextPageToken)
	if err != nil {
		return nil, nil, errors.WithMessagef(err, "region: %s", *pollerInput.Region)
	}

	resources := make([]apimodels.AddResourceEntry, 0, len(instances))
	for _, instance := range instances {
		rdsInstanceSnapshot, err := buildRDSInstanceSnapshot(rdsSvc, instance)
		if err != nil {
			return nil, nil, err
		}
		rdsInstanceSnapshot.AccountID = aws.String(pollerInput.AuthSourceParsedARN.AccountID)
		rdsInstanceSnapshot.Region = pollerInput.Region

		resources = append(resources, apimodels.AddResourceEntry{
			Attributes:      rdsInstanceSnapshot,
			ID:              *rdsInstanceSnapshot.ResourceID,
			IntegrationID:   *pollerInput.IntegrationID,
			IntegrationType: integrationType,
			Type:            awsmodels.RDSInstanceSchema,
		})
	}

	return resources, marker, nil
}
