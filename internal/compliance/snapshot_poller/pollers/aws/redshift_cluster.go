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
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/redshift"
	"github.com/aws/aws-sdk-go/service/redshift/redshiftiface"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	apimodels "github.com/panther-labs/panther/api/lambda/resources/models"
	awsmodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
	pollermodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/poller"
	"github.com/panther-labs/panther/internal/compliance/snapshot_poller/pollers/utils"
)

// Set as variables to be overridden in testing
var (
	RedshiftClientFunc = setupRedshiftClient
)

func setupRedshiftClient(sess *session.Session, cfg *aws.Config) interface{} {
	return redshift.New(sess, cfg)
}

func getRedshiftClient(pollerResourceInput *awsmodels.ResourcePollerInput, region string) (redshiftiface.RedshiftAPI, error) {
	client, err := getClient(pollerResourceInput, RedshiftClientFunc, "redshift", region)
	if err != nil {
		return nil, err
	}

	return client.(redshiftiface.RedshiftAPI), nil
}

// PollRedshiftCluster polls a single Redshift Cluster resource
func PollRedshiftCluster(
	pollerResourceInput *awsmodels.ResourcePollerInput,
	resourceARN arn.ARN,
	scanRequest *pollermodels.ScanEntry,
) (interface{}, error) {

	client, err := getRedshiftClient(pollerResourceInput, resourceARN.Region)
	if err != nil {
		return nil, err
	}

	clusterID := strings.Replace(resourceARN.Resource, "cluster:", "", 1)
	redshiftCluster, err := getRedshiftCluster(client, aws.String(clusterID))
	if err != nil || redshiftCluster == nil {
		return nil, err
	}

	snapshot, err := buildRedshiftClusterSnapshot(client, redshiftCluster)
	if err != nil {
		return nil, err
	}
	snapshot.ResourceID = scanRequest.ResourceID
	snapshot.AccountID = aws.String(resourceARN.AccountID)
	snapshot.Region = aws.String(resourceARN.Region)
	snapshot.ARN = scanRequest.ResourceID
	return snapshot, nil
}

// getRedshiftCluster returns a specific redshift cluster
func getRedshiftCluster(svc redshiftiface.RedshiftAPI, clusterID *string) (*redshift.Cluster, error) {
	cluster, err := svc.DescribeClusters(&redshift.DescribeClustersInput{
		ClusterIdentifier: clusterID,
	})
	if err != nil {
		var awsErr awserr.Error
		if errors.As(err, &awsErr) && awsErr.Code() == redshift.ErrCodeClusterNotFoundFault {
			zap.L().Warn("tried to scan non-existent resource",
				zap.String("resource", *clusterID),
				zap.String("resourceType", awsmodels.RedshiftClusterSchema))
			return nil, nil
		}
		return nil, errors.Wrapf(err, "Redshift.DescribeClusters: %s", aws.StringValue(clusterID))
	}

	if len(cluster.Clusters) != 1 {
		return nil, errors.WithMessagef(
			errors.New("Redshift.DescribeClusters"),
			"expected exactly 1 cluster from Redshift.DescribeClusters when describing %s, found %d clusters",
			aws.StringValue(clusterID),
			len(cluster.Clusters),
		)
	}
	return cluster.Clusters[0], nil
}

// describeClusters returns a list of all redshift cluster in the account
func describeClusters(redshiftSvc redshiftiface.RedshiftAPI, nextMarker *string) (clusters []*redshift.Cluster, marker *string, err error) {
	err = redshiftSvc.DescribeClustersPages(&redshift.DescribeClustersInput{
		Marker:     nextMarker,
		MaxRecords: aws.Int64(int64(defaultBatchSize)),
	},
		func(page *redshift.DescribeClustersOutput, lastPage bool) bool {
			return redshiftClusterIterator(page, &clusters, &marker)
		})
	if err != nil {
		return nil, nil, errors.Wrap(err, "Redshift.DescribeClustersPages")
	}
	return
}

func redshiftClusterIterator(page *redshift.DescribeClustersOutput, clusters *[]*redshift.Cluster, marker **string) bool {
	*clusters = append(*clusters, page.Clusters...)
	*marker = page.Marker
	return len(*clusters) < defaultBatchSize
}

// describeLoggingStatus determines whether or not a redshift cluster has logging enabled
func describeLoggingStatus(redshiftSvc redshiftiface.RedshiftAPI, clusterID *string) (*redshift.LoggingStatus, error) {
	out, err := redshiftSvc.DescribeLoggingStatus(
		&redshift.DescribeLoggingStatusInput{ClusterIdentifier: clusterID},
	)
	if err != nil {
		return nil, errors.Wrapf(err, "Redshift.DescribeLoggingStatus: %s", aws.StringValue(clusterID))
	}
	return out, nil
}

// buildRedshiftClusterSnapshot makes all the calls to build up a snapshot of a given Redshift cluster
func buildRedshiftClusterSnapshot(redshiftSvc redshiftiface.RedshiftAPI, cluster *redshift.Cluster) (*awsmodels.RedshiftCluster, error) {
	clusterSnapshot := &awsmodels.RedshiftCluster{
		GenericResource: awsmodels.GenericResource{
			TimeCreated:  cluster.ClusterCreateTime,
			ResourceType: aws.String(awsmodels.RedshiftClusterSchema),
		},
		GenericAWSResource: awsmodels.GenericAWSResource{
			Name: cluster.DBName,
			ID:   cluster.ClusterIdentifier,
			Tags: utils.ParseTagSlice(cluster.Tags),
		},
		AllowVersionUpgrade:              cluster.AllowVersionUpgrade,
		AutomatedSnapshotRetentionPeriod: cluster.AutomatedSnapshotRetentionPeriod,
		AvailabilityZone:                 cluster.AvailabilityZone,
		ClusterAvailabilityStatus:        cluster.ClusterAvailabilityStatus,
		ClusterNodes:                     cluster.ClusterNodes,
		ClusterParameterGroups:           cluster.ClusterParameterGroups,
		ClusterPublicKey:                 cluster.ClusterPublicKey,
		ClusterRevisionNumber:            cluster.ClusterRevisionNumber,
		ClusterSecurityGroups:            cluster.ClusterSecurityGroups,
		ClusterSnapshotCopyStatus:        cluster.ClusterSnapshotCopyStatus,
		ClusterStatus:                    cluster.ClusterStatus,
		ClusterSubnetGroupName:           cluster.ClusterSubnetGroupName,
		ClusterVersion:                   cluster.ClusterVersion,
		DataTransferProgress:             cluster.DataTransferProgress,
		DeferredMaintenanceWindows:       cluster.DeferredMaintenanceWindows,
		ElasticIpStatus:                  cluster.ElasticIpStatus,
		ElasticResizeNumberOfNodeOptions: cluster.ElasticResizeNumberOfNodeOptions,
		Encrypted:                        cluster.Encrypted,
		Endpoint:                         cluster.Endpoint,
		EnhancedVpcRouting:               cluster.EnhancedVpcRouting,
		HsmStatus:                        cluster.HsmStatus,
		IamRoles:                         cluster.IamRoles,
		KmsKeyId:                         cluster.KmsKeyId,
		MaintenanceTrackName:             cluster.MaintenanceTrackName,
		ManualSnapshotRetentionPeriod:    cluster.ManualSnapshotRetentionPeriod,
		MasterUsername:                   cluster.MasterUsername,
		ModifyStatus:                     cluster.ModifyStatus,
		NodeType:                         cluster.NodeType,
		NumberOfNodes:                    cluster.NumberOfNodes,
		PendingActions:                   cluster.PendingActions,
		PendingModifiedValues:            cluster.PendingModifiedValues,
		PreferredMaintenanceWindow:       cluster.PreferredMaintenanceWindow,
		PubliclyAccessible:               cluster.PubliclyAccessible,
		ResizeInfo:                       cluster.ResizeInfo,
		RestoreStatus:                    cluster.RestoreStatus,
		SnapshotScheduleIdentifier:       cluster.SnapshotScheduleIdentifier,
		SnapshotScheduleState:            cluster.SnapshotScheduleState,
		VpcId:                            cluster.VpcId,
		VpcSecurityGroups:                cluster.VpcSecurityGroups,
	}

	loggingStatus, err := describeLoggingStatus(redshiftSvc, cluster.ClusterIdentifier)
	if err != nil {
		return nil, err
	}
	clusterSnapshot.LoggingStatus = loggingStatus

	return clusterSnapshot, nil
}

// PollRedshiftClusters gathers information on each Redshift Cluster for an AWS account.
func PollRedshiftClusters(pollerInput *awsmodels.ResourcePollerInput) ([]apimodels.AddResourceEntry, *string, error) {
	zap.L().Debug("starting Redshift Cluster resource poller")
	redshiftSvc, err := getRedshiftClient(pollerInput, *pollerInput.Region)
	if err != nil {
		return nil, nil, err
	}

	// Start with generating a list of all clusters
	clusters, marker, err := describeClusters(redshiftSvc, pollerInput.NextPageToken)
	if err != nil {
		return nil, nil, errors.WithMessagef(err, "region: %s", *pollerInput.Region)
	}

	resources := make([]apimodels.AddResourceEntry, 0, len(clusters))
	for _, cluster := range clusters {
		redshiftClusterSnapshot, err := buildRedshiftClusterSnapshot(redshiftSvc, cluster)
		if err != nil {
			return nil, nil, err
		}

		resourceID := strings.Join(
			[]string{
				"arn",
				pollerInput.AuthSourceParsedARN.Partition,
				"redshift",
				*pollerInput.Region,
				pollerInput.AuthSourceParsedARN.AccountID,
				"cluster",
				*redshiftClusterSnapshot.ID},
			":",
		)
		// Populate generic fields
		redshiftClusterSnapshot.ResourceID = aws.String(resourceID)

		// Populate AWS generic fields
		redshiftClusterSnapshot.AccountID = aws.String(pollerInput.AuthSourceParsedARN.AccountID)
		redshiftClusterSnapshot.Region = pollerInput.Region
		redshiftClusterSnapshot.ARN = aws.String(resourceID)

		resources = append(resources, apimodels.AddResourceEntry{
			Attributes:      redshiftClusterSnapshot,
			ID:              resourceID,
			IntegrationID:   *pollerInput.IntegrationID,
			IntegrationType: integrationType,
			Type:            awsmodels.RedshiftClusterSchema,
		})
	}

	return resources, marker, nil
}
