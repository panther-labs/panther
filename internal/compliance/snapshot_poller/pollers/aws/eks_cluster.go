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
	"github.com/aws/aws-sdk-go/service/eks"
	"github.com/aws/aws-sdk-go/service/eks/eksiface"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	apimodels "github.com/panther-labs/panther/api/gateway/resources/models"
	awsmodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
	pollermodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/poller"
	"github.com/panther-labs/panther/internal/compliance/snapshot_poller/pollers/utils"
)

// Set as variables to be overridden in testing
var EksClientFunc = setupEksClient

func setupEksClient(sess *session.Session, cfg *aws.Config) interface{} {
	return eks.New(sess, cfg)
}

func getEksClient(pollerResourceInput *awsmodels.ResourcePollerInput, region string) (eksiface.EKSAPI, error) {
	client, err := getClient(pollerResourceInput, EksClientFunc, "eks", region)
	if err != nil {
		return nil, err
	}

	return client.(eksiface.EKSAPI), nil
}

// PollEKSCluster polls a single EKS cluster resource
func PollEKSCluster(
	pollerInput *awsmodels.ResourcePollerInput,
	resourceARN arn.ARN,
	scanRequest *pollermodels.ScanEntry,
) (interface{}, error) {

	client, err := getEksClient(pollerInput, resourceARN.Region)
	if err != nil {
		return nil, err
	}

	snapshot, err := buildEksClusterSnapshot(client, scanRequest.ResourceID)
	if err != nil {
		return nil, err
	}
	if snapshot == nil {
		return nil, nil
	}
	snapshot.Region = aws.String(resourceARN.Region)
	snapshot.AccountID = aws.String(resourceARN.AccountID)

	return snapshot, nil
}

// listEKSClusters returns all EKS clusters in the account
func listEKSClusters(eksSvc eksiface.EKSAPI, nextMarker *string) (clusters []*string, marker *string, err error) {
	err = eksSvc.ListClustersPages(&eks.ListClustersInput{
		NextToken:  nextMarker,
		MaxResults: aws.Int64(int64(defaultBatchSize)),
	},
		func(page *eks.ListClustersOutput, lastPage bool) bool {
			return eksClusterIterator(page, &clusters, &marker)
		})
	if err != nil {
		return nil, nil, errors.Wrap(err, "EKS.ListClustersPages")
	}
	return
}

func eksClusterIterator(page *eks.ListClustersOutput, clusters *[]*string, marker **string) bool {
	*clusters = append(*clusters, page.Clusters...)
	*marker = page.NextToken
	return len(*clusters) < defaultBatchSize
}

// describeEKSCluster provides detailed information for a given EKS cluster
func describeEKSCluster(eksSvc eksiface.EKSAPI, clusterName *string) (*eks.Cluster, error) {
	out, err := eksSvc.DescribeCluster(&eks.DescribeClusterInput{
		Name: clusterName,
	})
	if err != nil {
		return nil, errors.Wrapf(err, "EKS.DescribeClusters: %s", aws.StringValue(clusterName))
	}

	// Unlike describeECSCluster, we can only make an API call to describe a single cluster
	// Thus, we do not need to check then length of the returned output

	return out.Cluster, nil
}

// getEKSFargateProfile enumerates and then describes all Fargate Profiles of a cluster
func getEKSFargateProfile(eksSvc eksiface.EKSAPI, clusterName *string) ([]*awsmodels.EksFargateProfile, error) {
	// Enumerate tasks
	var fargateProfileNames []*string
	err := eksSvc.ListFargateProfilesPages(&eks.ListFargateProfilesInput{ClusterName: clusterName},
		func(page *eks.ListFargateProfilesOutput, lastPage bool) bool {
			fargateProfileNames = append(fargateProfileNames, page.FargateProfileNames...)
			return true
		})

	if err != nil {
		return nil, errors.Wrapf(err, "EKS.ListTasksPages: %s", aws.StringValue(clusterName))
	}

	// If there are no fargate profiles stop here
	if len(fargateProfileNames) == 0 {
		return nil, nil
	}

	// Describe fargate profiles
	fargateProfiles := make([]*awsmodels.EksFargateProfile, 0, len(fargateProfileNames))

	// Slightly different from the ECS Clusters since we have to make a call to describe each FargateProfile
	// rather than batching them all together.
	for _, fargateProfile := range fargateProfileNames {
		rawFargateProfile, err := eksSvc.DescribeFargateProfile(&eks.DescribeFargateProfileInput{
			ClusterName:        clusterName,
			FargateProfileName: fargateProfile,
		})

		if err != nil {
			return nil, errors.Wrapf(err, "EKS.DescribeFargateProfile: %s", aws.StringValue(clusterName))
		}

		profile := *rawFargateProfile.FargateProfile

		fargateProfiles = append(fargateProfiles, &awsmodels.EksFargateProfile{
			GenericAWSResource: awsmodels.GenericAWSResource{
				ARN:  profile.FargateProfileArn,
				Tags: utils.ParseTagSlice(profile.Tags),
			},
			FargateProfileArn:   profile.FargateProfileArn,
			FargateProfileName:  fargateProfile,
			PodExecutionRoleArn: profile.PodExecutionRoleArn,
			Selectors:           profile.Selectors,
			Status:              profile.Status,
			Subnets:             profile.Subnets,
			// Normalised Name for CreatedAt
			TimeCreated: utils.DateTimeFormat(aws.TimeValue(profile.CreatedAt)),
		})
	}

	return fargateProfiles, nil
}

// getEKSNodeGroups enumerates and then describes all active node groups of a cluster
func getEKSNodegroups(eksSvc eksiface.EKSAPI, clusterName *string) ([]*awsmodels.EksNodegroup, error) {
	// Enumerate Nodegroups
	var nodeGroups []*string
	err := eksSvc.ListNodegroupsPages(&eks.ListNodegroupsInput{ClusterName: clusterName},
		func(page *eks.ListNodegroupsOutput, lastPage bool) bool {
			nodeGroups = append(nodeGroups, page.Nodegroups...)
			return true
		})

	if err != nil {
		return nil, errors.Wrapf(err, "EKS.ListNodegroupsPages: %s", aws.StringValue(clusterName))
	}

	// If there are no services, stop here
	if len(nodeGroups) == 0 {
		return nil, nil
	}

	// Describe Nodegroup
	nodegroupResults := make([]*awsmodels.EksNodegroup, 0, len(nodeGroups))

	for _, nodegroup := range nodeGroups {
		rawNodegroup, err := eksSvc.DescribeNodegroup(&eks.DescribeNodegroupInput{
			ClusterName:   clusterName,
			NodegroupName: nodegroup,
		})

		if err != nil {
			return nil, errors.Wrapf(err, "EKS.DescribeNodegroup: %s", aws.StringValue(nodegroup))
		}

		curNodegroup := *rawNodegroup.Nodegroup
		nodegroupResults = append(nodegroupResults, &awsmodels.EksNodegroup{
			GenericAWSResource: awsmodels.GenericAWSResource{
				ARN:  curNodegroup.NodegroupArn,
				Tags: utils.ParseTagSlice(curNodegroup.Tags),
			},
			AmiType:         curNodegroup.AmiType,
			DiskSize:        curNodegroup.DiskSize,
			Health:          curNodegroup.Health,
			InstanceTypes:   curNodegroup.InstanceTypes,
			LaunchTemplate:  curNodegroup.LaunchTemplate,
			NodegroupArn:    curNodegroup.NodegroupArn,
			NodegroupName:   curNodegroup.NodegroupName,
			NodeRole:        curNodegroup.NodeRole,
			ReleaseVersion:  curNodegroup.ReleaseVersion,
			RemoteAccess:    curNodegroup.RemoteAccess,
			Resources:       curNodegroup.Resources,
			ScalingConfig:   curNodegroup.ScalingConfig,
			Subnets:         curNodegroup.Subnets,
			Version:         curNodegroup.Version,
			// Normalized name for CreatedAt
			TimeCreated: utils.DateTimeFormat(aws.TimeValue(curNodegroup.CreatedAt)),
		})
	}

	return nodegroupResults, nil
}

// buildEksClusterSnapshot returns a complete snapshot of an EKS cluster
func buildEksClusterSnapshot(eksSvc eksiface.EKSAPI, clusterName *string) (*awsmodels.EksCluster, error) {
	if clusterName == nil {
		return nil, nil
	}

	details, err := describeEKSCluster(eksSvc, clusterName)
	// Can details ever be nil without an error?
	if err != nil || details == nil {
		return nil, err
	}

	eksCluster := &awsmodels.EksCluster{
		GenericAWSResource: awsmodels.GenericAWSResource{
			ARN:  details.Arn,
			Name: details.Name,
			Tags: utils.ParseTagSlice(details.Tags),
		},
		GenericResource: awsmodels.GenericResource{
			ResourceID:   details.Arn,
			ResourceType: aws.String(awsmodels.EksClusterSchema),
		},
		CertificateAuthority: details.CertificateAuthority,
		EncryptionConfig:     details.EncryptionConfig,
		Endpoint:             details.Endpoint,
		Identity:             details.Identity,
		Logging:              details.Logging,
		PlatformVersion:      details.PlatformVersion,
		ResourcesVpcConfig:   details.ResourcesVpcConfig,
		RoleArn:              details.RoleArn,
		Status:               details.Status,
		Version:              details.Version,
	}

	eksCluster.FargateProfile, err = getEKSFargateProfile(eksSvc, details.Name)
	if err != nil {
		return nil, err
	}

	eksCluster.NodeGroup, err = getEKSNodegroups(eksSvc, details.Name)
	if err != nil {
		return nil, err
	}

	return eksCluster, nil
}

// PollEksCluster gathers information on each EKS Cluster for an AWS account.
func PollEksClusters(pollerInput *awsmodels.ResourcePollerInput) ([]*apimodels.AddResourceEntry, *string, error) {
	zap.L().Debug("starting EKS Cluster resource poller")
	eksClusterSnapshots := make(map[string]*awsmodels.EksCluster)

	eksSvc, err := getEksClient(pollerInput, *pollerInput.Region)
	if err != nil {
		return nil, nil, err
	}

	// Start with generating a list of all clusters
	clusters, marker, err := listEKSClusters(eksSvc, pollerInput.NextPageToken)
	if err != nil {
		return nil, nil, errors.WithMessagef(err, "region: %s", *pollerInput.Region)
	}

	resources := make([]*apimodels.AddResourceEntry, 0, len(eksClusterSnapshots))
	for _, clusterArn := range clusters {
		eksClusterSnapshot, err := buildEksClusterSnapshot(eksSvc, clusterArn)
		if err != nil {
			return nil, nil, err
		}
		eksClusterSnapshot.AccountID = aws.String(pollerInput.AuthSourceParsedARN.AccountID)
		eksClusterSnapshot.Region = pollerInput.Region

		resources = append(resources, &apimodels.AddResourceEntry{
			Attributes:      eksClusterSnapshot,
			ID:              apimodels.ResourceID(*eksClusterSnapshot.ResourceID),
			IntegrationID:   apimodels.IntegrationID(*pollerInput.IntegrationID),
			IntegrationType: apimodels.IntegrationTypeAws,
			Type:            awsmodels.EksClusterSchema,
		})
	}

	return resources, marker, nil
}
