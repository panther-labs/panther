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
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	apimodels "github.com/panther-labs/panther/api/lambda/resources/models"
	awsmodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
	pollermodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/poller"
	"github.com/panther-labs/panther/internal/compliance/snapshot_poller/pollers/utils"
)

// PollEC2Instance polls a single EC2 Instance resource
func PollEC2Instance(
	pollerResourceInput *awsmodels.ResourcePollerInput,
	resourceARN arn.ARN,
	scanRequest *pollermodels.ScanEntry,
) (interface{}, error) {

	ec2Client, err := getEC2Client(pollerResourceInput, resourceARN.Region)
	if err != nil {
		return nil, err
	}

	instanceID := strings.Replace(resourceARN.Resource, "instance/", "", 1)
	instance, err := getInstance(ec2Client, aws.String(instanceID))
	if err != nil {
		return nil, err
	}

	snapshot := buildEc2InstanceSnapshot(instance)
	if snapshot == nil {
		return nil, nil
	}
	snapshot.ResourceID = scanRequest.ResourceID
	snapshot.AccountID = aws.String(resourceARN.AccountID)
	snapshot.Region = aws.String(resourceARN.Region)
	snapshot.ARN = scanRequest.ResourceID
	return snapshot, nil
}

// getInstance returns a specific EC2 instance
func getInstance(svc ec2iface.EC2API, instanceID *string) (*ec2.Instance, error) {
	instance, err := svc.DescribeInstances(&ec2.DescribeInstancesInput{
		InstanceIds: []*string{instanceID},
	})
	if err != nil {
		var awsErr awserr.Error
		if errors.As(err, &awsErr) && awsErr.Code() == "InvalidInstanceID.NotFound" {
			zap.L().Warn("tried to scan non-existent resource",
				zap.String("resource", *instanceID),
				zap.String("resourceType", awsmodels.Ec2InstanceSchema))
			return nil, nil
		}
		return nil, errors.Wrapf(err, "EC2.DescribeInstances: %s", aws.StringValue(instanceID))
	}

	if len(instance.Reservations) != 1 || len(instance.Reservations[0].Instances) != 1 {
		instances := 0
		for _, reservation := range instance.Reservations {
			instances += len(reservation.Instances)
		}
		return nil, errors.WithMessagef(
			errors.New("EC2.DescribeInstances"),
			"expected exactly 1 reservation & 1 instance from EC2.DescribeInstances when describing %s, found %d reservations and %d instances",
			aws.StringValue(instanceID),
			len(instance.Reservations),
			instances,
		)
	}
	return instance.Reservations[0].Instances[0], nil
}

// describeInstances returns all EC2 instances in the current region
func describeInstances(ec2Svc ec2iface.EC2API, nextMarker *string) (instances []*ec2.Instance, marker *string, err error) {
	err = ec2Svc.DescribeInstancesPages(&ec2.DescribeInstancesInput{
		NextToken:  nextMarker,
		MaxResults: aws.Int64(int64(defaultBatchSize)),
	},
		func(page *ec2.DescribeInstancesOutput, lastPage bool) bool {
			return ec2InstanceIterator(page, &instances, &marker)
		})
	if err != nil {
		return nil, nil, errors.Wrap(err, "EC2.DescribeInstances")
	}
	return
}

func ec2InstanceIterator(page *ec2.DescribeInstancesOutput, instances *[]*ec2.Instance, marker **string) bool {
	for _, reservation := range page.Reservations {
		*instances = append(*instances, reservation.Instances...)
	}
	*marker = page.NextToken
	return len(*instances) < defaultBatchSize
}

// buildEc2InstanceSnapshot makes the necessary API calls to build a full Ec2InstanceSnapshot
func buildEc2InstanceSnapshot(instance *ec2.Instance) *awsmodels.Ec2Instance {
	if instance == nil {
		return nil
	}
	return &awsmodels.Ec2Instance{
		GenericResource: awsmodels.GenericResource{
			TimeCreated:  instance.LaunchTime,
			ResourceType: aws.String(awsmodels.Ec2InstanceSchema),
		},
		GenericAWSResource: awsmodels.GenericAWSResource{
			ID:   instance.InstanceId,
			Tags: utils.ParseTagSlice(instance.Tags),
		},
		AmiLaunchIndex:                          instance.AmiLaunchIndex,
		Architecture:                            instance.Architecture,
		BlockDeviceMappings:                     instance.BlockDeviceMappings,
		CapacityReservationId:                   instance.CapacityReservationId,
		CapacityReservationSpecification:        instance.CapacityReservationSpecification,
		ClientToken:                             instance.ClientToken,
		CpuOptions:                              instance.CpuOptions,
		EbsOptimized:                            instance.EbsOptimized,
		ElasticGpuAssociations:                  instance.ElasticGpuAssociations,
		ElasticInferenceAcceleratorAssociations: instance.ElasticInferenceAcceleratorAssociations,
		EnaSupport:                              instance.EnaSupport,
		HibernationOptions:                      instance.HibernationOptions,
		Hypervisor:                              instance.Hypervisor,
		IamInstanceProfile:                      instance.IamInstanceProfile,
		ImageId:                                 instance.ImageId,
		InstanceLifecycle:                       instance.InstanceLifecycle,
		InstanceType:                            instance.InstanceType,
		KernelId:                                instance.KernelId,
		KeyName:                                 instance.KeyName,
		Licenses:                                instance.Licenses,
		MetadataOptions:                         instance.MetadataOptions,
		Monitoring:                              instance.Monitoring,
		NetworkInterfaces:                       instance.NetworkInterfaces,
		Placement:                               instance.Placement,
		Platform:                                instance.Platform,
		PrivateDnsName:                          instance.PrivateDnsName,
		PrivateIpAddress:                        instance.PrivateIpAddress,
		ProductCodes:                            instance.ProductCodes,
		PublicDnsName:                           instance.PublicDnsName,
		PublicIpAddress:                         instance.PublicIpAddress,
		RamdiskId:                               instance.RamdiskId,
		RootDeviceName:                          instance.RootDeviceName,
		RootDeviceType:                          instance.RootDeviceType,
		SecurityGroups:                          instance.SecurityGroups,
		SourceDestCheck:                         instance.SourceDestCheck,
		SpotInstanceRequestId:                   instance.SpotInstanceRequestId,
		SriovNetSupport:                         instance.SriovNetSupport,
		State:                                   instance.State,
		StateReason:                             instance.StateReason,
		StateTransitionReason:                   instance.StateTransitionReason,
		SubnetId:                                instance.SubnetId,
		VirtualizationType:                      instance.VirtualizationType,
		VpcId:                                   instance.VpcId,
	}
}

// PollEc2Instances gathers information on each EC2 instance in an AWS account.
func PollEc2Instances(pollerInput *awsmodels.ResourcePollerInput) ([]apimodels.AddResourceEntry, *string, error) {
	zap.L().Debug("starting EC2 Instance resource poller")

	ec2Svc, err := getEC2Client(pollerInput, *pollerInput.Region)
	if err != nil {
		return nil, nil, err
	}

	// Start with generating a list of all EC2 instances
	instances, marker, err := describeInstances(ec2Svc, pollerInput.NextPageToken)
	if err != nil {
		return nil, nil, errors.WithMessagef(err, "region: %s", *pollerInput.Region)
	}

	// For each instance, build out a full snapshot
	zap.L().Debug("building EC2 Instance snapshots", zap.String("region", *pollerInput.Region))
	resources := make([]apimodels.AddResourceEntry, 0, len(instances))
	for _, instance := range instances {
		ec2Instance := buildEc2InstanceSnapshot(instance)

		// arn:aws:ec2:region:account-id:instance/instance-id
		resourceID := strings.Join(
			[]string{
				"arn",
				pollerInput.AuthSourceParsedARN.Partition,
				"ec2",
				*pollerInput.Region,
				pollerInput.AuthSourceParsedARN.AccountID,
				"instance/" + *ec2Instance.ID,
			},
			":",
		)

		// Populate generic fields
		ec2Instance.ResourceID = aws.String(resourceID)

		// Populate AWS generic fields
		ec2Instance.AccountID = aws.String(pollerInput.AuthSourceParsedARN.AccountID)
		ec2Instance.Region = pollerInput.Region
		ec2Instance.ARN = aws.String(resourceID)

		resources = append(resources, apimodels.AddResourceEntry{
			Attributes:      ec2Instance,
			ID:              resourceID,
			IntegrationID:   *pollerInput.IntegrationID,
			IntegrationType: integrationType,
			Type:            awsmodels.Ec2InstanceSchema,
		})
	}

	return resources, marker, nil
}
