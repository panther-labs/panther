package aws

/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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

	apimodels "github.com/panther-labs/panther/api/gateway/resources/models"
	awsmodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
	pollermodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/poller"
	"github.com/panther-labs/panther/internal/compliance/snapshot_poller/pollers/utils"
)

var (
	ec2Amis map[string][]*string
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
	instance := getInstance(ec2Client, aws.String(instanceID))

	snapshot := buildEc2InstanceSnapshot(ec2Client, instance)
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
func getInstance(svc ec2iface.EC2API, instanceID *string) *ec2.Instance {
	instance, err := svc.DescribeInstances(&ec2.DescribeInstancesInput{
		InstanceIds: []*string{instanceID},
	})
	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok {
			if awsErr.Code() == "InvalidInstanceID.NotFound" {
				zap.L().Warn("tried to scan non-existent resource",
					zap.String("resource", *instanceID),
					zap.String("resourceType", awsmodels.Ec2InstanceSchema))
				return nil
			}
		}
		utils.LogAWSError("EC2.DescribeInstances", err)
		return nil
	}

	return instance.Reservations[0].Instances[0]
}

// describeInstances returns all EC2 instances in the current region
func describeInstances(ec2Svc ec2iface.EC2API) (instances []*ec2.Instance, err error) {
	err = ec2Svc.DescribeInstancesPages(&ec2.DescribeInstancesInput{},
		func(page *ec2.DescribeInstancesOutput, lastPage bool) bool {
			for _, reservation := range page.Reservations {
				instances = append(instances, reservation.Instances...)
			}
			return true
		})
	if err != nil {
		return nil, errors.Wrap(err, "EC2.DescribeInstances")
	}
	return
}

// buildEc2InstanceSnapshot makes the necessary API calls to build a full Ec2InstanceSnapshot
func buildEc2InstanceSnapshot(_ ec2iface.EC2API, instance *ec2.Instance) *awsmodels.Ec2Instance {
	if instance == nil {
		return nil
	}
	ec2Instance := &awsmodels.Ec2Instance{
		GenericResource: awsmodels.GenericResource{
			TimeCreated:  utils.DateTimeFormat(*instance.LaunchTime),
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

	return ec2Instance
}

// PollEc2Instances gathers information on each EC2 instance in an AWS account.
func PollEc2Instances(pollerInput *awsmodels.ResourcePollerInput) ([]*apimodels.AddResourceEntry, error) {
	zap.L().Debug("starting EC2 Instance resource poller")
	ec2InstanceSnapshots := make(map[string]*awsmodels.Ec2Instance)

	// Reset list of AMIs
	ec2Amis = make(map[string][]*string)

	for _, regionID := range utils.GetServiceRegions(pollerInput.Regions, "ec2") {
		ec2Svc, err := getEC2Client(pollerInput, *regionID)
		if err != nil {
			continue // error is logged in getClient()
		}

		// Start with generating a list of all EC2 instances
		instances, err := describeInstances(ec2Svc)
		if err != nil {
			return nil, errors.Wrapf(err, "PollEc2Instances(%#v) in region %s", *pollerInput, *regionID)
		}

		// For each instance, build out a full snapshot
		zap.L().Debug("building EC2 Instance snapshots", zap.String("region", *regionID))
		for _, instance := range instances {
			ec2Instance := buildEc2InstanceSnapshot(ec2Svc, instance)

			// arn:aws:ec2:region:account-id:instance/instance-id
			resourceID := strings.Join(
				[]string{
					"arn",
					pollerInput.AuthSourceParsedARN.Partition,
					"ec2",
					*regionID,
					pollerInput.AuthSourceParsedARN.AccountID,
					"instance/" + *ec2Instance.ID,
				},
				":",
			)

			// Populate generic fields
			ec2Instance.ResourceID = aws.String(resourceID)

			// Populate AWS generic fields
			ec2Instance.AccountID = aws.String(pollerInput.AuthSourceParsedARN.AccountID)
			ec2Instance.Region = regionID
			ec2Instance.ARN = aws.String(resourceID)

			ec2Amis[*regionID] = append(ec2Amis[*regionID], ec2Instance.ImageId)
			if _, ok := ec2InstanceSnapshots[resourceID]; !ok {
				ec2InstanceSnapshots[resourceID] = ec2Instance
			} else {
				zap.L().Info("overwriting existing EC2 Instance snapshot", zap.String("resourceId", resourceID))
				ec2InstanceSnapshots[resourceID] = ec2Instance
			}
		}
	}

	resources := make([]*apimodels.AddResourceEntry, 0, len(ec2InstanceSnapshots))
	for resourceID, ec2InstanceSnapshot := range ec2InstanceSnapshots {
		resources = append(resources, &apimodels.AddResourceEntry{
			Attributes:      ec2InstanceSnapshot,
			ID:              apimodels.ResourceID(resourceID),
			IntegrationID:   apimodels.IntegrationID(*pollerInput.IntegrationID),
			IntegrationType: apimodels.IntegrationTypeAws,
			Type:            awsmodels.Ec2InstanceSchema,
		})
	}

	return resources, nil
}
