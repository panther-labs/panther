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
	"go.uber.org/zap"

	apimodels "github.com/panther-labs/panther/api/gateway/resources/models"
	awsmodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
	pollermodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/poller"
	"github.com/panther-labs/panther/internal/compliance/snapshot_poller/pollers/utils"
)

// PollEC2Volume polls a single EC2 Volume resource
func PollEC2Volume(
	pollerResourceInput *awsmodels.ResourcePollerInput,
	resourceARN arn.ARN,
	scanRequest *pollermodels.ScanEntry) (interface{}, error) {

	ec2Client, err := getEC2Client(pollerResourceInput, resourceARN.Region)
	if err != nil {
		return nil, err
	}

	volumeID := strings.Replace(resourceARN.Resource, "volume/", "", 1)
	volume := getVolume(ec2Client, aws.String(volumeID))
	snapshot := buildEc2VolumeSnapshot(ec2Client, volume)
	if snapshot == nil {
		return nil, nil
	}
	snapshot.ResourceID = scanRequest.ResourceID
	snapshot.AccountID = aws.String(resourceARN.AccountID)
	snapshot.Region = aws.String(resourceARN.Region)
	snapshot.ARN = scanRequest.ResourceID
	return snapshot, nil
}

// getVolume returns a specific EC2 volume
func getVolume(svc ec2iface.EC2API, volumeID *string) *ec2.Volume {
	volume, err := svc.DescribeVolumes(&ec2.DescribeVolumesInput{
		VolumeIds: []*string{volumeID},
	})
	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok {
			if awsErr.Code() == "InvalidVolume.NotFound" {
				zap.L().Warn("tried to scan non-existent resource",
					zap.String("resource", *volumeID),
					zap.String("resourceType", awsmodels.Ec2VolumeSchema))
				return nil
			}
		}
		utils.LogAWSError("EC2.DescribeVolumes", err)
		return nil
	}
	return volume.Volumes[0]
}

// describeVolumes returns all the EC2 volumes in the account
func describeVolumes(ec2Svc ec2iface.EC2API, nextMarker *string) (volumes []*ec2.Volume, marker *string) {
	err := ec2Svc.DescribeVolumesPages(&ec2.DescribeVolumesInput{
		NextToken: nextMarker,
	},
		func(page *ec2.DescribeVolumesOutput, lastPage bool) bool {
			volumes = append(volumes, page.Volumes...)
			if len(volumes) >= defaultBatchSize {
				if !lastPage {
					marker = page.NextToken
				}
				return false
			}
			return true
		})
	if err != nil {
		utils.LogAWSError("EC2.DescribeVolumes", err)
	}
	return
}

// describeSnapshots returns all the snapshots for a given EC2 volume
func describeSnapshots(ec2Svc ec2iface.EC2API, volumeID *string) (snapshots []*ec2.Snapshot) {
	in := &ec2.DescribeSnapshotsInput{Filters: []*ec2.Filter{
		{
			Name: aws.String("volume-id"),
			Values: []*string{
				volumeID,
			},
		}}}
	err := ec2Svc.DescribeSnapshotsPages(in,
		func(page *ec2.DescribeSnapshotsOutput, lastPage bool) bool {
			snapshots = append(snapshots, page.Snapshots...)
			return true
		})
	if err != nil {
		utils.LogAWSError("EC2.DescribeSnapshots", err)
	}
	return
}

// describeSnapshotAttribute returns the attributes for a given EC2 volume snapshot
func describeSnapshotAttribute(svc ec2iface.EC2API, snapshotID *string) ([]*ec2.CreateVolumePermission, error) {
	attributes, err := svc.DescribeSnapshotAttribute(&ec2.DescribeSnapshotAttributeInput{
		SnapshotId: snapshotID,
		Attribute:  aws.String("createVolumePermission")},
	)
	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok {
			if awsErr.Code() == "InvalidSnapshot.NotFound" {
				zap.L().Debug("invalid snapshot for attribute")
				return nil, err
			}
		}
		utils.LogAWSError("EC2.DescribeSnapshotAttributes", err)
		return nil, err
	}
	return attributes.CreateVolumePermissions, nil
}

// buildEc2VolumeSnapshot returns a complete snapshot of an EC2 Volume
func buildEc2VolumeSnapshot(ec2Svc ec2iface.EC2API, volume *ec2.Volume) *awsmodels.Ec2Volume {
	if volume == nil {
		return nil
	}

	ec2Volume := &awsmodels.Ec2Volume{
		GenericResource: awsmodels.GenericResource{
			TimeCreated:  utils.DateTimeFormat(*volume.CreateTime),
			ResourceType: aws.String(awsmodels.Ec2VolumeSchema),
		},
		GenericAWSResource: awsmodels.GenericAWSResource{
			ID:   volume.VolumeId,
			Tags: utils.ParseTagSlice(volume.Tags),
		},

		Attachments:      volume.Attachments,
		AvailabilityZone: volume.AvailabilityZone,
		Encrypted:        volume.Encrypted,
		Iops:             volume.Iops,
		KmsKeyId:         volume.KmsKeyId,
		Size:             volume.Size,
		SnapshotId:       volume.SnapshotId,
		State:            volume.State,
		VolumeType:       volume.VolumeType,
	}

	snapshots := describeSnapshots(ec2Svc, volume.VolumeId)
	if snapshots != nil {
		ec2Volume.Snapshots = make([]*awsmodels.Ec2Snapshot, 0, len(snapshots))
		for _, snapshot := range snapshots {
			volumeSnapshot := &awsmodels.Ec2Snapshot{Snapshot: snapshot}
			volumeAttribute, err := describeSnapshotAttribute(ec2Svc, snapshot.SnapshotId)
			if err == nil {
				volumeSnapshot.CreateVolumePermissions = volumeAttribute
			}
			ec2Volume.Snapshots = append(ec2Volume.Snapshots, volumeSnapshot)
		}
	}

	return ec2Volume
}

// PollEc2Volumes gathers information on each EC2 Volume for an AWS account.
func PollEc2Volumes(pollerInput *awsmodels.ResourcePollerInput) ([]*apimodels.AddResourceEntry, *string, error) {
	zap.L().Debug("starting EC2 Volume resource poller")
	ec2VolumeSnapshots := make(map[string]*awsmodels.Ec2Volume)

	ec2Svc, err := getEC2Client(pollerInput, *pollerInput.Region)
	if err != nil {
		return nil, nil, err
	}

	// Start with generating a list of all volumes
	volumes, marker := describeVolumes(ec2Svc, pollerInput.NextPageToken)
	if len(volumes) == 0 {
		zap.L().Debug("no EC2 Volumes found", zap.String("region", *pollerInput.Region))
		return nil, nil, nil
	}

	for _, volume := range volumes {
		ec2VolumeSnapshot := buildEc2VolumeSnapshot(ec2Svc, volume)
		if ec2VolumeSnapshot == nil {
			continue
		}

		// arn:aws:ec2:region:account-id:volume/volume-id
		resourceID := strings.Join(
			[]string{
				"arn",
				pollerInput.AuthSourceParsedARN.Partition,
				"ec2",
				*pollerInput.Region,
				pollerInput.AuthSourceParsedARN.AccountID,
				"volume/" + *ec2VolumeSnapshot.ID,
			},
			":",
		)
		// Populate generic fields
		ec2VolumeSnapshot.ResourceID = aws.String(resourceID)

		// Populate AWS generic fields
		ec2VolumeSnapshot.AccountID = aws.String(pollerInput.AuthSourceParsedARN.AccountID)
		ec2VolumeSnapshot.Region = pollerInput.Region
		ec2VolumeSnapshot.ARN = aws.String(resourceID)

		if _, ok := ec2VolumeSnapshots[resourceID]; !ok {
			ec2VolumeSnapshots[resourceID] = ec2VolumeSnapshot
		} else {
			zap.L().Info(
				"overwriting existing EC2 Volume snapshot",
				zap.String("resourceId", resourceID),
			)
			ec2VolumeSnapshots[resourceID] = ec2VolumeSnapshot
		}
	}

	resources := make([]*apimodels.AddResourceEntry, 0, len(ec2VolumeSnapshots))
	for resourceID, volumeSnapshot := range ec2VolumeSnapshots {
		resources = append(resources, &apimodels.AddResourceEntry{
			Attributes:      volumeSnapshot,
			ID:              apimodels.ResourceID(resourceID),
			IntegrationID:   apimodels.IntegrationID(*pollerInput.IntegrationID),
			IntegrationType: apimodels.IntegrationTypeAws,
			Type:            awsmodels.Ec2VolumeSchema,
		})
	}

	return resources, marker, nil
}
