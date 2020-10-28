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
	volume, err := getVolume(ec2Client, aws.String(volumeID))
	if err != nil {
		return nil, err
	}

	snapshot, err := buildEc2VolumeSnapshot(ec2Client, volume)
	if err != nil {
		return nil, err
	}
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
func getVolume(svc ec2iface.EC2API, volumeID *string) (*ec2.Volume, error) {
	volume, err := svc.DescribeVolumes(&ec2.DescribeVolumesInput{
		VolumeIds: []*string{volumeID},
	})
	if err != nil {
		var awsErr awserr.Error
		if errors.As(err, &awsErr) && awsErr.Code() == "InvalidVolume.NotFound" {
			zap.L().Warn("tried to scan non-existent resource",
				zap.String("resource", *volumeID),
				zap.String("resourceType", awsmodels.Ec2VolumeSchema))
			return nil, nil
		}
		return nil, errors.Wrapf(err, "EC2.DescribeVolumes: %s", aws.StringValue(volumeID))
	}
	if len(volume.Volumes) != 1 {
		return nil, errors.WithMessagef(
			errors.New("EC2.DescribeVolumes"),
			"expected exactly one volume when describing %s, but found %d volumes",
			aws.StringValue(volumeID),
			len(volume.Volumes),
		)
	}
	return volume.Volumes[0], nil
}

// describeVolumes returns all the EC2 volumes in the account
func describeVolumes(ec2Svc ec2iface.EC2API, nextMarker *string) (volumes []*ec2.Volume, marker *string, err error) {
	err = ec2Svc.DescribeVolumesPages(&ec2.DescribeVolumesInput{
		NextToken:  nextMarker,
		MaxResults: aws.Int64(int64(defaultBatchSize)),
	},
		func(page *ec2.DescribeVolumesOutput, lastPage bool) bool {
			return ec2VolumeIterator(page, &volumes, &marker)
		})
	if err != nil {
		return nil, nil, errors.Wrap(err, "EC2.DescribeVolumes")
	}
	return
}

func ec2VolumeIterator(page *ec2.DescribeVolumesOutput, volumes *[]*ec2.Volume, marker **string) bool {
	*volumes = append(*volumes, page.Volumes...)
	*marker = page.NextToken
	return len(*volumes) < defaultBatchSize
}

// describeSnapshots returns all the snapshots for a given EC2 volume
func describeSnapshots(ec2Svc ec2iface.EC2API, volumeID *string) (snapshots []*ec2.Snapshot, err error) {
	in := &ec2.DescribeSnapshotsInput{Filters: []*ec2.Filter{
		{
			Name: aws.String("volume-id"),
			Values: []*string{
				volumeID,
			},
		}}}
	err = ec2Svc.DescribeSnapshotsPages(in,
		func(page *ec2.DescribeSnapshotsOutput, lastPage bool) bool {
			snapshots = append(snapshots, page.Snapshots...)
			return true
		})
	if err != nil {
		return nil, errors.Wrapf(err, "EC2.DescribeSnapshots: %s", aws.StringValue(volumeID))
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
		var awsErr awserr.Error
		if errors.As(err, &awsErr) && awsErr.Code() == "InvalidSnapshot.NotFound" {
			zap.L().Debug("invalid snapshot for attribute")
			return nil, err
		}
		return nil, errors.Wrapf(err, "EC2.DescribeSnapshotAttributes: %s", aws.StringValue(snapshotID))
	}
	return attributes.CreateVolumePermissions, nil
}

// buildEc2VolumeSnapshot returns a complete snapshot of an EC2 Volume
func buildEc2VolumeSnapshot(ec2Svc ec2iface.EC2API, volume *ec2.Volume) (*awsmodels.Ec2Volume, error) {
	if volume == nil {
		return nil, nil
	}

	ec2Volume := &awsmodels.Ec2Volume{
		GenericResource: awsmodels.GenericResource{
			TimeCreated:  volume.CreateTime,
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

	snapshots, err := describeSnapshots(ec2Svc, volume.VolumeId)
	if err != nil {
		return nil, err
	}
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

	return ec2Volume, nil
}

// PollEc2Volumes gathers information on each EC2 Volume for an AWS account.
func PollEc2Volumes(pollerInput *awsmodels.ResourcePollerInput) ([]apimodels.AddResourceEntry, *string, error) {
	zap.L().Debug("starting EC2 Volume resource poller")

	ec2Svc, err := getEC2Client(pollerInput, *pollerInput.Region)
	if err != nil {
		return nil, nil, err
	}

	// Start with generating a list of all volumes
	volumes, marker, err := describeVolumes(ec2Svc, pollerInput.NextPageToken)
	if err != nil {
		return nil, nil, errors.WithMessagef(err, "region: %s", *pollerInput.Region)
	}

	resources := make([]apimodels.AddResourceEntry, 0, len(volumes))
	for _, volume := range volumes {
		ec2VolumeSnapshot, err := buildEc2VolumeSnapshot(ec2Svc, volume)
		if err != nil {
			return nil, nil, err
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

		resources = append(resources, apimodels.AddResourceEntry{
			Attributes:      ec2VolumeSnapshot,
			ID:              resourceID,
			IntegrationID:   *pollerInput.IntegrationID,
			IntegrationType: integrationType,
			Type:            awsmodels.Ec2VolumeSchema,
		})
	}

	return resources, marker, nil
}
