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

// PollEC2Image polls a single EC2 Image resource
func PollEC2Image(
	pollerResourceInput *awsmodels.ResourcePollerInput,
	resourceARN arn.ARN,
	scanRequest *pollermodels.ScanEntry,
) (interface{}, error) {

	ec2Client, err := getEC2Client(pollerResourceInput, resourceARN.Region)
	if err != nil {
		return nil, err
	}

	imageID := strings.Replace(resourceARN.Resource, "image/", "", 1)
	ami, err := getAMI(ec2Client, aws.String(imageID))
	if err != nil {
		return nil, err
	}

	snapshot := buildEc2AmiSnapshot(ami)
	if snapshot == nil {
		return nil, nil
	}
	snapshot.ResourceID = scanRequest.ResourceID
	snapshot.AccountID = aws.String(resourceARN.AccountID)
	snapshot.Region = aws.String(resourceARN.Region)
	snapshot.ARN = scanRequest.ResourceID
	return snapshot, nil
}

// getAMI returns a specific EC2 AMI
func getAMI(svc ec2iface.EC2API, imageID *string) (*ec2.Image, error) {
	image, err := svc.DescribeImages(&ec2.DescribeImagesInput{
		ImageIds: []*string{
			imageID,
		},
	})

	if err != nil {
		var awsErr awserr.Error
		if errors.As(err, &awsErr) && awsErr.Code() == "InvalidAMIID.NotFound" {
			zap.L().Warn("tried to scan non-existent resource",
				zap.String("resource", *imageID),
				zap.String("resourceType", awsmodels.Ec2AmiSchema))
			return nil, nil
		}
		return nil, errors.Wrapf(err, "EC2.DescribeImages: %s", aws.StringValue(imageID))
	}

	return image.Images[0], nil
}

// describeImages returns a union of the images owned by this account and the images in use by
// this account.
func describeImages(svc ec2iface.EC2API, nextMarker *string) ([]*ec2.Image, *string, error) {
	// Start iterating through instances looking for in use image IDs
	instances, marker, err := describeInstances(svc, nextMarker)
	if err != nil {
		return nil, nil, err
	}

	var imageIDs []*string
	imagesUnique := make(map[string]struct{})
	for _, instance := range instances {
		if _, ok := imagesUnique[*instance.ImageId]; !ok {
			imageIDs = append(imageIDs, instance.ImageId)
			imagesUnique[*instance.ImageId] = struct{}{}
		}
	}

	// Now that we know what images are in use, we can describe them without timing out (this call
	// does not support pagination on its own)
	imagesInUse := &ec2.DescribeImagesOutput{}
	if len(imageIDs) > 0 {
		imagesInUse, err = svc.DescribeImages(&ec2.DescribeImagesInput{
			ImageIds: imageIDs,
		})
		if err != nil {
			var imageIDStrings []string
			for _, image := range imageIDs {
				imageIDStrings = append(imageIDStrings, aws.StringValue(image))
			}
			return nil, nil, errors.Wrapf(err, "EC2.DescribeImages: %s", imageIDStrings)
		}
	}

	// If this is not the first page of a scan, just return now
	if nextMarker != nil {
		return imagesInUse.Images, marker, nil
	}

	// This call does not support pagination
	imagesOwned, err := svc.DescribeImages(&ec2.DescribeImagesInput{
		Owners: []*string{
			aws.String("self"),
		},
	})
	if err != nil {
		return nil, nil, errors.Wrap(err, "EC2.DescribeImages")
	}
	// Most likely at least some of the images this account owns are also in use by this
	// account, so don't include those duplicates here.
	for _, image := range imagesOwned.Images {
		if _, ok := imagesUnique[*image.ImageId]; !ok {
			imagesInUse.Images = append(imagesInUse.Images, image)
		}
	}

	return imagesInUse.Images, marker, nil
}

// buildEc2AmiSnapshot makes the necessary API calls to build a full Ec2AmiSnapshot
func buildEc2AmiSnapshot(image *ec2.Image) *awsmodels.Ec2Ami {
	if image == nil {
		return nil
	}
	return &awsmodels.Ec2Ami{
		GenericResource: awsmodels.GenericResource{
			TimeCreated:  utils.StringToDateTime(*image.CreationDate),
			ResourceType: aws.String(awsmodels.Ec2AmiSchema),
		},
		GenericAWSResource: awsmodels.GenericAWSResource{
			ID:   image.ImageId,
			Name: image.Name,
			Tags: utils.ParseTagSlice(image.Tags),
		},
		Architecture:        image.Architecture,
		BlockDeviceMappings: image.BlockDeviceMappings,
		Description:         image.Description,
		EnaSupport:          image.EnaSupport,
		Hypervisor:          image.Hypervisor,
		ImageLocation:       image.ImageLocation,
		ImageOwnerAlias:     image.ImageOwnerAlias,
		ImageType:           image.ImageType,
		KernelId:            image.KernelId,
		OwnerId:             image.OwnerId,
		Platform:            image.Platform,
		ProductCodes:        image.ProductCodes,
		Public:              image.Public,
		RamdiskId:           image.RamdiskId,
		RootDeviceName:      image.RootDeviceName,
		RootDeviceType:      image.RootDeviceType,
		SriovNetSupport:     image.SriovNetSupport,
		State:               image.State,
		StateReason:         image.StateReason,
		VirtualizationType:  image.VirtualizationType,
	}
}

// PollEc2Amis gathers information on each EC2 AMI in an AWS account.
func PollEc2Amis(pollerInput *awsmodels.ResourcePollerInput) ([]apimodels.AddResourceEntry, *string, error) {
	zap.L().Debug("starting EC2 AMI resource poller")
	ec2Svc, err := getEC2Client(pollerInput, *pollerInput.Region)
	if err != nil {
		return nil, nil, err
	}

	// Start with generating a list of all EC2 AMIs
	amis, marker, err := describeImages(ec2Svc, pollerInput.NextPageToken)
	if err != nil {
		return nil, nil, errors.WithMessagef(err, "region: %s", *pollerInput.Region)
	}

	zap.L().Debug("building EC2 AMI snapshots", zap.String("region", *pollerInput.Region))
	// For each image, build out a full snapshot
	resources := make([]apimodels.AddResourceEntry, 0, len(amis))
	for _, ami := range amis {
		ec2Ami := buildEc2AmiSnapshot(ami)
		if ec2Ami == nil {
			continue
		}

		accountID := aws.String("")
		if ec2Ami.OwnerId != nil {
			accountID = ec2Ami.OwnerId
		}
		// arn:aws:ec2:region:account-id(optional):image/image-id
		resourceID := strings.Join(
			[]string{
				"arn",
				pollerInput.AuthSourceParsedARN.Partition,
				"ec2",
				*pollerInput.Region,
				*accountID,
				"image/" + *ec2Ami.ID,
			},
			":",
		)

		// Populate generic fields
		ec2Ami.ResourceID = aws.String(resourceID)

		// Populate AWS generic fields
		ec2Ami.AccountID = aws.String(pollerInput.AuthSourceParsedARN.AccountID)
		ec2Ami.Region = pollerInput.Region
		ec2Ami.ARN = aws.String(resourceID)

		resources = append(resources, apimodels.AddResourceEntry{
			Attributes:      ec2Ami,
			ID:              resourceID,
			IntegrationID:   *pollerInput.IntegrationID,
			IntegrationType: integrationType,
			Type:            awsmodels.Ec2AmiSchema,
		})
	}

	return resources, marker, nil
}
