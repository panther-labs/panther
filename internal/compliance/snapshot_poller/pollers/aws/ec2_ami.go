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

	apimodels "github.com/panther-labs/panther/api/gateway/resources/models"
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
	ami := getAMI(ec2Client, aws.String(imageID))

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
func getAMI(svc ec2iface.EC2API, imageID *string) *ec2.Image {
	image, err := svc.DescribeImages(&ec2.DescribeImagesInput{
		ImageIds: []*string{
			imageID,
		},
	})

	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok {
			if awsErr.Code() == "InvalidAMIID.NotFound" {
				zap.L().Warn("tried to scan non-existent resource",
					zap.String("resource", *imageID),
					zap.String("resourceType", awsmodels.Ec2AmiSchema))
				return nil
			}
		}
		utils.LogAWSError("EC2.DescribeImages", err)
		return nil
	}

	return image.Images[0]
}

// buildImageList creates the ec2Ami cache if it does not exist, and populates it for a given region
func buildImageList(svc ec2iface.EC2API, region string) (err error) {
	// If ec2Amis is nil there is no cache yet at all
	if ec2Amis == nil {
		ec2Amis = make(map[string][]*string)
	}

	// Get all the instances in this region
	// TODO unfuck this tangle
	instances, err := describeInstances(svc)
	if err != nil {
		return err
	}

	// Populate the cache with the unique image IDs in use in this region
	var images []*string
	imagesUnique := make(map[string]struct{})
	for _, instance := range instances {
		if _, ok := imagesUnique[*instance.ImageId]; !ok {
			images = append(images, instance.ImageId)
			imagesUnique[*instance.ImageId] = struct{}{}
		}
	}
	ec2Amis[region] = images
	return nil
}

// describeImages returns all the EC2 AMIs the account has access to
func describeImages(svc ec2iface.EC2API, region string) ([]*ec2.Image, error) {
	// Start with the list of images this account owns
	imagesOwned, err := svc.DescribeImages(&ec2.DescribeImagesInput{
		Owners: []*string{
			aws.String("self"),
		},
	})
	if err != nil {
		utils.LogAWSError("EC2.DescribeImages", err)
		return nil, err
	}

	// Additionally, check all images this account is using in this region
	imageIDs := ec2Amis[region]

	// If imageIDs is nil there is no cache for this region from running the EC2 instance poller
	if imageIDs == nil {
		err = buildImageList(svc, region)
		if err != nil {
			return nil, err
		}
		imageIDs = ec2Amis[region]
	}

	// If imageIDs contains no elements, there are no EC2 AMIs in use in this region
	if len(imageIDs) == 0 {
		return imagesOwned.Images, nil
	}

	imagesInUse, err := svc.DescribeImages(&ec2.DescribeImagesInput{
		ImageIds: imageIDs,
	})
	if err != nil {
		utils.LogAWSError("EC2.DescribeImages", err)
		return nil, err
	}

	return append(imagesOwned.Images, imagesInUse.Images...), nil
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
func PollEc2Amis(pollerInput *awsmodels.ResourcePollerInput) ([]*apimodels.AddResourceEntry, *string, error) {
	zap.L().Debug("starting EC2 AMI resource poller")
	ec2AmiSnapshots := make(map[string]*awsmodels.Ec2Ami)

	ec2Svc, err := getEC2Client(pollerInput, *pollerInput.Region)
	if err != nil {
		return nil, nil, err // error is logged in getClient()
	}

	// Start with generating a list of all EC2 AMIs
	amis, err := describeImages(ec2Svc, *pollerInput.Region)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "PollEc2Amis(%#v) in region %s", *pollerInput, *pollerInput.Region)
	}
	if len(amis) == 0 {
		zap.L().Debug("no AMIs found in region", zap.String("region", *pollerInput.Region))
		return nil, nil, nil
	}

	zap.L().Debug("building EC2 AMI snapshots", zap.String("region", *pollerInput.Region))
	// For each image, build out a full snapshot
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

		if _, ok := ec2AmiSnapshots[resourceID]; !ok {
			ec2AmiSnapshots[resourceID] = ec2Ami
		} else {
			zap.L().Info("overwriting existing EC2 AMI snapshot", zap.String("resourceId", resourceID))
			ec2AmiSnapshots[resourceID] = ec2Ami
		}
	}

	resources := make([]*apimodels.AddResourceEntry, 0, len(ec2AmiSnapshots))
	for resourceID, ec2AmiSnapshot := range ec2AmiSnapshots {
		resources = append(resources, &apimodels.AddResourceEntry{
			Attributes:      ec2AmiSnapshot,
			ID:              apimodels.ResourceID(resourceID),
			IntegrationID:   apimodels.IntegrationID(*pollerInput.IntegrationID),
			IntegrationType: apimodels.IntegrationTypeAws,
			Type:            awsmodels.Ec2AmiSchema,
		})
	}

	// EC2 AMI's can't be paged
	return resources, nil, nil
}
