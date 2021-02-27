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
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/guardduty"
	"github.com/aws/aws-sdk-go/service/guardduty/guarddutyiface"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	apimodels "github.com/panther-labs/panther/api/lambda/resources/models"
	awsmodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
	pollermodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/poller"
	"github.com/panther-labs/panther/internal/compliance/snapshot_poller/pollers/utils"
)

// Set as variables to be overridden in testing
var (
	GuardDutyClientFunc = setupGuardDutyClient
)

func setupGuardDutyClient(sess *session.Session, cfg *aws.Config) interface{} {
	return guardduty.New(sess, cfg)
}

func getGuardDutyClient(pollerResourceInput *awsmodels.ResourcePollerInput, region string) (guarddutyiface.GuardDutyAPI, error) {
	client, err := getClient(pollerResourceInput, GuardDutyClientFunc, "guardduty", region)
	if err != nil {
		return nil, err
	}

	return client.(guarddutyiface.GuardDutyAPI), nil
}

// PollGuardDutyDetector polls a single AWS Config resource
func PollGuardDutyDetector(
	pollerResourceInput *awsmodels.ResourcePollerInput,
	parsedResourceID *utils.ParsedResourceID,
	scanRequest *pollermodels.ScanEntry,
) (interface{}, error) {

	gdClient, err := getGuardDutyClient(pollerResourceInput, parsedResourceID.Region)
	if err != nil {
		return nil, err
	}

	detector, err := getGuardDutyDetector(gdClient)
	if err != nil || detector == nil {
		// errors.WithMessagef() will still return nil if err is nil
		return nil, errors.WithMessagef(err, "region: %s", parsedResourceID.Region)
	}

	snapshot, err := buildGuardDutyDetectorSnapshot(gdClient, detector, pollerResourceInput)
	if err != nil {
		return nil, err
	}
	if snapshot == nil {
		return nil, nil
	}
	snapshot.ResourceID = scanRequest.ResourceID
	snapshot.AccountID = aws.String(parsedResourceID.AccountID)
	snapshot.Region = aws.String(parsedResourceID.Region)
	return snapshot, nil
}

// getGuardDutyDetector returns the detector ID for the guard duty detector in the current region
func getGuardDutyDetector(svc guarddutyiface.GuardDutyAPI) (*string, error) {
	detector, err := svc.ListDetectors(&guardduty.ListDetectorsInput{})
	if err != nil {
		return nil, errors.Wrap(err, "GuardDuty.ListDetectors")
	}

	if len(detector.DetectorIds) == 0 {
		zap.L().Warn("tried to scan non-existent resource",
			zap.String("resourceType", awsmodels.GuardDutySchema))
		return nil, nil
	}
	return detector.DetectorIds[0], nil
}

// listDetectors returns the GuardDuty detectors in the account
func listDetectors(guardDutySvc guarddutyiface.GuardDutyAPI) (detectorIDs []*string, err error) {
	err = guardDutySvc.ListDetectorsPages(&guardduty.ListDetectorsInput{},
		func(page *guardduty.ListDetectorsOutput, lastPage bool) bool {
			detectorIDs = append(detectorIDs, page.DetectorIds...)
			return true
		})
	if err != nil {
		return nil, errors.Wrap(err, "GuardDuty.ListDetectorsPages")
	}
	return
}

// getMasterAccount gets the account ID of the GuardDuty master account to this account
func getMasterAccount(guardDutySvc guarddutyiface.GuardDutyAPI, id *string) (*guardduty.Master, error) {
	out, err := guardDutySvc.GetMasterAccount(&guardduty.GetMasterAccountInput{DetectorId: id})
	if err != nil {
		return nil, errors.Wrapf(err, "GuardDuty.GetMasterAccount: %s", aws.StringValue(id))
	}

	return out.Master, nil
}

// getDetector gets detailed information for a given GuardDuty detector
func getDetector(guardDutySvc guarddutyiface.GuardDutyAPI, detectorID *string) (*guardduty.GetDetectorOutput, error) {
	out, err := guardDutySvc.GetDetector(&guardduty.GetDetectorInput{DetectorId: detectorID})
	if err != nil {
		return nil, errors.Wrapf(err, "GuardDuty.GetDetector: %s", aws.StringValue(detectorID))
	}

	return out, nil
}

// buildGuardDutyDetectorSnapshot makes all the calls to build up a snapshot of a given GuardDuty detector
func buildGuardDutyDetectorSnapshot(
	guardDutySvc guarddutyiface.GuardDutyAPI,
	detectorID *string,
	pollerInput *awsmodels.ResourcePollerInput,
) (*awsmodels.GuardDutyDetector, error) {

	detectorSnapshot := &awsmodels.GuardDutyDetector{
		GenericResource: awsmodels.GenericResource{
			ResourceType: aws.String(awsmodels.GuardDutySchema),
		},
		GenericAWSResource: awsmodels.GenericAWSResource{
			ID: detectorID,
		},
	}

	detectorDetails, err := getDetector(guardDutySvc, detectorID)
	if err != nil {
		return nil, err
	}

	// Check if ResourceID matches the integration's regex filter
	if pollerInput != nil {
		if pollerInput.ShouldIgnoreResource(*detectorSnapshot.ID) {
			return nil, nil
		}
	}
	detectorSnapshot.FindingPublishingFrequency = detectorDetails.FindingPublishingFrequency
	detectorSnapshot.ServiceRole = detectorDetails.ServiceRole
	detectorSnapshot.Status = detectorDetails.Status
	detectorSnapshot.UpdatedAt = utils.StringToDateTime(*detectorDetails.UpdatedAt)
	detectorSnapshot.TimeCreated = utils.StringToDateTime(*detectorDetails.CreatedAt)
	detectorSnapshot.Tags = detectorDetails.Tags

	master, err := getMasterAccount(guardDutySvc, detectorID)
	if err != nil {
		return nil, err
	}
	detectorSnapshot.Master = master

	return detectorSnapshot, nil
}

// PollGuardDutyDetectors gathers information on each GuardDuty detector for an AWS account.
func PollGuardDutyDetectors(pollerInput *awsmodels.ResourcePollerInput) ([]apimodels.AddResourceEntry, *string, error) {
	zap.L().Debug("starting GuardDuty Detector resource poller")
	guardDutyDetectorSnapshots := make(map[string]*awsmodels.GuardDutyDetector)

	// Get detectors in each region
	regions, err := GetServiceRegionsFunc(pollerInput, awsmodels.GuardDutySchema)
	if err != nil {
		return nil, nil, err
	}

	for _, regionID := range regions {
		guardDutySvc, err := getGuardDutyClient(pollerInput, *regionID)
		if err != nil {
			var e *RegionIgnoreListError
			if errors.As(err, &e) {
				zap.L().Debug("Skipping denied region in GuardDuty scan")
				continue
			}
			return nil, nil, err
		}

		// Start with generating a list of all detectors
		detectors, err := listDetectors(guardDutySvc)
		if err != nil {
			return nil, nil, errors.WithMessagef(err, "region: %s", *regionID)
		}

		for _, detectorID := range detectors {
			detectorSnapshot, err := buildGuardDutyDetectorSnapshot(guardDutySvc, detectorID, pollerInput)
			if err != nil {
				return nil, nil, err
			}
			if detectorSnapshot == nil {
				continue
			}

			resourceID := utils.GenerateResourceID(
				pollerInput.AuthSourceParsedARN.AccountID,
				*regionID,
				awsmodels.GuardDutySchema,
			)
			detectorSnapshot.ResourceID = aws.String(resourceID)
			detectorSnapshot.AccountID = aws.String(pollerInput.AuthSourceParsedARN.AccountID)
			detectorSnapshot.Region = regionID

			if _, ok := guardDutyDetectorSnapshots[resourceID]; !ok {
				guardDutyDetectorSnapshots[resourceID] = detectorSnapshot
			} else {
				zap.L().Info(
					"overwriting existing GuardDuty Detector snapshot",
					zap.String("resourceId", resourceID),
				)
				guardDutyDetectorSnapshots[resourceID] = detectorSnapshot
			}
		}
	}

	detectorMetaSnapshot := &awsmodels.GuardDutyMeta{
		GenericAWSResource: awsmodels.GenericAWSResource{
			AccountID: aws.String(pollerInput.AuthSourceParsedARN.AccountID),
			Region:    aws.String(awsmodels.GlobalRegion),
		},
		GenericResource: awsmodels.GenericResource{
			ResourceID: aws.String(utils.GenerateResourceID(
				pollerInput.AuthSourceParsedARN.AccountID,
				"",
				awsmodels.GuardDutyMetaSchema)),
			ResourceType: aws.String(awsmodels.GuardDutyMetaSchema),
		},
		Detectors: []*string{},
	}

	resources := make([]apimodels.AddResourceEntry, 0, len(guardDutyDetectorSnapshots)+1)
	for resourceID, guardDutyDetectorSnapshot := range guardDutyDetectorSnapshots {
		detectorMetaSnapshot.Detectors = append(detectorMetaSnapshot.Detectors, aws.String(resourceID))
		resources = append(resources, apimodels.AddResourceEntry{
			Attributes:      guardDutyDetectorSnapshot,
			ID:              resourceID,
			IntegrationID:   *pollerInput.IntegrationID,
			IntegrationType: integrationType,
			Type:            awsmodels.GuardDutySchema,
		})
	}

	resources = append(resources, apimodels.AddResourceEntry{
		Attributes:      detectorMetaSnapshot,
		ID:              *detectorMetaSnapshot.ResourceID,
		IntegrationID:   *pollerInput.IntegrationID,
		IntegrationType: integrationType,
		Type:            awsmodels.GuardDutyMetaSchema,
	})

	// We don't support paging for GuardDuty resources. Since there is a limit of 1 detector per
	// region, we should not run into timeout issues here anyways.
	//
	// Reference: https://docs.aws.amazon.com/general/latest/gr/guardduty.html
	return resources, nil, nil
}
