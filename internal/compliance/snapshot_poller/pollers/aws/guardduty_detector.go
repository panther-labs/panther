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
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/guardduty"
	"github.com/aws/aws-sdk-go/service/guardduty/guarddutyiface"
	"go.uber.org/zap"

	apimodels "github.com/panther-labs/panther/api/gateway/resources/models"
	awsmodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
	pollermodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/poller"
	"github.com/panther-labs/panther/internal/compliance/snapshot_poller/pollers/utils"
)

// Set as variables to be overridden in testing
var (
	GuardDutyClientFunc = setupGuardDutyClient
)

func setupGuardDutyClient(sess *session.Session, cfg *aws.Config) interface{} {
	cfg.MaxRetries = aws.Int(MaxRetries)
	return guardduty.New(sess, cfg)
}

// PollGuardDutyDetector polls a single AWS Config resource
func PollGuardDutyDetector(
	pollerResourceInput *awsmodels.ResourcePollerInput,
	parsedResourceID *utils.ParsedResourceID,
	scanRequest *pollermodels.ScanEntry,
) interface{} {

	client := getClient(pollerResourceInput, "guardduty", parsedResourceID.Region).(guarddutyiface.GuardDutyAPI)
	detector := getGuardDutyDetector(client)

	snapshot := buildGuardDutyDetectorSnapshot(client, detector)
	if snapshot == nil {
		return nil
	}
	snapshot.ResourceID = scanRequest.ResourceID
	snapshot.AccountID = aws.String(parsedResourceID.AccountID)
	snapshot.Region = aws.String(parsedResourceID.Region)
	return snapshot
}

// getGuardDutyDetector returns the detector ID for the guard duty detector in the current region
func getGuardDutyDetector(svc guarddutyiface.GuardDutyAPI) *string {
	detector, err := svc.ListDetectors(&guardduty.ListDetectorsInput{})
	if err != nil {
		utils.LogAWSError("GuardDuty.ListDetectors", err)
		return nil
	}

	if len(detector.DetectorIds) == 0 {
		zap.L().Warn("tried to scan non-existent resource",
			zap.String("resourceType", awsmodels.GuardDutySchema))
		return nil
	}
	return detector.DetectorIds[0]
}

// listDetectors returns the GuardDuty detectors in the account
func listDetectors(guardDutySvc guarddutyiface.GuardDutyAPI) (detectorIDs []*string) {
	err := guardDutySvc.ListDetectorsPages(&guardduty.ListDetectorsInput{},
		func(page *guardduty.ListDetectorsOutput, lastPage bool) bool {
			detectorIDs = append(detectorIDs, page.DetectorIds...)
			return true
		})
	if err != nil {
		utils.LogAWSError("GuardDuty.ListDetectorsPages", err)
	}
	return
}

// getMasterAccount gets the account ID of the GuardDuty master account to this account
func getMasterAccount(guardDutySvc guarddutyiface.GuardDutyAPI, id *string) (*guardduty.Master, error) {
	out, err := guardDutySvc.GetMasterAccount(&guardduty.GetMasterAccountInput{DetectorId: id})
	if err != nil {
		return nil, err
	}

	return out.Master, nil
}

// getDetector gets detailed information for a given GuardDuty detector
func getDetector(guardDutySvc guarddutyiface.GuardDutyAPI, detectorID *string) (*guardduty.GetDetectorOutput, error) {
	out, err := guardDutySvc.GetDetector(&guardduty.GetDetectorInput{DetectorId: detectorID})
	if err != nil {
		return nil, err
	}

	return out, nil
}

// buildGuardDutyDetectorSnapshot makes all the calls to build up a snapshot of a given GuardDuty detector
func buildGuardDutyDetectorSnapshot(guardDutySvc guarddutyiface.GuardDutyAPI, detectorID *string) *awsmodels.GuardDutyDetector {
	if detectorID == nil {
		return nil
	}

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
		utils.LogAWSError("GuardDuty.GetDetector", err)
		return nil
	}
	detectorSnapshot.FindingPublishingFrequency = detectorDetails.FindingPublishingFrequency
	detectorSnapshot.ServiceRole = detectorDetails.ServiceRole
	detectorSnapshot.Status = detectorDetails.Status
	detectorSnapshot.UpdatedAt = utils.StringToDateTime(*detectorDetails.UpdatedAt)
	detectorSnapshot.TimeCreated = utils.StringToDateTime(*detectorDetails.CreatedAt)
	detectorSnapshot.Tags = detectorDetails.Tags

	master, err := getMasterAccount(guardDutySvc, detectorID)
	if err != nil {
		utils.LogAWSError("GuardDuty.GetMasterAccount", err)
	} else {
		detectorSnapshot.Master = master
	}

	return detectorSnapshot
}

// PollGuardDutyDetectors gathers information on each GuardDuty detector for an AWS account.
func PollGuardDutyDetectors(pollerInput *awsmodels.ResourcePollerInput) ([]*apimodels.AddResourceEntry, error) {
	zap.L().Debug("starting GuardDuty Detector resource poller")
	guardDutyDetectorSnapshots := make(map[string]*awsmodels.GuardDutyDetector)

	// Get detectors in each region
	for _, regionID := range utils.GetServiceRegions(pollerInput.Regions, "guardduty") {
		sess := session.Must(session.NewSession(&aws.Config{Region: regionID}))
		creds, err := AssumeRoleFunc(pollerInput, sess)
		if err != nil {
			return nil, err
		}

		guardDutySvc := GuardDutyClientFunc(sess, &aws.Config{Credentials: creds}).(guarddutyiface.GuardDutyAPI)

		// Start with generating a list of all detectors
		detectors := listDetectors(guardDutySvc)
		for _, detectorID := range detectors {
			detectorSnapshot := buildGuardDutyDetectorSnapshot(guardDutySvc, detectorID)
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

	resources := make([]*apimodels.AddResourceEntry, 0, len(guardDutyDetectorSnapshots)+1)
	for resourceID, guardDutyDetectorSnapshot := range guardDutyDetectorSnapshots {
		detectorMetaSnapshot.Detectors = append(detectorMetaSnapshot.Detectors, aws.String(resourceID))
		resources = append(resources, &apimodels.AddResourceEntry{
			Attributes:      guardDutyDetectorSnapshot,
			ID:              apimodels.ResourceID(resourceID),
			IntegrationID:   apimodels.IntegrationID(*pollerInput.IntegrationID),
			IntegrationType: apimodels.IntegrationTypeAws,
			Type:            awsmodels.GuardDutySchema,
		})
	}

	resources = append(resources, &apimodels.AddResourceEntry{
		Attributes:      detectorMetaSnapshot,
		ID:              apimodels.ResourceID(*detectorMetaSnapshot.ResourceID),
		IntegrationID:   apimodels.IntegrationID(*pollerInput.IntegrationID),
		IntegrationType: apimodels.IntegrationTypeAws,
		Type:            awsmodels.GuardDutyMetaSchema,
	})

	return resources, nil
}
