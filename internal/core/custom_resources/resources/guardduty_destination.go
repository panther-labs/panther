package resources

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
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-lambda-go/cfn"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/guardduty"
)

type GuardDutyDestinationProperties = guardduty.CreatePublishingDestinationInput

// Currently, GuardDuty does not support destinations in CloudFormation
func customGuardDutyDestination(_ context.Context, event cfn.Event) (string, map[string]interface{}, error) {
	switch event.RequestType {
	case cfn.RequestCreate, cfn.RequestUpdate:
		var props GuardDutyDestinationProperties
		if err := parseProperties(event.ResourceProperties, &props); err != nil {
			return "", nil, err
		}

		detectorID, destinationID := parseGuardDutyPhysicalID(event.PhysicalResourceID)
		if event.RequestType == cfn.RequestUpdate && aws.StringValue(props.DetectorId) == detectorID {
			// The new and old detectorIDs are the same - this is an update
			_, err := guardDutyClient.UpdatePublishingDestination(&guardduty.UpdatePublishingDestinationInput{
				DestinationId:         &destinationID,
				DestinationProperties: props.DestinationProperties,
				DetectorId:            &detectorID,
			})
			return event.PhysicalResourceID, map[string]interface{}{"DestinationId": destinationID}, err
		}

		// This is either a create (existing detectorID is blank), OR
		// this could be an update where the detectorID changed.
		// Either way, we need to create a new destination for this detector.
		// (CloudFormation will automatically delete the old destination if the detector changed.)
		response, err := guardDutyClient.CreatePublishingDestination(&props)
		if err != nil {
			return "", nil, err
		}

		resourceID := fmt.Sprintf("custom:guardduty:destination:%s:%s",
			*props.DetectorId, *response.DestinationId)
		return resourceID, map[string]interface{}{"DestinationId": *response.DestinationId}, nil

	case cfn.RequestDelete:
		detectorID, destinationID := parseGuardDutyPhysicalID(event.PhysicalResourceID)
		if detectorID == "" || destinationID == "" {
			// invalid resourceID (e.g. CREATE_FAILED) - skip delete
			return event.PhysicalResourceID, nil, nil
		}

		_, err := guardDutyClient.DeletePublishingDestination(&guardduty.DeletePublishingDestinationInput{
			DetectorId:    &detectorID,
			DestinationId: &destinationID,
		})
		return event.PhysicalResourceID, nil, err

	default:
		return "", nil, fmt.Errorf("unknown request type %s", event.RequestType)
	}
}

// Returns DetectorId, DestinationId, parsed from the custom resource physical ID
func parseGuardDutyPhysicalID(id string) (string, string) {
	// "custom:guardduty:destination:DETECTOR_ID:DESTINATION_ID"
	split := strings.Split(id, ":")
	if len(split) < 5 {
		// invalid resourceID (e.g. CREATE_FAILED) - skip delete
		return "", ""
	}
	return split[3], split[4]
}
