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
	"github.com/aws/aws-sdk-go/service/guardduty"
)

type GuardDutyDestinationProperties = guardduty.CreatePublishingDestinationInput

func customGuardDutyDestination(_ context.Context, event cfn.Event) (string, map[string]interface{}, error) {
	switch event.RequestType {
	case cfn.RequestCreate, cfn.RequestUpdate:
		var props GuardDutyDestinationProperties
		if err := parseProperties(event.ResourceProperties, &props); err != nil {
			return "", nil, err
		}

		// currently GuardDuty does not support this in CF
		response, err := getGuardDutyClient().CreatePublishingDestination(&props)
		if err != nil && !strings.Contains(err.Error(), "already exists") {
			return "", nil, err
		}

		resourceID := fmt.Sprintf("custom:guardduty:destination:%s:%s",
			*props.DetectorId, *response.DestinationId)
		return resourceID, map[string]interface{}{"DestinationId": *response.DestinationId}, nil

	case cfn.RequestDelete:
		split := strings.Split(event.PhysicalResourceID, ":")
		if len(split) < 5 {
			// invalid resourceID (e.g. CREATE_FAILED) - skip delete
			return event.PhysicalResourceID, nil, nil
		}

		_, err := getGuardDutyClient().DeletePublishingDestination(
			&guardduty.DeletePublishingDestinationInput{
				DetectorId:    &split[3],
				DestinationId: &split[4],
			})
		return event.PhysicalResourceID, nil, err

	default:
		return "", nil, fmt.Errorf("unknown request type %s", event.RequestType)
	}
}
