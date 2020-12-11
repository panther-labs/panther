package forwarder

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
	lambdaevents "github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"

	"github.com/panther-labs/panther/internal/compliance/datalake_forwarder/forwarder/events"
)

type ComplianceChange struct {
	ChangeType       string `json:"changeType"`
	IntegrationID    string `json:"integrationId"`
	IntegrationLabel string `json:"integrationLabel"`
	LastUpdated      string `json:"lastUpdated"`
	PolicyID         string `json:"policyId"`
	PolicySeverity   string `json:"policySeverity"`
	ResourceID       string `json:"resourceId"`
	ResourceType     string `json:"resourceType"`
	Status           string `json:"status"`
	Suppressed       bool   `json:"suppressed"`
}

func (sh *StreamHandler) processComplianceSnapshot(record *events.DynamoDBEventRecord) (change *ComplianceChange, err error) {
	switch lambdaevents.DynamoDBOperationType(record.EventName) {
	case lambdaevents.DynamoDBOperationTypeInsert:
		change, err = recordToCompliance(record.Change.NewImage)
		if err != nil {
			return nil, err
		}
		change.ChangeType = ChangeTypeCreate
	case lambdaevents.DynamoDBOperationTypeRemove:
		change, err = recordToCompliance(record.Change.OldImage)
		if err != nil {
			return nil, err
		}
		change.ChangeType = ChangeTypeDelete
	case lambdaevents.DynamoDBOperationTypeModify:
		change, err = recordToCompliance(record.Change.NewImage)
		if err != nil {
			return nil, err
		}
		change.ChangeType = ChangeTypeModify
		oldStatus, err := recordToCompliance(record.Change.OldImage)
		if err != nil {
			return nil, err
		}
		// If the status didn't change and the suppression didn't change, no need to report anything
		if change.Status == oldStatus.Status && change.Suppressed == oldStatus.Suppressed {
			return nil, nil
		}
	default:
		return nil, nil
	}

	label, err := sh.getIntegrationLabel(change.IntegrationID)
	if err != nil || len(label) == 0 {
		return nil, err
	}
	change.IntegrationLabel = label
	return change, nil
}

func recordToCompliance(image map[string]*dynamodb.AttributeValue) (*ComplianceChange, error) {
	change := ComplianceChange{}
	err := dynamodbattribute.UnmarshalMap(image, &change)
	return &change, err
}
