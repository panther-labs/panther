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
	"github.com/go-playground/validator"

	"github.com/panther-labs/panther/internal/compliance/datalake_forwarder/forwarder/internal/events"
)

var validate = validator.New()

type ComplianceChange struct {
	ChangeType       string `json:"changeType" validate:"required"`
	IntegrationID    string `json:"integrationId" validate:"required"`
	IntegrationLabel string `json:"integrationLabel" validate:"required"`
	LastUpdated      string `json:"lastUpdated" validate:"required"`
	PolicyID         string `json:"policyId" validate:"required"`
	PolicySeverity   string `json:"policySeverity" validate:"required"`
	ResourceID       string `json:"resourceId" validate:"required"`
	ResourceType     string `json:"resourceType" validate:"required"`
	Status           string `json:"status" validate:"required"`
	Suppressed       bool   `json:"suppressed" validate:"required"`
}

func (sh *StreamHandler) processComplianceSnapshot(record *events.DynamoDBEventRecord) (change *ComplianceChange, err error) {
	switch record.EventName {
	case string(lambdaevents.DynamoDBOperationTypeInsert):
		change, err = dynamoRecordToCompliance(record.Change.NewImage)
		if err != nil {
			return nil, err
		}
		change.ChangeType = ChangeTypeCreate
	case string(lambdaevents.DynamoDBOperationTypeRemove):
		change, err = dynamoRecordToCompliance(record.Change.OldImage)
		if err != nil {
			return nil, err
		}
		change.ChangeType = ChangeTypeDelete
	case string(lambdaevents.DynamoDBOperationTypeModify):
		change, err = dynamoRecordToCompliance(record.Change.NewImage)
		if err != nil {
			return nil, err
		}
		change.ChangeType = ChangeTypeModify
		oldStatus, err := dynamoRecordToCompliance(record.Change.OldImage)
		if err != nil {
			return nil, err
		}
		// If the status didn't change and the suppression didn't change, no need to report anything
		if change.ChangeType == oldStatus.Status && change.Suppressed == oldStatus.Suppressed {
			return nil, nil
		}
	default:
		return nil, nil
	}
	label, err := sh.getIntegrationLabel(change.IntegrationID)
	if err != nil {
		return nil, err
	}
	if len(label) == 0 {
		return nil, nil
	}
	change.IntegrationLabel = label
	return change, nil
}

func dynamoRecordToCompliance(image map[string]*dynamodb.AttributeValue) (*ComplianceChange, error) {
	change := ComplianceChange{}
	if err := dynamodbattribute.UnmarshalMap(image, &change); err != nil {
		return nil, err
	}
	if err := validate.Struct(&change); err != nil {
		return nil, err
	}
	return &change, nil
}
