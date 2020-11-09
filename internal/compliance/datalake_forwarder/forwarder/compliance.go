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
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/go-playground/validator"
	jsoniter "github.com/json-iterator/go"
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

func (sh StreamHandler) processComplianceSnapshot(record events.DynamoDBEventRecord) (*ComplianceChange, error) {
	var newComplianceStatus *ComplianceChange
	var err error

	switch record.EventName {
	case string(events.DynamoDBOperationTypeInsert):
		newComplianceStatus, err = dynamoRecordToCompliance(record.Change.NewImage)
		if err != nil {
			return nil, err
		}
		newComplianceStatus.ChangeType = ChangeTypeCreate
	case string(events.DynamoDBOperationTypeRemove):
		newComplianceStatus, err = dynamoRecordToCompliance(record.Change.OldImage)
		if err != nil {
			return nil, err
		}
		newComplianceStatus.ChangeType = ChangeTypeDelete
	case string(events.DynamoDBOperationTypeModify):
		newComplianceStatus, err = dynamoRecordToCompliance(record.Change.NewImage)
		if err != nil {
			return nil, err
		}
		newComplianceStatus.ChangeType = ChangeTypeModify
		oldStatus, err := dynamoRecordToCompliance(record.Change.OldImage)
		if err != nil {
			return nil, err
		}
		// If the status didn't change and the suppression didn't change, no need to report anything
		if newComplianceStatus.ChangeType == oldStatus.Status && newComplianceStatus.Suppressed == oldStatus.Suppressed {
			return nil, nil
		}
	}

	newComplianceStatus.IntegrationLabel, err = sh.getIntegrationLabel(newComplianceStatus.IntegrationID)
	return newComplianceStatus, err
}

func dynamoRecordToCompliance(image map[string]events.DynamoDBAttributeValue) (*ComplianceChange, error) {
	change := ComplianceChange{}
	if err := unmarshalMap(image, &change); err != nil {
		return nil, err
	}
	if err := validate.Struct(&change); err != nil {
		return nil, err
	}
	return &change, nil
}

func unmarshalMap(attributes map[string]events.DynamoDBAttributeValue, out interface{}) error {
	m, err := convertDynamoDBAttributeValues(attributes)
	if err != nil {
		return err
	}
	return dynamodbattribute.UnmarshalMap(m, out)
}

func convertDynamoDBAttributeValues(attributes map[string]events.DynamoDBAttributeValue) (map[string]*dynamodb.AttributeValue, error) {
	out := map[string]*dynamodb.AttributeValue{}
	for key, value := range attributes {
		raw, err := value.MarshalJSON()
		if err != nil {
			return nil, err
		}
		attr := dynamodb.AttributeValue{}
		if err := jsoniter.Unmarshal(raw, &attr); err != nil {
			return nil, err
		}
		out[key] = &attr
	}
	return out, nil
}
