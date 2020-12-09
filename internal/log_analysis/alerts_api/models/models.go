package models

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
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/pkg/errors"
)

const (
	AlertTablePartitionKey        = "id"
	AlertTableLogTypesAttribute   = "logTypes"
	AlertTableEventCountAttribute = "eventCount"
	AlertTableUpdateTimeAttribute = "updateTime"
)

// AlertDedupEvent represents the event stored in the alert dedup DDB table by the rules engine
type AlertDedupEvent struct {
	RuleID              string    `dynamodbav:"ruleId"`
	RuleVersion         string    `dynamodbav:"ruleVersion"`
	DeduplicationString string    `dynamodbav:"dedup"`
	CreationTime        time.Time `dynamodbav:"creationTime"`
	UpdateTime          time.Time `dynamodbav:"updateTime"`
	EventCount          int64     `dynamodbav:"eventCount"`
	LogTypes            []string  `dynamodbav:"logTypes,stringset"`
	AlertContext        *string   `dynamodbav:"context,string"`
	Type                string    `dynamodbav:"type"`
	// Generated Fields
	GeneratedTitle        *string  `dynamodbav:"title,string"`
	GeneratedDescription  *string  `dynamodbav:"description,string"`
	GeneratedReference    *string  `dynamodbav:"reference"`
	GeneratedSeverity     *string  `dynamodbav:"severity"`
	GeneratedRunbook      *string  `dynamodbav:"runbook"`
	GeneratedDestinations []string `dynamodbav:"destinations,stringset"`
	AlertCount            int64    `dynamodbav:"-"` // There is no need to store this item in DDB
}

// AlertPolicy represents the policy-specific fields for alerts genereated by policies
type AlertPolicy struct {
	PolicyID          string   `dynamodbav:"policyId,string"`
	PolicyDisplayName string   `dynamodbav:"policyDisplayName,string"`
	PolicyVersion     string   `dynamodbav:"policyVersion,string"`
	PolicySourceID    string   `dynamodbav:"policySourceId,string"`
	ResourceTypes     []string `dynamodbav:"resourceTypes,stringset"`
	ResourceID        string   `dynamodbav:"resourceId,string"` // This is the failing resource
}

// Alert contains all the fields associated to the alert stored in DDB
type Alert struct {
	ID                  string    `dynamodbav:"id,string"`
	TimePartition       string    `dynamodbav:"timePartition,string"`
	Severity            *string   `dynamodbav:"severity,string"`
	RuleDisplayName     *string   `dynamodbav:"ruleDisplayName,string"`
	FirstEventMatchTime time.Time `dynamodbav:"firstEventMatchTime,string"`
	LogTypes            []string  `dynamodbav:"logTypes,stringset"`
	// Alert Title - will be the Python-generated title or a default one if no Python-generated title is available.
	Title string `dynamodbav:"title,string"`
	AlertDedupEvent
	AlertPolicy
}

func FromDynamodDBAttribute(input map[string]events.DynamoDBAttributeValue) (event *AlertDedupEvent, err error) {
	defer func() {
		if r := recover(); r != nil {
			var ok bool
			err, ok = r.(error)
			if !ok {
				err = errors.Wrap(err, "panicked while getting alert dedup event")
			}
		}
	}()

	if input == nil {
		return nil, nil
	}

	ruleID, err := getAttribute("ruleId", input)
	if err != nil {
		return nil, err
	}

	ruleVersion, err := getAttribute("ruleVersion", input)
	if err != nil {
		return nil, err
	}

	deduplicationString, err := getAttribute("dedup", input)
	if err != nil {
		return nil, err
	}

	alertCount, err := getIntegerAttribute("alertCount", input)
	if err != nil {
		return nil, err
	}

	alertCreationEpoch, err := getIntegerAttribute("alertCreationTime", input)
	if err != nil {
		return nil, err
	}

	alertUpdateEpoch, err := getIntegerAttribute("alertUpdateTime", input)
	if err != nil {
		return nil, err
	}

	eventCount, err := getIntegerAttribute("eventCount", input)
	if err != nil {
		return nil, err
	}

	logTypes, err := getAttribute("logTypes", input)
	if err != nil {
		return nil, err
	}

	result := &AlertDedupEvent{
		RuleID:              ruleID.String(),
		RuleVersion:         ruleVersion.String(),
		DeduplicationString: deduplicationString.String(),
		AlertCount:          alertCount,
		CreationTime:        time.Unix(alertCreationEpoch, 0).UTC(),
		UpdateTime:          time.Unix(alertUpdateEpoch, 0).UTC(),
		EventCount:          eventCount,
		LogTypes:            logTypes.StringSet(),
	}

	alertContext := getOptionalAttribute("context", input)
	if alertContext != nil {
		result.AlertContext = aws.String(alertContext.String())
	}

	// Generated Fields
	generatedTitle := getOptionalAttribute("title", input)
	if generatedTitle != nil {
		result.GeneratedTitle = aws.String(generatedTitle.String())
	}

	generatedDescription := getOptionalAttribute("description", input)
	if generatedDescription != nil {
		result.GeneratedDescription = aws.String(generatedDescription.String())
	}

	generatedReference := getOptionalAttribute("reference", input)
	if generatedReference != nil {
		result.GeneratedReference = aws.String(generatedReference.String())
	}

	generatedSeverity := getOptionalAttribute("severity", input)
	if generatedSeverity != nil {
		result.GeneratedSeverity = aws.String(generatedSeverity.String())
	}

	generatedRunbook := getOptionalAttribute("runbook", input)
	if generatedRunbook != nil {
		result.GeneratedRunbook = aws.String(generatedRunbook.String())
	}

	generatedDestinations := getOptionalAttribute("destinations", input)
	if generatedDestinations != nil {
		result.GeneratedDestinations = generatedDestinations.StringSet()
	}

	// End Generated Fields

	alertType := getOptionalAttribute("type", input)
	if alertType != nil {
		result.Type = alertType.String()
	}

	return result, nil
}

func getIntegerAttribute(key string, input map[string]events.DynamoDBAttributeValue) (int64, error) {
	value, err := getAttribute(key, input)
	if err != nil {
		return 0, err
	}
	integerValue, err := value.Integer()
	if err != nil {
		return 0, errors.Wrapf(err, "failed to convert attribute '%s' to integer", key)
	}
	return integerValue, nil
}

func getAttribute(key string, inputMap map[string]events.DynamoDBAttributeValue) (events.DynamoDBAttributeValue, error) {
	attributeValue, ok := inputMap[key]
	if !ok {
		return events.DynamoDBAttributeValue{}, errors.Errorf("could not find '%s' attribute", key)
	}
	return attributeValue, nil
}

func getOptionalAttribute(key string, inputMap map[string]events.DynamoDBAttributeValue) *events.DynamoDBAttributeValue {
	attributeValue, ok := inputMap[key]
	if !ok {
		return nil
	}
	return &attributeValue
}
