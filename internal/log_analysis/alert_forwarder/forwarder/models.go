package forwarder

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
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/pkg/errors"
)

// AlertDedupEvent represents the event stored in the alert dedup DDB table by the rules engine
type AlertDedupEvent struct {
	RuleID              string           `dynamodbav:"ruleId"`
	DeduplicationString string           `dynamodbav:"dedup"`
	AlertCount          int64            `dynamodbav:"-"` // Not storing this field in DDB
	CreationTime        time.Time        `dynamodbav:"creationTime"`
	UpdateTime          time.Time        `dynamodbav:"updateTime"`
	Severity            string           `dynamodbav:"severity"`
	EventPerLogType     map[string]int64 `dynamodbav:"eventsPerLogType"`
}

// Alert contains all the fields associated to the alert stored in DDB
type Alert struct {
	ID            string `dynamodbav:"id,string"`
	TimePartition string `dynamodbav:"timePartition,string"`
	AlertDedupEvent
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
	ruleID, err := getAttribute("ruleId", input)
	if err != nil {
		return nil, err
	}

	deduplicationString, err := getAttribute("dedup", input)
	if err != nil {
		return nil, err
	}

	severity, err := getAttribute("severity", input)
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

	eventsPerLogType, err := getMapStringIntAttribute("eventsPerLogType", input)
	if err != nil {
		return nil, err
	}

	event = &AlertDedupEvent{
		RuleID:              ruleID.String(),
		DeduplicationString: deduplicationString.String(),
		AlertCount:          alertCount,
		CreationTime:        time.Unix(alertCreationEpoch, 0).UTC(),
		UpdateTime:          time.Unix(alertUpdateEpoch, 0).UTC(),
		Severity:            severity.String(),
		EventPerLogType:     eventsPerLogType,
	}
	return event, nil
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

func getMapStringIntAttribute(key string, input map[string]events.DynamoDBAttributeValue) (map[string]int64, error) {
	value, err := getAttribute(key, input)
	if err != nil {
		return nil, err
	}

	result := make(map[string]int64)
	for key, value := range value.Map() {
		integerValue, err := value.Integer()
		if err != nil {
			return nil, errors.Wrapf(err, "failed to convert value with key '%s' to integer", key)
		}
		result[key] = integerValue
	}

	return result, nil
}

func getAttribute(key string, inputMap map[string]events.DynamoDBAttributeValue) (events.DynamoDBAttributeValue, error) {
	attributeValue, ok := inputMap[key]
	if !ok {
		return events.DynamoDBAttributeValue{}, errors.Errorf("could not find '%s' attribute", key)
	}
	return attributeValue, nil
}
