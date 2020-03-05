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
	RuleID              string    `dynamodbav:"ruleId,string"`
	RuleVersion         string    `dynamodbav:"ruleVersion,string"`
	DeduplicationString string    `dynamodbav:"dedup,string"`
	AlertCount          int64     `dynamodbav:"-"` // Not storing this field in DDB
	CreationTime        time.Time `dynamodbav:"creationTime,string"`
	UpdateTime          time.Time `dynamodbav:"updateTime,string"`
	EventCount          int64     `dynamodbav:"eventCount,number"`
	Severity            string    `dynamodbav:"severity,string"`
	LogTypes            []string  `dynamodbav:"logTypes,stringset"`
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

	ruleVersion, err := getAttribute("ruleVersion", input)
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

	eventCount, err := getIntegerAttribute("eventCount", input)
	if err != nil {
		return nil, err
	}

	logTypes, err := getAttribute("logTypes", input)
	if err != nil {
		return nil, err
	}

	return &AlertDedupEvent{
		RuleID:              ruleID.String(),
		RuleVersion:         ruleVersion.String(),
		DeduplicationString: deduplicationString.String(),
		AlertCount:          alertCount,
		CreationTime:        time.Unix(alertCreationEpoch, 0).UTC(),
		UpdateTime:          time.Unix(alertUpdateEpoch, 0).UTC(),
		EventCount:          eventCount,
		Severity:            severity.String(),
		LogTypes:            logTypes.StringSet(),
	}, nil
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
