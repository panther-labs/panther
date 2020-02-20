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
	DeduplicationString string    `dynamodbav:"dedup,string"`
	AlertCount          int64     `dynamodbav:"-"` // Not storing this field in DDB
	CreationTime        time.Time `dynamodbav:"creationTime,string"`
	UpdateTime          time.Time `dynamodbav:"updateTime,string"`
	EventCount          int64     `dynamodbav:"eventCount,number"`
}

// Alert contains all the fields associated to the alert stored in DDB
type Alert struct {
	ID            string `dynamodbav:"id,string"`
	TimePartition string `dynamodbav:"timePartition,string"`
	AlertDedupEvent
}

func FromDynamodDBAttribute(input map[string]events.DynamoDBAttributeValue) (*AlertDedupEvent, error) {
	alertCount, err := input["alertCount"].Integer()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get 'alertCount'")
	}

	alertCreationEpoch, err := input["alertCreationTime"].Integer()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get 'alertCreationTime'")
	}

	alertUpdateEpoch, err := input["alertUpdateTime"].Integer()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get 'alertUpdateTime'")
	}

	eventCount, err := input["eventCount"].Integer()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get 'eventCount'")
	}

	return &AlertDedupEvent{
		RuleID:              input["ruleId"].String(),
		DeduplicationString: input["dedup"].String(),
		AlertCount:          alertCount,
		CreationTime:        time.Unix(alertCreationEpoch, 0),
		UpdateTime:          time.Unix(alertUpdateEpoch, 0),
		EventCount:          eventCount,
	}, nil
}
