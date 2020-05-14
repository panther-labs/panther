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

	"github.com/aws/aws-lambda-go/cfn"
)

const (
	elbClientErrorAlarm       = "ELB4XXErrors"
	elbServerErrorAlarm       = "ELB5XXErrors"
	elbTargetClientErrorAlarm = "ELBTarget4XXErrors"
	elbTargetServerErrorAlarm = "ELBTarget5XXErrors"
	elbTargetLatencyAlarm     = "ELBTargetLatency"
	elbHealthAlarm            = "ELBHealth"
)

type ElbAlarmProperties struct {
	LoadBalancerName string `validate:"required"`
	AlarmTopicArn    string `validate:"required"`

	ElbClientErrorThreshold    int     `json:",string" validate:"omitempty,min=0"`
	TargetClientErrorThreshold int     `json:",string" validate:"omitempty,min=0"`
	LatencyThresholdSeconds    float64 `json:",string" validate:"omitempty,min=0"`
}

func customElbAlarms(_ context.Context, event cfn.Event) (string, map[string]interface{}, error) {
	var props ElbAlarmProperties
	if err := parseProperties(event.ResourceProperties, &props); err != nil {
		return "", nil, err
	}

	if props.LatencyThresholdSeconds == 0 {
		props.LatencyThresholdSeconds = 0.5
	}

	switch event.RequestType {
	case cfn.RequestCreate, cfn.RequestUpdate:
		return "custom:alarms:elb:" + props.LoadBalancerName, nil, nil

	case cfn.RequestDelete:
		return event.PhysicalResourceID, nil, nil

	default:
		return "", nil, fmt.Errorf("unknown request type %s", event.RequestType)
	}
}
