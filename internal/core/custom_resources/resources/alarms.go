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
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/cloudwatch"
	"go.uber.org/zap"
)

const alarmRunbook = "https://docs.runpanther.io/operations/runbooks"

// Wrapper function to reduce boilerplate for all the custom alarms.
//
// If not specified, fills in defaults for the following:
//    Tags:               Application=Panther
//    TreatMissingData:   notBreaching
func putMetricAlarm(input cloudwatch.PutMetricAlarmInput) error {
	if input.Tags == nil {
		input.Tags = []*cloudwatch.Tag{
			{Key: aws.String("Application"), Value: aws.String("Panther")},
		}
	}

	if input.TreatMissingData == nil {
		input.TreatMissingData = aws.String("notBreaching")
	}

	zap.L().Info("putting metric alarm", zap.String("alarmName", *input.AlarmName))
	if _, err := cloudWatchClient.PutMetricAlarm(&input); err != nil {
		return fmt.Errorf("failed to put alarm %s: %v", *input.AlarmName, err)
	}
	return nil
}

// Delete a group of metric alarms.
//
// Assumes physicalID is of the form custom:alarms:$SERVICE:$ID
// Assumes each alarm name is "Panther-$NAME-$ID"
func deleteMetricAlarms(physicalID string, alarmNames ...string) error {
	split := strings.Split(physicalID, ":")
	if len(split) < 4 {
		zap.L().Warn("invalid physicalID - skipping delete")
		return nil
	}
	id := split[3]

	fullAlarmNames := make([]string, 0, len(alarmNames))
	for _, name := range alarmNames {
		fullAlarmNames = append(fullAlarmNames, fmt.Sprintf("Panther-%s-%s", name, id))
	}

	zap.L().Info("deleting metric alarms", zap.Strings("alarmNames", fullAlarmNames))
	_, err := cloudWatchClient.DeleteAlarms(
		&cloudwatch.DeleteAlarmsInput{AlarmNames: aws.StringSlice(fullAlarmNames)})
	if err != nil {
		return fmt.Errorf("failed to delete %s alarms: %v", id, err)
	}

	return nil
}
