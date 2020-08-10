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

const (
	alarmRunbook = "https://docs.runpanther.io/operations/runbooks"

	consoleLinkTemplate = "\nhttps://%s.console.aws.amazon.com/cloudwatch/home?region=%s#alarmsV2:alarm/%s?\n"

	maxAlarmDescriptionSize = 1024
)

// Wrapper functions to reduce boilerplate for all the custom alarms.

// putMetricAlarm
// If not specified, fills in defaults for the following:
//    Tags:               Application=Panther
//    TreatMissingData:   notBreaching
func putMetricAlarm(input *cloudwatch.PutMetricAlarmInput) error {
	// copy because we mutate the Alarm description
	var copy cloudwatch.PutMetricAlarmInput = *input
	input = &copy

	if input.Tags == nil {
		input.Tags = []*cloudwatch.Tag{
			{Key: aws.String("Application"), Value: aws.String("Panther")},
		}
	}

	if input.TreatMissingData == nil {
		input.TreatMissingData = aws.String("notBreaching")
	}

	input.AlarmDescription = aws.String(createAlarmDescription(*input.AlarmName, *input.AlarmDescription))

	zap.L().Info("putting metric alarm", zap.String("alarmName", *input.AlarmName))
	if _, err := cloudWatchClient.PutMetricAlarm(input); err != nil {
		return fmt.Errorf("failed to put alarm %s: %v", *input.AlarmName, err)
	}
	return nil
}

// used to collect a set of alarms to create a composite alarm
type alarmDescription struct {
	name        string
	description string
}

// putCompositeAlarm creates a composite alarm as an OR over the supporting alarms.
// If not specified, fills in defaults for the following:
//    Tags:               Application=Panther
func putCompositeAlarm(input *cloudwatch.PutCompositeAlarmInput, alarmDescriptions []alarmDescription) error {
	if input.Tags == nil {
		input.Tags = []*cloudwatch.Tag{
			{Key: aws.String("Application"), Value: aws.String("Panther")},
		}
	}

	var compositeRule, compositeDescription string
	compositeDescription = "One or more of the following alarms triggered:\n"
	for i := range alarmDescriptions {
		compositeRule += "ALARM(" + alarmDescriptions[i].name + ")"
		compositeDescription += alarmDescriptions[i].description
		if i < len(alarmDescriptions)-1 {
			compositeRule += " OR "
			compositeDescription += "\n"
		}
	}
	input.AlarmRule = aws.String(compositeRule)

	input.AlarmDescription = aws.String(createAlarmDescription(*input.AlarmName, compositeDescription))

	zap.L().Info("putting composite alarm", zap.String("alarmName", *input.AlarmName))
	if _, err := cloudWatchClient.PutCompositeAlarm(input); err != nil {
		return fmt.Errorf("failed to put alarm %s: %v", *input.AlarmName, err)
	}
	return nil
}

// Delete a group of alarms.
//
// Assumes physicalID is of the form custom:alarms:$SERVICE:$ID
// Assumes each alarm name is "Panther-$NAME-$ID"
func deleteAlarms(physicalID string, alarmNames ...string) error {
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

	zap.L().Info("deleting alarms", zap.Strings("alarmNames", fullAlarmNames))
	_, err := cloudWatchClient.DeleteAlarms(
		&cloudwatch.DeleteAlarmsInput{AlarmNames: aws.StringSlice(fullAlarmNames)})
	if err != nil {
		return fmt.Errorf("failed to delete %s alarms: %v", id, err)
	}

	return nil
}

func createAlarmDescription(alarmName, alarmDesc string) string {
	// prepend alarmName, name, account and region, then console link
	alarmDesc = alarmName + " " + accountDescription + fmt.Sprintf(consoleLinkTemplate,
		*awsSession.Config.Region, *awsSession.Config.Region, alarmName) + alarmDesc

	// clip
	if len(alarmDesc) > maxAlarmDescriptionSize {
		alarmDesc = alarmDesc[0:maxAlarmDescriptionSize]
	}
	return alarmDesc
}
