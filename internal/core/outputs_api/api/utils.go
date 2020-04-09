package api

/**
 * A Cloud-Native SIEM for the Modern Security Team
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
	"errors"

	"github.com/aws/aws-sdk-go/aws"

	"github.com/panther-labs/panther/api/lambda/outputs/models"
	"github.com/panther-labs/panther/internal/core/outputs_api/table"
)

// AlertOutputToItem converts an AlertOutput to an AlertOutputItem
func AlertOutputToItem(input *models.AlertOutput) (*table.AlertOutputItem, error) {
	item := &table.AlertOutputItem{
		CreatedBy:          input.CreatedBy,
		CreationTime:       input.CreationTime,
		DisplayName:        input.DisplayName,
		LastModifiedBy:     input.LastModifiedBy,
		LastModifiedTime:   input.LastModifiedTime,
		OutputID:           input.OutputID,
		OutputType:         input.OutputType,
		DefaultForSeverity: input.DefaultForSeverity,
	}

	encryptedConfig, err := encryptionKey.EncryptConfig(input.OutputConfig)

	if err != nil {
		return nil, err
	}

	item.EncryptedConfig = encryptedConfig

	return item, nil
}

// ItemToAlertOutput converts an AlertOutputItem to an AlertOutput
func ItemToAlertOutput(input *table.AlertOutputItem) (alertOutput *models.AlertOutput, err error) {
	alertOutput = &models.AlertOutput{
		CreatedBy:          input.CreatedBy,
		CreationTime:       input.CreationTime,
		DisplayName:        input.DisplayName,
		LastModifiedBy:     input.LastModifiedBy,
		LastModifiedTime:   input.LastModifiedTime,
		OutputID:           input.OutputID,
		OutputType:         input.OutputType,
		DefaultForSeverity: input.DefaultForSeverity,
	}

	alertOutput.OutputConfig = &models.OutputConfig{}
	err = encryptionKey.DecryptConfig(input.EncryptedConfig, alertOutput.OutputConfig)

	if err != nil {
		return nil, err
	}

	return alertOutput, nil
}

func getOutputType(outputConfig *models.OutputConfig) (*string, error) {
	if outputConfig.Slack != nil {
		return aws.String("slack"), nil
	}
	if outputConfig.PagerDuty != nil {
		return aws.String("pagerduty"), nil
	}
	if outputConfig.Github != nil {
		return aws.String("github"), nil
	}
	if outputConfig.Jira != nil {
		return aws.String("jira"), nil
	}
	if outputConfig.Opsgenie != nil {
		return aws.String("opsgenie"), nil
	}
	if outputConfig.MsTeams != nil {
		return aws.String("msteams"), nil
	}
	if outputConfig.Sns != nil {
		return aws.String("sns"), nil
	}
	if outputConfig.Sqs != nil {
		return aws.String("sqs"), nil
	}
	if outputConfig.Asana != nil {
		return aws.String("asana"), nil
	}

	return nil, errors.New("no valid output configuration specified for alert output")
}
