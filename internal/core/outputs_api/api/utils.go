package api

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
	"errors"

	"github.com/aws/aws-sdk-go/aws"
	jsoniter "github.com/json-iterator/go"

	deliverymodel "github.com/panther-labs/panther/api/lambda/delivery/models"
	"github.com/panther-labs/panther/api/lambda/outputs/models"
	"github.com/panther-labs/panther/internal/core/alert_delivery/outputs"
	"github.com/panther-labs/panther/internal/core/outputs_api/table"
	"github.com/panther-labs/panther/pkg/genericapi"
)

const redacted = ""

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
		AlertTypes:         input.AlertTypes,
	}

	if input.OutputConfig != nil {
		encryptedConfig, err := encryptionKey.EncryptConfig(input.OutputConfig)
		if err != nil {
			return nil, err
		}
		item.EncryptedConfig = encryptedConfig
	}

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
		AlertTypes:         input.AlertTypes,
	}

	// Decrypt the output before returning to the caller
	alertOutput.OutputConfig = &models.OutputConfig{}
	err = encryptionKey.DecryptConfig(input.EncryptedConfig, alertOutput.OutputConfig)
	if err != nil {
		return nil, err
	}

	return alertOutput, nil
}

func redactOutput(outputConfig *models.OutputConfig) {
	if outputConfig.Slack != nil {
		outputConfig.Slack.WebhookURL = redacted
	}
	if outputConfig.PagerDuty != nil {
		outputConfig.PagerDuty.IntegrationKey = redacted
	}
	if outputConfig.Github != nil {
		outputConfig.Github.Token = redacted
	}
	if outputConfig.Jira != nil {
		outputConfig.Jira.APIKey = redacted
	}
	if outputConfig.Opsgenie != nil {
		outputConfig.Opsgenie.APIKey = redacted
	}
	if outputConfig.MsTeams != nil {
		outputConfig.MsTeams.WebhookURL = redacted
	}
	if outputConfig.Asana != nil {
		outputConfig.Asana.PersonalAccessToken = redacted
	}
	if outputConfig.CustomWebhook != nil {
		outputConfig.CustomWebhook.WebhookURL = redacted
	}
}

// TODO: remove this function when proper migrations are in place
// configureOutputFallbacks - function used to ensure backwards compatibility by backfilling previously missing fields
func configureOutputFallbacks(alertOutput *models.AlertOutput) {
	// Backfill an empty list to contain all the supported types.
	if len(alertOutput.AlertTypes) == 0 {
		alertOutput.AlertTypes = []string{deliverymodel.RuleType, deliverymodel.RuleErrorType, deliverymodel.PolicyType}
	}

	// Backfill an empty Opsgenie service region
	if alertOutput.OutputConfig.Opsgenie != nil {
		if alertOutput.OutputConfig.Opsgenie.ServiceRegion == "" {
			alertOutput.OutputConfig.Opsgenie.ServiceRegion = outputs.OpsgenieServiceRegionUS
		}
	}
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
	if outputConfig.CustomWebhook != nil {
		return aws.String("customwebhook"), nil
	}

	return nil, errors.New("no valid output configuration specified for alert output")
}

// mergeConfigs combines an old config with a new config based on the following rules:
// 1. For every value in the new config, use it
// 2. For every value in the old config, keep it if it is not overwritten by the new config
func mergeConfigs(oldConfig, newConfig *models.OutputConfig) (*models.OutputConfig, error) {
	// Convert the old config into bytes so we can merge it with the new config
	oldBytes, err := jsoniter.Marshal(oldConfig)
	if err != nil {
		return nil, &genericapi.InternalError{
			Message: "Unable to extract existing configuration from dynamo",
		}
	}
	// Turn the bytes into a map so we can work with it more easily
	var oldMap map[string]map[string]interface{}
	err = jsoniter.Unmarshal(oldBytes, &oldMap)
	if err != nil {
		return nil, &genericapi.InternalError{
			Message: "Unable to process existing configuration from dynamo",
		}
	}

	// Repeat for the new config
	newBytes, err := jsoniter.Marshal(newConfig)
	if err != nil {
		return nil, &genericapi.InternalError{
			Message: "Unable to extract the new configuration",
		}
	}
	var newMap map[string]map[string]interface{}
	err = jsoniter.Unmarshal(newBytes, &newMap)
	if err != nil {
		return nil, &genericapi.InternalError{
			Message: "Unable to process the new configuration",
		}
	}

	// Overwrite the existing configurations with the new configurations
	for configType, configMap := range newMap {
		for configKey, configValue := range configMap {
			if configValue == "" {
				continue
			}
			oldMap[configType][configKey] = configValue
		}
	}

	// Turn the map back into bytes
	combinedBytes, err := jsoniter.Marshal(oldMap)
	if err != nil {
		return nil, &genericapi.InternalError{
			Message: "Unable to marshal the combined configuration",
		}
	}

	// Turn the bytes back into a struct
	combinedConfig := &models.OutputConfig{}
	err = jsoniter.Unmarshal(combinedBytes, combinedConfig)
	if err != nil {
		return nil, &genericapi.InternalError{
			Message: "Unable to process the combined configuration",
		}
	}

	return combinedConfig, nil
}

func validateConfigByType(config *models.OutputConfig, outputType *string) error {
	switch *outputType {
	case "slack":
		if config.Slack.WebhookURL != "" {
			return nil
		}
	case "pagerduty":
		if config.PagerDuty.IntegrationKey != "" {
			return nil
		}
	case "github":
		if config.Github.RepoName != "" && config.Github.Token != "" {
			return nil
		}
	case "jira":
		// The Type and AssigneeId are apparently optional, although the frontend requires them
		if config.Jira.APIKey != "" && config.Jira.UserName != "" && config.Jira.ProjectKey != "" && config.Jira.OrgDomain != "" {
			return nil
		}
	case "opsgenie":
		if config.Opsgenie.APIKey != "" {
			return nil
		}
	case "msteams":
		if config.MsTeams.WebhookURL != "" {
			return nil
		}
	case "sns":
		if config.Sns.TopicArn != "" {
			return nil
		}
	case "sqs":
		if config.Sqs.QueueURL != "" {
			return nil
		}
	case "asana":
		if len(config.Asana.ProjectGids) != 0 && config.Asana.PersonalAccessToken != "" {
			return nil
		}
	case "customwebhook":
		if config.CustomWebhook.WebhookURL != "" {
			return nil
		}
	}

	return errors.New("invalid output configuration specified for alert output, missing required fields")
}
