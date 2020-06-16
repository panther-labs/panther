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

	"github.com/panther-labs/panther/api/lambda/outputs/models"
	"github.com/panther-labs/panther/internal/core/outputs_api/table"
)

var redacted = aws.String("********")

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

// mergeOuutputConfigs takes two outputConfigs, and condenses them into one based on updating
func mergeOutputConfigs(old *models.OutputConfig, new *models.OutputConfigUpdate) *models.OutputConfig {
	if new.Asana != nil {
		if new.Asana.PersonalAccessToken != nil {
			old.Asana.PersonalAccessToken = new.Asana.PersonalAccessToken
		}
		if new.Asana.ProjectGids != nil {
			old.Asana.ProjectGids = new.Asana.ProjectGids
		}
	}
	if new.Github != nil {
		if new.Github.Token != nil {
			old.Github.Token = new.Github.Token
		}
		if new.Github.RepoName != nil {
			old.Github.RepoName = new.Github.Token
		}
	}
	if new.Jira != nil {
		if new.Jira.Type != nil {
			old.Jira.Type = new.Jira.Type
		}
		if new.Jira.APIKey != nil {
			old.Jira.APIKey = new.Jira.APIKey
		}
		if new.Jira.AssigneeID != nil {
			old.Jira.AssigneeID = new.Jira.AssigneeID
		}
		if new.Jira.OrgDomain != nil {
			old.Jira.OrgDomain = new.Jira.OrgDomain
		}
		if new.Jira.ProjectKey != nil {
			old.Jira.ProjectKey = new.Jira.ProjectKey
		}
		if new.Jira.UserName != nil {
			old.Jira.UserName = new.Jira.UserName
		}
	}
	if new.Slack != nil {
		if new.Slack.WebhookURL != nil {
			old.Slack.WebhookURL = new.Slack.WebhookURL
		}
	}
	if new.PagerDuty != nil {
		if new.PagerDuty.IntegrationKey != nil {
			old.PagerDuty.IntegrationKey = new.PagerDuty.IntegrationKey
		}
	}
	if new.Opsgenie != nil {
		if new.Opsgenie.APIKey != nil {
			old.Opsgenie.APIKey = new.Opsgenie.APIKey
		}
	}
	if new.MsTeams != nil {
		if new.MsTeams.WebhookURL != nil {
			old.MsTeams.WebhookURL = new.MsTeams.WebhookURL
		}
	}
	if new.Sns != nil {
		if new.Sns.TopicArn != nil {
			old.Sns.TopicArn = new.Sns.TopicArn
		}
	}
	if new.Sqs != nil {
		if new.Sqs.QueueURL != nil {
			old.Sqs.QueueURL = new.Sqs.QueueURL
		}
	}
	if new.CustomWebhook != nil {
		if new.CustomWebhook.WebhookURL != nil {
			old.CustomWebhook.WebhookURL = new.CustomWebhook.WebhookURL
		}
	}
	return old
}
