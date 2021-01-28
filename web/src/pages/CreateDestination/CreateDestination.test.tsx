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

import React from 'react';
import {
  render,
  fireEvent,
  buildDestination,
  faker,
  buildGithubConfigInput,
  buildJiraConfigInput,
  buildPagerDutyConfigInput,
  buildSqsConfigInput,
  buildSnsConfigInput,
  buildCustomWebhookConfigInput,
  buildMsTeamsConfigInput,
  buildOpsgenieConfigInput,
  buildAsanaConfigInput,
  fireClickAndMouseEvents,
} from 'test-utils';
import urls from 'Source/urls';
import { mockAddDestination } from 'Components/wizards/CreateDestinationWizard';
import { DestinationFull } from 'Source/graphql/fragments/DestinationFull.generated';
import { AlertTypesEnum, DestinationTypeEnum, SeverityEnum } from 'Generated/schema';
import CreateDestination from './index';

const criticalSeverity = SeverityEnum.Critical;
const allAlertTypes = [AlertTypesEnum.Rule, AlertTypesEnum.RuleError, AlertTypesEnum.Policy];

const validUrl = faker.internet.url();

describe('CreateDestination', () => {
  it('renders a list of destinations', () => {
    const { getByText, getByAltText } = render(<CreateDestination />);

    expect(getByText('Slack')).toBeInTheDocument();
    expect(getByAltText('Slack')).toBeInTheDocument();

    expect(getByText('Jira')).toBeInTheDocument();
    expect(getByAltText('Jira')).toBeInTheDocument();

    expect(getByText('Github')).toBeInTheDocument();
    expect(getByAltText('Github')).toBeInTheDocument();

    expect(getByText('AWS SQS')).toBeInTheDocument();
    expect(getByAltText('AWS SQS')).toBeInTheDocument();

    expect(getByText('AWS SNS')).toBeInTheDocument();
    expect(getByAltText('AWS SNS')).toBeInTheDocument();

    expect(getByText('Asana')).toBeInTheDocument();
    expect(getByAltText('Asana')).toBeInTheDocument();

    expect(getByText('Custom Webhook')).toBeInTheDocument();
    expect(getByAltText('Custom Webhook')).toBeInTheDocument();

    expect(getByText('PagerDuty')).toBeInTheDocument();
    expect(getByAltText('PagerDuty')).toBeInTheDocument();

    expect(getByText('Microsoft Teams')).toBeInTheDocument();
    expect(getByAltText('Microsoft Teams')).toBeInTheDocument();

    expect(getByText('Opsgenie')).toBeInTheDocument();
    expect(getByAltText('Opsgenie')).toBeInTheDocument();
  });

  it('shows a form as soon as you click on one item', () => {
    const { getByText, getByLabelText } = render(<CreateDestination />);

    fireEvent.click(getByText('Slack'));

    // Expect proper form input  fields
    expect(getByLabelText('* Display Name')).toBeInTheDocument();
    expect(getByLabelText('Slack Webhook URL')).toBeInTheDocument();
  });

  it('can create a Slack destination', async () => {
    const createdDestination = buildDestination() as DestinationFull;
    const slackDisplayName = 'test';

    const mocks = [
      mockAddDestination({
        variables: {
          input: {
            displayName: slackDisplayName,
            outputType: DestinationTypeEnum.Slack,
            defaultForSeverity: [criticalSeverity],
            alertTypes: allAlertTypes,
            outputConfig: {
              slack: {
                webhookURL: validUrl,
              },
            },
          },
        },
        data: { addDestination: createdDestination },
      }),
    ];
    const { getByText, findByText, getByLabelText, getAllByLabelText } = render(
      <CreateDestination />,
      {
        mocks,
      }
    );

    // Select Slack
    fireEvent.click(getByText('Slack'));

    const displayInput = getByLabelText('* Display Name');
    const webhookUrlInput = getByLabelText('Slack Webhook URL');
    const severityField = getAllByLabelText('Severity')[0];
    const alertTypeField = getAllByLabelText('Alert Types')[0];

    // Fill in the correct data + submit
    fireEvent.change(displayInput, { target: { value: slackDisplayName } });
    fireEvent.change(webhookUrlInput, { target: { value: validUrl } });
    fireEvent.change(severityField, { target: { value: 'Critical' } });
    fireClickAndMouseEvents(getByText('Critical'));
    fireEvent.change(alertTypeField, { target: { value: 'Rule Matches' } });
    fireClickAndMouseEvents(getByText('Rule Matches'));
    fireEvent.click(getByText('Add Destination'));

    // Expect success screen with proper redirect link
    expect(await findByText('Everything looks good!'));
    expect(getByText('Finish Setup')).toHaveAttribute('href', urls.settings.destinations.list());
  });

  it('can create a Github destination', async () => {
    const createdDestination = buildDestination() as DestinationFull;
    const githubDisplayName = 'Github Destination';
    const githubConfig = buildGithubConfigInput();
    const mocks = [
      mockAddDestination({
        variables: {
          input: {
            displayName: githubDisplayName,
            outputType: DestinationTypeEnum.Github,
            defaultForSeverity: [criticalSeverity],
            alertTypes: allAlertTypes,
            outputConfig: {
              github: githubConfig,
            },
          },
        },
        data: { addDestination: createdDestination },
      }),
    ];
    const { getByText, findByText, getByLabelText, getAllByLabelText } = render(
      <CreateDestination />,
      {
        mocks,
      }
    );

    // Select Github
    fireEvent.click(getByText('Github'));

    const displayInput = getByLabelText('* Display Name');
    const repositoryInput = getByLabelText('Repository name');
    const tokenInput = getByLabelText('Token');
    const severityField = getAllByLabelText('Severity')[0];
    const alertTypeField = getAllByLabelText('Alert Types')[0];

    // Fill in the correct data + submit
    fireEvent.change(displayInput, { target: { value: githubDisplayName } });
    fireEvent.change(repositoryInput, { target: { value: githubConfig.repoName } });
    fireEvent.change(tokenInput, { target: { value: githubConfig.token } });
    fireEvent.change(severityField, { target: { value: 'Critical' } });
    fireClickAndMouseEvents(getByText('Critical'));
    fireEvent.change(alertTypeField, { target: { value: 'Rule Matches' } });
    fireClickAndMouseEvents(getByText('Rule Matches'));
    fireEvent.click(getByText('Add Destination'));
    // Expect success screen with proper redirect link
    expect(await findByText('Everything looks good!'));
    expect(getByText('Finish Setup')).toHaveAttribute('href', urls.settings.destinations.list());
  });

  it('can create a Jira destination', async () => {
    const createdDestination = buildDestination() as DestinationFull;
    const jiraDisplayName = 'Jira Destination';
    const jiraConfig = buildJiraConfigInput({ orgDomain: validUrl });
    const mocks = [
      mockAddDestination({
        variables: {
          input: {
            displayName: jiraDisplayName,
            outputType: DestinationTypeEnum.Jira,
            defaultForSeverity: [criticalSeverity],
            alertTypes: allAlertTypes,
            outputConfig: { jira: jiraConfig },
          },
        },
        data: { addDestination: createdDestination },
      }),
    ];
    const { getByText, findByText, getByLabelText, getAllByLabelText } = render(
      <CreateDestination />,
      {
        mocks,
      }
    );

    // Select Jira
    fireEvent.click(getByText('Jira'));

    const displayInput = getByLabelText('* Display Name');
    const domainInput = getByLabelText('* Organization Domain');
    const projectKeyInput = getByLabelText('* Project Key');
    const userNameInput = getByLabelText('* Email');
    const apiKeyInput = getByLabelText('* Jira API Key');
    const issueInput = getByLabelText('* Issue Type');
    const labelsInput = getByLabelText('Labels', { selector: 'input' });
    const assigneeInput = getByLabelText('Assignee ID');
    const severityField = getAllByLabelText('Severity')[0];
    const alertTypeField = getAllByLabelText('Alert Types')[0];

    // Fill in the correct data + submit
    fireEvent.change(displayInput, { target: { value: jiraDisplayName } });
    fireEvent.change(domainInput, { target: { value: jiraConfig.orgDomain } });
    fireEvent.change(projectKeyInput, { target: { value: jiraConfig.projectKey } });
    fireEvent.change(userNameInput, { target: { value: jiraConfig.userName } });
    fireEvent.change(apiKeyInput, { target: { value: jiraConfig.apiKey } });
    fireEvent.change(issueInput, { target: { value: jiraConfig.issueType } });
    fireEvent.change(assigneeInput, { target: { value: jiraConfig.assigneeId } });
    jiraConfig.labels.forEach(label => {
      fireEvent.change(labelsInput, {
        target: {
          value: label,
        },
      });
      fireEvent.blur(labelsInput);
    });
    fireEvent.change(severityField, { target: { value: 'Critical' } });
    fireClickAndMouseEvents(getByText('Critical'));
    fireEvent.change(alertTypeField, { target: { value: 'Rule Matches' } });
    fireClickAndMouseEvents(getByText('Rule Matches'));

    fireEvent.click(getByText('Add Destination'));
    // Expect success screen with proper redirect link
    expect(await findByText('Everything looks good!'));
    expect(getByText('Finish Setup')).toHaveAttribute('href', urls.settings.destinations.list());
  });

  it('can create a PagerDuty destination', async () => {
    const createdDestination = buildDestination() as DestinationFull;
    const pageDutyDisplayName = 'PagerDuty Destination';
    const pagerDutyIntegrationKey = "X9gYq>vB[6fbPQw3ugc]')fH$(e,LDgD";
    const pagerDutyConfig = buildPagerDutyConfigInput({ integrationKey: pagerDutyIntegrationKey });
    const mocks = [
      mockAddDestination({
        variables: {
          input: {
            displayName: pageDutyDisplayName,
            outputType: DestinationTypeEnum.Pagerduty,
            defaultForSeverity: [criticalSeverity],
            alertTypes: allAlertTypes,
            outputConfig: { pagerDuty: pagerDutyConfig },
          },
        },
        data: { addDestination: createdDestination },
      }),
    ];
    const { getByText, findByText, getByLabelText, getAllByLabelText } = render(
      <CreateDestination />,
      {
        mocks,
      }
    );

    // Select PagerDuty
    fireEvent.click(getByText('PagerDuty'));

    const displayInput = getByLabelText('* Display Name');
    const integrationKeyInput = getByLabelText('Integration Key');
    const severityField = getAllByLabelText('Severity')[0];
    const alertTypeField = getAllByLabelText('Alert Types')[0];

    // Fill in the correct data + submit
    fireEvent.change(displayInput, { target: { value: pageDutyDisplayName } });
    fireEvent.change(integrationKeyInput, { target: { value: pagerDutyConfig.integrationKey } });

    fireEvent.change(severityField, { target: { value: 'Critical' } });
    fireClickAndMouseEvents(getByText('Critical'));
    fireEvent.change(alertTypeField, { target: { value: 'Rule Matches' } });
    fireClickAndMouseEvents(getByText('Rule Matches'));

    fireEvent.click(getByText('Add Destination'));
    // Expect success screen with proper redirect link
    expect(await findByText('Everything looks good!'));
    expect(getByText('Finish Setup')).toHaveAttribute('href', urls.settings.destinations.list());
  });

  it('can create a SQS destination', async () => {
    const createdDestination = buildDestination() as DestinationFull;
    const sqsDisplayName = 'SQS Destination';
    const sqsConfig = buildSqsConfigInput({ queueUrl: validUrl });
    const mocks = [
      mockAddDestination({
        variables: {
          input: {
            displayName: sqsDisplayName,
            outputType: DestinationTypeEnum.Sqs,
            defaultForSeverity: [criticalSeverity],
            alertTypes: allAlertTypes,
            outputConfig: { sqs: sqsConfig },
          },
        },
        data: { addDestination: createdDestination },
      }),
    ];
    const { getByText, findByText, getByLabelText, getAllByLabelText } = render(
      <CreateDestination />,
      {
        mocks,
      }
    );

    // Select SQS
    fireEvent.click(getByText('AWS SQS'));

    const displayInput = getByLabelText('* Display Name');
    const queueUrlInput = getByLabelText('Queue URL');
    const severityField = getAllByLabelText('Severity')[0];
    const alertTypeField = getAllByLabelText('Alert Types')[0];

    // Fill in the correct data + submit
    fireEvent.change(displayInput, { target: { value: sqsDisplayName } });
    fireEvent.change(queueUrlInput, { target: { value: sqsConfig.queueUrl } });

    fireEvent.change(severityField, { target: { value: 'Critical' } });
    fireClickAndMouseEvents(getByText('Critical'));
    fireEvent.change(alertTypeField, { target: { value: 'Rule Matches' } });
    fireClickAndMouseEvents(getByText('Rule Matches'));

    fireEvent.click(getByText('Add Destination'));
    // Expect success screen with proper redirect link
    expect(await findByText('Everything looks good!'));
    expect(getByText('Finish Setup')).toHaveAttribute('href', urls.settings.destinations.list());
  });

  it('can create a SNS destination', async () => {
    const createdDestination = buildDestination() as DestinationFull;
    const snsDisplayName = 'SNS Destination';
    const snsConfig = buildSnsConfigInput({
      topicArn: 'arn:aws:sns:us-east-2:123456789012:MyTopic',
    });
    const mocks = [
      mockAddDestination({
        variables: {
          input: {
            displayName: snsDisplayName,
            outputType: DestinationTypeEnum.Sns,
            defaultForSeverity: [criticalSeverity],
            alertTypes: allAlertTypes,
            outputConfig: { sns: snsConfig },
          },
        },
        data: { addDestination: createdDestination },
      }),
    ];
    const { getByText, findByText, getByLabelText, getAllByLabelText } = render(
      <CreateDestination />,
      {
        mocks,
      }
    );

    // Select SNS
    fireEvent.click(getByText('AWS SNS'));

    const displayInput = getByLabelText('* Display Name');
    const topicArnInput = getByLabelText('Topic ARN');
    const severityField = getAllByLabelText('Severity')[0];
    const alertTypeField = getAllByLabelText('Alert Types')[0];

    // Fill in the correct data + submit
    fireEvent.change(displayInput, { target: { value: snsDisplayName } });
    fireEvent.change(topicArnInput, { target: { value: snsConfig.topicArn } });

    fireEvent.change(severityField, { target: { value: 'Critical' } });
    fireClickAndMouseEvents(getByText('Critical'));
    fireEvent.change(alertTypeField, { target: { value: 'Rule Matches' } });
    fireClickAndMouseEvents(getByText('Rule Matches'));

    fireEvent.click(getByText('Add Destination'));
    // Expect success screen with proper redirect link
    expect(await findByText('Everything looks good!'));
    expect(getByText('Finish Setup')).toHaveAttribute('href', urls.settings.destinations.list());
  });

  it('can create a Webhook destination', async () => {
    const createdDestination = buildDestination() as DestinationFull;
    const webhookDisplayName = 'Webhook Destination';
    const webhookConfig = buildCustomWebhookConfigInput({ webhookURL: validUrl });
    const mocks = [
      mockAddDestination({
        variables: {
          input: {
            displayName: webhookDisplayName,
            outputType: DestinationTypeEnum.Customwebhook,
            defaultForSeverity: [criticalSeverity],
            alertTypes: allAlertTypes,
            outputConfig: { customWebhook: webhookConfig },
          },
        },
        data: { addDestination: createdDestination },
      }),
    ];
    const { getByText, findByText, getByLabelText, getAllByLabelText } = render(
      <CreateDestination />,
      {
        mocks,
      }
    );

    // Select Custom Webhook
    fireEvent.click(getByText('Custom Webhook'));

    const displayInput = getByLabelText('* Display Name');
    const webhookUrlInput = getByLabelText('Custom Webhook URL');
    const severityField = getAllByLabelText('Severity')[0];
    const alertTypeField = getAllByLabelText('Alert Types')[0];

    // Fill in the correct data + submit
    fireEvent.change(displayInput, { target: { value: webhookDisplayName } });
    fireEvent.change(webhookUrlInput, { target: { value: webhookConfig.webhookURL } });

    fireEvent.change(severityField, { target: { value: 'Critical' } });
    fireClickAndMouseEvents(getByText('Critical'));
    fireEvent.change(alertTypeField, { target: { value: 'Rule Matches' } });
    fireClickAndMouseEvents(getByText('Rule Matches'));

    fireEvent.click(getByText('Add Destination'));
    // Expect success screen with proper redirect link
    expect(await findByText('Everything looks good!'));
    expect(getByText('Finish Setup')).toHaveAttribute('href', urls.settings.destinations.list());
  });

  it('can create a Teams destination', async () => {
    const createdDestination = buildDestination() as DestinationFull;
    const teamsDisplayName = 'Teams Destination';
    const teamsConfig = buildMsTeamsConfigInput({ webhookURL: validUrl });
    const mocks = [
      mockAddDestination({
        variables: {
          input: {
            displayName: teamsDisplayName,
            outputType: DestinationTypeEnum.Msteams,
            defaultForSeverity: [criticalSeverity],
            alertTypes: allAlertTypes,
            outputConfig: { msTeams: teamsConfig },
          },
        },
        data: { addDestination: createdDestination },
      }),
    ];
    const { getByText, findByText, getByLabelText, getAllByLabelText } = render(
      <CreateDestination />,
      {
        mocks,
      }
    );

    // Select Microsoft Teams
    fireEvent.click(getByText('Microsoft Teams'));

    const displayInput = getByLabelText('* Display Name');
    const webhookUrlInput = getByLabelText('Microsoft Teams Webhook URL');
    const severityField = getAllByLabelText('Severity')[0];
    const alertTypeField = getAllByLabelText('Alert Types')[0];

    // Fill in the correct data + submit
    fireEvent.change(displayInput, { target: { value: teamsDisplayName } });
    fireEvent.change(webhookUrlInput, { target: { value: teamsConfig.webhookURL } });

    fireEvent.change(severityField, { target: { value: 'Critical' } });
    fireClickAndMouseEvents(getByText('Critical'));
    fireEvent.change(alertTypeField, { target: { value: 'Rule Matches' } });
    fireClickAndMouseEvents(getByText('Rule Matches'));

    fireEvent.click(getByText('Add Destination'));
    // Expect success screen with proper redirect link
    expect(await findByText('Everything looks good!'));
    expect(getByText('Finish Setup')).toHaveAttribute('href', urls.settings.destinations.list());
  });

  it('can create a Opsgenie destination', async () => {
    const createdDestination = buildDestination() as DestinationFull;
    const opsgenieDisplayName = 'Opsgenie Destination';
    const opsgenieConfig = buildOpsgenieConfigInput();
    const mocks = [
      mockAddDestination({
        variables: {
          input: {
            displayName: opsgenieDisplayName,
            outputType: DestinationTypeEnum.Opsgenie,
            defaultForSeverity: [criticalSeverity],
            alertTypes: allAlertTypes,
            outputConfig: { opsgenie: opsgenieConfig },
          },
        },
        data: { addDestination: createdDestination },
      }),
    ];
    const { getByText, findByText, getByLabelText, getAllByLabelText } = render(
      <CreateDestination />,
      {
        mocks,
      }
    );

    // Select Opsgenie
    fireEvent.click(getByText('Opsgenie'));

    const displayInput = getByLabelText('* Display Name');
    const opsgenieApiKey = getByLabelText('Opsgenie API key');
    const severityField = getAllByLabelText('Severity')[0];
    const alertTypeField = getAllByLabelText('Alert Types')[0];

    // Fill in the correct data + submit
    fireEvent.change(displayInput, { target: { value: opsgenieDisplayName } });
    fireEvent.change(opsgenieApiKey, { target: { value: opsgenieConfig.apiKey } });

    fireEvent.change(severityField, { target: { value: 'Critical' } });
    fireClickAndMouseEvents(getByText('Critical'));
    fireEvent.change(alertTypeField, { target: { value: 'Rule Matches' } });
    fireClickAndMouseEvents(getByText('Rule Matches'));

    fireEvent.click(getByText('Add Destination'));
    // Expect success screen with proper redirect link
    expect(await findByText('Everything looks good!'));
    expect(getByText('Finish Setup')).toHaveAttribute('href', urls.settings.destinations.list());
  });

  it('can create a Asana destination', async () => {
    const createdDestination = buildDestination() as DestinationFull;
    const asanaDisplayName = 'Asana Destination';
    const asanaConfig = buildAsanaConfigInput({ projectGids: ['123', '345'] });
    const mocks = [
      mockAddDestination({
        variables: {
          input: {
            displayName: asanaDisplayName,
            outputType: DestinationTypeEnum.Asana,
            defaultForSeverity: [criticalSeverity],
            alertTypes: allAlertTypes,
            outputConfig: { asana: asanaConfig },
          },
        },
        data: { addDestination: createdDestination },
      }),
    ];
    const { getByText, findByText, getByLabelText, getAllByLabelText } = render(
      <CreateDestination />,
      {
        mocks,
      }
    );

    // Select Asana
    fireEvent.click(getByText('Asana'));

    const displayInput = getByLabelText('* Display Name');
    const tokenInput = getByLabelText('Access Token');
    const projectGidsInput = getByLabelText('Project GIDs', { selector: 'input' });
    const severityField = getAllByLabelText('Severity')[0];
    const alertTypeField = getAllByLabelText('Alert Types')[0];

    // Fill in the correct data + submit
    fireEvent.change(displayInput, { target: { value: asanaDisplayName } });
    fireEvent.change(tokenInput, { target: { value: asanaConfig.personalAccessToken } });
    asanaConfig.projectGids.forEach(gid => {
      fireEvent.change(projectGidsInput, {
        target: {
          value: gid,
        },
      });
      fireEvent.blur(projectGidsInput);
    });

    fireEvent.change(severityField, { target: { value: 'Critical' } });
    fireClickAndMouseEvents(getByText('Critical'));
    fireEvent.change(alertTypeField, { target: { value: 'Rule Matches' } });
    fireClickAndMouseEvents(getByText('Rule Matches'));

    fireEvent.click(getByText('Add Destination'));
    // Expect success screen with proper redirect link
    expect(await findByText('Everything looks good!'));
    expect(getByText('Finish Setup')).toHaveAttribute('href', urls.settings.destinations.list());
  });
});
