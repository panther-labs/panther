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
  buildDestination,
  buildDestinationConfig,
  buildOpsgenieConfig,
  faker,
  fireEvent,
  render,
} from 'test-utils';
import urls from 'Source/urls';
import EditDestination, {
  mockGetDestinationDetails,
  mockUpdateDestination,
} from 'Components/wizards/EditDestinationWizard';
import { DestinationFull } from 'Source/graphql/fragments/DestinationFull.generated';
import { DestinationTypeEnum, OpsgenieServiceRegionEnum, SeverityEnum } from 'Generated/schema';

const validUrl = faker.internet.url();

describe('EditDestination', () => {
  it('shows a spinner that gets replaced by a form as soon as data arrives', async () => {
    const destination = buildDestination({
      outputType: DestinationTypeEnum.Slack,
      defaultForSeverity: [SeverityEnum.Critical],
    }) as DestinationFull;

    const mocks = [mockGetDestinationDetails({ data: { destination } })];

    const { findByLabelText, getByAriaLabel, getAllByLabelText } = render(<EditDestination />, {
      mocks,
    });

    // Expect loading
    expect(getByAriaLabel('Loading...')).toBeInTheDocument();

    // Expect a form
    const displayInput = (await findByLabelText('* Display Name')) as HTMLInputElement;
    const webhookUrlInput = (await findByLabelText('Slack Webhook URL')) as HTMLInputElement;
    expect(getAllByLabelText('Severity')[0]).toBeInTheDocument();
    expect(getAllByLabelText('Alert Types')[0]).toBeInTheDocument();

    // With correct pre-populated values
    expect(displayInput.value).toEqual(destination.displayName);
    expect(webhookUrlInput.value).toEqual(destination.outputConfig.slack.webhookURL);
  });

  it('can successfully edit Slack destination', async () => {
    const oldDisplayName = 'OldSlackName';
    const newDisplayName = 'NewSlackName';

    const destination = buildDestination({
      displayName: oldDisplayName,
      outputType: DestinationTypeEnum.Slack,
      defaultForSeverity: [SeverityEnum.Critical],
    }) as DestinationFull;
    destination.outputConfig.slack.webhookURL = faker.internet.url();

    const mocks = [
      mockGetDestinationDetails({ data: { destination } }),
      mockUpdateDestination({
        variables: {
          input: {
            displayName: newDisplayName,
            outputId: destination.outputId,
            outputType: destination.outputType,
            defaultForSeverity: destination.defaultForSeverity,
            alertTypes: destination.alertTypes,
            outputConfig: {
              slack: {
                webhookURL: destination.outputConfig.slack.webhookURL,
              },
            },
          },
        },
        data: { updateDestination: { ...destination, displayName: newDisplayName } },
      }),
    ];

    const { findByLabelText, findByText, getByText } = render(<EditDestination />, { mocks });

    // Wait for fields to show
    const displayInput = (await findByLabelText('* Display Name')) as HTMLInputElement;
    const submitButton = getByText('Update Destination');

    // Expect the submit button to be disabled when no changes are present
    expect(submitButton).toHaveAttribute('disabled');

    // Change the value + submit
    fireEvent.change(displayInput, { target: { value: newDisplayName } });
    fireEvent.click(submitButton);

    // Expect success screen with proper redirect link
    expect(await findByText('Everything looks good!'));
    expect(getByText('Finish Setup')).toHaveAttribute(
      'href',
      urls.integrations.destinations.list()
    );
  });

  it('can successfully edit Github destination', async () => {
    const oldDisplayName = 'OldName';
    const newDisplayName = 'NewName';

    const destination = buildDestination({
      displayName: oldDisplayName,
      outputType: DestinationTypeEnum.Github,
      defaultForSeverity: [SeverityEnum.Critical],
    }) as DestinationFull;

    const mocks = [
      mockGetDestinationDetails({ data: { destination } }),
      mockUpdateDestination({
        variables: {
          input: {
            displayName: newDisplayName,
            outputId: destination.outputId,
            outputType: destination.outputType,
            defaultForSeverity: destination.defaultForSeverity,
            alertTypes: destination.alertTypes,
            outputConfig: {
              github: {
                token: destination.outputConfig.github.token,
                repoName: destination.outputConfig.github.repoName,
              },
            },
          },
        },
        data: { updateDestination: { ...destination, displayName: newDisplayName } },
      }),
    ];

    const { findByLabelText, findByText, getByText } = render(<EditDestination />, { mocks });

    // Wait for fields to show
    const displayInput = (await findByLabelText('* Display Name')) as HTMLInputElement;
    const submitButton = getByText('Update Destination');

    // Expect the submit button to be disabled when no changes are present
    expect(submitButton).toHaveAttribute('disabled');

    // Change the value + submit
    fireEvent.change(displayInput, { target: { value: newDisplayName } });
    fireEvent.click(submitButton);

    // Expect success screen with proper redirect link
    expect(await findByText('Everything looks good!'));
    expect(getByText('Finish Setup')).toHaveAttribute(
      'href',
      urls.integrations.destinations.list()
    );
  });

  it('can successfully edit Jira destination', async () => {
    const oldDisplayName = 'OldName';
    const newDisplayName = 'NewName';

    const destination = buildDestination({
      displayName: oldDisplayName,
      outputType: DestinationTypeEnum.Jira,
      defaultForSeverity: [SeverityEnum.Critical],
    }) as DestinationFull;
    destination.outputConfig.jira.orgDomain = validUrl;

    const mocks = [
      mockGetDestinationDetails({ data: { destination } }),
      mockUpdateDestination({
        variables: {
          input: {
            displayName: newDisplayName,
            outputId: destination.outputId,
            outputType: destination.outputType,
            defaultForSeverity: destination.defaultForSeverity,
            alertTypes: destination.alertTypes,
            outputConfig: {
              jira: {
                orgDomain: destination.outputConfig.jira.orgDomain,
                projectKey: destination.outputConfig.jira.projectKey,
                userName: destination.outputConfig.jira.userName,
                apiKey: destination.outputConfig.jira.apiKey,
                assigneeId: destination.outputConfig.jira.assigneeId,
                issueType: destination.outputConfig.jira.issueType,
                labels: destination.outputConfig.jira.labels,
              },
            },
          },
        },
        data: { updateDestination: { ...destination, displayName: newDisplayName } },
      }),
    ];

    const { findByLabelText, findByText, getByText } = render(<EditDestination />, { mocks });

    // Wait for fields to show
    const displayInput = (await findByLabelText('* Display Name')) as HTMLInputElement;
    const submitButton = getByText('Update Destination');

    // Expect the submit button to be disabled when no changes are present
    expect(submitButton).toHaveAttribute('disabled');

    // Change the value + submit
    fireEvent.change(displayInput, { target: { value: newDisplayName } });
    fireEvent.click(submitButton);

    // Expect success screen with proper redirect link
    expect(await findByText('Everything looks good!'));
    expect(getByText('Finish Setup')).toHaveAttribute(
      'href',
      urls.integrations.destinations.list()
    );
  });

  it('can successfully edit PagerDuty destination', async () => {
    const oldDisplayName = 'OldName';
    const newDisplayName = 'NewName';
    const deductedPagerDutyIntegrationKey = '';

    const destination = buildDestination({
      displayName: oldDisplayName,
      outputType: DestinationTypeEnum.Pagerduty,
      defaultForSeverity: [SeverityEnum.Critical],
    }) as DestinationFull;
    destination.outputConfig.pagerDuty.integrationKey = deductedPagerDutyIntegrationKey;

    const mocks = [
      mockGetDestinationDetails({ data: { destination } }),
      mockUpdateDestination({
        variables: {
          input: {
            displayName: newDisplayName,
            outputId: destination.outputId,
            outputType: destination.outputType,
            defaultForSeverity: destination.defaultForSeverity,
            alertTypes: destination.alertTypes,
            outputConfig: {
              pagerDuty: {
                integrationKey: destination.outputConfig.pagerDuty.integrationKey,
              },
            },
          },
        },
        data: { updateDestination: { ...destination, displayName: newDisplayName } },
      }),
    ];

    const { findByLabelText, findByText, getByText } = render(<EditDestination />, { mocks });

    // Wait for fields to show
    const displayInput = (await findByLabelText('* Display Name')) as HTMLInputElement;
    const submitButton = getByText('Update Destination');

    // Expect the submit button to be disabled when no changes are present
    expect(submitButton).toHaveAttribute('disabled');

    // Change the value + submit
    fireEvent.change(displayInput, { target: { value: newDisplayName } });
    fireEvent.click(submitButton);

    // Expect success screen with proper redirect link
    expect(await findByText('Everything looks good!'));
    expect(getByText('Finish Setup')).toHaveAttribute(
      'href',
      urls.integrations.destinations.list()
    );
  });

  it('can successfully edit SQS destination', async () => {
    const oldDisplayName = 'OldName';
    const newDisplayName = 'NewName';

    const destination = buildDestination({
      displayName: oldDisplayName,
      outputType: DestinationTypeEnum.Sqs,
      defaultForSeverity: [SeverityEnum.Critical],
    }) as DestinationFull;
    destination.outputConfig.sqs.queueUrl = validUrl;

    const mocks = [
      mockGetDestinationDetails({ data: { destination } }),
      mockUpdateDestination({
        variables: {
          input: {
            displayName: newDisplayName,
            outputId: destination.outputId,
            outputType: destination.outputType,
            defaultForSeverity: destination.defaultForSeverity,
            alertTypes: destination.alertTypes,
            outputConfig: {
              sqs: {
                queueUrl: destination.outputConfig.sqs.queueUrl,
              },
            },
          },
        },
        data: { updateDestination: { ...destination, displayName: newDisplayName } },
      }),
    ];

    const { findByLabelText, findByText, getByText } = render(<EditDestination />, { mocks });

    // Wait for fields to show
    const displayInput = (await findByLabelText('* Display Name')) as HTMLInputElement;
    const submitButton = getByText('Update Destination');

    // Expect the submit button to be disabled when no changes are present
    expect(submitButton).toHaveAttribute('disabled');

    // Change the value + submit
    fireEvent.change(displayInput, { target: { value: newDisplayName } });
    fireEvent.click(submitButton);

    // Expect success screen with proper redirect link
    expect(await findByText('Everything looks good!'));
    expect(getByText('Finish Setup')).toHaveAttribute(
      'href',
      urls.integrations.destinations.list()
    );
  });

  it('can successfully edit SNS destination', async () => {
    const oldDisplayName = 'OldName';
    const newDisplayName = 'NewName';
    const topicArn = 'arn:aws:sns:us-east-2:123456789012:MyTopic';

    const destination = buildDestination({
      displayName: oldDisplayName,
      outputType: DestinationTypeEnum.Sns,
      defaultForSeverity: [SeverityEnum.Critical],
    }) as DestinationFull;
    destination.outputConfig.sns.topicArn = topicArn;

    const mocks = [
      mockGetDestinationDetails({ data: { destination } }),
      mockUpdateDestination({
        variables: {
          input: {
            displayName: newDisplayName,
            outputId: destination.outputId,
            outputType: destination.outputType,
            defaultForSeverity: destination.defaultForSeverity,
            alertTypes: destination.alertTypes,
            outputConfig: {
              sns: {
                topicArn: destination.outputConfig.sns.topicArn,
              },
            },
          },
        },
        data: { updateDestination: { ...destination, displayName: newDisplayName } },
      }),
    ];

    const { findByLabelText, findByText, getByText } = render(<EditDestination />, { mocks });

    // Wait for fields to show
    const displayInput = (await findByLabelText('* Display Name')) as HTMLInputElement;
    const submitButton = getByText('Update Destination');

    // Expect the submit button to be disabled when no changes are present
    expect(submitButton).toHaveAttribute('disabled');

    // Change the value + submit
    fireEvent.change(displayInput, { target: { value: newDisplayName } });
    fireEvent.click(submitButton);

    // Expect success screen with proper redirect link
    expect(await findByText('Everything looks good!'));
    expect(getByText('Finish Setup')).toHaveAttribute(
      'href',
      urls.integrations.destinations.list()
    );
  });

  it('can successfully edit Custom Webhook destination', async () => {
    const oldDisplayName = 'OldName';
    const newDisplayName = 'NewName';

    const destination = buildDestination({
      displayName: oldDisplayName,
      outputType: DestinationTypeEnum.Customwebhook,
      defaultForSeverity: [SeverityEnum.Critical],
    }) as DestinationFull;
    destination.outputConfig.customWebhook.webhookURL = validUrl;

    const mocks = [
      mockGetDestinationDetails({ data: { destination } }),
      mockUpdateDestination({
        variables: {
          input: {
            displayName: newDisplayName,
            outputId: destination.outputId,
            outputType: destination.outputType,
            defaultForSeverity: destination.defaultForSeverity,
            alertTypes: destination.alertTypes,
            outputConfig: {
              customWebhook: {
                webhookURL: destination.outputConfig.customWebhook.webhookURL,
              },
            },
          },
        },
        data: { updateDestination: { ...destination, displayName: newDisplayName } },
      }),
    ];

    const { findByLabelText, findByText, getByText } = render(<EditDestination />, { mocks });

    // Wait for fields to show
    const displayInput = (await findByLabelText('* Display Name')) as HTMLInputElement;
    const submitButton = getByText('Update Destination');

    // Expect the submit button to be disabled when no changes are present
    expect(submitButton).toHaveAttribute('disabled');

    // Change the value + submit
    fireEvent.change(displayInput, { target: { value: newDisplayName } });
    fireEvent.click(submitButton);

    // Expect success screen with proper redirect link
    expect(await findByText('Everything looks good!'));
    expect(getByText('Finish Setup')).toHaveAttribute(
      'href',
      urls.integrations.destinations.list()
    );
  });

  it('can successfully edit MS Teams destination', async () => {
    const oldDisplayName = 'OldName';
    const newDisplayName = 'NewName';

    const destination = buildDestination({
      displayName: oldDisplayName,
      outputType: DestinationTypeEnum.Msteams,
      defaultForSeverity: [SeverityEnum.Critical],
    }) as DestinationFull;
    destination.outputConfig.msTeams.webhookURL = validUrl;

    const mocks = [
      mockGetDestinationDetails({ data: { destination } }),
      mockUpdateDestination({
        variables: {
          input: {
            displayName: newDisplayName,
            outputId: destination.outputId,
            outputType: destination.outputType,
            defaultForSeverity: destination.defaultForSeverity,
            alertTypes: destination.alertTypes,
            outputConfig: {
              msTeams: {
                webhookURL: destination.outputConfig.msTeams.webhookURL,
              },
            },
          },
        },
        data: { updateDestination: { ...destination, displayName: newDisplayName } },
      }),
    ];

    const { findByLabelText, findByText, getByText } = render(<EditDestination />, { mocks });

    // Wait for fields to show
    const displayInput = (await findByLabelText('* Display Name')) as HTMLInputElement;
    const submitButton = getByText('Update Destination');

    // Expect the submit button to be disabled when no changes are present
    expect(submitButton).toHaveAttribute('disabled');

    // Change the value + submit
    fireEvent.change(displayInput, { target: { value: newDisplayName } });
    fireEvent.click(submitButton);

    // Expect success screen with proper redirect link
    expect(await findByText('Everything looks good!'));
    expect(getByText('Finish Setup')).toHaveAttribute(
      'href',
      urls.integrations.destinations.list()
    );
  });

  it('can successfully edit Opsgenie destination', async () => {
    const oldDisplayName = 'OldName';
    const newDisplayName = 'NewName';

    const destination = buildDestination({
      displayName: oldDisplayName,
      outputType: DestinationTypeEnum.Opsgenie,
      defaultForSeverity: [SeverityEnum.Critical],
      outputConfig: buildDestinationConfig({
        opsgenie: buildOpsgenieConfig({
          apiKey: '',
          serviceRegion: OpsgenieServiceRegionEnum.Us,
        }),
      }),
    }) as DestinationFull;

    const mocks = [
      mockGetDestinationDetails({ data: { destination } }),
      mockUpdateDestination({
        variables: {
          input: {
            displayName: newDisplayName,
            outputId: destination.outputId,
            outputType: destination.outputType,
            defaultForSeverity: destination.defaultForSeverity,
            alertTypes: destination.alertTypes,
            outputConfig: {
              opsgenie: {
                apiKey: destination.outputConfig.opsgenie.apiKey,
                serviceRegion: destination.outputConfig.opsgenie.serviceRegion,
              },
            },
          },
        },
        data: { updateDestination: { ...destination, displayName: newDisplayName } },
      }),
    ];

    const { findByLabelText, findByText, getByText } = render(<EditDestination />, { mocks });

    // Wait for fields to show
    const displayInput = (await findByLabelText('* Display Name')) as HTMLInputElement;
    const submitButton = getByText('Update Destination');

    // Expect the submit button to be disabled when no changes are present
    expect(submitButton).toHaveAttribute('disabled');

    // Change the value + submit
    fireEvent.change(displayInput, { target: { value: newDisplayName } });
    fireEvent.click(submitButton);

    // Expect success screen with proper redirect link
    expect(await findByText('Everything looks good!'));
    expect(getByText('Finish Setup')).toHaveAttribute(
      'href',
      urls.integrations.destinations.list()
    );
  });

  it('can successfully edit Asana destination', async () => {
    const oldDisplayName = 'OldName';
    const newDisplayName = 'NewName';

    const destination = buildDestination({
      displayName: oldDisplayName,
      outputType: DestinationTypeEnum.Asana,
      defaultForSeverity: [SeverityEnum.Critical],
    }) as DestinationFull;
    destination.outputConfig.asana.projectGids = ['123'];

    const mocks = [
      mockGetDestinationDetails({ data: { destination } }),
      mockUpdateDestination({
        variables: {
          input: {
            displayName: newDisplayName,
            outputId: destination.outputId,
            outputType: destination.outputType,
            defaultForSeverity: destination.defaultForSeverity,
            alertTypes: destination.alertTypes,
            outputConfig: {
              asana: {
                projectGids: destination.outputConfig.asana.projectGids,
                personalAccessToken: destination.outputConfig.asana.personalAccessToken,
              },
            },
          },
        },
        data: { updateDestination: { ...destination, displayName: newDisplayName } },
      }),
    ];

    const { findByLabelText, findByText, getByText } = render(<EditDestination />, { mocks });

    // Wait for fields to show
    const displayInput = (await findByLabelText('* Display Name')) as HTMLInputElement;
    const submitButton = getByText('Update Destination');

    // Expect the submit button to be disabled when no changes are present
    expect(submitButton).toHaveAttribute('disabled');

    // Change the value + submit
    fireEvent.change(displayInput, { target: { value: newDisplayName } });
    fireEvent.click(submitButton);

    // Expect success screen with proper redirect link
    expect(await findByText('Everything looks good!'));
    expect(getByText('Finish Setup')).toHaveAttribute(
      'href',
      urls.integrations.destinations.list()
    );
  });
});
