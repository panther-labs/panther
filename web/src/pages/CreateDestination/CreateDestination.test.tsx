import React from 'react';
import { render, fireEvent, buildDestination } from 'test-utils';
import urls from 'Source/urls';
import { mockAddDestination } from 'Components/wizards/CreateDestinationWizard';
import { DestinationFull } from 'Source/graphql/fragments/DestinationFull.generated';
import { DestinationTypeEnum, SeverityEnum } from 'Generated/schema';
import CreateDestination from './index';

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
    const slackWebhookUrl = 'https://test.com';
    const slackSeverity = SeverityEnum.Critical;

    const mocks = [
      mockAddDestination({
        variables: {
          input: {
            displayName: slackDisplayName,
            outputType: DestinationTypeEnum.Slack,
            defaultForSeverity: [slackSeverity],
            outputConfig: {
              slack: {
                webhookURL: slackWebhookUrl,
              },
            },
          },
        },
        data: { addDestination: createdDestination },
      }),
    ];
    const { getByText, findByText, getByLabelText } = render(<CreateDestination />, {
      mocks,
    });

    // Select Slack
    fireEvent.click(getByText('Slack'));

    const displayInput = getByLabelText('* Display Name');
    const webhookUrlInput = getByLabelText('Slack Webhook URL');
    const criticalSeverityCheckbox = getByLabelText(slackSeverity);

    // Fill in the correct data + submit
    fireEvent.change(displayInput, { target: { value: slackDisplayName } });
    fireEvent.change(webhookUrlInput, { target: { value: slackWebhookUrl } });
    fireEvent.click(criticalSeverityCheckbox);
    fireEvent.click(getByText('Add Destination'));

    // Expect success screen with proper redirect link
    expect(await findByText('Everything looks good!'));
    expect(getByText('Finish Setup')).toHaveAttribute('href', urls.settings.destinations.list());
  });
});
