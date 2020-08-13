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
import { buildDestination, faker, fireEvent, render } from 'test-utils';
import urls from 'Source/urls';
import EditDestination, {
  mockGetDestinationDetails,
  mockUpdateDestination,
} from 'Components/wizards/EditDestinationWizard';
import { DestinationFull } from 'Source/graphql/fragments/DestinationFull.generated';
import { DestinationTypeEnum, SeverityEnum } from 'Generated/schema';

describe('EditDestination', () => {
  it('shows a spinner that gets replaced by a form as soon as data arrives', async () => {
    const destination = buildDestination({
      outputType: DestinationTypeEnum.Slack,
      defaultForSeverity: [SeverityEnum.Critical],
    }) as DestinationFull;

    const mocks = [mockGetDestinationDetails({ data: { destination } })];

    const { findByLabelText, getByAriaLabel } = render(<EditDestination />, { mocks });

    // Expect loading
    expect(getByAriaLabel('Loading...')).toBeInTheDocument();

    // Expect a form
    const displayInput = (await findByLabelText('* Display Name')) as HTMLInputElement;
    const webhookUrlInput = (await findByLabelText('Slack Webhook URL')) as HTMLInputElement;
    const criticalSeverityCheckbox = (await findByLabelText(
      SeverityEnum.Critical
    )) as HTMLInputElement;

    // With correct pre-populated values
    expect(displayInput.value).toEqual(destination.displayName);
    expect(webhookUrlInput.value).toEqual(destination.outputConfig.slack.webhookURL);
    expect(criticalSeverityCheckbox.checked).toBeTruthy();
    expect(criticalSeverityCheckbox.value).toBeTruthy();
  });

  it('can successfully edit a destination', async () => {
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
    expect(getByText('Finish Setup')).toHaveAttribute('href', urls.settings.destinations.list());
  });
});
