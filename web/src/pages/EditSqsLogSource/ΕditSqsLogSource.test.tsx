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
  buildSqsLogSourceIntegration,
  waitFor,
  waitMs,
  buildUpdateSqsLogIntegrationInput,
} from 'test-utils';
import { EventEnum, SrcEnum, trackEvent } from 'Helpers/analytics';
import { mockListAvailableLogTypes } from 'Source/graphql/queries';
import { Route } from 'react-router';
import urls from 'Source/urls';
import EditSqsLogSource from './EditSqsLogSource';
import { mockGetSqsLogSource } from './graphql/getSqsLogSource.generated';
import { mockUpdateSqsLogSource } from './graphql/updateSqsLogSource.generated';

jest.mock('Helpers/analytics');

describe('EditSqsLogSource', () => {
  beforeAll(() => {
    document.execCommand = jest.fn();
  });

  afterAll(() => {
    (document.execCommand as jest.MockedFunction<any>).mockClear();
  });

  it('can successfully update an Sqs log source', async () => {
    const logSource = buildSqsLogSourceIntegration({ integrationId: 'test' });
    const { logTypes } = logSource.sqsConfig;

    const updatedLogSource = buildSqsLogSourceIntegration({
      ...logSource,
      integrationLabel: 'new-value',
    });

    const mocks = [
      mockGetSqsLogSource({
        variables: {
          id: logSource.integrationId,
        },
        data: {
          getSqsLogIntegration: logSource,
        },
      }),
      mockListAvailableLogTypes({
        data: {
          listAvailableLogTypes: {
            logTypes,
          },
        },
      }),
      mockUpdateSqsLogSource({
        variables: {
          input: buildUpdateSqsLogIntegrationInput({
            integrationId: logSource.integrationId,
            integrationLabel: updatedLogSource.integrationLabel,
            sqsConfig: {
              logTypes: logSource.sqsConfig.logTypes,
              allowedPrincipalArns: logSource.sqsConfig.allowedPrincipalArns,
              allowedSourceArns: logSource.sqsConfig.allowedSourceArns,
            },
          }),
        },
        data: {
          updateSqsLogIntegration: updatedLogSource,
        },
      }),
    ];
    const { getByText, getByLabelText, findByText } = render(
      <Route path={urls.integrations.logSources.edit(':id', ':type')}>
        <EditSqsLogSource />
      </Route>,
      {
        mocks,
        initialRoute: urls.integrations.logSources.edit(logSource.integrationId, 'sqs'),
      }
    );

    const nameField = getByLabelText('Name') as HTMLInputElement;

    //  Wait for GET api request to populate the form
    await waitFor(() => expect(nameField).toHaveValue('Loading...'));
    await waitFor(() => expect(nameField).toHaveValue(logSource.integrationLabel));

    // Fill in  the form and press continue
    fireEvent.change(nameField, { target: { value: updatedLogSource.integrationLabel } });

    // Wait for form validation to kick in and move on to the next screen
    await waitMs(1);
    fireEvent.click(getByText('Continue Setup'));

    // Expect to see a loading animation while the resource is being validated ...
    expect(getByText('Updating your SQS queue')).toBeInTheDocument();

    // ... replaced by a success screen
    expect(await findByText('Your SQS source was successfully updated')).toBeInTheDocument();
    expect(getByText('Finish Setup')).toBeInTheDocument();

    // Expect to see a copy button that works
    fireEvent.click(getByText('Copy SQS Queue URL'));
    expect(document.execCommand).toHaveBeenCalledWith('copy');
    expect(getByText('Copied to clipboard')).toBeInTheDocument();

    // Expect analytics to have been called
    expect(trackEvent).toHaveBeenCalledWith({
      event: EventEnum.UpdatedLogSource,
      src: SrcEnum.LogSources,
      ctx: 'SQS',
    });
  });
});
