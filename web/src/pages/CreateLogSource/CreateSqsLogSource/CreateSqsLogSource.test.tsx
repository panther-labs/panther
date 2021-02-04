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
  waitMs,
  buildAddSqsLogIntegrationInput,
} from 'test-utils';
import { EventEnum, SrcEnum, trackEvent } from 'Helpers/analytics';
import { mockListAvailableLogTypes } from 'Source/graphql/queries';
import CreateSqsLogSource from './CreateSqsLogSource';
import { mockAddSqsLogSource } from './graphql/addSqsLogSource.generated';

jest.mock('Helpers/analytics');

describe('CreateSqsLogSource', () => {
  beforeAll(() => {
    document.execCommand = jest.fn();
  });

  afterAll(() => {
    (document.execCommand as jest.MockedFunction<any>).mockClear();
  });

  it('can successfully create an Sqs log source', async () => {
    const logSource = buildSqsLogSourceIntegration();
    const { logTypes } = logSource.sqsConfig;

    const mocks = [
      mockListAvailableLogTypes({
        data: {
          listAvailableLogTypes: {
            logTypes,
          },
        },
      }),
      mockAddSqsLogSource({
        variables: {
          input: buildAddSqsLogIntegrationInput({
            integrationLabel: logSource.integrationLabel,
            sqsConfig: {
              logTypes: logSource.sqsConfig.logTypes,
              allowedPrincipalArns: logSource.sqsConfig.allowedPrincipalArns,
              allowedSourceArns: logSource.sqsConfig.allowedSourceArns,
            },
          }),
        },
        data: {
          addSqsLogIntegration: logSource,
        },
      }),
    ];
    const { getByText, getByLabelText, findByText, getAllByLabelText } = render(
      <CreateSqsLogSource />,
      {
        mocks,
      }
    );

    // Fill in  the form and press continue
    fireEvent.change(getByLabelText('Name'), { target: { value: logSource.integrationLabel } });

    const logTypesField = getAllByLabelText('Log Types')[0];
    fireEvent.change(logTypesField, { target: { value: logSource.sqsConfig.logTypes[0] } });
    fireEvent.click(await findByText(logSource.sqsConfig.logTypes[0]));

    const principalArnField = getAllByLabelText('Allowed AWS Principal ARNs')[0];
    fireEvent.change(principalArnField, {
      target: { value: logSource.sqsConfig.allowedPrincipalArns[0] },
    });
    fireEvent.keyDown(principalArnField, { key: 'Enter', code: 'Enter' });

    const sourceArnField = getAllByLabelText('Allowed Source ARNs')[0];
    fireEvent.change(sourceArnField, {
      target: { value: logSource.sqsConfig.allowedSourceArns[0] },
    });
    fireEvent.keyDown(sourceArnField, { key: 'Enter', code: 'Enter' });

    // Wait for form validation to kick in and move on to the next screen
    await waitMs(1);
    fireEvent.click(getByText('Continue Setup'));

    // Expect to see a loading animation while the resource is being validated ...
    expect(getByText('Creating an SQS queue')).toBeInTheDocument();

    // ... replaced by a success screen
    expect(await findByText('An SQS Queue has been created for you!')).toBeInTheDocument();
    expect(getByText('Finish Setup')).toBeInTheDocument();
    expect(getByText('Add Another')).toBeInTheDocument();

    // Expect to see a copy button that works
    fireEvent.click(getByText('Copy SQS Queue URL'));
    expect(document.execCommand).toHaveBeenCalledWith('copy');
    expect(getByText('Copied to clipboard')).toBeInTheDocument();

    // Expect analytics to have been called
    expect(trackEvent).toHaveBeenCalledWith({
      event: EventEnum.AddedLogSource,
      src: SrcEnum.LogSources,
      ctx: 'SQS',
    });
  });
});
