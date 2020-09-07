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
  buildComplianceIntegration,
  waitFor,
  waitMs,
  buildUpdateComplianceIntegrationInput,
} from 'test-utils';
import EditComplianceSource from './EditComplianceSource';
import { mockGetComplianceSource } from './graphql/getComplianceSource.generated';
import { mockUpdateComplianceSource } from './graphql/updateComplianceSource.generated';

describe('EditComplianceSource', () => {
  it('can successfully update a compliance source', async () => {
    const complianceSource = buildComplianceIntegration({
      awsAccountId: '123123123123',
    });

    const updatedComplianceSource = buildComplianceIntegration({
      integrationLabel: 'new-test',
      awsAccountId: '123123123123',
    });

    const mocks = [
      mockGetComplianceSource({
        data: {
          getComplianceIntegration: complianceSource,
        },
      }),
      mockUpdateComplianceSource({
        variables: {
          input: buildUpdateComplianceIntegrationInput({
            integrationId: undefined, // normally it's derived from react-router params, but we don't have <Route> defined in our tests
            integrationLabel: updatedComplianceSource.integrationLabel,
            cweEnabled: complianceSource.cweEnabled,
            remediationEnabled: complianceSource.remediationEnabled,
          }),
        },
        data: {
          updateComplianceIntegration: updatedComplianceSource,
        },
      }),
    ];
    const { getByText, getByLabelText, getByAltText, findByText } = render(
      <EditComplianceSource />,
      { mocks }
    );

    const nameField = getByLabelText('Name') as HTMLInputElement;

    //  Wait for GET api request to populate the form
    await waitFor(() => expect(nameField).toHaveValue('Loading...'));
    await waitFor(() => expect(nameField).toHaveValue(complianceSource.integrationLabel));

    // Update the name  and press continue
    fireEvent.change(nameField, { target: { value: updatedComplianceSource.integrationLabel } });

    // Wait for form validation to kick in and move on to the next screen
    await waitMs(50);
    fireEvent.click(getByText('Continue Setup'));

    // Initially we expect a disabled button while the template is being fetched ...
    expect(getByText('Get template file')).toHaveAttribute('disabled');

    // ... replaced by an active button as soon as it's fetched
    await waitFor(() => expect(getByText('Get template file')).not.toHaveAttribute('disabled'));

    // We move on to the final screen
    fireEvent.click(getByText('Continue'));

    // Expect to see a loading animation while the resource is being validated ...
    expect(getByAltText('Validating source health...')).toBeInTheDocument();
    expect(getByText('Cancel')).toBeInTheDocument();

    // ... replaced by a success screen
    expect(await findByText('Everything looks good!')).toBeInTheDocument();
    expect(getByText('Finish Setup')).toBeInTheDocument();
  });
});
