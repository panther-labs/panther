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
import { render, fireEvent, buildComplianceIntegration, waitFor } from 'test-utils';
import { mockGetComplianceCfnTemplate } from 'Components/wizards/ComplianceSourceWizard';
import EditComplianceSource from './EditComplianceSource';
import { mockGetComplianceSource } from './graphql/getComplianceSource.generated';
import { mockUpdateComplianceSource } from './graphql/updateComplianceSource.generated';

const newTestName = 'new-test';
const mockPantherAwsAccountId = '456456456456';

describe('EditComplianceSource', () => {
  let prevPantherAwsAccountId;
  beforeAll(() => {
    prevPantherAwsAccountId = process.env.AWS_ACCOUNT_ID;
    process.env.PANTHER_VERSION = mockPantherAwsAccountId;
  });

  afterAll(() => {
    process.env.PANTHER_VERSION = prevPantherAwsAccountId;
  });

  it('can successfully update a compliance source', async () => {
    const complianceSource = buildComplianceIntegration();
    const mocks = [
      mockGetComplianceSource({
        data: {
          getComplianceIntegration: complianceSource,
        },
      }),
      mockGetComplianceCfnTemplate({
        variables: {
          input: {
            awsAccountId: mockPantherAwsAccountId,
            integrationLabel: newTestName,
            remediationEnabled: false,
            cweEnabled: false,
          },
        },
        data: {
          getComplianceIntegrationTemplate: {
            stackName: 'test-stackname',
            body: 'test-body',
          },
        },
      }),
      mockUpdateComplianceSource({
        variables: {
          input: {
            integrationId: complianceSource.integrationId,
            integrationLabel: newTestName,
            cweEnabled: complianceSource.cweEnabled,
            remediationEnabled: complianceSource.remediationEnabled,
          },
        },
        data: {
          updateComplianceIntegration: {
            ...buildComplianceIntegration(),
            integrationLabel: newTestName,
          },
        },
      }),
    ];
    const { getByText, getByLabelText, getByAltText, findByText } = render(
      <EditComplianceSource />,
      { mocks }
    );

    // Fill in  the form and press continue
    fireEvent.change(getByLabelText('Name'), { target: { value: newTestName } });
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
