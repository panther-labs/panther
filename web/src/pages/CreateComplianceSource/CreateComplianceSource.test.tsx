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
import { GraphQLError } from 'graphql';
import { render, fireEvent, buildComplianceIntegration, waitFor } from 'test-utils';
import { mockGetComplianceCfnTemplate } from 'Components/wizards/ComplianceSourceWizard';
import { mockAddComplianceSource } from './graphql/addComplianceSource.generated';
import CreateComplianceSource from './CreateComplianceSource';

const testName = 'test';
const testAwsAccountID = '123123123123';
const mockPantherAwsAccountId = '456456456456';

describe('CreateComplianceSource', () => {
  let prevPantherAwsAccountId;
  beforeAll(() => {
    prevPantherAwsAccountId = process.env.AWS_ACCOUNT_ID;
    process.env.PANTHER_VERSION = mockPantherAwsAccountId;
  });

  afterAll(() => {
    process.env.PANTHER_VERSION = prevPantherAwsAccountId;
  });

  it('can successfully onboard a compliance source', async () => {
    const mocks = [
      mockGetComplianceCfnTemplate({
        variables: {
          input: {
            awsAccountId: mockPantherAwsAccountId,
            integrationLabel: testName,
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
      mockAddComplianceSource({
        variables: {
          input: {
            integrationLabel: testName,
            awsAccountId: testAwsAccountID,
            cweEnabled: false,
            remediationEnabled: false,
          },
        },
        data: {
          addComplianceIntegration: buildComplianceIntegration() as any,
        },
      }),
    ];
    const {
      getByText,
      getByLabelText,
      getByAltText,
      findByText,
    } = render(<CreateComplianceSource />, { mocks });

    // Fill in  the form and press continue
    fireEvent.change(getByLabelText('Name'), { target: { value: testName } });
    fireEvent.change(getByLabelText('AWS Account ID'), { target: { value: testAwsAccountID } });
    fireEvent.click(getByLabelText('Real-Time AWS Resource Scans'));
    fireEvent.click(getByLabelText('AWS Automatic Remediations'));
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
    expect(getByText('Add Another')).toBeInTheDocument();
  });

  it('shows a proper fail message when source validation fails', async () => {
    const errorMessage = "No-can-do's-ville, baby doll";
    const mocks = [
      mockGetComplianceCfnTemplate({
        variables: {
          input: {
            awsAccountId: mockPantherAwsAccountId,
            integrationLabel: testName,
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
      mockAddComplianceSource({
        variables: {
          input: {
            integrationLabel: testName,
            awsAccountId: testAwsAccountID,
            cweEnabled: false,
            remediationEnabled: false,
          },
        },
        data: null,
        errors: [new GraphQLError(errorMessage)],
      }),
    ];
    const {
      getByText,
      getByLabelText,
      getByAltText,
      findByText,
    } = render(<CreateComplianceSource />, { mocks });

    // Fill in  the form and press continue
    fireEvent.change(getByLabelText('Name'), { target: { value: testName } });
    fireEvent.change(getByLabelText('AWS Account ID'), { target: { value: testAwsAccountID } });
    fireEvent.click(getByLabelText('Real-Time AWS Resource Scans'));
    fireEvent.click(getByLabelText('AWS Automatic Remediations'));

    // Move on to the next screen
    fireEvent.click(getByText('Continue Setup'));

    // We move on to the final screen
    fireEvent.click(getByText('Continue'));

    // Expect to see a loading animation while the resource is being validated ...
    expect(getByAltText('Validating source health...')).toBeInTheDocument();
    expect(getByText('Cancel')).toBeInTheDocument();

    // ... replaced by a failure screen
    expect(await findByText("Something didn't go as planned")).toBeInTheDocument();
    expect(getByText('Start over')).toBeInTheDocument();
    expect(getByText(errorMessage)).toBeInTheDocument();
  });
});
