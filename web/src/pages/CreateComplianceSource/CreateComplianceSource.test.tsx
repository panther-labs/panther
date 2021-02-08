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
import {
  render,
  fireEvent,
  buildComplianceIntegration,
  waitFor,
  waitMs,
  buildAddComplianceIntegrationInput,
  fireClickAndMouseEvents,
} from 'test-utils';
import { EventEnum, SrcEnum, trackError, TrackErrorEnum, trackEvent } from 'Helpers/analytics';
import { AWS_REGIONS, CLOUD_SECURITY_REAL_TIME_DOC_URL, RESOURCE_TYPES } from 'Source/constants';
import { mockAddComplianceSource } from './graphql/addComplianceSource.generated';
import CreateComplianceSource from './CreateComplianceSource';

jest.mock('Helpers/analytics');

describe('CreateComplianceSource', () => {
  it('can successfully onboard a compliance source without real-time', async () => {
    const complianceSource = buildComplianceIntegration({
      awsAccountId: '123123123123',
      remediationEnabled: false,
      cweEnabled: false,
      regionIgnoreList: [],
      resourceTypeIgnoreList: [],
    });

    const mocks = [
      mockAddComplianceSource({
        variables: {
          input: buildAddComplianceIntegrationInput({
            integrationLabel: complianceSource.integrationLabel,
            awsAccountId: complianceSource.awsAccountId,
            cweEnabled: complianceSource.cweEnabled,
            remediationEnabled: complianceSource.remediationEnabled,
            regionIgnoreList: complianceSource.regionIgnoreList,
            resourceTypeIgnoreList: complianceSource.resourceTypeIgnoreList,
          }),
        },
        data: {
          addComplianceIntegration: buildComplianceIntegration() as any,
        },
      }),
    ];

    const {
      getByText,
      getByLabelText,
      getByAriaLabel,
      getByAltText,
      findByText,
    } = render(<CreateComplianceSource />, { mocks });

    // Fill in  the form and press continue
    fireEvent.change(getByLabelText('Name'), {
      target: { value: complianceSource.integrationLabel },
    });
    fireEvent.change(getByLabelText('AWS Account ID'), {
      target: { value: complianceSource.awsAccountId },
    });
    fireEvent.click(getByAriaLabel('Real-Time AWS Resource Scans'));
    fireEvent.click(getByAriaLabel('AWS Automatic Remediations'));

    // Wait for form validation to kick in and move on to the next screen
    await waitMs(1);
    fireEvent.click(getByText('Continue Setup'));

    // Initially we expect a disabled button while the template is being fetched ...
    expect(getByText('Get template file')).toHaveAttribute('disabled');

    // ... replaced by an active button as soon as it's fetched
    await waitFor(() => expect(getByText('Get template file')).not.toHaveAttribute('disabled'));

    // We move on to the final screen
    fireEvent.click(getByText('Continue'));

    // Expect to see a loading animation while the resource is being validated ...
    expect(getByAltText('Validating source health...')).toBeInTheDocument();

    // ... replaced by a success screen
    expect(await findByText('Everything looks good!')).toBeInTheDocument();
    expect(getByText('Finish Setup')).toBeInTheDocument();
    expect(getByText('Add Another')).toBeInTheDocument();
  });

  it('can successfully onboard a compliance source with real-time support', async () => {
    const complianceSource = buildComplianceIntegration({
      awsAccountId: '123123123123',
      remediationEnabled: true,
      cweEnabled: true,
      regionIgnoreList: [AWS_REGIONS[0]],
      resourceTypeIgnoreList: [RESOURCE_TYPES[0]],
    });

    const mocks = [
      mockAddComplianceSource({
        variables: {
          input: buildAddComplianceIntegrationInput({
            integrationLabel: complianceSource.integrationLabel,
            awsAccountId: complianceSource.awsAccountId,
            cweEnabled: complianceSource.cweEnabled,
            remediationEnabled: complianceSource.remediationEnabled,
            regionIgnoreList: complianceSource.regionIgnoreList,
            resourceTypeIgnoreList: complianceSource.resourceTypeIgnoreList,
          }),
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
      getAllByLabelText,
    } = render(<CreateComplianceSource />, { mocks });

    // Fill in  the form and press continue
    fireEvent.change(getByLabelText('Name'), {
      target: { value: complianceSource.integrationLabel },
    });
    fireEvent.change(getByLabelText('AWS Account ID'), {
      target: { value: complianceSource.awsAccountId },
    });

    fireEvent.change(getAllByLabelText('Exclude AWS Regions')[0], {
      target: { value: AWS_REGIONS[0] },
    });
    fireClickAndMouseEvents(await findByText(AWS_REGIONS[0]));

    fireEvent.change(getAllByLabelText('Exclude Resource Types')[0], {
      target: { value: RESOURCE_TYPES[0] },
    });
    fireClickAndMouseEvents(await findByText(RESOURCE_TYPES[0]));

    // Wait for form validation to kick in and move on to the next screen
    await waitMs(1);
    fireEvent.click(getByText('Continue Setup'));

    // We move on to the final screen
    fireEvent.click(getByText('Continue'));

    // Expect to see a loading animation while the resource is being validated ...
    expect(getByAltText('Validating source health...')).toBeInTheDocument();

    // ... replaced by a "configure real-time" screen
    expect(await findByText('Configuring Real-Time Monitoring')).toBeInTheDocument();
    expect(getByText('steps found here')).toHaveAttribute('href', CLOUD_SECURITY_REAL_TIME_DOC_URL);

    // ... and then by a success screen
    fireEvent.click(getByText('I Have Setup Real-Time'));
    expect(getByText('Everything looks good!')).toBeInTheDocument();
    expect(getByText('Finish Setup')).toBeInTheDocument();
    expect(getByText('Add Another')).toBeInTheDocument();

    // Expect analytics to have been called
    expect(trackEvent).toHaveBeenCalledWith({
      event: EventEnum.AddedComplianceSource,
      src: SrcEnum.ComplianceSources,
    });
  });

  it('shows a proper fail message when source validation fails', async () => {
    const errorMessage = "No-can-do's-ville, baby doll";

    const complianceSource = buildComplianceIntegration({
      awsAccountId: '123123123123',
      remediationEnabled: false,
      cweEnabled: false,
      regionIgnoreList: [],
      resourceTypeIgnoreList: [],
    });

    const mocks = [
      mockAddComplianceSource({
        variables: {
          input: buildAddComplianceIntegrationInput({
            integrationLabel: complianceSource.integrationLabel,
            awsAccountId: complianceSource.awsAccountId,
            cweEnabled: complianceSource.cweEnabled,
            remediationEnabled: complianceSource.remediationEnabled,
            regionIgnoreList: complianceSource.regionIgnoreList,
            resourceTypeIgnoreList: complianceSource.resourceTypeIgnoreList,
          }),
        },
        data: null,
        errors: [new GraphQLError(errorMessage)],
      }),
    ];

    const {
      getByText,
      getByLabelText,
      getByAltText,
      getByAriaLabel,
      findByText,
    } = render(<CreateComplianceSource />, { mocks });

    // Fill in  the form and press continue
    fireEvent.change(getByLabelText('Name'), {
      target: { value: complianceSource.integrationLabel },
    });
    fireEvent.change(getByLabelText('AWS Account ID'), {
      target: { value: complianceSource.awsAccountId },
    });
    fireEvent.click(getByAriaLabel('Real-Time AWS Resource Scans'));
    fireEvent.click(getByAriaLabel('AWS Automatic Remediations'));

    // Wait for form validation to kick in and move on to the next screen
    await waitMs(1);
    fireEvent.click(getByText('Continue Setup'));

    // We move on to the final screen
    fireEvent.click(getByText('Continue'));

    // Expect to see a loading animation while the resource is being validated ...
    expect(getByAltText('Validating source health...')).toBeInTheDocument();

    // ... replaced by a failure screen
    expect(await findByText("Something didn't go as planned")).toBeInTheDocument();
    expect(getByText('Start over')).toBeInTheDocument();
    expect(getByText(errorMessage)).toBeInTheDocument();

    // Expect analytics to have been called
    expect(trackError).toHaveBeenCalledWith({
      event: TrackErrorEnum.FailedToAddComplianceSource,
      src: SrcEnum.ComplianceSources,
    });
  });
});
