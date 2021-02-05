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
import urls from 'Source/urls';
import { Route } from 'react-router';
import { AWS_REGIONS, CLOUD_SECURITY_REAL_TIME_DOC_URL } from 'Source/constants';
import { EventEnum, SrcEnum, trackEvent } from 'Helpers/analytics';
import EditComplianceSource from './EditComplianceSource';
import { mockGetComplianceSource } from './graphql/getComplianceSource.generated';
import { mockUpdateComplianceSource } from './graphql/updateComplianceSource.generated';

jest.mock('Helpers/analytics');

describe('EditComplianceSource', () => {
  it('can successfully update a compliance source without real-time', async () => {
    const complianceSource = buildComplianceIntegration({
      awsAccountId: '123123123123',
      cweEnabled: false,
      regionIgnoreList: [AWS_REGIONS[0]],
      resourceTypeIgnoreList: [],
    });

    const updatedComplianceSource = buildComplianceIntegration({
      ...complianceSource,
      integrationLabel: 'new-test',
    });

    const mocks = [
      mockGetComplianceSource({
        variables: {
          id: complianceSource.integrationId,
        },
        data: {
          getComplianceIntegration: complianceSource,
        },
      }),
      mockUpdateComplianceSource({
        variables: {
          input: buildUpdateComplianceIntegrationInput({
            integrationId: complianceSource.integrationId,
            integrationLabel: updatedComplianceSource.integrationLabel,
            cweEnabled: complianceSource.cweEnabled,
            remediationEnabled: complianceSource.remediationEnabled,
            regionIgnoreList: complianceSource.regionIgnoreList,
            resourceTypeIgnoreList: complianceSource.resourceTypeIgnoreList,
          }),
        },
        data: {
          updateComplianceIntegration: updatedComplianceSource,
        },
      }),
    ];
    const { getByText, getByLabelText, getByAltText, findByText } = render(
      <Route path={urls.compliance.sources.edit(':id')}>
        <EditComplianceSource />
      </Route>,
      { mocks, initialRoute: urls.compliance.sources.edit(complianceSource.integrationId) }
    );

    const nameField = getByLabelText('Name') as HTMLInputElement;

    //  Wait for GET api request to populate the form
    await waitFor(() => expect(nameField).toHaveValue('Loading...'));
    await waitFor(() => expect(nameField).toHaveValue(complianceSource.integrationLabel));

    // Update the name  and press continue
    fireEvent.change(nameField, { target: { value: updatedComplianceSource.integrationLabel } });

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

    // Expect analytics to have been called
    expect(trackEvent).toHaveBeenCalledWith({
      event: EventEnum.UpdatedComplianceSource,
      src: SrcEnum.ComplianceSources,
    });
  });

  it('can successfully update a compliance source & enable real-time', async () => {
    const complianceSource = buildComplianceIntegration({
      awsAccountId: '123123123123',
      cweEnabled: false,
      regionIgnoreList: [AWS_REGIONS[0]],
      resourceTypeIgnoreList: [],
    });

    const updatedComplianceSource = buildComplianceIntegration({
      ...complianceSource,
      cweEnabled: true,
    });

    const mocks = [
      mockGetComplianceSource({
        variables: {
          id: complianceSource.integrationId,
        },
        data: {
          getComplianceIntegration: complianceSource,
        },
      }),
      mockUpdateComplianceSource({
        variables: {
          input: buildUpdateComplianceIntegrationInput({
            integrationId: complianceSource.integrationId,
            integrationLabel: updatedComplianceSource.integrationLabel,
            cweEnabled: updatedComplianceSource.cweEnabled,
            remediationEnabled: updatedComplianceSource.remediationEnabled,
            regionIgnoreList: updatedComplianceSource.regionIgnoreList,
            resourceTypeIgnoreList: updatedComplianceSource.resourceTypeIgnoreList,
          }),
        },
        data: {
          updateComplianceIntegration: updatedComplianceSource,
        },
      }),
    ];
    const {
      getByText,
      getByLabelText,
      getByAriaLabel,
      getByAltText,
      findByText,
      queryByText,
    } = render(
      <Route path={urls.compliance.sources.edit(':id')}>
        <EditComplianceSource />
      </Route>,
      { mocks, initialRoute: urls.compliance.sources.edit(complianceSource.integrationId) }
    );

    const nameField = getByLabelText('Name') as HTMLInputElement;

    //  Wait for GET api request to populate the form
    await waitFor(() => expect(nameField).toHaveValue(complianceSource.integrationLabel));

    fireEvent.click(getByAriaLabel('Real-Time AWS Resource Scans'));

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
    expect(queryByText('Add Another')).not.toBeInTheDocument();

    // Expect analytics to have been called
    expect(trackEvent).toHaveBeenCalledWith({
      event: EventEnum.UpdatedComplianceSource,
      src: SrcEnum.ComplianceSources,
    });
  });
});
