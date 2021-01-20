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
  waitForElementToBeRemoved,
  waitFor,
  fireClickAndMouseEvents,
  buildDetectionTestDefinition,
  buildPolicy,
} from 'test-utils';
import urls from 'Source/urls';
import { Route } from 'react-router-dom';
import { mockListRemediations } from 'Components/forms/PolicyForm/PolicyFormAutoRemediationSection/graphql/listRemediations.generated';
import { mockGetPolicyDetails } from './graphql/getPolicyDetails.generated';
import EditPolicy from './EditPolicy';

describe('EditPolicy', () => {
  it('renders the initial tabs and fields', async () => {
    // Tests should get overriden as the component expects a string in JSON format.
    const tests = [
      buildDetectionTestDefinition({
        resource: '{"CreateDate":"2019-01-01T00:00:00Z"}',
      }),
    ];
    const policy = buildPolicy({ tests });

    const mocks = [
      mockGetPolicyDetails({
        data: { policy },
        variables: {
          input: {
            id: policy.id,
          },
        },
      }),
    ];
    const { getByTestId, getByText, getByLabelText, getByAriaLabel } = render(
      <Route exact path={urls.compliance.policies.edit(':id')}>
        <EditPolicy />
      </Route>,
      {
        mocks,
        initialRoute: urls.compliance.policies.edit(policy.id),
      }
    );

    const loadingInterfaceElement = getByTestId('policy-edit-loading');

    expect(loadingInterfaceElement).toBeTruthy();
    await waitForElementToBeRemoved(loadingInterfaceElement);

    // Fields
    expect(getByText('Enabled')).toBeInTheDocument();
    expect(getByText('Severity')).toBeInTheDocument();
    expect(getByLabelText('Display Name')).toBeInTheDocument();
    expect(getByLabelText('Policy ID')).toBeInTheDocument();
    expect(getByLabelText('Description')).toBeInTheDocument();
    expect(getByLabelText('Runbook')).toBeInTheDocument();
    expect(getByLabelText('Reference')).toBeInTheDocument();
    expect(getByText('Resource Types')).toBeInTheDocument();
    expect(getByText('Custom Tags')).toBeInTheDocument();
    expect(getByText('Ignore Patterns')).toBeInTheDocument();
    expect(getByText('Destination Overrides')).toBeInTheDocument();

    // Helper text
    expect(getByText('Required')).toBeInTheDocument();
    expect(getByText('Optional')).toBeInTheDocument();

    // Tabs
    expect(getByText('Policy Settings')).toBeInTheDocument();
    expect(getByText('Functions & Tests')).toBeInTheDocument();
    expect(getByText('Auto Remediation')).toBeInTheDocument();

    // Buttons
    expect(getByText('Update')).toBeInTheDocument();
    expect(getByAriaLabel('Cancel Policy editing')).toBeInTheDocument();
  });

  it('renders the function and tests tab', async () => {
    // Tests should get overriden as the component expects a string in JSON format.
    const tests = [
      buildDetectionTestDefinition({
        resource: '{"CreateDate":"2019-01-01T00:00:00Z"}',
      }),
    ];
    const policy = buildPolicy({ tests });

    const mocks = [
      mockGetPolicyDetails({
        data: { policy },
        variables: {
          input: {
            id: policy.id,
          },
        },
      }),
    ];
    const { getByTestId, getByText, getByAriaLabel } = render(
      <Route exact path={urls.compliance.policies.edit(':id')}>
        <EditPolicy />
      </Route>,
      {
        mocks,
        initialRoute: urls.compliance.policies.edit(policy.id),
      }
    );

    const loadingInterfaceElement = getByTestId('policy-edit-loading');

    expect(loadingInterfaceElement).toBeTruthy();
    await waitForElementToBeRemoved(loadingInterfaceElement);

    // Fields
    fireEvent.click(getByText('Functions & Tests'));

    await waitFor(() => {
      expect(getByText('Policy Function')).toBeInTheDocument();
    });
    expect(getByText('Test resource should be compliant')).toBeInTheDocument();

    expect(getByAriaLabel('Toggle Editor visibility')).toBeInTheDocument();
    expect(getByAriaLabel('Toggle Tests visibility')).toBeInTheDocument();
    expect(getByAriaLabel('Create test')).toBeInTheDocument();
  });

  it('renders the Auto Remediation tab', async () => {
    // Tests should get overriden as the component expects a string in JSON format.
    const tests = [
      buildDetectionTestDefinition({
        resource: '{"CreateDate":"2019-01-01T00:00:00Z"}',
      }),
    ];
    const policy = buildPolicy({
      tests,
      autoRemediationId: '',
      autoRemediationParameters: '{}',
    });

    const mocks = [
      mockGetPolicyDetails({
        data: { policy },
        variables: {
          input: {
            id: policy.id,
          },
        },
      }),
      mockListRemediations({
        data: {
          remediations:
            '{"AWS.EC2.TerminateInstance":{},"AWS.IAM.DeleteInactiveAccessKeys":{},"AWS.RDS.DisableSnapshotPublicAccess":{},"AWS.DDB.EncryptTable":{},"AWS.EC2.StopInstance":{}}',
        },
      }),
    ];
    const { getByTestId, getAllByLabelText, getByText, getByAriaLabel } = render(
      <Route exact path={urls.compliance.policies.edit(':id')}>
        <EditPolicy />
      </Route>,
      {
        mocks,
        initialRoute: urls.compliance.policies.edit(policy.id),
      }
    );

    const loadingInterfaceElement = getByTestId('policy-edit-loading');

    expect(loadingInterfaceElement).toBeTruthy();
    await waitForElementToBeRemoved(loadingInterfaceElement);

    // Fields
    fireEvent.click(getByText('Auto Remediation'));

    const remediationLoading = getByAriaLabel('Loading...');
    expect(remediationLoading).toBeTruthy();
    await waitForElementToBeRemoved(remediationLoading);

    await waitFor(() => {
      expect(getByText('Remediation')).toBeInTheDocument();
    });

    const remedationField = getAllByLabelText('Remediation')[0];
    expect(remedationField).toHaveValue('(No remediation)');

    // The combobox is searchable thus we need to focus first
    await fireEvent.focus(remedationField);
    await fireClickAndMouseEvents(remedationField);
    await fireClickAndMouseEvents(getByText('AWS.IAM.DeleteInactiveAccessKeys'));

    await waitFor(() => {
      expect(getByAriaLabel('Auto Remediation Parameters')).toBeInTheDocument();
    });
  });
});
