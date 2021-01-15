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
  fireEvent,
  render,
  waitForElementToBeRemoved,
  buildPolicy,
  buildListComplianceItemsResponse,
} from 'test-utils';
import { Route } from 'react-router-dom';
import urls from 'Source/urls';
import PolicyDetails from 'Pages/PolicyDetails';
import { mockGetPolicyDetails } from './graphql/getPolicyDetails.generated';

describe('PolicyDetails', () => {
  it('renders the rule details page', async () => {
    const policy = buildPolicy({
      id: '123',
      displayName: 'This is an amazing policy',
      description: 'This is an amazing description',
      runbook: 'Panther labs runbook',
    });

    const mocks = [
      mockGetPolicyDetails({
        data: { policy, resourcesForPolicy: buildListComplianceItemsResponse() },
        variables: {
          policyDetailsInput: { id: policy.id },
          resourcesForPolicyInput: { policyId: policy.id },
        },
      }),
    ];

    const { getByText, getAllByAriaLabel } = render(
      <Route exact path={urls.compliance.policies.details(':id')}>
        <PolicyDetails />
      </Route>,
      {
        mocks,
        initialRoute: `${urls.compliance.policies.details(policy.id)}`,
      }
    );
    const loadingInterfaceElement = getAllByAriaLabel('Loading interface...');
    expect(loadingInterfaceElement).toBeTruthy();

    await waitForElementToBeRemoved(loadingInterfaceElement);

    // Policy info
    expect(getByText('This is an amazing policy')).toBeTruthy();
    expect(getByText('FAIL')).toBeTruthy();
    expect(getByText('MEDIUM')).toBeTruthy();
    expect(getByText('This is an amazing description')).toBeTruthy();
    expect(getByText('Panther labs runbook')).toBeTruthy();
    // Tabs
    expect(getByText('Details')).toBeTruthy();
    expect(getByText('Resources (1426)')).toBeTruthy();
  });

  it('allows URL matching of tab navigation', async () => {
    const policy = buildPolicy({
      id: '123',
      displayName: 'This is an amazing policy',
      description: 'This is an amazing description',
      runbook: 'Panther labs runbook',
    });

    const mocks = [
      mockGetPolicyDetails({
        data: { policy, resourcesForPolicy: buildListComplianceItemsResponse() },
        variables: {
          policyDetailsInput: { id: policy.id },
          resourcesForPolicyInput: { policyId: policy.id },
        },
      }),
    ];

    const { getByText, getAllByAriaLabel, history } = render(
      <Route exact path={urls.compliance.policies.details(':id')}>
        <PolicyDetails />
      </Route>,
      {
        mocks,
        initialRoute: `${urls.compliance.policies.details(policy.id)}`,
      }
    );
    const loadingInterfaceElement = getAllByAriaLabel('Loading interface...');
    expect(loadingInterfaceElement).toBeTruthy();

    await waitForElementToBeRemoved(loadingInterfaceElement);
    fireEvent.click(getByText('Resources (1426)'));
    expect(history.location.search).toBe('?section=resources');
    fireEvent.click(getByText('Details'));
    expect(history.location.search).toBe('?section=details');
  });
});
