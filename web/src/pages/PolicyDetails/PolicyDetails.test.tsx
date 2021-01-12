import React from 'react';
import {
  fireEvent,
  render,
  waitForElementToBeRemoved,
  buildPolicyDetails,
  buildListComplianceItemsResponse,
} from 'test-utils';
import { Route } from 'react-router-dom';
import urls from 'Source/urls';
import PolicyDetails from 'Pages/PolicyDetails/PolicyDetails';
import { mockPolicyDetails } from './graphql/policyDetails.generated';

describe('PolicyDetails', () => {
  it('allows URL matching of tab navigation', async () => {
    const policy = buildPolicyDetails({
      id: '123',
      displayName: 'This is an amazing policy',
      description: 'This is an amazing description',
      runbook: 'Panther labs runbook',
    });

    const mocks = [
      mockPolicyDetails({
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
