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
import { render, buildRuleDetails, waitForElementToBeRemoved, fireEvent } from 'test-utils';
import { Route } from 'react-router-dom';
import urls from 'Source/urls';
import RuleDetails from './RuleDetails';
import { mockRuleDetails } from './graphql/ruleDetails.generated';

describe('RuleDetails', () => {
  it('renders the rule details page', async () => {
    const rule = buildRuleDetails({
      id: '123',
      displayName: 'This is an amazing rule',
      description: 'This is an amazing description',
      runbook: 'Panther labs runbook',
    });
    const mocks = [
      mockRuleDetails({
        data: { rule },
        variables: {
          input: {
            ruleId: '123',
          },
        },
      }),
    ];

    const { getByText, getByTestId } = render(
      <Route exact path={urls.logAnalysis.rules.details(':id')}>
        <RuleDetails />
      </Route>,
      {
        mocks,
        initialRoute: `${urls.logAnalysis.rules.details(rule.id)}`,
      }
    );
    const loadingInterfaceElement = getByTestId('rule-details-loading');
    expect(loadingInterfaceElement).toBeTruthy();

    await waitForElementToBeRemoved(loadingInterfaceElement);

    // Rule info
    expect(getByText('This is an amazing rule')).toBeTruthy();
    expect(getByText('DISABLED')).toBeTruthy();
    expect(getByText('LOW')).toBeTruthy();
    expect(getByText('This is an amazing description')).toBeTruthy();
    expect(getByText('Panther labs runbook')).toBeTruthy();
    // Tabs
    expect(getByText('Details')).toBeTruthy();
    expect(getByText('Rule Matches')).toBeTruthy();
    expect(getByText('Rule Errors')).toBeTruthy();
  });

  it('allows URL matching of tab navigation', async () => {
    const rule = buildRuleDetails({
      id: '123',
      displayName: 'This is an amazing rule',
      description: 'This is an amazing description',
      runbook: 'Panther labs runbook',
    });
    const mocks = [
      mockRuleDetails({
        data: { rule },
        variables: {
          input: {
            ruleId: '123',
          },
        },
      }),
    ];

    const { getByText, getByTestId, history } = render(
      <Route exact path={urls.logAnalysis.rules.details(':id')}>
        <RuleDetails />
      </Route>,
      {
        mocks,
        initialRoute: `${urls.logAnalysis.rules.details(rule.id)}`,
      }
    );
    const loadingInterfaceElement = getByTestId('rule-details-loading');
    expect(loadingInterfaceElement).toBeTruthy();

    await waitForElementToBeRemoved(loadingInterfaceElement);
    fireEvent.click(getByText('Rule Matches'));
    expect(history.location.search).toBe('?section=matches');
    fireEvent.click(getByText('Rule Errors'));
    expect(history.location.search).toBe('?section=errors');
    fireEvent.click(getByText('Details'));
    expect(history.location.search).toBe('?section=details');
  });
});
