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
import queryString from 'query-string';
import {
  render,
  buildRuleDetails,
  waitMs,
  buildAlertSummary,
  buildListAlertsResponse,
  waitFor,
  waitForElementToBeRemoved,
  fireEvent,
} from 'test-utils';
import { DEFAULT_LARGE_PAGE_SIZE, DEFAULT_SMALL_PAGE_SIZE } from 'Source/constants';
import { AlertTypesEnum, ListAlertsSortFieldsEnum, SortDirEnum } from 'Generated/schema';
import { Route } from 'react-router-dom';
import urls from 'Source/urls';
import RuleDetails from './RuleDetails';
import { mockRuleDetails } from './graphql/ruleDetails.generated';
import { mockListAlertsForRule } from './graphql/listAlertsForRule.generated';

const queryStringOptions = {
  arrayFormat: 'bracket' as const,
  parseNumbers: true,
  parseBooleans: true,
};

const queryStringToObj = q => {
  return queryString.parse(q, queryStringOptions);
};

beforeEach(() => {
  // IntersectionObserver isn't available in test environment
  const mockIntersectionObserver = jest.fn();
  mockIntersectionObserver.mockReturnValue({
    observe: () => null,
    unobserve: () => null,
    disconnect: () => null,
  });
  window.IntersectionObserver = mockIntersectionObserver;
});

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

  it('shows the tabs as disabled when no alerts are in place', async () => {
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
      mockListAlertsForRule({
        data: {
          alerts: {
            ...buildListAlertsResponse(),
            alertSummaries: [],
          },
        },
        variables: {
          input: {
            ruleId: '123',
            type: AlertTypesEnum.RuleError,
            pageSize: DEFAULT_SMALL_PAGE_SIZE,
          },
        },
      }),
      mockListAlertsForRule({
        data: {
          alerts: {
            ...buildListAlertsResponse(),
            alertSummaries: [
              buildAlertSummary({
                ruleId: '123',
                title: `Alert 1`,
                alertId: `alert_1`,
                type: AlertTypesEnum.Rule,
              }),
            ],
          },
        },
        variables: {
          input: {
            ruleId: '123',
            type: AlertTypesEnum.Rule,
            pageSize: DEFAULT_SMALL_PAGE_SIZE,
          },
        },
      }),
    ];

    const { getAllByTestId, getByTestId } = render(
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
    await waitMs(500);
    const matchesTab = getAllByTestId('rule-matches');
    const errorsTab = getAllByTestId('rule-errors');

    const styleMatches = window.getComputedStyle(matchesTab[0]);
    const styleError = window.getComputedStyle(errorsTab[0]);

    expect(styleMatches.opacity).toBe('1');
    expect(styleError.opacity).toBe('0.5');
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

  it('fetches the alerts matching the rule', async () => {
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
      mockListAlertsForRule({
        data: {
          alerts: {
            ...buildListAlertsResponse(),
            alertSummaries: [
              buildAlertSummary({
                ruleId: '123',
                title: `Alert 1`,
                alertId: `alert_1`,
                type: AlertTypesEnum.Rule,
              }),
            ],
          },
        },
        variables: {
          input: {
            ruleId: '123',
            type: AlertTypesEnum.Rule,
            pageSize: DEFAULT_LARGE_PAGE_SIZE,
          },
        },
      }),
    ];

    const { getByText, getByTestId, getByAriaLabel } = render(
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

    const loadingListingInterfaceElement = getByTestId('rule-alerts-listing-loading');
    expect(loadingListingInterfaceElement).toBeTruthy();
    await waitForElementToBeRemoved(loadingListingInterfaceElement);
    expect(getByText('Alert 1')).toBeInTheDocument();

    expect(getByText('Alert Type')).toBeInTheDocument();
    expect(getByText('Rule Match')).toBeInTheDocument();

    expect(getByText('Destinations')).toBeInTheDocument();
    expect(getByText('Log Types')).toBeInTheDocument();
    expect(getByText('Events')).toBeInTheDocument();
    expect(getByAriaLabel('Change Alert Status')).toBeInTheDocument();
  });

  it('fetches the alerts matching the rule errors', async () => {
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
      mockListAlertsForRule({
        data: {
          alerts: {
            ...buildListAlertsResponse(),
            alertSummaries: [
              buildAlertSummary({
                ruleId: '123',
                title: `Error 1`,
                alertId: `error_1`,
                type: AlertTypesEnum.RuleError,
              }),
            ],
          },
        },
        variables: {
          input: {
            ruleId: '123',
            type: AlertTypesEnum.RuleError,
            pageSize: DEFAULT_LARGE_PAGE_SIZE,
          },
        },
      }),
    ];

    const { getByText, getByTestId, getByAriaLabel } = render(
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
    fireEvent.click(getByText('Rule Errors'));

    const loadingListingInterfaceElement = getByTestId('rule-alerts-listing-loading');
    expect(loadingListingInterfaceElement).toBeTruthy();
    await waitForElementToBeRemoved(loadingListingInterfaceElement);
    expect(getByText('Error 1')).toBeInTheDocument();

    expect(getByText('Alert Type')).toBeInTheDocument();
    expect(getByText('Rule Error')).toBeInTheDocument();

    expect(getByText('Destinations')).toBeInTheDocument();
    expect(getByText('Log Types')).toBeInTheDocument();
    expect(getByText('Events')).toBeInTheDocument();
    expect(getByAriaLabel('Change Alert Status')).toBeInTheDocument();
  });

  it('fetches the alerts matching the rule & shows an empty fallback if no alerts exist', async () => {
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
            ruleId: rule.id,
          },
        },
      }),
      mockListAlertsForRule({
        data: {
          alerts: buildListAlertsResponse({
            alertSummaries: [],
            lastEvaluatedKey: null,
          }),
        },
        variables: {
          input: {
            type: AlertTypesEnum.Rule,
            ruleId: rule.id,
            pageSize: DEFAULT_LARGE_PAGE_SIZE,
          },
        },
      }),
    ];

    const { getByText, getByAltText, getAllByAriaLabel } = render(
      <Route exact path={urls.logAnalysis.rules.details(':id')}>
        <RuleDetails />
      </Route>,
      {
        mocks,
        initialRoute: `${urls.logAnalysis.rules.details(rule.id)}`,
      }
    );
    const loadingInterfaceElement = getAllByAriaLabel('Loading interface...');
    expect(loadingInterfaceElement).toBeTruthy();

    await waitForElementToBeRemoved(loadingInterfaceElement);
    fireEvent.click(getByText('Rule Matches'));

    const loadingListingInterfaceElement = getAllByAriaLabel('Loading interface...');
    expect(loadingListingInterfaceElement).toBeTruthy();
    await waitForElementToBeRemoved(loadingListingInterfaceElement);

    const emptyFallback = getByAltText('Empty Box Illustration');
    expect(emptyFallback).toBeTruthy();
  });

  it('shows an empty illustration if filtering returns no results', async () => {
    const rule = buildRuleDetails();
    const alert = buildAlertSummary();

    const mocks = [
      mockRuleDetails({
        data: { rule },
        variables: {
          input: {
            ruleId: rule.id,
          },
        },
      }),
      mockListAlertsForRule({
        data: {
          alerts: buildListAlertsResponse({
            alertSummaries: [alert],
            lastEvaluatedKey: null,
          }),
        },
        variables: {
          input: {
            type: AlertTypesEnum.Rule,
            ruleId: rule.id,
            pageSize: DEFAULT_LARGE_PAGE_SIZE,
          },
        },
      }),
      mockListAlertsForRule({
        data: {
          alerts: buildListAlertsResponse({
            alertSummaries: [],
            lastEvaluatedKey: null,
          }),
        },
        variables: {
          input: {
            nameContains: 'test',
            type: AlertTypesEnum.Rule,
            ruleId: rule.id,
            pageSize: DEFAULT_LARGE_PAGE_SIZE,
          },
        },
      }),
    ];

    const { findByText, findByAltText, getByLabelText } = render(
      <Route exact path={urls.logAnalysis.rules.details(':id')}>
        <RuleDetails />
      </Route>,
      {
        mocks,
        initialRoute: `${urls.logAnalysis.rules.details(rule.id)}?section=matches`,
      }
    );

    await findByText(alert.title);

    fireEvent.change(getByLabelText('Filter Alerts by text'), { target: { value: 'test' } });

    expect(await findByAltText('Document and magnifying glass')).toBeInTheDocument();
    expect(await findByText('No Results')).toBeInTheDocument();
  });

  it('allows conditionally filtering the alerts matching the rule rule', async () => {
    const rule = buildRuleDetails({
      id: '123',
    });

    let counter = 0;
    const conditionalFilteringAlertsMock = (overrides = {}) => {
      counter += 1;
      return mockListAlertsForRule({
        data: {
          alerts: {
            ...buildListAlertsResponse(),
            alertSummaries: [
              buildAlertSummary({
                ruleId: '123',
                title: `Unique alert ${counter}`,
                alertId: `alert_${counter}`,
                type: AlertTypesEnum.Rule,
              }),
            ],
          },
        },
        variables: {
          input: {
            ruleId: '123',
            type: AlertTypesEnum.Rule,
            pageSize: DEFAULT_LARGE_PAGE_SIZE,
            ...overrides,
          },
        },
      });
    };

    const mocks = [
      mockRuleDetails({
        data: { rule },
        variables: {
          input: {
            ruleId: '123',
          },
        },
      }),
      conditionalFilteringAlertsMock(), // all rules
      conditionalFilteringAlertsMock({
        nameContains: 'foo',
      }),
      conditionalFilteringAlertsMock({
        nameContains: 'foo',
        sortBy: ListAlertsSortFieldsEnum.CreatedAt,
        sortDir: SortDirEnum.Ascending,
      }),
    ];

    const { getByText, getByTestId, findByTestId, findByLabelText, history } = render(
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

    const loadingListingInterfaceElement = getByTestId('rule-alerts-listing-loading');
    expect(loadingListingInterfaceElement).toBeTruthy();
    await waitForElementToBeRemoved(loadingListingInterfaceElement);
    expect(getByText('Unique alert 1')).toBeInTheDocument();

    const input = (await findByLabelText('Filter Alerts by text')) as HTMLInputElement;
    fireEvent.focus(input);
    await waitFor(() => {
      fireEvent.change(input, {
        target: {
          value: 'foo',
        },
      });
    });

    // wait for autosave to kick in
    await waitMs(210);
    expect(getByText('Unique alert 2')).toBeInTheDocument();
    expect(queryStringToObj(history.location.search)).toEqual({
      nameContains: 'foo',
      section: 'matches',
    });

    const sortyBy = (await findByTestId('list-alert-sorting')) as HTMLInputElement;

    await waitFor(() => {
      fireEvent.focus(sortyBy);
    });

    const oldestOption = (await findByTestId('sort-by-oldest')) as HTMLInputElement;

    fireEvent.click(oldestOption);

    await waitMs(210);
    expect(getByText('Unique alert 3')).toBeInTheDocument();

    // once again wait for autosave to kick in
    await waitMs(210);

    expect(queryStringToObj(history.location.search)).toEqual({
      nameContains: 'foo',
      section: 'matches',
      sortBy: ListAlertsSortFieldsEnum.CreatedAt,
      sortDir: SortDirEnum.Ascending,
    });
  });
});
