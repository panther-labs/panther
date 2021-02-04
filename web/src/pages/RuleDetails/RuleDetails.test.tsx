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
  buildAlertSummary,
  buildAlertSummaryRuleInfo,
  buildListAlertsResponse,
  buildRule,
  fireClickAndMouseEvents,
  fireEvent,
  render,
  waitFor,
  waitForElementToBeRemoved,
  waitMs,
  within,
} from 'test-utils';
import { DEFAULT_LARGE_PAGE_SIZE, DEFAULT_SMALL_PAGE_SIZE } from 'Source/constants';
import {
  AlertStatusesEnum,
  AlertTypesEnum,
  ListAlertsSortFieldsEnum,
  SortDirEnum,
} from 'Generated/schema';
import { Route } from 'react-router-dom';
import urls from 'Source/urls';
import { mockUpdateAlertStatus } from 'Source/graphql/queries';
import RuleDetails from './RuleDetails';
import { mockGetRuleDetails } from './graphql/getRuleDetails.generated';
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
    const rule = buildRule({
      id: '123',
      displayName: 'This is an amazing rule',
      description: 'This is an amazing description',
      runbook: 'Panther labs runbook',
    });
    const mocks = [
      mockGetRuleDetails({
        data: { rule },
        variables: {
          input: {
            id: '123',
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
    expect(getByText('HIGH')).toBeTruthy();
    expect(getByText('This is an amazing description')).toBeTruthy();
    expect(getByText('Panther labs runbook')).toBeTruthy();
    // Tabs
    expect(getByText('Details')).toBeTruthy();
    expect(getByText('Rule Matches')).toBeTruthy();
    expect(getByText('Rule Errors')).toBeTruthy();
  });

  it('shows the tabs as disabled when no alerts are in place', async () => {
    const rule = buildRule({
      id: '123',
      displayName: 'This is an amazing rule',
      description: 'This is an amazing description',
      runbook: 'Panther labs runbook',
    });
    const mocks = [
      mockGetRuleDetails({
        data: { rule },
        variables: {
          input: {
            id: '123',
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
            types: [AlertTypesEnum.RuleError],
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
                detection: buildAlertSummaryRuleInfo({
                  ruleId: '123',
                }),
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
            types: [AlertTypesEnum.Rule],
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
    await waitMs(1);
    const matchesTab = getAllByTestId('rule-matches');
    const errorsTab = getAllByTestId('rule-errors');

    const styleMatches = window.getComputedStyle(matchesTab[0]);
    const styleError = window.getComputedStyle(errorsTab[0]);

    expect(styleMatches.opacity).toBe('1');
    expect(styleError.opacity).toBe('0.5');
  });

  it('allows URL matching of tab navigation', async () => {
    const rule = buildRule({
      id: '123',
      displayName: 'This is an amazing rule',
      description: 'This is an amazing description',
      runbook: 'Panther labs runbook',
    });
    const mocks = [
      mockGetRuleDetails({
        data: { rule },
        variables: {
          input: {
            id: '123',
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
    const rule = buildRule({
      id: '123',
      displayName: 'This is an amazing rule',
      description: 'This is an amazing description',
      runbook: 'Panther labs runbook',
    });
    const mocks = [
      mockGetRuleDetails({
        data: { rule },
        variables: {
          input: {
            id: '123',
          },
        },
      }),
      mockListAlertsForRule({
        data: {
          alerts: {
            ...buildListAlertsResponse(),
            alertSummaries: [
              buildAlertSummary({
                detection: buildAlertSummaryRuleInfo({
                  ruleId: '123',
                }),
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
            types: [AlertTypesEnum.Rule],
            pageSize: DEFAULT_LARGE_PAGE_SIZE,
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
    fireEvent.click(getByText('Rule Matches'));

    const loadingListingInterfaceElement = getByTestId('rule-alerts-listing-loading');
    await waitForElementToBeRemoved(loadingListingInterfaceElement);
    const withinTabPanel = within(getByTestId('rule-matches-tabpanel'));
    expect(withinTabPanel.getByText('Alert 1')).toBeInTheDocument();
    expect(withinTabPanel.getByText('Rule Match')).toBeInTheDocument();

    expect(withinTabPanel.getByText('Destinations')).toBeInTheDocument();
    expect(withinTabPanel.getByText('Log Types')).toBeInTheDocument();
    expect(withinTabPanel.getByText('Events')).toBeInTheDocument();
  });

  it('fetches the alerts matching the rule errors', async () => {
    const rule = buildRule({
      id: '123',
      displayName: 'This is an amazing rule',
      description: 'This is an amazing description',
      runbook: 'Panther labs runbook',
    });
    const mocks = [
      mockGetRuleDetails({
        data: { rule },
        variables: {
          input: {
            id: '123',
          },
        },
      }),
      mockListAlertsForRule({
        data: {
          alerts: {
            ...buildListAlertsResponse(),
            alertSummaries: [
              buildAlertSummary({
                detection: buildAlertSummaryRuleInfo({
                  ruleId: '123',
                }),
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
            types: [AlertTypesEnum.RuleError],
            pageSize: DEFAULT_LARGE_PAGE_SIZE,
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
    fireEvent.click(getByText('Rule Errors'));

    const loadingListingInterfaceElement = getByTestId('rule-alerts-listing-loading');
    await waitForElementToBeRemoved(loadingListingInterfaceElement);
    const withinTabPanel = within(getByTestId('rule-errors-tabpanel'));
    expect(withinTabPanel.getByText('Error 1')).toBeInTheDocument();
    expect(withinTabPanel.getByText('Rule Error')).toBeInTheDocument();
    expect(withinTabPanel.getByText('Destinations')).toBeInTheDocument();
    expect(withinTabPanel.getByText('Log Types')).toBeInTheDocument();
    expect(withinTabPanel.getByText('Events')).toBeInTheDocument();
  });

  it('fetches the alerts matching the rule & shows an empty fallback if no alerts exist', async () => {
    const rule = buildRule({
      id: '123',
      displayName: 'This is an amazing rule',
      description: 'This is an amazing description',
      runbook: 'Panther labs runbook',
    });
    const mocks = [
      mockGetRuleDetails({
        data: { rule },
        variables: {
          input: {
            id: rule.id,
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
            types: [AlertTypesEnum.Rule],
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
    const rule = buildRule();
    const alert = buildAlertSummary();

    const mocks = [
      mockGetRuleDetails({
        data: { rule },
        variables: {
          input: {
            id: rule.id,
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
            types: [AlertTypesEnum.Rule],
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
            types: [AlertTypesEnum.Rule],
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
    const rule = buildRule({
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
                detection: buildAlertSummaryRuleInfo({
                  ruleId: '123',
                }),
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
            types: [AlertTypesEnum.Rule],
            pageSize: DEFAULT_LARGE_PAGE_SIZE,
            ...overrides,
          },
        },
      });
    };

    const mocks = [
      mockGetRuleDetails({
        data: { rule },
        variables: {
          input: {
            id: '123',
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

    const { getByText, getByTestId, findByTestId, findByLabelText, history, findByText } = render(
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
    fireEvent.change(input, {
      target: {
        value: 'foo',
      },
    });

    // wait for autosave to kick in
    expect(await findByText('Unique alert 2')).toBeInTheDocument();
    expect(queryStringToObj(history.location.search)).toEqual({
      nameContains: 'foo',
      section: 'matches',
    });

    fireEvent.focus(await findByTestId('list-alert-sorting'));
    fireEvent.click(await findByTestId('sort-by-oldest'));

    expect(await findByText('Unique alert 3')).toBeInTheDocument();

    await waitFor(() =>
      expect(queryStringToObj(history.location.search)).toEqual({
        nameContains: 'foo',
        section: 'matches',
        sortBy: ListAlertsSortFieldsEnum.CreatedAt,
        sortDir: SortDirEnum.Ascending,
      })
    );
  });

  it('can select and bulk update status for rule matches', async () => {
    const rule = buildRule({
      id: '123',
      displayName: 'This is an amazing rule',
      description: 'This is an amazing description',
      runbook: 'Panther labs runbook',
    });
    const alertSummaries = [
      buildAlertSummary({
        detection: buildAlertSummaryRuleInfo({
          ruleId: '123',
        }),
        title: `Alert 1`,
        alertId: `alert_1`,
        type: AlertTypesEnum.Rule,
      }),
      buildAlertSummary({
        detection: buildAlertSummaryRuleInfo({
          ruleId: '123',
        }),
        title: `Alert 2`,
        alertId: `alert_2`,
        type: AlertTypesEnum.Rule,
      }),
    ];
    const mocks = [
      mockGetRuleDetails({
        data: { rule },
        variables: {
          input: {
            id: '123',
          },
        },
      }),
      mockListAlertsForRule({
        data: {
          alerts: {
            ...buildListAlertsResponse(),
            alertSummaries,
          },
        },
        variables: {
          input: {
            ruleId: '123',
            types: [AlertTypesEnum.Rule],
            pageSize: DEFAULT_LARGE_PAGE_SIZE,
          },
        },
      }),
      mockUpdateAlertStatus({
        variables: {
          input: {
            // Set API call, so that it will change status for 2 alerts to Closed
            alertIds: [alertSummaries[1].alertId],
            status: AlertStatusesEnum.Closed,
          },
        },
        data: {
          updateAlertStatus: [
            // Expected Response
            { ...alertSummaries[1], status: AlertStatusesEnum.Closed },
          ],
        },
      }),
      // Second update
      mockUpdateAlertStatus({
        variables: {
          input: {
            // Set API call, so that it will change status for 2 alerts to Closed
            alertIds: alertSummaries.map(a => a.alertId),
            status: AlertStatusesEnum.Open,
          },
        },
        data: {
          updateAlertStatus: alertSummaries.map(a => ({
            ...a,
            status: AlertStatusesEnum.Open,
          })),
        },
      }),
    ];

    const {
      getByText,
      getByTestId,
      getByAriaLabel,
      getAllByAriaLabel,
      findAllByText,
      queryByAriaLabel,
      getAllByLabelText,
      queryAllByText,
    } = render(
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
    alertSummaries.forEach(alertSummary => {
      expect(getByText(alertSummary.title)).toBeInTheDocument();
    });

    // Single select all of 2 Alerts
    const [checkboxForAlert1, checkboxForAlert2] = getAllByAriaLabel(`select item`);

    fireClickAndMouseEvents(checkboxForAlert1);
    expect(getByText('1 Selected')).toBeInTheDocument();

    fireClickAndMouseEvents(checkboxForAlert2);
    expect(getByText('2 Selected')).toBeInTheDocument();

    // Deselect first alert
    fireClickAndMouseEvents(checkboxForAlert1);
    expect(getByText('1 Selected')).toBeInTheDocument();

    // Expect status field to have Resolved as default
    const statusField = getAllByLabelText('Status')[0];
    expect(statusField).toHaveValue('Resolved');

    // Change its value to Invalid (Closed)
    fireClickAndMouseEvents(statusField);
    fireClickAndMouseEvents(getByText('Invalid'));
    expect(statusField).toHaveValue('Invalid');

    expect(await queryAllByText('INVALID')).toHaveLength(0);
    fireClickAndMouseEvents(getByText('Apply'));
    // Find the alerts with the updated status
    expect(await findAllByText('INVALID')).toHaveLength(1);
    // And expect that the selection has been reset
    expect(await queryByAriaLabel(`unselect item`)).not.toBeInTheDocument();

    // Now select all Rule Matches and updated to Open
    const selectAllCheckbox = getByAriaLabel('select all');
    fireClickAndMouseEvents(selectAllCheckbox);

    expect(getAllByAriaLabel(`unselect item`)).toHaveLength(alertSummaries.length);
    // Expect status field to have Resolved as default

    fireClickAndMouseEvents(getAllByLabelText('Status')[0]);
    fireClickAndMouseEvents(getByText('Open'));
    expect(getAllByLabelText('Status')[0]).toHaveValue('Open');
    fireClickAndMouseEvents(getByText('Apply'));
    expect(await findAllByText('OPEN')).toHaveLength(2);
  });

  it('can select and bulk update status for rule errors', async () => {
    const rule = buildRule({
      id: '123',
      displayName: 'This is an amazing rule',
      description: 'This is an amazing description',
      runbook: 'Panther labs runbook',
    });
    const alertSummaries = [
      buildAlertSummary({
        detection: buildAlertSummaryRuleInfo({
          ruleId: '123',
        }),
        title: `Error 1`,
        alertId: `error_1`,
        type: AlertTypesEnum.RuleError,
      }),
      buildAlertSummary({
        detection: buildAlertSummaryRuleInfo({
          ruleId: '123',
        }),
        title: `Error 2`,
        alertId: `error_2`,
        type: AlertTypesEnum.RuleError,
      }),
    ];
    const mocks = [
      mockGetRuleDetails({
        data: { rule },
        variables: {
          input: {
            id: '123',
          },
        },
      }),
      mockListAlertsForRule({
        data: {
          alerts: {
            ...buildListAlertsResponse(),
            alertSummaries,
          },
        },
        variables: {
          input: {
            ruleId: '123',
            types: [AlertTypesEnum.RuleError],
            pageSize: DEFAULT_LARGE_PAGE_SIZE,
          },
        },
      }),
      mockUpdateAlertStatus({
        variables: {
          input: {
            // Set API call, so that it will change status for 2 alerts to Closed
            alertIds: [alertSummaries[1].alertId],
            status: AlertStatusesEnum.Closed,
          },
        },
        data: {
          updateAlertStatus: [
            // Expected Response
            { ...alertSummaries[1], status: AlertStatusesEnum.Closed },
          ],
        },
      }),
      // Second update
      mockUpdateAlertStatus({
        variables: {
          input: {
            // Set API call, so that it will change status for 2 alerts to Closed
            alertIds: alertSummaries.map(a => a.alertId),
            status: AlertStatusesEnum.Open,
          },
        },
        data: {
          updateAlertStatus: alertSummaries.map(a => ({
            ...a,
            status: AlertStatusesEnum.Open,
          })),
        },
      }),
    ];

    const {
      getByText,
      getByTestId,
      getByAriaLabel,
      getAllByAriaLabel,
      findAllByText,
      queryByAriaLabel,
      getAllByLabelText,
      queryAllByText,
    } = render(
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

    alertSummaries.forEach(alertSummary => {
      expect(getByText(alertSummary.title)).toBeInTheDocument();
    });

    // Single select all of 2 Alerts
    const [checkboxForAlert1, checkboxForAlert2] = getAllByAriaLabel(`select item`);

    fireClickAndMouseEvents(checkboxForAlert1);
    expect(getByText('1 Selected')).toBeInTheDocument();

    fireClickAndMouseEvents(checkboxForAlert2);
    expect(getByText('2 Selected')).toBeInTheDocument();

    // Deselect first alert
    fireClickAndMouseEvents(checkboxForAlert1);
    expect(getByText('1 Selected')).toBeInTheDocument();

    // Expect status field to have Resolved as default
    const statusField = getAllByLabelText('Status')[0];
    expect(statusField).toHaveValue('Resolved');

    // Change its value to Invalid (Closed)
    fireClickAndMouseEvents(statusField);
    fireClickAndMouseEvents(getByText('Invalid'));
    expect(statusField).toHaveValue('Invalid');

    expect(await queryAllByText('INVALID')).toHaveLength(0);
    fireClickAndMouseEvents(getByText('Apply'));
    // Find the alerts with the updated status
    expect(await findAllByText('INVALID')).toHaveLength(1);
    // And expect that the selection has been reset
    expect(await queryByAriaLabel(`unselect item`)).not.toBeInTheDocument();

    // Now select all Rule Matches and updated to Open
    const selectAllCheckbox = getByAriaLabel('select all');
    fireClickAndMouseEvents(selectAllCheckbox);

    expect(getAllByAriaLabel(`unselect item`)).toHaveLength(alertSummaries.length);

    // Expect status field to have Resolved as default

    fireClickAndMouseEvents(getAllByLabelText('Status')[0]);
    fireClickAndMouseEvents(getByText('Open'));
    expect(getAllByLabelText('Status')[0]).toHaveValue('Open');
    fireClickAndMouseEvents(getByText('Apply'));
    expect(await findAllByText('OPEN')).toHaveLength(2);
  });
});
