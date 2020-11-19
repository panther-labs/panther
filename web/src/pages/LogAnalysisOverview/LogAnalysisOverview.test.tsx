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
import MockDate from 'mockdate';
import { AlertStatusesEnum, SeverityEnum } from 'Generated/schema';
import {
  buildAlertSummary,
  buildListAlertsResponse,
  buildLogAnalysisMetricsResponse,
  buildSingleValue,
  fireEvent,
  render,
  waitForElementToBeRemoved,
} from 'test-utils';
import { MockedResponse } from '@apollo/client/testing';
import { getGraphqlSafeDateRange } from 'Helpers/utils';
import { mockGetOverviewAlerts } from 'Pages/LogAnalysisOverview/graphql/getOverviewAlerts.generated';
import LogAnalysisOverview, { DEFAULT_PAST_DAYS, DEFAULT_INTERVAL } from './LogAnalysisOverview';
import { mockGetLogAnalysisMetrics } from './graphql/getLogAnalysisMetrics.generated';

let defaultMocks: MockedResponse[];

const recentAlerts = [buildAlertSummary({ alertId: '1', ruleId: 'rule_1' })];

const highSeverityAlerts = [
  buildAlertSummary({ alertId: '2', ruleId: 'rule_2', severity: SeverityEnum.Critical }),
  buildAlertSummary({ alertId: '3', ruleId: 'rule_3', severity: SeverityEnum.High }),
];

describe('Log Analysis Overview', () => {
  beforeAll(() => {
    // https://github.com/boblauer/MockDate#example
    // Forces a fixed resolution on `Date.now()`
    MockDate.set('1/30/2000');
  });

  afterAll(() => {
    MockDate.reset();
  });

  beforeEach(() => {
    const [mockedFromDate, mockedToDate] = getGraphqlSafeDateRange({ days: DEFAULT_PAST_DAYS });

    defaultMocks = [
      mockGetLogAnalysisMetrics({
        data: {
          getLogAnalysisMetrics: buildLogAnalysisMetricsResponse({
            totalAlertsDelta: [
              buildSingleValue({ label: 'Previous Period' }),
              buildSingleValue({ label: 'Current Period' }),
            ],
          }),
        },
        variables: {
          input: {
            metricNames: [
              'eventsProcessed',
              'totalAlertsDelta',
              'alertsBySeverity',
              'eventsLatency',
              'alertsByRuleID',
            ],
            fromDate: mockedFromDate,
            toDate: mockedToDate,
            intervalMinutes: DEFAULT_INTERVAL,
          },
        },
      }),
      mockGetOverviewAlerts({
        data: {
          recentAlerts: buildListAlertsResponse({
            alertSummaries: recentAlerts,
          }),
          topAlerts: buildListAlertsResponse({
            alertSummaries: highSeverityAlerts,
          }),
        },
        variables: {
          recentAlertsInput: {
            pageSize: 10,
            status: [AlertStatusesEnum.Open, AlertStatusesEnum.Triaged],
          },
        },
      }),
    ];
  });

  it('should render 2 canvas, click on tab button and render latency chart', async () => {
    const { getByTestId, getAllByTitle, getByText } = render(<LogAnalysisOverview />, {
      mocks: defaultMocks,
    });

    // Expect to see 3 loading interfaces
    const loadingInterfaceElements = getAllByTitle('Loading interface...');
    expect(loadingInterfaceElements.length).toEqual(3);

    // Waiting for all loading interfaces to be removed;
    await Promise.all(loadingInterfaceElements.map(ele => waitForElementToBeRemoved(ele)));

    const alertsChart = getByTestId('alert-by-severity-chart');
    const eventChart = getByTestId('events-by-log-type-chart');

    expect(alertsChart).toBeInTheDocument();
    expect(eventChart).toBeInTheDocument();

    // Checking tab click works and renders Data Latency tab
    const latencyChartTabButton = getByText('Data Latency by Log Type');
    fireEvent.click(latencyChartTabButton);
    const latencyChart = getByTestId('events-by-latency');
    expect(latencyChart).toBeInTheDocument();
    // Checking tab click works and renders Most Active rules tab
    const mostActiveRulesTabButton = getByText('Most Active Rules');
    fireEvent.click(mostActiveRulesTabButton);
    const mostActiveRulesChart = getByTestId('most-active-rules-chart');
    expect(mostActiveRulesChart).toBeInTheDocument();
  });

  it('should display Alerts Cards for Top Alerts and Recent Alerts', async () => {
    const { getAllByTitle, getByText, getByAriaLabel } = render(<LogAnalysisOverview />, {
      mocks: defaultMocks,
    });
    // Expect to see 3 loading interfaces
    const loadingInterfaceElements = getAllByTitle('Loading interface...');
    expect(loadingInterfaceElements.length).toEqual(3);

    // Waiting for all loading interfaces to be removed;
    await Promise.all(loadingInterfaceElements.map(ele => waitForElementToBeRemoved(ele)));

    recentAlerts.forEach(alert => {
      expect(getByAriaLabel(`Link to rule ${alert.ruleId}`));
    });
    const topAlertsTabButton = getByText('High Severity Alerts (2)');
    fireEvent.click(topAlertsTabButton);
    highSeverityAlerts.forEach(alert => {
      expect(getByAriaLabel(`Link to rule ${alert.ruleId}`));
    });
  });
});
