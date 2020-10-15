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
import * as utils from 'Helpers/utils';
import { SeverityEnum } from 'Generated/schema';
import {
  buildAlertSummary,
  buildListAlertsResponse,
  buildLogAnalysisMetricsInput,
  buildLogAnalysisMetricsResponse,
  buildSingleValue,
  fireEvent,
  render,
  waitForElementToBeRemoved,
} from 'test-utils';
import { mockGetOverviewAlerts } from 'Pages/LogAnalysisOverview/graphql/getOverviewAlerts.generated';
import LogAnalysisOverview, { defaultPastDays, intervalMinutes } from './LogAnalysisOverview';
import { mockGetLogAnalysisMetrics } from './graphql/getLogAnalysisMetrics.generated';

const mockedToDate = '2020-07-22T19:04:33Z';
const getLogAnalysisMetrics = buildLogAnalysisMetricsResponse();
const mockedFromDate = utils.subtractDays(mockedToDate, defaultPastDays);
const getLogAnalysisMetricsInput = buildLogAnalysisMetricsInput({
  metricNames: [
    'eventsProcessed',
    'totalAlertsDelta',
    'alertsBySeverity',
    'eventsLatency',
    'alertsByRuleID',
  ],
  fromDate: mockedFromDate,
  toDate: mockedToDate,
  intervalMinutes,
});

// Mocking getCurrentDate in order to have a common date for the query
const mockedGetCurrentDate = jest.spyOn(utils, 'getCurrentDate');
mockedGetCurrentDate.mockImplementation(() => mockedToDate);

function genAlert(severity) {
  return buildAlertSummary({ severity });
}

const recentAlerts = buildListAlertsResponse();
const topAlerts = buildListAlertsResponse({
  alertSummaries: [genAlert(SeverityEnum.Critical), genAlert(SeverityEnum.High)],
});

const defaultMocks = [
  mockGetLogAnalysisMetrics({
    data: {
      getLogAnalysisMetrics: {
        ...getLogAnalysisMetrics,
        totalAlertsDelta: [
          buildSingleValue({ label: 'Previous Period' }),
          buildSingleValue({ label: 'Current Period' }),
        ],
      },
    },
    variables: { input: getLogAnalysisMetricsInput },
  }),
  mockGetOverviewAlerts({
    data: { recentAlerts, topAlerts },
    variables: {
      recentAlertsInput: {
        pageSize: 10,
      },
    },
  }),
];

describe('Log Analysis Overview', () => {
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
    const { getAllByTitle, getByText, getAllByText } = render(<LogAnalysisOverview />, {
      mocks: defaultMocks,
    });
    // Expect to see 3 loading interfaces
    const loadingInterfaceElements = getAllByTitle('Loading interface...');
    expect(loadingInterfaceElements.length).toEqual(3);

    // Waiting for all loading interfaces to be removed;
    await Promise.all(loadingInterfaceElements.map(ele => waitForElementToBeRemoved(ele)));

    const recentAlertCards = getAllByText('View Rule');
    expect(recentAlertCards.length).toEqual(1);
    const topAlertsTabButton = getByText('High Severity Alerts (2)');
    fireEvent.click(topAlertsTabButton);
    const alertCards = getAllByText('View Rule');
    // There are 3 alerts cards because previous Alerts cards are not unmounted
    expect(alertCards.length).toEqual(3);
  });
});
