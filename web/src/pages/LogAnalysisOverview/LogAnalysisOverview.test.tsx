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
import { DEFAULT_LARGE_PAGE_SIZE } from 'Source/constants';
import {
  buildLogAnalysisMetricsResponse,
  buildLogAnalysisMetricsInput,
  render,
  waitForElementToBeRemoved,
  buildSingleValue,
  buildListAlertsResponse,
} from 'test-utils';
import { mockListAlerts } from 'Pages/ListAlerts/graphql/listAlerts.generated';
import LogAnalysisOverview, { intervalMinutes, defaultPastDays } from './LogAnalysisOverview';
import { mockGetLogAnalysisMetrics } from './graphql/getLogAnalysisMetrics.generated';

describe('Log Analysis Overview', () => {
  test('render 2 canvas', async () => {
    const mockedToDate = '2020-07-22T19:04:33Z';
    const getLogAnalysisMetrics = buildLogAnalysisMetricsResponse();
    const mockedFromDate = utils.subtractDays(mockedToDate, defaultPastDays);
    const getLogAnalysisMetricsInput = buildLogAnalysisMetricsInput({
      metricNames: ['eventsProcessed', 'totalAlertsDelta', 'alertsBySeverity'],
      fromDate: mockedFromDate,
      toDate: mockedToDate,
      intervalMinutes,
    });

    // Mocking getCurrentDate in order to have a common date for the query
    const mockedGetCurrentDate = jest.spyOn(utils, 'getCurrentDate');
    mockedGetCurrentDate.mockImplementation(() => mockedToDate);

    const alerts = buildListAlertsResponse();
    const mocks = [
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
      mockListAlerts({
        data: { alerts },
        variables: {
          input: {
            severity: [SeverityEnum.Critical, SeverityEnum.High],
            pageSize: DEFAULT_LARGE_PAGE_SIZE,
          },
        },
      }),
    ];

    const { getByTestId, getAllByTitle } = render(<LogAnalysisOverview />, {
      mocks,
    });

    // Expect to see 3 loading interfaces
    const loadingInterfaceElements = getAllByTitle('Loading interface...');
    expect(loadingInterfaceElements.length).toEqual(3);

    // Waiting for all loading interfaces to be removed;
    await Promise.all(loadingInterfaceElements.map(ele => waitForElementToBeRemoved(ele)));

    const alertsChart = getByTestId('alert-by-severity-chart');
    const eventChart = getByTestId('events-by-log-type-chart');

    expect(alertsChart).toBeTruthy();
    expect(eventChart).toBeTruthy();
  });
});
