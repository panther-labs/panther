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
import { AlertStatusesEnum, AlertSummaryRuleInfo, SeverityEnum } from 'Generated/schema';
import {
  buildAlertSummary,
  buildAlertSummaryRuleInfo,
  buildLogAnalysisMetricsResponse,
  buildSingleValue,
  render,
  waitForElementToBeRemoved,
} from 'test-utils';
import { getGraphqlSafeDateRange } from 'Helpers/utils';
import AlertsOverview, { DEFAULT_PAST_DAYS, DEFAULT_INTERVAL } from './AlertsOverview';
import { mockGetLogAnalysisMetrics } from './graphql/getLogAnalysisMetrics.generated';
import { mockGetOverviewAlerts } from './graphql/getOverviewAlerts.generated';

const recentAlerts = [
  buildAlertSummary({
    alertId: '1',
    detection: buildAlertSummaryRuleInfo({
      ruleId: 'rule_1',
    }),
    severity: SeverityEnum.High,
  }),
  buildAlertSummary({
    alertId: '2',
    detection: buildAlertSummaryRuleInfo({
      ruleId: 'rule_2',
    }),
    severity: SeverityEnum.Critical,
  }),
  buildAlertSummary({
    alertId: '3',
    detection: buildAlertSummaryRuleInfo({
      ruleId: 'rule_3',
    }),
    severity: SeverityEnum.High,
  }),
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

  it('should render all alerts overview sections', async () => {
    const [mockedFromDate, mockedToDate] = getGraphqlSafeDateRange({ days: DEFAULT_PAST_DAYS });
    const [mockedPastDay] = getGraphqlSafeDateRange({ days: 1 });
    const mocks = [
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
            metricNames: ['totalAlertsDelta', 'alertsBySeverity', 'alertsByRuleID'],
            fromDate: mockedFromDate,
            toDate: mockedToDate,
            intervalMinutes: DEFAULT_INTERVAL,
          },
        },
      }),
      mockGetOverviewAlerts({
        data: {
          alerts: { alertSummaries: recentAlerts },
        },
        variables: {
          input: {
            severity: [SeverityEnum.Critical, SeverityEnum.High],
            pageSize: 5,
            status: [AlertStatusesEnum.Open],
            createdAtAfter: mockedPastDay,
            createdAtBefore: mockedToDate,
          },
        },
      }),
    ];

    const { getByTestId, getAllByTitle, getByAriaLabel, findByText, getByText, container } = render(
      <AlertsOverview />,
      {
        mocks,
      }
    );

    // Expect to see 3 loading interfaces
    const loadingInterfaceElements = getAllByTitle('Loading interface...');
    expect(loadingInterfaceElements.length).toEqual(3);

    // Waiting for all loading interfaces to be removed
    await Promise.all(loadingInterfaceElements.map(ele => waitForElementToBeRemoved(ele)));

    // Alerts overview section
    expect(await findByText('Total Alerts')).toBeInTheDocument();
    expect(getByText('Alerts Overview')).toBeInTheDocument();
    expect(getByTestId('alert-by-severity-chart')).toBeInTheDocument();

    // Top 5 High Priority Alerts
    expect(getByText('Top 5 High Priority Alerts')).toBeInTheDocument();
    recentAlerts.forEach(alert => {
      expect(getByAriaLabel(`Link to rule ${(alert.detection as AlertSummaryRuleInfo).ruleId}`));
    });
    // Most Active Detections
    expect(getByText('Most Active Detections')).toBeInTheDocument();
    expect(getByTestId('alert-by-severity-chart')).toBeInTheDocument();

    expect(container).toMatchSnapshot();
  });
});
