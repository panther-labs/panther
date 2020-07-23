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
import { countPoliciesBySeverityAndStatus } from 'Helpers/utils';
import sum from 'lodash/sum';
import { OrganizationReportBySeverity } from 'Generated/schema';
import { Flex } from 'pouncejs';
import BarChart from 'Components/charts/BarChart';
import ChartSummary from 'Components/charts/ChartSummary';

const severities = [
  'critical',
  'high',
  'medium',
  'low',
  'info',
] as (keyof OrganizationReportBySeverity)[];

interface PoliciesOverviewChartData {
  policies: OrganizationReportBySeverity;
}

const PoliciesOverviewChart: React.FC<PoliciesOverviewChartData> = ({ policies }) => {
  const passingPolicies = sum(
    severities.map((severity: keyof OrganizationReportBySeverity) =>
      countPoliciesBySeverityAndStatus(policies, severity, ['pass'])
    )
  );
  const failingPolicies = sum(
    severities.map((severity: keyof OrganizationReportBySeverity) =>
      countPoliciesBySeverityAndStatus(policies, severity, ['fail', 'error'])
    )
  );

  const totalPolicies = passingPolicies + failingPolicies;
  const policiesOverviewChartData = [
    {
      value: failingPolicies,
      label: 'Failing',
      color: 'red-300' as const,
    },
    {
      value: passingPolicies,
      label: 'Passing',
      color: 'green-400' as const,
    },
  ];

  return (
    <Flex height="100%">
      <ChartSummary total={totalPolicies} title="Total Policies" color="blue-400" />
      <BarChart data={policiesOverviewChartData} alignment="horizontal" />
    </Flex>
  );
};

export default React.memo(PoliciesOverviewChart);
