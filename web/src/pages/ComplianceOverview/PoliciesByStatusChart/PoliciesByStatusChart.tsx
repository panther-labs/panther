/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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
import { capitalize, countPoliciesBySeverityAndStatus } from 'Helpers/utils';
import DonutChart from 'Components/DonutChart';
import map from 'lodash-es/map';
import sum from 'lodash-es/sum';
import { OrganizationReportBySeverity } from 'Generated/schema';
import { theme } from 'pouncejs';

const severityToColorMapping: {
  [key in keyof OrganizationReportBySeverity]: keyof typeof theme['colors'];
} = {
  critical: 'red300',
  high: 'red200',
  medium: 'blue100',
  low: 'grey100',
  info: 'grey50',
};

interface PoliciesByStatusChartData {
  policies: OrganizationReportBySeverity;
}

const PoliciesByStatusChart: React.FC<PoliciesByStatusChartData> = ({ policies }) => {
  const severities = Object.keys(severityToColorMapping);
  const totalPolicies = sum(
    severities.map((severity: keyof OrganizationReportBySeverity) =>
      countPoliciesBySeverityAndStatus(policies, severity, ['fail', 'error', 'pass'])
    )
  );

  const failingPoliciesChartData = [
    ...map(severityToColorMapping, (color, severity: keyof OrganizationReportBySeverity) => ({
      value: countPoliciesBySeverityAndStatus(policies, severity, ['fail', 'error']),
      label: capitalize(severity),
      color,
    })),
    {
      value: sum(
        Object.keys(severityToColorMapping).map((severity: keyof OrganizationReportBySeverity) =>
          countPoliciesBySeverityAndStatus(policies, severity, ['pass'])
        )
      ),
      label: 'Passing',
      color: 'green100' as const,
    },
  ];

  return (
    <DonutChart
      data={failingPoliciesChartData}
      renderLabel={(chartData, index) => {
        const { value: severityGroupingValue } = chartData[index];
        const percentage = Math.round((severityGroupingValue * 100) / totalPolicies).toFixed(0);

        return `${severityGroupingValue}\n{small|${percentage}% of all}`;
      }}
    />
  );
};

export default React.memo(PoliciesByStatusChart);
