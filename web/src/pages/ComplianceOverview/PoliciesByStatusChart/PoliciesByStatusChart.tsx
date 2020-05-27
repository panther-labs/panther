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
import { capitalize, countPoliciesBySeverityAndStatus } from 'Helpers/utils';
import map from 'lodash-es/map';
import sum from 'lodash-es/sum';
import { OrganizationReportBySeverity } from 'Generated/schema';
import { theme } from 'pouncejs';
import { Bars } from 'Components/Charts';

const severityToColorMapping: {
  [key in keyof OrganizationReportBySeverity]: keyof typeof theme['colors'];
} = {
  critical: 'red300',
  high: 'orange300',
  medium: 'yellow300',
  low: 'grey300',
  info: 'grey100',
};

interface PoliciesByStatusChartData {
  policies: OrganizationReportBySeverity;
}

const PoliciesByStatusChart: React.FC<PoliciesByStatusChartData> = ({ policies }) => {
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
      color: 'green200' as const,
    },
  ];

  return <Bars data={failingPoliciesChartData} />;
};

export default React.memo(PoliciesByStatusChart);
