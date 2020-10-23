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
import { Flex, theme } from 'pouncejs';
import sum from 'lodash/sum';
import { capitalize, countPoliciesBySeverityAndStatus } from 'Helpers/utils';
import map from 'lodash/map';
import { OrganizationReportBySeverity } from 'Generated/schema';
import BarChart from 'Components/charts/BarChart';
import ChartSummary from 'Components/charts/ChartSummary';
import mapKeys from 'lodash/mapKeys';
import { SEVERITY_COLOR_MAP } from 'Source/constants';

const severityToGrayscaleMapping: {
  [key in keyof OrganizationReportBySeverity]: keyof typeof theme['colors'];
} = mapKeys(SEVERITY_COLOR_MAP, (value, key) => key.toLowerCase());

interface PoliciesBySeverityChartData {
  policies: OrganizationReportBySeverity;
}

const PoliciesBySeverityChart: React.FC<PoliciesBySeverityChartData> = ({ policies }) => {
  const severities = Object.keys(severityToGrayscaleMapping);
  const totalPolicies = sum(
    severities.map((severity: keyof OrganizationReportBySeverity) =>
      countPoliciesBySeverityAndStatus(policies, severity, ['fail', 'error', 'pass'])
    )
  );

  const allPoliciesChartData = map(
    severityToGrayscaleMapping,
    (color, severity: keyof OrganizationReportBySeverity) => ({
      value: countPoliciesBySeverityAndStatus(policies, severity, ['fail', 'error', 'pass']),
      label: capitalize(severity),
      color,
    })
  );

  return (
    <Flex height="100%">
      <ChartSummary total={totalPolicies} title="Total Enabled Policies" color="violet-400" />
      <BarChart data={allPoliciesChartData} />
    </Flex>
  );
};

export default React.memo(PoliciesBySeverityChart);
