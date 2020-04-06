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
import { theme } from 'pouncejs';
import { capitalize, countPoliciesBySeverityAndStatus } from 'Helpers/utils';
import DonutChart from 'Components/DonutChart';
import map from 'lodash-es/map';
import { OrganizationReportBySeverity } from 'Generated/schema';

const severityToGrayscaleMapping: {
  [key in keyof OrganizationReportBySeverity]: keyof typeof theme['colors'];
} = {
  critical: 'grey500',
  high: 'grey400',
  medium: 'grey300',
  low: 'grey200',
  info: 'grey100',
};

interface PoliciesBySeverityChartData {
  policies: OrganizationReportBySeverity;
}

const PoliciesBySeverityChart: React.FC<PoliciesBySeverityChartData> = ({ policies }) => {
  const allPoliciesChartData = map(
    severityToGrayscaleMapping,
    (color, severity: keyof OrganizationReportBySeverity) => ({
      value: countPoliciesBySeverityAndStatus(policies, severity, ['fail', 'error', 'pass']),
      label: capitalize(severity),
      color,
    })
  );

  return (
    <DonutChart data={allPoliciesChartData} renderLabel={(data, index) => data[index].value} />
  );
};

export default React.memo(PoliciesBySeverityChart);
