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
import DonutChart from 'Components/DonutChart';
import { ScannedResources } from 'Generated/schema';
import { countResourcesByStatus } from 'Helpers/utils';

interface ResourcesByStatusChartProps {
  resources: ScannedResources;
}

const ResourcesByStatusChart: React.FC<ResourcesByStatusChartProps> = ({ resources }) => {
  const totalResources = countResourcesByStatus(resources, ['fail', 'error', 'pass']);

  const failingResourcesChartData = [
    {
      value: countResourcesByStatus(resources, ['fail', 'error']),
      label: 'Failing',
      color: 'red200' as const,
    },
    {
      value: countResourcesByStatus(resources, ['pass']),
      label: 'Passing',
      color: 'green100' as const,
    },
  ];

  return (
    <DonutChart
      data={failingResourcesChartData}
      renderLabel={(chartData, index) => {
        const { value: statusGroupingValue } = chartData[index];
        const percentage = Math.round((statusGroupingValue * 100) / totalResources).toFixed(0);

        return `${statusGroupingValue}\n{small|${percentage}% of all}`;
      }}
    />
  );
};

export default React.memo(ResourcesByStatusChart);
