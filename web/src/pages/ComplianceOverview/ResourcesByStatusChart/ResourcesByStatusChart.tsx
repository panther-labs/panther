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
import { ScannedResources } from 'Generated/schema';
import { countResourcesByStatus } from 'Helpers/utils';
import { Bars } from 'Components/Charts';

interface ResourcesByStatusChartProps {
  resources: ScannedResources;
}

const ResourcesByStatusChart: React.FC<ResourcesByStatusChartProps> = ({ resources }) => {
  const failingResourcesChartData = [
    {
      value: countResourcesByStatus(resources, ['fail', 'error']),
      label: 'Failing',
      color: 'red300' as const,
    },
    {
      value: countResourcesByStatus(resources, ['pass']),
      label: 'Passing',
      color: 'green200' as const,
    },
  ];

  return <Bars data={failingResourcesChartData} horizontal />;
};

export default React.memo(ResourcesByStatusChart);
