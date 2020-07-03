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
import { Flex } from 'pouncejs';
import BarChart from 'Components/charts/BarChart';
import ChartSummary from 'Components/charts/ChartSummary';

interface ResourcesByPlatformProps {
  resources: ScannedResources;
}

const ResourcesByPlatform: React.FC<ResourcesByPlatformProps> = ({ resources }) => {
  const allResourcesChartData = [
    {
      value: resources.byType.length,
      label: 'AWS',
      color: 'gray-600' as const,
    },
  ];

  return (
    <Flex height="100%">
      <ChartSummary total={resources.byType.length} title="Resource Types" color="gray-200" />
      <BarChart data={allResourcesChartData} alignment="horizontal" />
    </Flex>
  );
};

export default React.memo(ResourcesByPlatform);
