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
import { Bars, ChartSummary } from 'Components/Charts';

interface ResourcesByPlatformProps {
  resources: ScannedResources;
}

const ResourcesByPlatform: React.FC<ResourcesByPlatformProps> = ({ resources }) => {
  console.log('Resources', resources);
  const allResourcesChartData = [
    {
      value: resources.byType.length,
      label: 'AWS',
      color: 'grey300' as const,
    },
  ];

  return (
    <Flex height="100%">
      <ChartSummary total={resources.byType.length} title="Resource Types" color="grey200" />
      <Bars data={allResourcesChartData} horizontal />
    </Flex>
  );
};

export default React.memo(ResourcesByPlatform);
