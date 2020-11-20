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
import { Box, Flex, SimpleGrid } from 'pouncejs';
import TimeSeriesChart from 'Components/charts/TimeSeriesChart';
import { LongSeriesData } from 'Generated/schema';
import { stringToPaleColor } from 'Helpers/colors';

interface EventsByLogTypesProps {
  events: LongSeriesData;
}

const getTooltip = (aggregate: { [key: string]: number }) => {
  return (
    <SimpleGrid columns={2} spacing={3}>
      {Object.keys(aggregate).map(logType => (
        <Flex key={logType} justify="space-between" spacing={2}>
          <Flex spacing={2} align="center">
            <Box
              as="span"
              width={12}
              height={12}
              backgroundColor={stringToPaleColor(logType) as any}
              // @ts-ignore The pounce property is not transformed for unknown reasons
              borderRadius="10px"
            />
            <Box as="span" fontSize="x-small" fontWeight="normal" lineHeight="typical">
              {logType}
            </Box>
          </Flex>
          <Box font="mono" fontWeight="bold">
            {aggregate[logType].toLocaleString('en')}
            {` Hits`}
          </Box>
        </Flex>
      ))}
    </SimpleGrid>
  );
};
const EventsByLogTypes: React.FC<EventsByLogTypesProps> = ({ events }) => {
  const metadata = events.series[0].values
    .map(value => ({
      'AWS.ALB': value / 4,
      'Okta.SystemLog': value / 4,
      'AWS.S3': value / 8,
      'AWS.1': value / 8,
      'AWS.2': value / 8,
      'GSuite:': value / 16,
      'Slackaa.1': value / 16,
      'Slackaaaaaa.2': value / 16,
    }))
    .map(obj => ({ tooltip: getTooltip(obj) }));
  const data = {
    series: [{ ...events.series[0], color: 'indigo-600' }],
    timestamps: events.timestamps,
    metadata,
  };
  return (
    <Flex data-testid="events-by-log-type-chart" height="100%" position="relative">
      <TimeSeriesChart
        data={data}
        zoomable
        chartType="bar"
        hideLegend
        units="Hits"
        hideSeriesLabels={false}
      />
    </Flex>
  );
};

export default React.memo(EventsByLogTypes);
