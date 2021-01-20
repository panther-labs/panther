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
import { Box, Flex, Text } from 'pouncejs';
import { formatDatetime, secondsToString } from 'Helpers/utils';

export interface ChartTooltipProps {
  params: any[];
  units?: string;
}

const ChartTooltip: React.FC<ChartTooltipProps> = ({ params, units }) => {
  return (
    <Box
      font="primary"
      backgroundColor="navyblue-300"
      minWidth={200}
      boxShadow="dark250"
      p={4}
      borderRadius="medium"
    >
      <Text fontSize="small-medium" mb={3}>
        {formatDatetime(params[0].value[0], true)}
      </Text>
      <Flex direction="column" spacing={2} fontSize="x-small">
        {params.map((seriesInfo, i) => {
          return (
            <Flex key={`chart-tooltip ${i}`} direction="column" spacing={2} fontSize="x-small">
              <Flex key={seriesInfo.seriesName} justify="space-between">
                <Box as="dt">
                  <span dangerouslySetInnerHTML={{ __html: seriesInfo.marker }} />
                  {seriesInfo.seriesName}
                </Box>
                <Box as="dd" font="mono" fontWeight="bold">
                  {units === 'sec'
                    ? secondsToString(seriesInfo.value[1])
                    : `${seriesInfo.value[1].toLocaleString('en')}${units ? ` ${units}` : ''}`}
                </Box>
              </Flex>
            </Flex>
          );
        })}
      </Flex>
    </Box>
  );
};

export default ChartTooltip;
