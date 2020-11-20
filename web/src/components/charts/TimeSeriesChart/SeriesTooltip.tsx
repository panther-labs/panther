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
import { Box, Flex } from 'pouncejs';
import { Metadata } from './TimeSeriesChart';

const SeriesTooltip: React.FC<{ seriesInfo: any; units: string }> = ({ seriesInfo, units }) => {
  const [, value, metadata]: [any, number, Metadata] = seriesInfo.value;
  return (
    <Flex direction="column" spacing={2} fontSize="x-small">
      <Flex key={seriesInfo.seriesName} justify="space-between">
        {metadata?.tooltip ? (
          <React.Fragment>{metadata.tooltip}</React.Fragment>
        ) : (
          <React.Fragment>
            <Box as="dt">
              <span dangerouslySetInnerHTML={{ __html: seriesInfo.marker }} />
              {seriesInfo.seriesName}
            </Box>
            <Box as="dd" font="mono" fontWeight="bold">
              {value.toLocaleString('en')}
              {units ? ` ${units}` : ''}
            </Box>
          </React.Fragment>
        )}
      </Flex>
    </Flex>
  );
};

export default React.memo(SeriesTooltip);
