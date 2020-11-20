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
import { stringToPaleColor } from 'Helpers/colors';

const SeriesTooltip: React.FC<{ seriesInfo: any; units: string }> = ({ seriesInfo, units }) => {
  const [, value, metadata] = seriesInfo.value;
  return (
    <Flex direction="column" spacing={2} fontSize="x-small">
      <Flex key={seriesInfo.seriesName} justify="space-between">
        {metadata ? (
          <SimpleGrid columns={2} spacing={3}>
            {Object.keys(metadata).map(logType => (
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
                  {metadata[logType].toLocaleString('en')}
                  {units ? ` ${units}` : ''}
                </Box>
              </Flex>
            ))}
          </SimpleGrid>
        ) : (
          <>
            <Box as="dt">
              <span dangerouslySetInnerHTML={{ __html: seriesInfo.marker }} />
              {seriesInfo.seriesName}
            </Box>
            <Box as="dd" font="mono" fontWeight="bold">
              {value.toLocaleString('en')}
              {units ? ` ${units}` : ''}
            </Box>
          </>
        )}
      </Flex>
    </Flex>
  );
};

export default React.memo(SeriesTooltip);
