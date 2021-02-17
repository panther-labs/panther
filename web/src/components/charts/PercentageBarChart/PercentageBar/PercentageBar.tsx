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

/**
 * Copyright (C) 2020 Panther Labs Inc
 *
 * Panther Enterprise is licensed under the terms of a commercial license available from
 * Panther Labs Inc ("Panther Commercial License") by contacting contact@runpanther.com.
 * All use, distribution, and/or modification of this software, whether commercial or non-commercial,
 * falls under the Panther Commercial License to the extent it is permitted.
 */

import React from 'react';
import { Box, Flex, Text, Theme } from 'pouncejs';
import { slugify } from 'Helpers/utils';

interface PercentageBarProps {
  /** The title of each bar */
  title: string;

  /** The value displayed next to the bar */
  value: number;

  /** A number between [0,1] specifying the width percentage that the bar will occupy relative to
   * its container
   */
  percentage: number;

  /** The color of the bar */
  color?: keyof Theme['colors'];

  /** The height of the bar */
  height?: number;
}

const PercentageBar: React.FC<PercentageBarProps> = ({
  title,
  value,
  percentage,
  color = 'pink-700',
  height = 32,
}) => {
  const id = slugify(title);

  return (
    <Box py={3} overflow="hidden">
      <Text id={id} fontSize="small-medium" mx={2} mb={1} truncated>
        {title}
      </Text>
      <Flex align="center" spacing={2}>
        <Box
          as="span"
          id={id}
          backgroundColor={color}
          borderRadius="pill"
          height={height}
          width={percentage}
          flexShrink={1}
          aria-valuenow={value}
          aria-labelledby={id}
        />
        <Box mr={0} ml={'auto'} as="span" fontSize="x-large" fontWeight="bold" flexShrink={0}>
          {value}
        </Box>
      </Flex>
    </Box>
  );
};

export default React.memo(PercentageBar);
