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
