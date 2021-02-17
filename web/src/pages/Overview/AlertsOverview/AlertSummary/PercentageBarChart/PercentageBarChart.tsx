/**
 * Copyright (C) 2020 Panther Labs Inc
 *
 * Panther Enterprise is licensed under the terms of a commercial license available from
 * Panther Labs Inc ("Panther Commercial License") by contacting contact@runpanther.com.
 * All use, distribution, and/or modification of this software, whether commercial or non-commercial,
 * falls under the Panther Commercial License to the extent it is permitted.
 */

import React from 'react';
import { Box, Theme } from 'pouncejs';
import PercentageBar from './PercentageBar';

interface Data {
  /** The title of each bar */
  title: string;

  /** The value displayed next to the bar */
  value: number;

  /** The color of each bar */
  color?: keyof Theme['colors'];
}

interface PercentageBarChartProps {
  data: Data[];
  barHeight?: number;
}

const PercentageBarChart: React.FC<PercentageBarChartProps> = ({ data, barHeight }) => {
  const maxValue = React.useMemo(() => Math.max(...data.map(d => d.value)), [data]);

  return (
    <Box as="ol" borderTop="1px solid" borderColor="navyblue-300">
      {data.map(d => (
        <Box as="li" key={d.title} borderBottom="1px solid" borderColor="navyblue-300">
          <PercentageBar {...d} percentage={d.value / maxValue} height={barHeight} />
        </Box>
      ))}
    </Box>
  );
};

export default PercentageBarChart;
