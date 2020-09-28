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
import { EChartOption } from 'echarts';

interface ChartSummaryProps {
  scaleType: string;
  onSelection: (option: EChartOption.BasicComponents.CartesianAxis.Type) => void;
}

const ScaleControls: React.FC<ChartSummaryProps> = ({ scaleType = 'value', onSelection }) => {
  return (
    <Flex
      position="absolute"
      width="30%"
      maxWidth="200px"
      ml="210px"
      justify="left"
      spacing={2}
      zIndex={5}
    >
      <Box
        borderRadius="circle"
        py={1}
        px={4}
        size="small"
        backgroundColor={scaleType === 'value' ? 'blue-400' : 'transparent'}
        color="white"
        fontSize="small"
        cursor="pointer"
        onClick={() => onSelection('value')}
        as="button"
      >
        Linear
      </Box>
      <Box
        borderRadius="circle"
        py={1}
        px={4}
        size="small"
        backgroundColor={scaleType !== 'value' ? 'blue-400' : 'transparent'}
        color="white"
        fontSize="small"
        cursor="pointer"
        onClick={() => onSelection('log')}
        as="button"
      >
        Logarithmic
      </Box>
    </Flex>
  );
};

export default ScaleControls;
