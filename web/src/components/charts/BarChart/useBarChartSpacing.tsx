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
import { GridPosition, Spacing } from './BarChart';

interface UseBarChartSpacingProps {
  gridPosition: GridPosition;
  barWidth: number;
  barGap: number | string;
  isHorizontal: boolean;
}

const getGrid = (gridPosition, isHorizontal): GridPosition => {
  return {
    left: 100,
    right: 20,
    bottom: 20,
    top: isHorizontal ? 0 : 30,
    ...gridPosition,
  };
};

const useBarChartSpacing = ({
  gridPosition,
  barGap,
  barWidth,
  isHorizontal,
}: UseBarChartSpacingProps): Spacing => {
  return React.useMemo(() => {
    return {
      grid: getGrid(gridPosition, isHorizontal),
      barGap: barGap || (isHorizontal ? '-20%' : '-100%'),
      barWidth,
    };
  }, [gridPosition, barGap, barWidth, isHorizontal]);
};

export default useBarChartSpacing;
