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
import { remToPx } from 'Helpers/utils';
import { FloatSeries, LongSeries } from 'Generated/schema';
import { useTheme } from 'pouncejs';

type GetLegendProps = {
  series: (LongSeries | FloatSeries)[];
  title?: string;
};

type GetLegendFunc = (props: GetLegendProps) => any;

const useChartOptions = () => {
  const theme = useTheme();
  const getLegend: GetLegendFunc = React.useCallback(
    ({ series, title }) => {
      /*
       * 'legendData' must be an array of values that matches 'series.name' in order
       * to display them in correct order and color
       * e.g. [AWS.ALB, AWS.S3, ...etc]
       */
      const legendData = series.map(({ label }) => label);
      return {
        type: 'scroll' as const,
        orient: 'vertical' as const,
        left: 'auto',
        right: 'auto',
        // Pushing down legend to fit title
        top: title ? 30 : 'auto',
        icon: 'circle',
        data: legendData,
        inactiveColor: theme.colors['gray-400'],
        textStyle: {
          color: theme.colors['gray-50'],
          fontFamily: theme.fonts.primary,
          fontSize: remToPx(theme.fontSizes['x-small']),
        },
        pageIcons: {
          vertical: ['M7 10L12 15L17 10H7Z', 'M7 14L12 9L17 14H7Z'],
        },
        pageIconColor: theme.colors['gray-50'],
        pageIconInactiveColor: theme.colors['navyblue-300'],
        pageIconSize: 12,
        pageTextStyle: {
          fontFamily: theme.fonts.primary,
          color: theme.colors['gray-50'],
          fontWeight: theme.fontWeights.bold as any,
          fontSize: remToPx(theme.fontSizes['x-small']),
        },
        pageButtonGap: theme.space[3] as number,
      };
    },
    [theme]
  );

  return React.useMemo(() => ({ getLegend }), [getLegend]);
};

export default useChartOptions;
