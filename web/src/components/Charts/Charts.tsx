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
import { Text } from 'pouncejs';
import echarts from 'echarts';

import { TimeSeriesLines, TimeSeriesZoomableLines } from './components';
import { ChartsThemeEnum, ChartThemeType, ChartType, ThemeOptions } from './constants';

interface ChartsProps {
  /**
   *
   */
  title?: string;
  /**
   *
   */
  chartType: ChartType;
  /**
   *
   * Defaults to ChartsThemeEnum.Light
   */
  theme?: ChartThemeType;
  /**
   *
   * Defaults to 300px
   */
  height?: number | string;
  /**
   *
   * Defaults to 100%
   */
  width?: number | string;
  /**
   *
   */
  data: any;
}

const getComponent = (type: ChartType) => {
  switch (type) {
    case 'ZoomableLines':
      return TimeSeriesZoomableLines;
    case 'Lines':
    default:
      return TimeSeriesLines;
  }
};

const Charts: React.FC<ChartsProps> = ({
  title,
  data,
  chartType,
  theme = ChartsThemeEnum.light,
  height,
  width,
}) => {
  const Chart = getComponent(chartType);

  echarts.registerTheme(theme, ThemeOptions[theme]);

  return (
    <>
      <Text size="large" mb={5}>
        {title}
      </Text>
      <Chart data={data} theme={theme} height={height} width={width} />
    </>
  );
};

export default Charts;
