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
import echarts from 'echarts';
import { theme as Theme } from 'pouncejs';
import ReactEcharts from 'echarts-for-react';
import { ChartsThemeEnum, ChartThemeType, ThemeOptions } from '../constants';

interface Data {
  value: number;
  label: string;
  color?: keyof typeof Theme['colors'];
}

interface BarsProps {
  data: Data[];
  theme?: ChartThemeType;
  height?: number | string;
  width?: number | string;
  loading?: boolean;
}

const Bars: React.FC<BarsProps> = ({
  data,
  theme = ChartsThemeEnum.light,
  height,
  width,
  loading,
}) => {
  echarts.registerTheme(theme, ThemeOptions[theme]);
  /*
   * 'xAxisData' must be an array of values that is common for all series
   * Must be ordered
   * e.g. [05/14, 05/15, [04,16]
   */
  // const xAxisData = data[Object.keys(data)[0]].points.map(p => p.timestamp);

  /*
   * 'legendData' must be an array of values that matches 'series.name'in order
   * to display them in correct order and color
   * e.g. [AWS.ALB]
   */
  const legendData = data.map(e => e.label);

  /*
   * 'series' must be an array of objects that includes some graph options
   * like 'type', 'symbol' and 'itemStyle' and most importantly 'data' which
   * is an array of values for all datapoints
   * Must be ordered
   */

  const series = data.map((e, seriesIndex) => {
    return {
      name: e.label,
      type: 'bar',
      // stack: 'a',
      barWidth: 30,
      // progressive: 5000,
      barGap: '-100%',
      label: {
        show: true,
        position: 'top',
        color: 'black',
      },
      itemStyle: {
        color: Theme.colors[e.color],
        barBorderRadius: 24,
      },
      data: data.map((d, i) => (i === seriesIndex ? d.value : '-')),
    };
  });

  const options = {
    grid: {
      left: 100,
      right: 20,
      bottom: 20,
      top: 30,
      containLabel: true,
    },
    tooltip: {
      // trigger: 'axis',
      position: pt => [pt[0], '100%'],
      // axisPointer: {
      //   // 坐标轴指示器，坐标轴触发有效
      //   type: 'shadow', // 默认为直线，可选为：'line' | 'shadow'
      // },
      formatter: params => {
        return `${params.seriesName} : ${params.value}`;
      },
    },
    legend: {
      type: 'scroll',
      orient: 'vertical',
      left: 'left',
      icon: 'circle',
      data: legendData,
    },
    xAxis: {
      // FIXME: This probably need to change to 'time' value with real data
      show: false,
      type: 'category',
      boundaryGap: true,
      data: data.map((e, i) => i),
    },
    yAxis: {
      show: false,
      type: 'value',
      boundaryGap: true,
    },
    series,
  };

  /*
   * 'loadingOption' sets up an out-of-box loading component 'echarts' is offering
   * to show a spinning loading animation
   */
  const loadingOption = {
    text: 'Loading',
    color: '#4413c2',
    textColor: '#270240',
    maskColor: 'rgba(176,175,175,0.3)',
  };

  return (
    <ReactEcharts
      // @ts-ignore
      option={options}
      theme={theme}
      loadingOption={loadingOption}
      style={{ width, height }}
      showLoading={loading}
    />
  );
};

export default Bars;
