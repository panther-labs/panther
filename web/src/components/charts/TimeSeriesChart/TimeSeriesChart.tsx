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
import { Box, theme } from 'pouncejs';
import { LineColors } from '../constants';

interface TimeSeriesLinesProps {
  // TODO: To be defined properly
  data: any;
}

const TimeSeriesChart: React.FC<TimeSeriesLinesProps> = ({ data }) => {
  const container = React.useRef<HTMLDivElement>(null);
  React.useEffect(() => {
    const { timestamps, series } = data;
    /*
     * 'legendData' must be an array of values that matches 'series.name'in order
     * to display them in correct order and color
     * e.g. [AWS.ALB]
     */
    const legendData = series.map(({ label }) => label);

    /*
     * 'series' must be an array of objects that includes some graph options
     * like 'type', 'symbol' and 'itemStyle' and most importantly 'data' which
     * is an array of values for all datapoints
     * Must be ordered
     */
    const seriesData = series.map(({ label, values }) => {
      return {
        name: label,
        type: 'line',
        smooth: true,
        symbol: 'none',
        itemStyle: {
          color: LineColors[label],
        },
        data: values.map((v, i) => {
          return {
            name: label,
            value: [timestamps[i], v],
          };
        }),
      };
    });

    const options = {
      grid: {
        left: 180,
        right: 20,
        bottom: 20,
        top: 10,
        containLabel: true,
      },
      tooltip: {
        trigger: 'axis',
        position: pt => [pt[0], '100%'],
      },
      legend: {
        type: 'scroll',
        orient: 'vertical',
        left: 'auto',
        right: 'auto',
        icon: 'circle',
        data: legendData,
        textStyle: {
          color: theme.colors['gray-50'],
        },
      },
      xAxis: {
        type: 'time',
        splitLine: {
          show: false,
        },
        axisLabel: {
          show: true,
          textStyle: {
            color: () => {
              return '#F6F6F6';
            },
          },
        },
      },
      yAxis: {
        type: 'value',
        splitNumber: 4,
        axisLabel: {
          padding: [0, 20, 0, 0],
          interval: 1,
          show: true,
          textStyle: {
            color: () => {
              return '#F6F6F6';
            },
          },
        },
        axisLine: {
          show: true,
        },
        splitLine: {
          lineStyle: {
            color: 'rgba(246,246,246)',
            opacity: 0.15,
            type: 'dashed',
          },
        },
      },
      series: seriesData,
    };

    // load the timeSeriesChart
    const timeSeriesChart = echarts.init(container.current);
    // @ts-ignore
    timeSeriesChart.setOption(options);
  }, []);

  return <Box ref={container} width="100%" height="100%" />;
};

export default React.memo(TimeSeriesChart);
