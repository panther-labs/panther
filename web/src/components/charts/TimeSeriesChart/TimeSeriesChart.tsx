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
import { Box } from 'pouncejs';
import { LineColors } from '../constants';
import { transform } from 'lodash-es';

interface TimeSeriesLinesProps {
  // TODO: To be defined properly
  data: any;
}

const monthString = [
  'JAN',
  'FEB',
  'MAR',
  'APR',
  'MAY',
  'JUN',
  'JUL',
  'AUG',
  'SEP',
  'OCT',
  'NOV',
  'DEC',
];

function transformTimestamps(timestamp) {
  const d = new Date(timestamp);
  const date = d.getDate();
  const month = d.getMonth();
  return `${monthString[month]} ${date}`;
}

const TimeSeriesChart: React.FC<TimeSeriesLinesProps> = ({ data }) => {
  const container = React.useRef<HTMLDivElement>(null);
  React.useEffect(() => {
    /*
     * 'xAxisData' must be an array of values that is common for all series
     * Must be ordered
     * e.g. [05/14, 05/15, [04,16]
     */
    const xAxisData = data[0].timestamps;
    // .map(transformTimestamps);

    /*
     * 'legendData' must be an array of values that matches 'series.name'in order
     * to display them in correct order and color
     * e.g. [AWS.ALB]
     */
    const legendData = Object.keys(data);

    /*
     * 'series' must be an array of objects that includes some graph options
     * like 'type', 'symbol' and 'itemStyle' and most importantly 'data' which
     * is an array of values for all datapoints
     * Must be ordered
     */
    const series = data.map(({ label, values, timestamps }) => {
      return {
        name: label,
        type: 'line',
        smooth: true,
        sampling: 'average',
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
        left: 200,
        right: 20,
        bottom: 20,
        top: 10,
        // show: true,
        containLabel: true,
      },
      tooltip: {
        trigger: 'axis',
        position: pt => [pt[0], '100%'],
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
        type: 'time',
        boundaryGap: 0,
        data: xAxisData,
        splitLine: {
          show: false,
        },
      },
      yAxis: {
        type: 'value',
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
      series,
    };

    // load the timeSeriesChart
    const timeSeriesChart = echarts.init(container.current);
    // @ts-ignore
    timeSeriesChart.setOption(options);
  }, []);

  return <Box ref={container} width="100%" height="100%" />;
};

export default React.memo(TimeSeriesChart);
