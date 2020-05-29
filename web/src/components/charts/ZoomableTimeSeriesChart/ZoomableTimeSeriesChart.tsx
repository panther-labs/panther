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

interface ZoomableTimeSeriesChartProps {
  data: any;
}

const ZoomableTimeSeriesChart: React.FC<ZoomableTimeSeriesChartProps> = ({ data }) => {
  const container = React.useRef<HTMLDivElement>(null);

  React.useEffect(() => {
    /*
     * 'xAxisData' must be an array of values that is common for all series
     * Must be ordered
     * e.g. [05/14, 05/15, [04,16]
     */
    const xAxisData = data[Object.keys(data)[0]].points.map(p => p.timestamp);

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
    const series = Object.keys(data).map(key => {
      const dataPoints = data[key].points.map(point => point.count);
      return {
        name: key,
        type: 'line',
        smooth: true,
        sampling: 'average',
        itemStyle: {
          color: LineColors[key],
        },
        data: dataPoints,
      };
    });

    const options = {
      grid: {
        left: 200,
        right: 20,
        bottom: 40,
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
        left: 'left',
        icon: 'circle',
        data: legendData,
      },
      dataZoom: [
        {
          type: 'inside',
          start: 0,
          end: 25,
        },
        {
          start: 0,
          end: 25,
          handleIcon:
            'M10.7,11.9v-1.3H9.3v1.3c-4.9,0.3-8.8,4.4-8.8,9.4c0,5,3.9,9.1,8.8,9.4v1.3h1.3v-1.3c4.9-0.3,8.8-4.4,8.8-9.4C19.5,16.3,15.6,12.2,10.7,11.9z M13.3,24.4H6.7V23h6.6V24.4z M13.3,19.6H6.7v-1.4h6.6V19.6z',
          handleSize: '80%',
          handleStyle: {
            color: '#fff',
            shadowBlur: 3,
            shadowColor: 'rgba(0, 0, 0, 0.6)',
            shadowOffsetX: 2,
            shadowOffsetY: 2,
          },
        },
      ],
      xAxis: {
        // FIXME: This probably need to change to 'time' value with real data
        type: 'category',
        boundaryGap: 0,
        data: xAxisData,
      },
      yAxis: {
        type: 'value',
        boundaryGap: [0, '100%'],
      },
      series,
    };

    // load the line chart
    const lineChart = echarts.init(container.current);
    // @ts-ignore
    lineChart.setOption(options);
  }, [data]);

  return <Box ref={container} width="100%" height="100%" />;
};

export default React.memo(ZoomableTimeSeriesChart);
