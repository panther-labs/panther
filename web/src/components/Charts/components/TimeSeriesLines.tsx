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

interface TimeSeriesLinesProps {
  // TODO: To be defined properly
  data: any;
}

const TimeSeriesLines: React.FC<TimeSeriesLinesProps> = ({ data }) => {
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
        left: 'left',
        icon: 'circle',
        data: legendData,
      },
      xAxis: {
        // FIXME: This probably need to change to 'time' value with real data
        type: 'category',
        boundaryGap: 0,
        data: xAxisData,
      },
      yAxis: {
        type: 'value',
        boundaryGap: 0,
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

export default React.memo(TimeSeriesLines);
